//! Phone session: a 6-digit PIN with Face ID / Touch ID on top.
//!
//! The keystore stays exactly what it is on the desktop: the mnemonic sealed under a
//! password with Argon2id + ChaCha20-Poly1305. On a phone that password is a random
//! 32-byte *device secret* the user never sees. The secret is kept in two places:
//!
//! * `pin.json`: the secret sealed under the PIN (same Argon2id cost as the keystore),
//!   plus the failure counter and the lockout clock. Five wrong PINs start a 30 s lockout
//!   that doubles each time. A 6-digit PIN has only a million values, so on iOS the
//!   sealed secret is encrypted once more under a random key that lives in the Keychain
//!   and never leaves this device: a copy of `pin.json` (a backup, a file dump) gives
//!   nothing to test a guess against. The price is that a backup restored onto another
//!   phone cannot be opened with the PIN there; it needs the recovery phrase.
//! * The iOS Keychain item holding the secret for Face ID / Touch ID: device-only and
//!   bound to the biometrics enrolled when it was written. The system itself asks for
//!   Face ID when the item is read and refuses the read without it, so no code path in
//!   the app, and no file or Keychain dump, gets the secret without the owner's face or
//!   finger. Enrolling a new face or finger voids the item; the PIN switches it on again.
//! * On Android, `bio.key`: the secret encrypted under an Android Keystore AES-GCM key
//!   (hardware-backed, non-exportable, usable only inside a strong-biometric prompt and
//!   voided by a new fingerprint enrollment). The prompt and the decryption are one
//!   operation, so a copied `bio.key` is useless without the phone and its owner.
//!
//! Face ID can be switched off (the Keychain copy is deleted); the PIN always works.

use super::{keystore_path, ok, unseal, AppState, Keystore, R};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tauri::State;
use zcrypt_core::keys;
use zeroize::Zeroizing;

const PIN_FILE: &str = "pin.json";
#[cfg(not(target_os = "ios"))]
const BIO_FILE: &str = "bio.key"; // non-iOS fallback for the Keychain item
const FREE_ATTEMPTS: u32 = 5;
const FIRST_LOCKOUT_S: u64 = 30;
const MAX_LOCKOUT_S: u64 = 60 * 60;

#[derive(Serialize, Deserialize)]
struct PinFile {
    sealed: Keystore, // device secret under the PIN
    /// Set when `sealed.ct` is encrypted again under this device's Keychain key: the
    /// nonce of that outer layer. Absent in files written before the key existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    wrap: Option<String>,
    #[serde(default)]
    fails: u32,
    #[serde(default)]
    locked_until: u64, // unix seconds, 0 = not locked
}

#[derive(Serialize)]
pub struct AuthStatus {
    /// A keystore exists on this device.
    pub wallet: bool,
    /// The wallet files came from another phone (a restored backup): the key that
    /// protects the PIN is not on this one, so only the recovery phrase can open it.
    pub copied: bool,
    /// A PIN protects it (false on a wallet created by the desktop flow).
    pub pin: bool,
    /// Face ID / Touch ID unlock is switched on for this wallet.
    pub biometric: bool,
    /// The device can do biometrics right now (hardware present and enrolled).
    pub biometry_available: bool,
    /// "faceid", "touchid" or "none".
    pub biometry_type: String,
    /// Seconds before another PIN may be tried (0 = now).
    pub locked_for_s: u64,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn pin_path(dir: &str) -> PathBuf {
    Path::new(dir).join(PIN_FILE)
}

fn read_pin_file(dir: &str) -> Result<PinFile, String> {
    let raw = std::fs::read_to_string(pin_path(dir)).map_err(|_| "no PIN is set on this device")?;
    serde_json::from_str(&raw).map_err(|e| format!("pin file: {e}"))
}

fn write_pin_file(dir: &str, f: &PinFile) -> Result<(), String> {
    // A file that is not under the device key yet goes under it now. If the Keychain
    // cannot give a key the file is written as it is: a wallet that opens is worth more
    // than the extra layer, and the next write tries again.
    let wrapped = match (&f.wrap, keychain::wrap_key(true)) {
        (None, Ok(Some(key))) => wrap_pin_file(f, &key),
        _ => None,
    };
    let json = serde_json::to_string(wrapped.as_ref().unwrap_or(f)).map_err(|e| e.to_string())?;
    super::privfs::write_private(&pin_path(dir), json.as_bytes()).map_err(|e| e.to_string())
}

const COPIED: &str = "this wallet was copied from another phone; restore it with the recovery phrase";

/// The outer layer: `sealed.ct` encrypted under the device key. Salt and nonce of the
/// inner layer stay readable; without the inner ciphertext they verify nothing.
fn wrap_pin_file(f: &PinFile, key: &[u8; 32]) -> Option<PinFile> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    let inner = hex::decode(&f.sealed.ct).ok()?;
    let nonce = keys::random_seed();
    let ct = ChaCha20Poly1305::new_from_slice(key).ok()?.encrypt(Nonce::from_slice(&nonce[..12]), inner.as_ref()).ok()?;
    Some(PinFile {
        sealed: Keystore { salt: f.sealed.salt.clone(), nonce: f.sealed.nonce.clone(), ct: hex::encode(ct) },
        wrap: Some(hex::encode(&nonce[..12])),
        fails: f.fails,
        locked_until: f.locked_until,
    })
}

/// What the PIN is checked against: `sealed` as it is, or with the outer layer taken
/// off. `key` is the device key, `None` when this device has none.
fn pin_sealed(f: &PinFile, key: Option<&[u8; 32]>) -> Result<Keystore, String> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    let mut ct = f.sealed.ct.clone();
    if let Some(nonce) = &f.wrap {
        let open = || -> Option<String> {
            let nonce = hex::decode(nonce).ok().filter(|n| n.len() == 12)?;
            let outer = hex::decode(&f.sealed.ct).ok()?;
            let inner = ChaCha20Poly1305::new_from_slice(key?).ok()?.decrypt(Nonce::from_slice(&nonce), outer.as_ref()).ok()?;
            Some(hex::encode(inner))
        };
        ct = open().ok_or(COPIED)?;
    }
    Ok(Keystore { salt: f.sealed.salt.clone(), nonce: f.sealed.nonce.clone(), ct })
}

/// True when `pin.json` is under a device key this phone does not have. A Keychain that
/// cannot be read right now is not that: only a clean "no such item" counts.
fn is_copied(f: &PinFile) -> bool {
    f.wrap.is_some() && matches!(keychain::wrap_key(false), Ok(None))
}

fn valid_pin(pin: &str) -> Result<(), String> {
    if pin.len() != 6 || !pin.bytes().all(|b| b.is_ascii_digit()) {
        return Err("the PIN must be exactly 6 digits".into());
    }
    Ok(())
}

fn new_device_secret() -> Zeroizing<String> {
    Zeroizing::new(hex::encode(keys::random_seed()))
}

fn seal_secret(pin: &str, secret: &str) -> PinFile {
    PinFile { sealed: super::seal(pin, secret), wrap: None, fails: 0, locked_until: 0 }
}

/// Check the PIN against `pin.json`, applying and recording the lockout policy.
/// One PIN attempt at a time: the failure counter is read, bumped and written back, so
/// attempts are serialized to keep the count exact.
static PIN_ATTEMPT: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn open_with_pin(dir: &str, pin: &str) -> Result<Zeroizing<String>, String> {
    let _one_at_a_time = PIN_ATTEMPT.lock().unwrap_or_else(|e| e.into_inner());
    let mut f = read_pin_file(dir)?;
    let t = now();
    if f.locked_until > t {
        return Err(format!("locked:{}", f.locked_until - t));
    }
    let key = keychain::wrap_key(false)?;
    let sealed = pin_sealed(&f, key.as_ref())?;
    match unseal(pin, &sealed) {
        Some(secret) => {
            if f.fails != 0 || f.locked_until != 0 {
                f.fails = 0;
                f.locked_until = 0;
                let _ = write_pin_file(dir, &f);
            }
            Ok(secret)
        }
        None => {
            f.fails += 1;
            if f.fails >= FREE_ATTEMPTS {
                let doublings = (f.fails - FREE_ATTEMPTS).min(12);
                let wait = (FIRST_LOCKOUT_S << doublings).min(MAX_LOCKOUT_S);
                f.locked_until = t + wait;
            }
            let left = FREE_ATTEMPTS.saturating_sub(f.fails);
            write_pin_file(dir, &f)?;
            if f.locked_until > t {
                Err(format!("locked:{}", f.locked_until - t))
            } else {
                Err(format!("wrong:{left}"))
            }
        }
    }
}

// ---- the biometric copy of the device secret -------------------------------------------

#[cfg(target_os = "ios")]
mod keychain {
    use security_framework::access_control::{ProtectionMode, SecAccessControl};
    use security_framework::base::Error;
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password, set_generic_password_options, AccessControlOptions,
        PasswordOptions,
    };
    use security_framework_sys::base::errSecItemNotFound;

    const SERVICE: &str = "io.zcrypt.wallet";
    /// The device secret, readable only through Face ID / Touch ID.
    const ACCOUNT: &str = "device-secret";
    /// Says that `ACCOUNT` is the protected kind. It is written before the protected item
    /// and holds nothing secret; it lets the app know biometrics are on without reading
    /// the protected item, which would raise the Face ID sheet.
    const MARKER: &str = "device-secret-protected";
    /// The key `pin.json` is wrapped under.
    const WRAP: &str = "pin-wrap-key";

    fn missing(e: &Error) -> bool {
        e.code() == errSecItemNotFound
    }
    fn get(account: &str) -> Result<Option<Vec<u8>>, Error> {
        match get_generic_password(SERVICE, account) {
            Ok(v) => Ok(Some(v)),
            Err(e) if missing(&e) => Ok(None),
            Err(e) => Err(e),
        }
    }
    fn remove(account: &str) -> Result<(), String> {
        match delete_generic_password(SERVICE, account) {
            Ok(()) => Ok(()),
            Err(e) if missing(&e) => Ok(()),
            Err(e) => Err(format!("keychain: {e}")),
        }
    }
    /// Add an item that stays on this device, with `flags` as its access control. The
    /// old item goes first: an update cannot change the protection of an existing one.
    fn add(account: &str, value: &[u8], mode: ProtectionMode, flags: AccessControlOptions) -> Result<(), String> {
        remove(account)?;
        let mut options = PasswordOptions::new_generic_password(SERVICE, account);
        options.set_access_control(SecAccessControl::create_with_protection(Some(mode), flags.bits()).map_err(|e| format!("keychain: {e}"))?);
        set_generic_password_options(value, options).map_err(|e| format!("keychain: {e}"))
    }

    pub fn store(secret: &str) -> Result<(), String> {
        set_generic_password(SERVICE, MARKER, b"1").map_err(|e| format!("keychain: {e}"))?;
        let stored = add(
            ACCOUNT,
            secret.as_bytes(),
            ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly,
            AccessControlOptions::BIOMETRY_CURRENT_SET,
        );
        if stored.is_err() {
            let _ = remove(MARKER);
        }
        stored
    }
    /// Reads the protected item: the system shows Face ID / Touch ID and blocks until the
    /// owner answers, so this must not run on the main thread. Anything but success is a
    /// `biometric:` error, which the screens answer by asking for the PIN.
    pub fn load() -> Result<Option<Vec<u8>>, String> {
        match get(ACCOUNT) {
            Ok(Some(v)) => Ok(Some(v)),
            Ok(None) => {
                // Voided by a new face or finger, or never written.
                let _ = remove(MARKER);
                Ok(None)
            }
            Err(e) => Err(format!("biometric:{e}")),
        }
    }
    pub fn delete() -> Result<(), String> {
        remove(ACCOUNT)?;
        remove(MARKER)
    }
    /// Whether biometric unlock is on. Never raises the Face ID sheet. An item written by
    /// a build that did not protect it is read here (that one needs no Face ID) and put
    /// back protected.
    pub fn exists() -> bool {
        if matches!(get(MARKER), Ok(Some(_))) {
            return true;
        }
        match get(ACCOUNT) {
            Ok(Some(old)) => match String::from_utf8(old) {
                Ok(secret) => store(&secret).is_ok(),
                Err(_) => false,
            },
            _ => false,
        }
    }
    /// The key `pin.json` is wrapped under: `Ok(None)` when this device has none and
    /// `create` is off. It stays on this device and is readable while it is unlocked.
    pub fn wrap_key(create: bool) -> Result<Option<[u8; 32]>, String> {
        let as_key = |v: Vec<u8>| <[u8; 32]>::try_from(v.as_slice()).map_err(|_| "keychain: the PIN key has the wrong size".to_string());
        if let Some(v) = get(WRAP).map_err(|e| format!("keychain: {e}"))? {
            return as_key(v).map(Some);
        }
        if !create {
            return Ok(None);
        }
        let key = zcrypt_core::keys::random_seed();
        add(WRAP, &key, ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly, AccessControlOptions::empty())?;
        // Use the key only if the Keychain really kept it.
        match get(WRAP).map_err(|e| format!("keychain: {e}"))? {
            Some(v) => as_key(v).map(Some),
            None => Err("keychain: the PIN key was not kept".into()),
        }
    }
}

#[cfg(not(target_os = "ios"))]
mod keychain {
    //! A private file in the wallet directory. On Android it holds the Keystore
    //! ciphertext of the secret (see [`store_bio`]); on the desktop biometrics are never
    //! offered, so the file is never written.
    use std::path::{Path, PathBuf};
    fn path() -> PathBuf {
        Path::new(&super::DIR.read().unwrap().clone()).join(super::BIO_FILE)
    }
    pub fn store(secret: &str) -> Result<(), String> {
        super::super::privfs::write_private(&path(), secret.as_bytes()).map_err(|e| e.to_string())
    }
    #[cfg_attr(not(target_os = "android"), allow(dead_code))]
    pub fn load() -> Result<Option<Vec<u8>>, String> {
        match std::fs::read(path()) {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
    pub fn delete() -> Result<(), String> {
        match std::fs::remove_file(path()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }
    pub fn exists() -> bool {
        path().exists()
    }
    /// No device key here: `pin.json` stays as the PIN sealed it.
    pub fn wrap_key(_create: bool) -> Result<Option<[u8; 32]>, String> {
        Ok(None)
    }
}

// Process-wide, not thread-local: the commands that set it `.await` before the file is
// touched, and an async task can resume on a different worker thread. A thread-local
// would then read as empty there, and `bio.key` would be written relative to the working
// directory (or not at all, leaving biometrics silently off).
#[cfg(not(target_os = "ios"))]
static DIR: std::sync::RwLock<String> = std::sync::RwLock::new(String::new());
#[cfg(not(target_os = "ios"))]
fn set_dir(dir: &str) {
    *DIR.write().unwrap() = dir.to_string();
}
#[cfg(target_os = "ios")]
fn set_dir(_dir: &str) {}

// ---- the OS prompt --------------------------------------------------------------------

#[cfg(mobile)]
fn biometry(app: &tauri::AppHandle) -> (bool, String) {
    use tauri_plugin_biometric::{BiometricExt, BiometryType};
    match app.biometric().status() {
        Ok(s) => {
            let kind = match s.biometry_type {
                BiometryType::FaceID => "faceid",
                BiometryType::TouchID => "touchid",
                BiometryType::None => "none",
            };
            (s.is_available, kind.to_string())
        }
        Err(_) => (false, "none".to_string()),
    }
}
#[cfg(not(mobile))]
fn biometry(_app: &tauri::AppHandle) -> (bool, String) {
    (false, "none".to_string())
}

/// Put the device secret behind the phone's biometric. iOS: a Keychain item. Android: the
/// biometric plugin's Keystore key encrypts it inside a prompt (so the user confirms the
/// biometric works before it is switched on) and the ciphertext goes to `bio.key`.
#[cfg(target_os = "android")]
async fn store_bio(app: tauri::AppHandle, secret: &str) -> Result<(), String> {
    use tauri_plugin_biometric::{AuthOptions, BiometricExt};
    let secret = secret.to_string();
    let sealed = tauri::async_runtime::spawn_blocking(move || {
        app.biometric()
            .biometric_cipher(
                String::new(), // the title carries the message; the reason would repeat it
                AuthOptions {
                    title: Some("Turn on biometric unlock".into()),
                    cancel_title: Some("Cancel".into()),
                    data_to_encrypt: Some(secret),
                    ..Default::default()
                },
            )
            .map_err(|e| format!("biometric:{e}"))
    })
    .await
    .map_err(|e| e.to_string())??;
    keychain::store(&sealed.data)
}
#[cfg(not(target_os = "android"))]
async fn store_bio(_app: tauri::AppHandle, secret: &str) -> Result<(), String> {
    keychain::store(secret)
}

/// The biometric sheet → the device secret. Android decrypts `bio.key` inside the prompt.
#[cfg(target_os = "android")]
async fn load_bio(app: tauri::AppHandle, reason: &str) -> Result<Zeroizing<String>, String> {
    use tauri_plugin_biometric::{AuthOptions, BiometricExt};
    let sealed = keychain::load()?.ok_or("biometric:not enabled")?;
    let sealed = String::from_utf8(sealed).map_err(|_| "bio.key is corrupt".to_string())?;
    let title = reason.to_string();
    let out = tauri::async_runtime::spawn_blocking(move || {
        app.biometric()
            .biometric_cipher(
                String::new(), // the title carries the message; the reason would repeat it
                AuthOptions {
                    title: Some(title),
                    cancel_title: Some("Use PIN".into()),
                    data_to_decrypt: Some(sealed),
                    ..Default::default()
                },
            )
            .map_err(|e| format!("biometric:{e}"))
    })
    .await
    .map_err(|e| e.to_string())??;
    Ok(Zeroizing::new(out.data))
}
/// iOS: reading the Keychain item IS the Face ID check. The system raises the sheet and
/// releases the secret only to the enrolled owner, so there is no separate prompt whose
/// answer the app could ignore.
#[cfg(target_os = "ios")]
async fn load_bio(_app: tauri::AppHandle, _reason: &str) -> Result<Zeroizing<String>, String> {
    let bytes = tauri::async_runtime::spawn_blocking(keychain::load)
        .await
        .map_err(|e| e.to_string())??
        .ok_or("biometric:not enabled")?;
    String::from_utf8(bytes).map(Zeroizing::new).map_err(|_| "keychain item is corrupt".to_string())
}
#[cfg(not(any(target_os = "android", target_os = "ios")))]
async fn load_bio(_app: tauri::AppHandle, _reason: &str) -> Result<Zeroizing<String>, String> {
    Err("biometric:not available on this device".into())
}

/// Either the PIN (`Some`) or the biometric sheet (`None`) → the device secret.
async fn authenticate(app: tauri::AppHandle, dir: &str, pin: Option<String>, reason: &str) -> Result<Zeroizing<String>, String> {
    set_dir(dir);
    match pin {
        Some(p) => {
            let dir = dir.to_string();
            tauri::async_runtime::spawn_blocking(move || open_with_pin(&dir, &p)).await.map_err(|e| e.to_string())?
        }
        None => {
            if !keychain::exists() {
                return Err("biometric:not enabled".into());
            }
            load_bio(app, reason).await
        }
    }
}

// ---- commands ---------------------------------------------------------------------------

#[tauri::command]
pub async fn mobile_auth_status(app: tauri::AppHandle, state: State<'_, AppState>) -> R<AuthStatus> {
    let dir = state.data_dir.lock().unwrap().clone();
    set_dir(&dir);
    let wallet = keystore_path(&dir).exists();
    let pin = read_pin_file(&dir).ok();
    let locked_for_s = pin.as_ref().map(|f| f.locked_until.saturating_sub(now())).unwrap_or(0);
    let (biometry_available, biometry_type) = biometry(&app);
    // A PIN file from before the device key existed is put under it on this launch.
    if let Some(f) = pin.as_ref().filter(|f| f.wrap.is_none()) {
        let _ = write_pin_file(&dir, f);
    }
    ok(AuthStatus {
        wallet,
        copied: wallet && pin.as_ref().is_some_and(is_copied),
        pin: pin.is_some(),
        biometric: keychain::exists(),
        biometry_available,
        biometry_type,
        locked_for_s,
    })
}

/// Create a new wallet (no `mnemonic`) or restore one, protected by `pin`. The device
/// secret is generated here and never shown. With `biometric`, Face ID unlock is switched
/// on right away.
#[tauri::command]
pub async fn mobile_create(
    pin: String,
    mnemonic: Option<String>,
    biometric: bool,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> R<super::CreateResult> {
    valid_pin(&pin)?;
    let dir = state.data_dir.lock().unwrap().clone();
    set_dir(&dir);
    let secret = new_device_secret();
    // An existing wallet is never replaced (`refuse_if_wallet_exists`), so from here on
    // the keystore on disk is the one this call wrote.
    let created = match mnemonic {
        Some(m) => super::restore_wallet(secret.to_string(), m, state).await?,
        None => super::create_wallet(secret.to_string(), state).await?,
    };
    // The keystore is sealed under a device secret only the PIN file can give back. If
    // the PIN file cannot be written, that keystore can never be opened and would block
    // every later attempt, so the half-made wallet is removed again. Nothing is lost: a
    // new wallet's phrase has not been shown yet, and a restored one came from the user.
    let sealed = tauri::async_runtime::spawn_blocking({
        let secret = secret.clone();
        move || seal_secret(&pin, &secret)
    })
    .await
    .map_err(|e| e.to_string())
    .and_then(|pin_file| write_pin_file(&dir, &pin_file));
    if let Err(e) = sealed {
        let _ = std::fs::remove_file(super::keystore_path(&dir));
        return Err(format!("could not finish setting up the wallet: {e}"));
    }
    // A cancelled or failed prompt here must not cost the user the wallet just made:
    // biometrics simply stay off and can be switched on from Settings.
    if !biometric || store_bio(app, &secret).await.is_err() {
        let _ = keychain::delete();
    }
    Ok(created)
}

/// Unlock with the PIN, or with Face ID when `pin` is `None`. Errors are machine-readable:
/// `wrong:<attempts left>`, `locked:<seconds>`, `biometric:<reason>`.
#[tauri::command]
pub async fn mobile_unlock(pin: Option<String>, app: tauri::AppHandle, state: State<'_, AppState>) -> R<bool> {
    let dir = state.data_dir.lock().unwrap().clone();
    let secret = authenticate(app, &dir, pin, "Unlock your ZCrypt wallet").await?;
    super::unlock_wallet(secret.to_string(), state).await
}

/// Confirm the owner is present before a payment leaves the wallet. Same inputs and
/// errors as `mobile_unlock`; the wallet must already be open.
#[tauri::command]
pub async fn mobile_confirm(pin: Option<String>, app: tauri::AppHandle, state: State<'_, AppState>) -> R<bool> {
    if state.wallet.lock().unwrap().is_none() {
        return Err("wallet is locked".into());
    }
    let dir = state.data_dir.lock().unwrap().clone();
    authenticate(app, &dir, pin, "Confirm this payment").await?;
    ok(true)
}

/// Show the 24-word recovery phrase, after Face ID or the PIN. The authentication
/// releases the device secret, which then unseals the keystore, so a cancelled Face ID
/// or a wrong PIN reveals nothing. The phrase is not kept anywhere by the shell.
#[tauri::command]
pub async fn mobile_reveal_phrase(pin: Option<String>, app: tauri::AppHandle, state: State<'_, AppState>) -> R<super::SecretString> {
    if state.wallet.lock().unwrap().is_none() {
        return Err("wallet is locked".into());
    }
    let dir = state.data_dir.lock().unwrap().clone();
    let secret = authenticate(app, &dir, pin, "Show your recovery phrase").await?;
    let raw = std::fs::read_to_string(keystore_path(&dir)).map_err(|_| "no wallet")?;
    let ks: Keystore = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    let phrase = unseal(&secret, &ks).ok_or("wrong password")?;
    ok(super::SecretString(Zeroizing::new(phrase.to_string())))
}

/// Show the private key of ONE shielded (stealth) address, after Face ID or the PIN: the
/// phone's form of `reveal_stealth_backup`, which asks for the wallet password a phone
/// user never types. One key per check, never the whole list.
#[tauri::command]
pub async fn mobile_reveal_stealth(index: u32, pin: Option<String>, app: tauri::AppHandle, state: State<'_, AppState>) -> R<super::SecretString> {
    if state.wallet.lock().unwrap().is_none() {
        return Err("wallet is locked".into());
    }
    let dir = state.data_dir.lock().unwrap().clone();
    authenticate(app, &dir, pin, "Show this address's private key").await?;
    let g = state.wallet.lock().unwrap();
    let w = g.as_ref().ok_or("wallet is locked")?;
    let seed = w.stealth_seeds.get(index as usize).ok_or("no such shielded address")?;
    ok(super::SecretString(Zeroizing::new(hex::encode(seed))))
}

/// Switch Face ID unlock on (needs the PIN to release the secret) or off.
#[tauri::command]
pub async fn mobile_set_biometric(enabled: bool, pin: Option<String>, app: tauri::AppHandle, state: State<'_, AppState>) -> R<bool> {
    let dir = state.data_dir.lock().unwrap().clone();
    set_dir(&dir);
    if enabled {
        let secret = authenticate(app.clone(), &dir, Some(pin.ok_or("the PIN is needed to switch Face ID on")?), "").await?;
        store_bio(app, &secret).await?;
    } else {
        keychain::delete()?;
    }
    ok(true)
}

/// A wallet copied from another phone cannot be opened here with its PIN. Put its files
/// aside (renamed, not deleted) so the recovery phrase can restore the wallet on this
/// phone. Refused for a wallet this phone can open.
#[tauri::command]
pub async fn mobile_forget_copied(state: State<'_, AppState>) -> R<bool> {
    let dir = state.data_dir.lock().unwrap().clone();
    set_dir(&dir);
    if !is_copied(&read_pin_file(&dir)?) {
        return Err("this wallet belongs to this phone; it is not removed".into());
    }
    *state.wallet.lock().unwrap() = None;
    let stamp = now();
    for path in [keystore_path(&dir), pin_path(&dir), super::coins_path(&dir)] {
        if path.exists() {
            let mut aside = path.clone().into_os_string();
            aside.push(format!(".copied-{stamp}"));
            std::fs::rename(&path, &aside).map_err(|e| format!("could not put {} aside: {e}", path.display()))?;
        }
    }
    let _ = keychain::delete();
    ok(true)
}

#[tauri::command]
pub async fn mobile_change_pin(old: String, new: String, app: tauri::AppHandle, state: State<'_, AppState>) -> R<bool> {
    valid_pin(&new)?;
    let dir = state.data_dir.lock().unwrap().clone();
    let secret = authenticate(app, &dir, Some(old), "").await?;
    let f = tauri::async_runtime::spawn_blocking(move || seal_secret(&new, &secret)).await.map_err(|e| e.to_string())?;
    write_pin_file(&dir, &f)?;
    ok(true)
}

/// A wallet that was created with a password (desktop flow, or an earlier build of this
/// app) is moved under a PIN: the mnemonic is unsealed with the password and sealed again
/// under a fresh device secret. The password stops working afterwards.
#[tauri::command]
pub async fn mobile_adopt(password: String, pin: String, biometric: bool, app: tauri::AppHandle, state: State<'_, AppState>) -> R<bool> {
    valid_pin(&pin)?;
    let dir = state.data_dir.lock().unwrap().clone();
    set_dir(&dir);
    let raw = std::fs::read_to_string(keystore_path(&dir)).map_err(|_| "no wallet on disk")?;
    let ks: Keystore = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    let secret = new_device_secret();
    let (ks2, pin_file) = tauri::async_runtime::spawn_blocking({
        let secret = secret.clone();
        move || -> Result<(Keystore, PinFile), String> {
            let mnemonic = unseal(&password, &ks).ok_or("wrong password")?;
            Ok((super::seal(&secret, &mnemonic), seal_secret(&pin, &secret)))
        }
    })
    .await
    .map_err(|e| e.to_string())??;
    super::write_keystore(&dir, &ks2)?;
    write_pin_file(&dir, &pin_file)?;
    if !biometric || store_bio(app, &secret).await.is_err() {
        let _ = keychain::delete();
    }
    super::unlock_wallet(secret.to_string(), state).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_round_trip_and_lockout() {
        let tmp = std::env::temp_dir().join(format!("zc-pin-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let dir = tmp.to_string_lossy().to_string();
        write_pin_file(&dir, &seal_secret("123456", "s3cret")).unwrap();
        assert_eq!(open_with_pin(&dir, "123456").unwrap().as_str(), "s3cret");
        for left in (1..FREE_ATTEMPTS).rev() {
            assert_eq!(open_with_pin(&dir, "000000").unwrap_err(), format!("wrong:{left}"));
        }
        // the fifth miss starts the 30 s lockout, and the right PIN is refused during it
        assert!(open_with_pin(&dir, "000000").unwrap_err().starts_with("locked:"));
        assert!(open_with_pin(&dir, "123456").unwrap_err().starts_with("locked:"));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_wrapped_pin_file_opens_only_with_the_device_key() {
        let plain = seal_secret("123456", "s3cret");
        let key = [7u8; 32];
        let wrapped = wrap_pin_file(&plain, &key).expect("wrap");
        assert!(wrapped.wrap.is_some());
        assert_ne!(wrapped.sealed.ct, plain.sealed.ct);
        // With the key the PIN opens it, and a wrong PIN is still just a wrong PIN.
        let sealed = pin_sealed(&wrapped, Some(&key)).expect("unwrap");
        assert_eq!(unseal("123456", &sealed).unwrap().as_str(), "s3cret");
        assert!(unseal("000000", &sealed).is_none());
        // Without the key, or with another phone's key, there is nothing to try a PIN on.
        assert_eq!(pin_sealed(&wrapped, None).err().as_deref(), Some(COPIED));
        assert_eq!(pin_sealed(&wrapped, Some(&[8u8; 32])).err().as_deref(), Some(COPIED));
        // The inner ciphertext is not in the file: the right PIN fails against the outer one.
        assert!(unseal("123456", &wrapped.sealed).is_none());
        // A file from before the device key reads as it always did, and survives a round trip.
        let old: PinFile = serde_json::from_str(&serde_json::to_string(&plain).unwrap()).unwrap();
        assert!(old.wrap.is_none());
        assert_eq!(unseal("123456", &pin_sealed(&old, None).unwrap()).unwrap().as_str(), "s3cret");
        let back: PinFile = serde_json::from_str(&serde_json::to_string(&wrapped).unwrap()).unwrap();
        assert_eq!(unseal("123456", &pin_sealed(&back, Some(&key)).unwrap()).unwrap().as_str(), "s3cret");
    }

    #[test]
    fn pin_shape() {
        assert!(valid_pin("012345").is_ok());
        assert!(valid_pin("12345").is_err());
        assert!(valid_pin("1234567").is_err());
        assert!(valid_pin("12345a").is_err());
    }
}
