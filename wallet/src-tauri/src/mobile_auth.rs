//! Phone session: a 6-digit PIN with Face ID / Touch ID on top.
//!
//! The keystore stays exactly what it is on the desktop: the mnemonic sealed under a
//! password with Argon2id + ChaCha20-Poly1305. On a phone that password is a random
//! 32-byte *device secret* the user never sees. The secret is kept in two places:
//!
//! * `pin.json`: the secret sealed under the PIN (same Argon2id cost as the keystore,
//!   so a copied file still costs 64 MiB per guess), plus the failure counter and the
//!   lockout clock. Five wrong PINs start a 30 s lockout that doubles each time.
//! * The iOS Keychain (device-only item): read only after the OS has confirmed the
//!   owner with Face ID / Touch ID. The prompt is raised from Rust, so the JavaScript
//!   side never holds the secret and cannot skip the check.
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
    #[serde(default)]
    fails: u32,
    #[serde(default)]
    locked_until: u64, // unix seconds, 0 = not locked
}

#[derive(Serialize)]
pub struct AuthStatus {
    /// A keystore exists on this device.
    pub wallet: bool,
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
    let json = serde_json::to_string(f).map_err(|e| e.to_string())?;
    super::privfs::write_private(&pin_path(dir), json.as_bytes()).map_err(|e| e.to_string())
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
    PinFile { sealed: super::seal(pin, secret), fails: 0, locked_until: 0 }
}

/// Check the PIN against `pin.json`, applying and recording the lockout policy.
fn open_with_pin(dir: &str, pin: &str) -> Result<Zeroizing<String>, String> {
    let mut f = read_pin_file(dir)?;
    let t = now();
    if f.locked_until > t {
        return Err(format!("locked:{}", f.locked_until - t));
    }
    match unseal(pin, &f.sealed) {
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
    const SERVICE: &str = "io.zcrypt.wallet";
    const ACCOUNT: &str = "device-secret";
    pub fn store(secret: &str) -> Result<(), String> {
        security_framework::passwords::set_generic_password(SERVICE, ACCOUNT, secret.as_bytes())
            .map_err(|e| format!("keychain: {e}"))
    }
    pub fn load() -> Result<Option<Vec<u8>>, String> {
        match security_framework::passwords::get_generic_password(SERVICE, ACCOUNT) {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.code() == security_framework_sys::base::errSecItemNotFound => Ok(None),
            Err(e) => Err(format!("keychain: {e}")),
        }
    }
    pub fn delete() -> Result<(), String> {
        match security_framework::passwords::delete_generic_password(SERVICE, ACCOUNT) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == security_framework_sys::base::errSecItemNotFound => Ok(()),
            Err(e) => Err(format!("keychain: {e}")),
        }
    }
    pub fn exists() -> bool {
        matches!(load(), Ok(Some(_)))
    }
}

#[cfg(not(target_os = "ios"))]
mod keychain {
    //! Desktop and Android stand-in: a private file in the wallet directory. The Face ID
    //! gate still runs in front of it on a device that has one.
    use std::path::{Path, PathBuf};
    fn path() -> PathBuf {
        Path::new(&super::DIR.with(|d| d.borrow().clone())).join(super::BIO_FILE)
    }
    pub fn store(secret: &str) -> Result<(), String> {
        super::super::privfs::write_private(&path(), secret.as_bytes()).map_err(|e| e.to_string())
    }
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
}

#[cfg(not(target_os = "ios"))]
thread_local! {
    static DIR: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
}
#[cfg(not(target_os = "ios"))]
fn set_dir(dir: &str) {
    DIR.with(|d| *d.borrow_mut() = dir.to_string());
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

/// Raise the system Face ID / Touch ID sheet and wait for the answer. The app's own PIN
/// is the fallback, so the device passcode is deliberately not offered here.
#[cfg(mobile)]
async fn prompt(app: tauri::AppHandle, reason: &str) -> Result<(), String> {
    use tauri_plugin_biometric::{AuthOptions, BiometricExt};
    let reason = reason.to_string();
    tauri::async_runtime::spawn_blocking(move || {
        app.biometric()
            .authenticate(
                reason,
                AuthOptions {
                    allow_device_credential: false,
                    cancel_title: Some("Cancel".into()),
                    fallback_title: Some("Use PIN".into()),
                    ..Default::default()
                },
            )
            .map_err(|e| format!("biometric:{e}"))
    })
    .await
    .map_err(|e| e.to_string())?
}
#[cfg(not(mobile))]
async fn prompt(_app: tauri::AppHandle, _reason: &str) -> Result<(), String> {
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
            prompt(app, reason).await?;
            let bytes = keychain::load()?.ok_or("biometric:not enabled")?;
            String::from_utf8(bytes).map(Zeroizing::new).map_err(|_| "keychain item is corrupt".to_string())
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
    ok(AuthStatus {
        wallet,
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
    state: State<'_, AppState>,
) -> R<super::CreateResult> {
    valid_pin(&pin)?;
    let dir = state.data_dir.lock().unwrap().clone();
    set_dir(&dir);
    let secret = new_device_secret();
    let created = match mnemonic {
        Some(m) => super::restore_wallet(secret.to_string(), m, state).await?,
        None => super::create_wallet(secret.to_string(), state).await?,
    };
    let pin_file = tauri::async_runtime::spawn_blocking({
        let secret = secret.clone();
        move || seal_secret(&pin, &secret)
    })
    .await
    .map_err(|e| e.to_string())?;
    write_pin_file(&dir, &pin_file)?;
    if biometric {
        keychain::store(&secret)?;
    } else {
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

/// Switch Face ID unlock on (needs the PIN to release the secret) or off.
#[tauri::command]
pub async fn mobile_set_biometric(enabled: bool, pin: Option<String>, app: tauri::AppHandle, state: State<'_, AppState>) -> R<bool> {
    let dir = state.data_dir.lock().unwrap().clone();
    set_dir(&dir);
    if enabled {
        let secret = authenticate(app, &dir, Some(pin.ok_or("the PIN is needed to switch Face ID on")?), "").await?;
        keychain::store(&secret)?;
    } else {
        keychain::delete()?;
    }
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
pub async fn mobile_adopt(password: String, pin: String, biometric: bool, state: State<'_, AppState>) -> R<bool> {
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
    if biometric {
        keychain::store(&secret)?;
    } else {
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
    fn pin_shape() {
        assert!(valid_pin("012345").is_ok());
        assert!(valid_pin("12345").is_err());
        assert!(valid_pin("1234567").is_err());
        assert!(valid_pin("12345a").is_err());
    }
}
