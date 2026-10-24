//! Desktop entry point. The whole wallet lives in the library crate so the same code
//! is the iOS app (`tauri::mobile_entry_point`) and the macOS / Linux / Windows binary.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    zcrypt_wallet_lib::run()
}
