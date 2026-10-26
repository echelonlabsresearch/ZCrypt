/**
 * A browser-only stand-in for the Rust backend, so the screens can be viewed and styled in
 * a plain browser (`npm run dev`, then open http://localhost:1420/?mock=1). Loaded only in
 * dev builds and only with that query flag; production bundles never include it. Every
 * number here is invented.
 */
type Resp = { success: boolean; data?: unknown; error?: string };

const ZC = "zc1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw5d8rt4hk0x2pv8mrw5v6e7uy3lgwk2fqe8t4u5d7q9k2m3r5xg7m0pzwjsdq3u4l8h";
const STEALTH = "zc1stealthq9x8gf2tvdw0s3jn54khce6mua7lmqqqxw5d8rt4hk0x2pv8mrw5v6e7uy3lgwk2fqe8t4u5d7q9k2m3r5xg7m0pzwjsdq3u4";
const ZBTC = "1234567890123456789";

const receipt = (id: string, kind: string, amount: number, asset: string, dec: number, recipient: string, ts: number) => ({
  id,
  kind,
  amount,
  asset_id: asset,
  decimals: dec,
  recipient,
  timestamp: ts,
  text: `zcrypt-receipt/1\nkind ${kind}\namount ${amount}\nasset ${asset}\nrecipient ${recipient}\nowner_pk 7a1f…\nblind 9c0e…\ncommitment 3b5d…\n`,
});

const fresh = new URLSearchParams(window.location.search).has("fresh");
const DATA: Record<string, unknown> = {
  wallet_exists: !fresh,
  // phone shell
  mobile_auth_status: { wallet: !fresh, pin: !fresh, biometric: !fresh, biometry_available: true, biometry_type: "faceid", locked_for_s: 0 },
  mobile_unlock: true,
  mobile_confirm: true,
  mobile_create: { address: ZC, seed_phrase: "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual" },
  mobile_adopt: true,
  mobile_set_biometric: true,
  mobile_change_pin: true,
  create_bearer: "zcrypt-bearer/1\ncoin zcb1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw5d8rt4hk0x2pv8mrw5v6e7uy3lgwk2fqe8t4u5d7q9k2m3r5xg7m0pzwjsdq3u4l8h\ngas zcb1q8f2tvdw0s3jn54khce6mua7lmqqqxw5d8rt4hk0x2pv8mrw5v6e7uy3lgwk2fqe8t4u5d7q9k2m3r5xg7m0pzwjsdq3u4l8h\n",
  send_onchain: null,
  send_stealth: { file: "zcrypt-note/1\n7a1f9c0e3b5d…" },
  claim_bearer: { amount: 25_000_000, coin_id: "ab12", ticker: "ZCRYPT", decimals: 6 },
  new_stealth_address: null,
  dismiss_pending_secret: null,
  check_receipt: { on_chain: true, names_recipient: true, summary: "On chain: the coin was created for that address." },
  take_opened_files: [],
  prover_selftest: { prove_ms: 2300, verify_ms: 19, proof_bytes: 1_947_000, peak_rss_mb: 640, threads: 6 },
  unlock_wallet: null,
  lock_wallet: null,
  get_address: ZC,
  get_balance: { total: 1_234_567_890, coin_count: 3 },
  held_assets: [
    { asset_id: "0", ticker: "ZCRYPT", decimals: 6, balance: 1_234_567_890 },
    { asset_id: ZBTC, ticker: "zBTC", decimals: 8, balance: 2_500_000 },
  ],
  whitelisted_assets: ["zBTC", "zETH", "zSOL", "zBNB", "zTON", "zDAI", "zUSDT", "zGOLD"],
  scan_onchain: 0,
  wallet_health: { save_error: null, pending_secrets: 0, pending_deposits: 0, pending_redeems: 0 },
  list_pending_secrets: [],
  btc_wallet_info: { connected: true, balance: 0.0153, deposit_address: "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq" },
  btc_deposit_address: "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
  list_stealth_addresses: [{ index: 1, address: STEALTH }],
  get_view_key: "zcview1q8f2tvdw0s3jn54khce6mua7lmqqqxw5d8rt4hk0x2pv8mrw5v6e7uy3lgwk2fqe8t4u5d7q9k2m3r5xg7m0pzwjsdq3u4l8h",
  get_history: [
    { tx_id: "send-41", kind: "send", amount: -250_000_000, counterparty: "zc1qpzry…l8h", timestamp: 41, at: 1761388200, status: "confirmed", asset_id: "0", decimals: 6, receipt_id: "receipt-42" },
    { tx_id: "receive-38", kind: "receive", amount: 500_000_000, counterparty: "bearer claim", timestamp: 38, at: 1761300000, status: "confirmed", asset_id: "0", decimals: 6, receipt_id: "" },
    { tx_id: "bearer-30", kind: "bearer", amount: -1_000_000, counterparty: "bearer coin", timestamp: 30, at: 0, status: "confirmed", asset_id: ZBTC, decimals: 8, receipt_id: "" },
    { tx_id: "shield-12", kind: "shield", amount: 3_500_000, counterparty: "BTC→zBTC", timestamp: 12, status: "confirmed", asset_id: ZBTC, decimals: 8, receipt_id: "" },
    { tx_id: "reward-9", kind: "reward", amount: 14_000_000, counterparty: "epoch 2273", timestamp: 9, status: "confirmed", asset_id: "0", decimals: 6, receipt_id: "" },
  ],
  list_receipts: [receipt("receipt-42", "normal", 250_000_000, "0", 6, ZC, 42), receipt("receipt-31", "bearer", 1_000_000, ZBTC, 8, "", 31)],
  get_settings: {
    node_url: "https://rpc.zcrypt.network",
    btc_url: "http://localhost:18443",
    btc_user: "zcrypt",
    btc_pass: "zcrypt",
    btc_wallet: "demo",
    btc_network: "bitcoin",
    btc_selfcustody: true,
    esplora_url: "https://blockstream.info/api",
    tor_enabled: false,
    tor_proxy: "127.0.0.1:9050",
    broadcast_jitter: true,
  },
  save_settings: null,
  node_status: { connected: true, height: 227_512, app: "zcrypt-registry", version: "2.0.0", error: "" },
  tor_status: { enabled: false, reachable: false, node_routed: false, bridge_routed: false, proxy: "127.0.0.1:9050", detail: "" },
  chain_pin: "zcrypt-1",
  my_assets: [],
  list_validators: [{ pubkey: "f957727d5d1db6206f074f0149930f94bf2d4122cb9ed54f6456056d52a51e38", stake: "10000000000", commission_pct: 10 }],
  my_unbonding: [],
  validator_identity: {
    pubkey_hex: "f957727d5d1db6206f074f0149930f94bf2d4122cb9ed54f6456056d52a51e38",
    env_line: "VALIDATOR_KEY=eyJhZGRyZXNzIjoi…",
    bonded: true,
    stake: 10_000_000_000,
    commission_pct: 10,
    ever_bonded: true,
    signed_this_epoch: 0,
    epoch_progress: 56,
    epoch_blocks: 100,
  },
  address_kind: "normal",
  estimate_btc_send: { amount_sats: 500_000, fee_sats: 1_118, fee_rate_sat_vb: 7.3, inputs: 2 },
  btc_max_send: { amount_sats: 1_528_882, fee_sats: 1_118, fee_rate_sat_vb: 7.3, inputs: 2 },
};

export function installMock() {
  const w = window as unknown as { __TAURI_INTERNALS__?: unknown };
  if (w.__TAURI_INTERNALS__) return;
  w.__TAURI_INTERNALS__ = {
    invoke: async (cmd: string, args?: Record<string, unknown>): Promise<unknown> => {
      await new Promise((r) => setTimeout(r, 80));
      if (cmd === "plugin:barcode-scanner|check_permissions" || cmd === "plugin:barcode-scanner|request_permissions") return { camera: "granted" };
      if (cmd === "plugin:barcode-scanner|scan") {
        await new Promise((r) => setTimeout(r, 2500)); // a browser has no camera layer: pretend a code was read
        return { content: ZC, format: "QR_CODE" };
      }
      if (cmd === "plugin:barcode-scanner|cancel") return null;
      if (cmd.startsWith("plugin:")) return 1; // event listen/unlisten ids
      console.log("[mock]", cmd, args ?? "");
      if (cmd in DATA) return { success: true, data: DATA[cmd] } satisfies Resp;
      return { success: false, error: `mock: no canned answer for ${cmd}` } satisfies Resp;
    },
    metadata: { currentWindow: { label: "main" }, currentWebview: { label: "main" } },
    convertFileSrc: (p: string) => p,
    transformCallback: (cb: (v: unknown) => void) => cb,
  };
}
