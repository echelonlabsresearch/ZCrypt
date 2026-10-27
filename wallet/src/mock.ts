/**
 * A browser-only stand-in for the Rust backend, so the screens can be viewed and styled in
 * a plain browser (`npm run dev`, then open http://localhost:1420/?mock=1). Loaded only in
 * dev builds and only with that query flag; production bundles never include it. Every
 * number here is invented.
 */
type Resp = { success: boolean; data?: unknown; error?: string };

// A real zc1 address is 2,008 characters (the ML-KEM key is inside), so the mock uses one of
// that length: QR size and layout in the browser preview then match the real wallet.
const ZC = "zc15feryxhrdz9m6y09mr8wrerwzgj6f8ntxvhxyrdlm5aahn0t09nl4ujy8624fl6zy54klay937yrnujckpak28lrdjg0eel92ue3gm36kcwf9tfwwqltsjqf6h5graeeeex7ervydu284rxqfxhpydcfskh788la77n9fx4s72pdhfpn9sh2kw4wv0ewvlkpp37svkukh9wxw7v4d7q7k98cv7tm49eae922gpfaf7kfgpqxgmvdpsdj05s6grka6gfputqftf78r57xr0v3zxupyu5v3u70svug68eu5y0mydn8fhfsgawxel2w2me46vk59hp4aupc4jy8wx9s3zt3gmsefl593rtmy3p9s9wys8aq463gz082srtvnndjut3kpszqpv70uxmlendw4vgekrgqysm2r9cj0jzat23uqsh450zndktq4c973v0q9s9fezepnnw9fc5lfjfzmgpw9pzghxcurp0lsqay9y7sys0dwalcy7jzvyf4sngq7rl3xdljjaaa8vn97pjayu3cddy9fshg38hwllep2qluenf6kc584q54e8vqjshyecyhm3r3xrjf03m5vhmped9r6ugjlrg2764jnsse0n7e822ydlwu4umgv09t4950hsvp6c6dc34rl3hgd930ceumnpgzm7lqyeau0xwffxa9zqgwzngsm8xynvcswqqna350700p6nrpvl69swmhwlz46hevqjydlvnvwawsjxltwl6rferdpf6rrteu58924vtaznch4u2xq939k68dcknm9r7vhuv5h7p60ezczayrsvy4h34zs53nqypwx7acsmlgltqnf055ah9ve206yz752mxys9dx6lutwg6a08jj33hssvu0t00fjv5yes0wxazxq7wuhzjw8rvvyhtusqxkdzh4fzdszdq56htnydzl7y6xef92e36jn6rnk66phveedqm2m89eha2gqrfe9h2fkj22yxclvngz75rc92wev7tdze2ck8f0vzz58can6n0mchuutpqla0uat7exygkmh9uzzg959rcgpy8vglj2wyks253afs7ds05hzvte235c2s8rhuxsehschfh49uwtrjsn5qzwfjm6hrglwzprqknxkw6ngdh72gq0fuxyf3esqrkul02qzrpet02rxqvf6v6tnynr7qcma9utwxswz84sr3msjd9q2s0v25vc40c77qpmwndey2fzp8x2kfppzgzyzyhvycx0dd8zz9j7xgxdj54mspksjrh57jp6pmxk7rd9j2mqvjrqklxltlks2jdwl289lx5kxee9mphdnsm2cwagzk5fu52auswg4a0v3nff05k205vsx2xvcffnnm3vxx3dcazqemwjapfseq0m6wwt8am5sx60e2sm7ap6t5qclxzsd2vkxad7ph46adte8krs3cerqy66ksxwnewead2gyv7wfk6ajg7kw3csmt7q3k0n57lm9hfncr95gkqqdyjsxfwtukfde29nvld9u88s6wg7lr7afl0l2q25aljahm6ythppz4x7lfzd6g4xh47djm4msrjjkle43kdl84v5ng9zeerenxqzv7rcf9dzatxtz6xqhgnsnt6z5pmrlz86euyqcf76x97dfqmqq89d8g7p30utrhf9jlasrzqrq9cnn2lr5hu72f8h267cu34j3r4qfnm0cccwujq5s3m2zjff3lk9lcvwnreadsqca9kywes57vvdv9tjhkef0zlhxha9f5pk3pxzdlds3mxugsz4vtc9przhalye89s5w9etu2h0wtzskrprs7rxf5qvnux75hsc8h7c2u0fqavz2wyhguxcpyu45w78hf4wrtufuf3660fp3j42slx5a78frd7j8svhms00xcj62rjfpu4guqjthmz6d3tgtwtv99l3tdgvnvqy6rk4jl9q67g30thz2hqkuy8k05crjxlupgp09wt2xnsppxvspa0uxkxtz38al3888";
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

// The sale desk ("send Bitcoin, get ZCRYPT"): an order advances waiting -> seen -> paid on
// successive polls so the Buy screen's whole life can be viewed.
const SALE_QUOTE = { price_sats: 2_500, min_sats: 20_000, max_sats: 100_000_000, stock_atomic: 184_250_000_000, min_conf: 1, network: "bitcoin", ttl_secs: 86_400 };
const saleOrders: Record<string, { sats: number; polls: number; created: number }> = {};
function saleView(id: string) {
  const o = saleOrders[id];
  const status = o.polls < 2 ? "waiting" : o.polls < 4 ? "seen" : "paid";
  return {
    id,
    btc_address: "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
    sats: o.sats,
    price_sats: SALE_QUOTE.price_sats,
    created: o.created,
    expires: o.created + SALE_QUOTE.ttl_secs,
    status,
    paid_sats: status === "waiting" ? 0 : o.sats,
    confirmations: status === "paid" ? 1 : 0,
    min_conf: SALE_QUOTE.min_conf,
    zcrypt_atomic: status === "paid" ? Math.floor((o.sats * 1_000_000) / SALE_QUOTE.price_sats) : 0,
    zc_txhash: status === "paid" ? "9f1c…e2" : "",
  };
}

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
      if (cmd === "buy_quote") return { success: true, data: SALE_QUOTE } satisfies Resp;
      if (cmd === "buy_order") {
        const id = Math.random().toString(16).slice(2).padEnd(32, "0").slice(0, 32);
        saleOrders[id] = { sats: Number(args?.sats ?? 0), polls: 0, created: Math.floor(Date.now() / 1000) };
        return { success: true, data: saleView(id) } satisfies Resp;
      }
      if (cmd === "buy_status") {
        const id = String(args?.id ?? "");
        if (!saleOrders[id]) return { success: false, error: "no such order" } satisfies Resp;
        saleOrders[id].polls += 1;
        return { success: true, data: saleView(id) } satisfies Resp;
      }
      if (cmd === "buy_orders") return { success: true, data: Object.keys(saleOrders).reverse().map((id) => ({ id, sale_url: "mock", created: saleOrders[id].created })) } satisfies Resp;
      if (cmd === "buy_forget") {
        delete saleOrders[String(args?.id ?? "")];
        return { success: true, data: true } satisfies Resp;
      }
      if (cmd in DATA) return { success: true, data: DATA[cmd] } satisfies Resp;
      return { success: false, error: `mock: no canned answer for ${cmd}` } satisfies Resp;
    },
    metadata: { currentWindow: { label: "main" }, currentWebview: { label: "main" } },
    convertFileSrc: (p: string) => p,
    transformCallback: (cb: (v: unknown) => void) => cb,
  };
}
