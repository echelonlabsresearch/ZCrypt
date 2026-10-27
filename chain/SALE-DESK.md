# Sale desk: "send Bitcoin, get ZCRYPT"

The sale desk is a small daemon the foundation runs next to a node. The wallet's Buy tab
asks it for a price, gets a fresh Bitcoin address for the order, and polls until the desk
has sent the ZCRYPT. The Bitcoin lands in an address derived from the desk's own seed,
the ZCRYPT comes from shielded coins the desk holds. Nothing in consensus changes.

```
buyer wallet  --POST /order-->  desk  --fresh bc1q… address-->  buyer
buyer's Bitcoin wallet  --BTC-->  that address (watched through Esplora)
desk  --0x6A shielded transfer-->  buyer's zc1… address (after min_conf)
```

## 1. Make the desk's phrase

One BIP-39 phrase gives both sides: the ZCrypt account that holds the stock and the
BIP-84 Bitcoin account the buyers pay (`m/84'/0'/0'/0/<order index>`, one address per
order). Generate it in the desktop wallet (Create wallet) or any BIP-39 tool, and keep it
like a treasury key: whoever has it can spend every Bitcoin ever paid and every ZCRYPT in
stock.

The daemon makes one for you, straight into a 0400 file, and never prints it:

```
docker compose run --rm -v $PWD/secrets:/secrets sale zcrypt_sale --new-phrase /secrets/sale-phrase.txt
# or, with the binary on any machine:  zcrypt_sale --new-phrase secrets/sale-phrase.txt
cat secrets/sale-phrase.txt      # once: copy the 24 words to paper, two places
```

It refuses to overwrite an existing file. The paper copy is the backup; the file is
what the daemon reads. If you already have a phrase, put it in that file yourself:

```
install -m 0400 /dev/stdin secrets/sale-phrase.txt <<< "word word … word"
```

Print the funding address and the Bitcoin xpub:

```
SALE_MNEMONIC_FILE=/srv/zcrypt-sale/phrase.txt zcrypt_sale --address
```

## 2. Stock it

Send ZCRYPT from the foundation wallet to the desk's ZCrypt address: the liquid
allocation to start, then validator rewards as they are claimed. The desk scans the chain
on each pass and picks the coins up on its own. Two or three coins of different sizes are
better than one: a payout spends at most two coins and returns one change coin, so a
single huge coin means every sale is serialized behind the previous change coin landing.

## 3. Price and limits

```
SALE_PRICE_SATS=2500        # satoshis per whole ZCRYPT; 0 closes the desk
SALE_PRICE_FILE=/srv/zcrypt-sale/price.txt   # optional: the same number in a file,
                                             # re-read on every quote, change it any time
SALE_MIN_SATS=20000         # 0.0002 BTC
SALE_MAX_SATS=100000000     # 1 BTC
SALE_MIN_CONF=1             # Bitcoin confirmations before paying; 0 pays on first sight
SALE_TTL_SECS=86400         # an unpaid order stays open this long (a late payment is still honoured)
```

A buyer's order locks the price it was quoted at. Whatever they actually send to the
address is converted at that price, rounded down, so overpaying or underpaying is fine.

## 4. Run it

### On the foundation VPS (docker compose, the normal way)

The desk is a `sale` profile in `chain/docker-compose.yml`, built from the same image as
the node, with Caddy terminating TLS at `https://$SALE_DOMAIN`.

```
# DNS first: A record  buy.zcrypt.network -> the VPS public IP (same as rpc.*)
ssh root@<vps>
cd zcrypt-v2 && git pull && cd chain

umask 077; mkdir -p secrets
docker compose run --rm -v $PWD/secrets:/secrets sale zcrypt_sale --new-phrase /secrets/sale-phrase.txt
chown 10001:10001 secrets/sale-phrase.txt; chmod 400 secrets/sale-phrase.txt

# .env: add
#   SALE_DOMAIN=buy.zcrypt.network
#   SALE_PRICE_SATS=2500            (0 keeps it closed while you fund it)
docker compose --profile sale up -d --build      # builds the image, (re)starts caddy + sale
docker compose logs -f sale                      # prints the desk's ZCrypt address: fund it
curl -s https://buy.zcrypt.network/quote         # from anywhere: the posted terms
```

Change the price: edit `SALE_PRICE_SATS` in `.env`, then `docker compose --profile sale
up -d` (a restart, no rebuild). The state file lives in the `sale-data` volume; back it up
with the other volumes, it holds the desk's coin secrets.

The wallet's default desk is `https://buy.zcrypt.network`, so once this answers, every
wallet's Buy tab works with no setting changed.

### By hand (any machine)

```
ZC_URL=http://localhost:36657            # a node you run
ESPLORA_URL=https://blockstream.info/api # or your own Esplora; it only ever sees addresses
BTC_NETWORK=bitcoin
SALE_LISTEN=127.0.0.1:8787
SALE_STATE=/srv/zcrypt-sale/state.json   # written 0600: holds the desk's coin secrets
zcrypt_sale
```

Put a TLS reverse proxy in front (the daemon speaks plain HTTP) and point the wallet at
it: Settings, "Sale desk URL". The wallet refuses a remote desk that is not `https://` or
`.onion`. The routes are `GET /quote`, `POST /order` (`{"address":"zc1…","sats":N}`) and
`GET /order/<id>`.

Logs are one line per event: a received coin, an order opened, a payment confirmed, a
payout sent. Secrets are never printed.

## 5. Take the Bitcoin out

The desk never spends Bitcoin. Restore the phrase in the desktop wallet (self-custody
Bitcoin mode) to sweep it, or watch the balance in any wallet with the xpub. If many
orders in a row stay unpaid, raise the wallet's gap limit when restoring, since each order
used one receive index.

## Operational notes

- One daemon per state file. A second copy on the same state would pay the same order
  twice.
- A payout that fails (node down, stock short) is retried on the next pass; the order
  stays `seen` until it succeeds.
- "Sold out" is the quote's `stock_atomic`: the two largest unspent coins minus gas. Top
  up and it reopens by itself.
- Selling tokens for Bitcoin is a regulated activity in many places. Get the legal view
  before opening the desk to the public.
