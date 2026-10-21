# ZCrypt

**Cash is a file.**

ZCrypt is a proof-of-stake ledger with one shielded pool. Native coins and every other asset live in that pool as hiding commitments. Spending one publishes nullifiers, fresh commitments, encrypted notes, and a STARK proof. The amount, the asset, and the participants stay inside the proof. The reference network is chain id `zcrypt-1`.

The formal paper is [Cash Is a File](whitepaper/whitepaper.pdf) (version 9.4). The sections below are the short version, and the table at the end is where each topic goes deeper.

## Why it is different

- **One pool is the whole ledger.** A spend proves, inside the circuit, a Merkle path to a recent root of the global commitment tree. The anonymity set of that spend is every coin ever created. Shielded transfer is the only way pool coins move, so every payment joins the same set.
- **The spend path is post-quantum.** Proofs are STARKs over hash functions, with no trusted setup. Authority to spend is knowledge of a hash preimage, proved in the circuit. Notes are encrypted to ML-KEM-768 keys, so a ciphertext recorded today stays closed against a later quantum computer. Asset issuance uses ML-DSA threshold signatures. The Bitcoin bridge still verifies secp256k1 signatures, because those signatures are Bitcoin's.
- **A payment can be a file.** A bearer payment is a text file a person can forward the way they forward a photo: one line for the coin and one line for the gas that spends it. The first sweep takes the money. Until that sweep is in a block, a copy of the file is still a spend.
- **A receipt can be checked by a third party.** The wallet writes a local `zcrypt-receipt/1` file for each payment it sends. Anyone holding that file can recompute the commitment and look for the leaf. The check does not move the coin.
- **Bitcoin enters the same pool.** Validators run a Bitcoin header chain. A deposit mints shielded zBTC against an SPV proof that real BTC was locked to the reserve key. The depositor receives the locked amount minus 10 basis points, paid to ZCRYPT stakers in zBTC. The locked coins stay backed one for one.
- **The rules are readable.** Each transparent operation has one short bytecode program, and consensus runs it. The shielded transfer has a program of the same kind as its specification; consensus checks the STARK. Total issuance is a function of block height committed in the state root.

## How a coin moves

A coin is four fields: a value, a blind, a spend secret, and an asset id. The chain stores the commitment. Spending the coin reveals a nullifier derived from that same opening, so a second spend collides in the public nullifier set and is rejected. The native asset is ZCRYPT, identifier 0, with 6 decimals. A registered asset shares the pool. Its identifier is inside the commitment, and the circuit refuses to treat one asset as another.

A user transfer is two proofs, applied together. The main proof moves any asset and carries a fee of zero. The gas proof burns exactly 0.01 ZCRYPT to a key with no known preimage. A one-input spend is padded with a value-zero phantom, so every transfer publishes two nullifiers and two commitments per proof. Each proof is on the order of a megabyte. The wallet builds both proofs locally. Validators learn that a valid spend happened, and the fee.

### Three ways to hand someone a coin

All three are the same on-chain transfer. They differ in how the recipient learns the opening.

| | What you hand over | What the chain shows | The 24-word phrase |
|---|---|---|---|
| **Normal** | a `zc1` address | an encrypted note that address can open | restores the coins |
| **Stealth** | a one-time `zc1` address, and a `zct1` note sent off chain | a cover note of the same size | restores change sent to stealth accounts derived from the phrase. A stealth address made from fresh randomness is not in the phrase |
| **Bearer** | a `zcrypt-bearer/1` file with a `coin` line and a `gas` line | the mints that created those two coins, and no recipient | does not restore it |

A normal address has a view key: the note-decryption key without the spend secret. It opens incoming notes to that address and cannot spend. Stealth payments and bearer files are outside it.

Creating a bearer file costs the sender 0.03 ZCRYPT on top of the value. That is a 0.01 gas coin inside the file, plus 0.01 of gas for each of the two mints. The claim burns the gas coin from the file, so the recipient needs no prior balance and receives the full value. A lone `zcb1` string is not a payment. The first sweep wins, and the sender cannot cancel a copy they kept.

A receipt is not a payment. It records the kind (normal, stealth, or bearer), the amount, the asset, the commitment, and the blind. A normal or stealth receipt names the recipient. A bearer receipt names nobody and records the nullifier, not the spend secret. Publishing the file reveals the opening of that leaf. Keeping it does not. A restore from the phrase does not bring receipts back.

### Bitcoin, in and out

A depositor locks BTC in a hash-time-locked output that pays the chain's reserve key on the success path and the depositor on the timeout path. Every validator checks the header chain, the Merkle inclusion, and the script. The gross mint matches the locked satoshis one for one. The depositor's coin is that amount minus 10 basis points. The fee accrues to ZCRYPT stakers, in zBTC, by the same weight as the block reward, once the deposit matures. Until then the new coin sits immature, outside the pool, so a reorg can still void it.

Redeeming locks zBTC in a burn escrow. A provider who holds the reserve's BTC pays the redeemer on Bitcoin against the same preimage, and the burn reduces tracked supply. The chain does not pay that provider. The reserve key can spend the locked BTC. Losing or leaking it leaves the zBTC supply in place and strands redemption. The key can be rotated on chain, and only to another reserve key. The operator deployment stores one key.

Two people can swap one shielded asset for another without leaving the pool. Each side locks coins under one hashlock. The amounts, the asset ids, and the hashlock are public, because an atomic swap has to show them. The coins that funded each leg stay hidden. A timed-out lock returns to its locker.

### Stake, assets, and issuance

Bonding spends shielded ZCRYPT into the burn key and publishes the validator. The minimum bond is 10,000 ZCRYPT. Delegators pledge the same way and share the rewards and the slash. Unbonding takes 10 days. Equivocation evidence slashes 5% and tombstones the validator.

Anyone can register a ticker, a decimal precision, and a supply cap. Minting more of that asset requires an M-of-N ML-DSA authorization over that exact escrow. The wallet's own flows use a 1-of-1 key derived from the seed. zBTC has no such authority. Consensus will not mint it except through the SPV gate.

The supply is 21,000,000 ZCRYPT. Twenty percent is the foundation allocation: 50,000 liquid at genesis, a 25% cliff at month 12, then a monthly unlock through month 48. The chain rejects an early claim. Eighty percent is mined, starting at 0.14 ZCRYPT per block and halving every 60,000,000 blocks, at a one-second target block time. Rewards pay out every 100 blocks. The state root commits to this schedule. That commitment shows the schedule was followed. It does not show that the pool contains only the coins the schedule created.

### Consensus

Each node is a Rust state machine beside CometBFT. Blocks target one second and are final on commit. The application hash commits to the commitment tree, the nullifier set, the staking ledger, the asset registry, the escrow book, the Bitcoin header chain, and the immature-mint queue. Two nodes that disagree about any of those disagree about the hash.

## Read next

| If you want | Read |
|---|---|
| The paper: *Cash Is a File*, version 9.4 | [whitepaper/whitepaper.pdf](whitepaper/whitepaper.pdf) |
| What an observer sees, including the edges | [privacy.md](privacy.md) |
| The cryptographic assumptions, custody of the reserve, and what is proved | [security.md](security.md) |
| Every transaction tag, the fee, emission, staking, and the bridge | [protocol.md](protocol.md) |
| The bytecode that specifies each rule | [vm.md](vm.md) |
| The Lean proofs, and the boundary around them | [formal/README.md](formal/README.md) and [FORMAL-VERIFICATION-SCOPE.md](FORMAL-VERIFICATION-SCOPE.md) |
| Run a node, bond a validator, or build the wallet | [running.md](running.md) |
| Join a running chain as a validator | [chain/README-validator.md](chain/README-validator.md) |
| The production genesis and go-live order | [chain/LAUNCH.md](chain/LAUNCH.md) |
| Take the Bitcoin bridge through signet before mainnet | [impl/bridge/MAINNET.md](impl/bridge/MAINNET.md) |
| Build and run the desktop wallet | [wallet/README.md](wallet/README.md) |
| What the explorer shows, and what it refuses to show | [impl/explorer/README.md](impl/explorer/README.md) |
| The acceptance tests | [UAT.md](UAT.md) |
| The source | [`impl/`](impl/) is the state machine and the circuit. [`chain/`](chain/) is the Docker stack. [`wallet/`](wallet/) is the Tauri app. |

## See it

The reference network is chain id `zcrypt-1`.

- Explorer: <https://explorer.zcrypt.network>
- RPC: <https://rpc.zcrypt.network>

A local playground is [running.md](running.md). Production compose refuses to start without a foundation address and a Bitcoin checkpoint. For a local chain, set `ABCI_FEATURES=devnet` and `ZCRYPT_BTC_NET=regtest` in `chain/.env`, then:

```sh
cd chain
docker compose --profile dev up --build -d
curl -s http://localhost:36657/status | grep latest_block_height
```

`--profile dev` starts a regtest bitcoind on localhost for the bridge demo. Leave that profile off for any other deployment. The desktop wallet lives in `wallet/` (`npm install && npm run tauri:dev`) and sends node traffic over Tor by default.

## Before you trust it with value

The hiding layer of the proofs is not proved. The soundness floor the node checks is the Johnson bound, 132 bits. The 244-bit number is a list-decoding conjecture, not that floor. The AIR itself is not machine-checked. The Lean development proves the transfer specification's conservation arithmetic, and it reduces a coin-layer break to a hash collision. The BTC behind zBTC is spendable by the reserve key. No external audit is published. The full account is [security.md](security.md). Reports go to security@zcrypt.network.

License: MIT (`impl/Cargo.toml`).
