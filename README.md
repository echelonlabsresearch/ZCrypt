# ZCrypt

ZCrypt is a shielded chain you can use without a centralized exchange.

The native coin is ZCRYPT. On top of it, anyone can issue an asset into the same pool, swap that asset for ZCRYPT or for any other asset on the chain, and hand the result to someone as a file. A payment does not publish who paid whom, which asset moved, or how much. The market for those assets is part of the protocol. It does not live on a website that can delist you.

The paper is [Cash Is a File](whitepaper/whitepaper.pdf). The rest of this page is the plain version.

## Privacy coins died at the door

A privacy coin can hide a payment perfectly and still be useless. For years the way to buy one, sell one, or trade it for anything else was a centralized exchange. The exchange sees both sides, keeps the order book, and can close the market whenever it wants. When the listing goes, the coin is still private and nobody can get in or out. The privacy survived. The economy did not.

ZCrypt is built so that door is not required. ZCRYPT is the native coin, and it is private in the strong sense: every coin of every asset sits in one pool, and a spend hides among every coin that pool has ever held. The part that makes the chain more than another private coin is the layer above ZCRYPT. Issuing an asset, sending it, and exchanging it are protocol actions. They use the same pool, the same proofs, and the same rules as the native coin. An asset you create does not need to be wrapped onto another chain, listed on an exchange, or routed through someone else's swap contract before another person can hold it and trade it.

Bitcoin can still come in, as shielded zBTC, when you want a door to Bitcoin. An asset issued on ZCrypt does not need that door.

## The exchange is the chain

On Ethereum, Solana, and Bitcoin, the coin and the market are different things. The chain moves the coin. A separate service, a centralized exchange or a swap contract deployed by someone else, is where one asset becomes another. That service is a third party. It can go offline, change the rules, freeze a pool, or simply refuse the asset.

On ZCrypt the trade is two escrows in the protocol. Two people agree on an exchange. Each locks what they are offering, under one shared secret. Revealing the secret settles both sides together. If the time runs out first, each side gets its own coins back. One side can be ZCRYPT. The other side can be ZCRYPT, or any asset someone has issued. There is no order book to host, no router, and no outside chain that has to accept the asset first.

The escrow record names the amount and the asset of that particular trade, because the two people have to be able to see what they are locking. Where those coins came from, and where the coins they receive go after the trade, is an ordinary payment in the shared pool. Finding someone to trade with can happen in any chat. The settlement itself does not leave ZCrypt, and it does not depend on an exchange staying online.

## Your asset gets the coin's protection

ZCRYPT is the gas and the native money. The unusual layer is the one above it.

You register a ticker, a precision, and a supply cap. From then on that asset is minted, sent, swapped, and turned into a bearer file under the same rules as ZCRYPT. The asset identifier sits inside the coin, hidden. A transfer of your asset and a transfer of ZCRYPT publish the same shape of data. The proof checks that a payment does not turn one asset into another, so hiding the type is not a way to print a different coin.

The cap is fixed when you register. Minting more requires an authorization over that exact mint, signed with a post-quantum signature. The wallet's own flow uses a single key from your seed. zBTC is the exception: nobody's signature mints it. A Bitcoin deposit proof does.

So the security you get for a coin you invent is the security of the pool, not a weaker token standard bolted on beside it.

## A bearer coin is a file

This is the part no other chain gives you, for the native coin and for every asset you issue.

A bearer payment is a small text file. You send it the way you send a photo: WhatsApp, email, a USB stick, a piece of paper. The receiver opens their wallet, drops the file onto the receive page, and the value is credited. They can paste it instead. They do not need an address, and they do not need a balance already. The file carries the fee that spends it.

There is no recipient on the chain. The chain learns that two new coins exist in the pool, and later that someone swept them. It does not learn who handed the file to whom. Because every asset shares that pool, the sweep also does not reveal which asset moved or how much. A ZCRYPT bearer and a bearer of an asset you issued are indistinguishable on the wire.

The file is the money until it is claimed. The first sweep takes it. A copy you kept, or a copy a chat app kept, can still spend it until that sweep is in a block. Send it the way you would hand over cash, then delete your copy. A 24-word restore does not bring the file back. The wallet writes it for you as `zcrypt-bearer.txt`, with a coin line and a gas line. A loose coin string on its own is not a payment.

## The money was built to survive a quantum computer

Most chains add privacy, and hope to add quantum resistance later, on top of signatures a quantum computer is expected to forge. ZCrypt was designed the other way. The parts that create value, hold value, and move value inside the pool are hash-based or lattice-based from the start.

A spend is not a signature. It is knowledge of a secret, proved inside a STARK. STARKs are built from hash functions. There is no trusted setup and no elliptic curve under the coin. Notes are encrypted to ML-KEM keys, the lattice encryption standardized so that a ciphertext recorded today stays closed if a quantum computer arrives later. Issuing and rotating an asset authority uses ML-DSA, the matching lattice signature.

Two edges stay classical, and both are outside the pool. Ordering blocks uses the consensus signatures of CometBFT. The Bitcoin reserve uses Bitcoin's own signatures, because a lock on Bitcoin cannot use anything else. Neither of those can forge a shielded coin or mint an issued asset.

## Hidden payments still have a public rulebook

A private chain asks you to trust a proof you cannot read. That trust has gone wrong before. A bug in a zero-knowledge circuit can mint coins in a pool that, by design, nobody can audit by eye. The math is hard, the implementations are easy to get wrong, and an inflation bug is invisible until it is too late.

ZCrypt keeps a second, readable copy of the rules. Every kind of transaction has one short program, a handful of named checks. The shielded payment's program is seven lines: each amount is in range, every coin in the payment is the same asset, what comes out equals what went in plus the fee, the spent coins are marked spent, the new coins are exactly the commitments that were published, each spent coin really is in the pool, and then stop. The proof is a proof that this program passed. It is not a proof of some other statement written beside it.

The wallet runs that plain program on the real values before it will broadcast, and it refuses to send if the program and the proof disagree. A test suite feeds the same good and bad payments to the program and to the circuit and requires the same answer from both. For every other action that moves value, bonds, claims, mints, swaps, the chain runs the program itself. A failed check is a rejected transaction.

The [explorer](https://explorer.zcrypt.network) shows this on every transaction. Open one and you get the program, step by step. You do not get the sender, the receiver, the asset, or the amount. On a shielded payment the explorer checks the proof and shows the checks that proof covers. On everything else it walks the same program the chain ran and re-runs the checks it can re-run from the public data. The point of the page is that the rules are visible even though the money is not.

## The no-inflation rule is machine-checked

The check that matters most in a hidden pool is the one that says value cannot appear from nowhere. ZCrypt has a machine-checked proof of that check, written in Lean and accepted by Lean's kernel with no unfinished holes.

In plain terms the proof says two things. A payment the rules accept never pays out more than it took in. And the arithmetic inside the proof, which is done in a small finite field rather than ordinary integers, cannot wrap around in a way that invents a coin. That wraparound is a known way hidden ledgers have been inflated. Here it is a theorem, not a comment.

The proofs cover that arithmetic. They are a careful model of the rules, checked by a theorem prover. They are not a claim that every line of the system has been proved, and they do not prove that the hash function itself is unbreakable. What they take off the table is the specific failure where a payment creates money. The boundary is written down in [formal/README.md](formal/README.md).

## See it

The reference network is chain id `zcrypt-1`.

- Explorer: <https://explorer.zcrypt.network>
- RPC: <https://rpc.zcrypt.network>

The desktop wallet is in [`wallet/`](wallet/). On Receive, drop a bearer file or paste it. On Send, choose "bearer coin" and the wallet writes the file. Building and running it is [wallet/README.md](wallet/README.md). Running a node is [running.md](running.md).

## Read next

| If you want | Read |
|---|---|
| The paper | [whitepaper/whitepaper.pdf](whitepaper/whitepaper.pdf) |
| What a stranger can and cannot see | [privacy.md](privacy.md) |
| The cryptographic assumptions, and what is proved | [security.md](security.md) |
| Transactions, fees, staking, issuance, the bridge | [protocol.md](protocol.md) |
| The opcode programs | [vm.md](vm.md) |
| The Lean proofs and their boundary | [formal/README.md](formal/README.md) |
| Run a node or a validator | [running.md](running.md), [chain/README-validator.md](chain/README-validator.md) |
| The explorer | [impl/explorer/README.md](impl/explorer/README.md) |

License: MIT (`impl/Cargo.toml`). Vulnerability reports go to security@zcrypt.network.
