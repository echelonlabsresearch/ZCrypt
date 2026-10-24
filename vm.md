# The Auditability VM

ZCrypt's answer to an old objection: "if the money is hidden, how do I know the
rules are being followed?" The answer is a virtual machine small enough to read
in one sitting, whose bytecode **is** the consensus rule.

## The idea

What the ledger hides is who and how much. What it must never hide is the law.
So every transaction type has exactly one canonical bytecode program, a few
opcodes long, and three parties run it:

1. **Consensus** executes the program as the admission gate: the node builds the
   context from chain state and calls the same evaluator the docs describe.
   There is no second implementation to drift.
2. **The test suite** differentially tests each program against the node
   (`VM accepts iff the node accepts`, on valid and adversarial inputs) and, for
   the transfer, against the ZK circuit itself.
3. **The explorer** replays the program for any transaction you click:
   re-executing every check that is a pure function of the published bytes,
   showing the actual values flowing through each instruction, and re-verifying
   the STARK proof live.

The result: you can read a dozen lines of disassembly and know, not trust, what
a valid transaction is.

## The transfer program (the circuit's public twin)

The shielded transfer is specified by a fixed 7-instruction program:

```
0x01 CHECK_RANGE          every value (inputs, outputs, fee) within bounds
0x03 CHECK_SINGLE_ASSET   all coins in this transfer carry one asset id
0x04 CHECK_CONSERVATION   sum(inputs) = sum(outputs) + fee
0x05 COMPUTE_NULLIFIERS   emit the canonical nullifier per input
0x06 COMPUTE_OUTPUTS      emit the output commitments (the new coins)
0x07 CHECK_MEMBERSHIP     each input is a real leaf under the anchor root
0x00 HALT                 accept
```

The circuit is the zero-knowledge enforcement of exactly this program: each
opcode corresponds to circuit constraints, and the pair is differentially
tested. The program cannot be *re-run* publicly for a given transfer, because
it needs the private witness: that is precisely why the proof exists. What can
be checked publicly is checked publicly: the explorer verifies the STARK (tens
of milliseconds) and displays the values the COMPUTE steps emitted.

## The consensus gate programs

Every other value-affecting transaction is gated by a program over guard
opcodes (`0x10`..`0x21`), each a single readable predicate:

```
BOND        = [CHECK_MIN_STAKE, HALT]
CLAIM       = [CHECK_AMOUNT_POSITIVE, CHECK_AMOUNT_LE_CLAIMABLE, HALT]
REGISTER    = [CHECK_TICKER_VALID, CHECK_TICKER_FREE, HALT]
HTLC_OPEN   = [CHECK_ASSET_HAS_AUTHORITY, CHECK_THRESHOLD_SIG, HALT]
HTLC_CLAIM  = [CHECK_ESCROW_OPEN, CHECK_BEFORE_TIMEOUT, CHECK_PREIMAGE, HALT]
HTLC_EXPIRE = [CHECK_ESCROW_OPEN, CHECK_AT_OR_AFTER_TIMEOUT, HALT]
BURN_LOCK   = [CHECK_ASSET_REGISTERED, CHECK_BURN_OUTPUT, HALT]
ROTATE_AUTH = [CHECK_ASSET_HAS_AUTHORITY, CHECK_THRESHOLD_SIG, HALT]
ZCRYPT_TRANSFER  = [CHECK_BURN_OUTPUT, HALT]
SWAP_LOCK_NATIVE = [CHECK_ASSET_REGISTERED, CHECK_BURN_OUTPUT, CHECK_GAS_PAID, HALT]
```

Guards read a small register file (`Ctx`): stake, amount, claimable, ticker,
escrow state, height, timeout, hashlock, preimage, the M-of-N key set and
signatures, and `gas_ok` (`CHECK_GAS_PAID`, `0x21`): a native swap lock either
burned its own ZCRYPT fee inside its proof or is sponsored by the live, paired
ZCRYPT swap lock that named it. Note what lives in `CHECK_AMOUNT_LE_CLAIMABLE`: for the foundation
address, `claimable` is the vesting schedule, so "the foundation cannot claim
early" is not policy, it is an opcode.

## Seeing it run

Open the explorer, click any transaction:

* the **raw bytes** (full hex for compact transactions, structural map for
  MB-scale proofs) with every byte range labeled by the register it loads;
* the **program**, stepped, with real values: `Ctx.amount = 1,000,000 ZCRYPT ;
  1000000000000 > 0 : pass`;
* explorer **re-execution** of every pure check (ticker validity, burn-output
  recomputation, threshold-signature verification, preimage hashing) with a
  match-against-consensus verdict;
* honest annotations for state-dependent checks (the state has moved on;
  inclusion proves what consensus evaluated at that height);
* the **STARK verdict** for transfers, verified in your request, timed.

## Why this design earns trust

* **One source of truth**: the node calls the same `evaluate()` the
  documentation quotes. A discrepancy between docs and consensus is a failing
  test, not a footnote.
* **Adversarial differential tests**: every program is tested to agree with the
  node on both valid and malicious inputs, and the transfer program is tested
  against the circuit.
* **Total coverage**: there is no value-affecting path that bypasses a program.
  If it moves, mints, locks, claims, bonds, or rotates, a bytecode program
  admitted it.

Where the programs live: `impl/core/src/zvm.rs` (gate) and the shield crate's
`zvm` module (transfer). The explorer's decoder: `impl/explorer/src/decode.rs`.

Related: [protocol.md](protocol.md) for the transactions these programs gate.
