# agent_drep — a DRep with a mandate

A Cardano script that acts as a DRep credential. A human owns it. An AI
agent may cast **exactly the votes the human signed, once each, before
they expire**. The human can always vote directly, register or update the
DRep, and rotate either key without changing the script hash, so the DRep
keeps its delegations.

This is the on-chain half of phase G3 in
[`cardano-governance`](https://github.com/AdaSouls/cardano-governance)
(`docs/phases/G3-mandate-drep.md`). Both gaps that phase names are closed
here: replay protection and key rotation.

Aiken `v1.1.24`, stdlib `v4.0.0`, Plutus V3. 27 tests pass.

## How it works

One UTxO at the script address holds the state, marked by a token the
script mints once (policy id = script hash, name `alma-drep-state`):

```
State { sequence: Int, human_vkey: VerificationKey, agent_vkh: VerificationKeyHash }
```

| Who | Does | Redeemer | Needs |
|---|---|---|---|
| Human | Votes directly | `vote: Human` | state as reference input, human key witness |
| Human | Registers / updates / retires the DRep | `publish` | same |
| Human | Rotates keys or jumps the sequence | `spend: Rotate` | human key witness; sequence may not go down |
| Human | Creates / destroys the state token | `mint: Create` / `Destroy` | human key witness; `Create` spends the seed UTxO once |
| Agent | Casts one authorized vote | `vote: Agent { authorization, signature }` + `spend: Advance` | see below |

An agent vote is valid only if, in the same transaction:

1. the state UTxO is spent and written back with `sequence + 1`, same keys;
2. the agent key witnesses the transaction;
3. `authorization.sequence` equals the state's `sequence`;
4. the human's Ed25519 signature verifies over the exact bytes of
   `alma/vote.message` (domain, DRep script hash, action id, vote,
   sequence, expiry — 95 bytes, no CBOR);
5. the validity range ends at or before `authorization.expires_at`;
6. the transaction's votes by this DRep are exactly
   `[(authorization.action, authorization.vote)]`.

So an authorization cannot be replayed (the sequence is consumed), cannot
be altered (one byte changes the signature), cannot be delayed past its
deadline, and cannot be bundled with another vote. The agent cannot
advance the sequence without a vote, so it cannot void the human's
outstanding authorizations either; the human can, by jumping the sequence
with `Rotate`.

Nothing here moves funds. The script never sees a private key: the human's
signature travels inside the redeemer, the agent's is an ordinary witness.

## Layout

```
lib/alma/vote.ak            Authorization + the signed bytes, with the test vector
validators/agent_drep.ak    the validator: mint / spend / vote / publish
validators/agent_drep.test.ak   27 scenario tests
scripts/gen-vote-vectors.py  regenerates the Ed25519 vectors the tests use
plutus.json                 blueprint from `aiken build`
```

## Build and test

```bash
aiken check     # tests
aiken build     # plutus.json
```

If `aiken check` cannot fetch the stdlib (no GitHub API access), vendor it:

```bash
mkdir -p build/packages
git clone --depth 1 --branch v4.0.0 https://github.com/aiken-lang/stdlib build/packages/aiken-lang-stdlib
rm -rf build/packages/aiken-lang-stdlib/.git
printf '[[packages]]\nname = "aiken-lang/stdlib"\nversion = "v4.0.0"\nsource = "github"\n' > build/packages/packages.toml
```

## Off-chain (G3.2, not here)

The signer and the transaction builder live in `cardano-governance`. They
must reproduce `alma/vote.message` byte for byte — `digest_vector` in
`lib/alma/vote.ak` and `scripts/gen-vote-vectors.py` are the shared
reference — and build the vote with the `Agent` redeemer, the state UTxO
as input and output, and a validity range that ends before `expires_at`.

## Not done

- Not deployed, not audited. Preprod only until audited (G3.3).
- The seed `OutputReference` parameter makes each deployment a distinct
  script hash: register the DRep after minting the state.
- Costs measured in tests, not on a network: an authorized vote plus the
  state advance runs ~160M CPU steps in the test harness.
