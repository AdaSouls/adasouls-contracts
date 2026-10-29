# adasouls-contracts

On-chain contracts for AdaSouls. The first is planned: a Safe module that
pays out only what AdaSouls authorized, so an agent can't make a payment
on-chain that AdaSouls didn't authorize. Design note:
https://claude.ai/artifact/EAvZ7VQunmxVJaNCUDrmFb

**Status: spike only.** Nothing here is deployable. `src/spike/` holds the
gas measurements that chose the signing key; the module itself isn't
written yet.

## The rule these contracts keep

AdaSouls never holds a key that moves money (adasouls-api README,
"Keys"). The module follows from that:

- The Safe's owners hold its keys and keep full control. AdaSouls is never
  an owner and never signs a transaction.
- The agent's key is not an owner. It can only ask the module to pay an
  authorization.
- AdaSouls signs authorizations with its issuer key (decided 2026-10-29).
  That key can refuse a payment, never make one: an authorization moves
  nothing without the agent's call, and pays only the payee it names.
- Deploying or configuring anything must not need an AdaSouls key either.

## Layout

| Path | What |
| --- | --- |
| `src/spike/SclEd25519Verifier.sol` | Ed25519 check with Smooth Crypto Lib, and the key setup from a public key alone |
| `src/spike/Eip712Verifier.sol` | The fallback: secp256k1, EIP-712 |
| `test/spike/Ed25519Gas.t.sol` | Correctness and gas |
| `spike/` | Test vectors (`vectors.json`) and their generator |
| `lib/crypto-lib` | [Smooth Crypto Lib](https://github.com/get-smooth/crypto-lib), pinned at `d714e98` |

## Running

Needs [Foundry](https://getfoundry.sh).

```bash
git clone --recurse-submodules git@github.com:AdaSouls/adasouls-contracts.git
cd adasouls-contracts
forge test -vv                          # Prague rules
FOUNDRY_PROFILE=osaka forge test -vv    # Osaka rules (EIP-7883 ModExp repricing)
```

New vectors (Node 22): `cd spike && npm ci && npm run vectors`.

## Gas spike (2026-10-29)

What one payment authorization costs to check, as an external call:

| Verifier | Message | Gas (Osaka) |
| --- | --- | --- |
| Smooth Crypto Lib, Ed25519 | 32-byte digest | 514,360 |
| Smooth Crypto Lib, Ed25519 | 244-byte authorization | 1,061,344 |
| secp256k1, EIP-712 | typed struct | 10,684 |

On Base at 0.006 gwei and ETH at $2,302.79, the digest check is about
$0.007 per payment. So:

- **Sign a 32-byte digest.** SHA-512 runs in Solidity, so cost grows with
  the message. The module will hash the fields with the SHA-256 precompile
  and check the signature over that digest.
- **The key comes from its public half.** Smooth Crypto Lib's `SetKey`
  needs the private seed, which a KMS key never gives.
  `keyFromPublic` builds the same key from the 32-byte public key
  (about 121k gas, once per key). It is our code, not the audited
  library's, so it goes in our audit.
- **Interoperable with KMS.** The vectors are signed by Node's RFC 8032
  Ed25519, the scheme of AWS KMS `ED25519_SHA_512`.

Not measured yet: the Safe module call, the token transfer, and Base's L1
data fee.

## Next

1. Confirm what the Veridise audit of Smooth Crypto Lib covered: commit and
   files, `libSCL_EIP6565` in particular.
2. alma-core: the `alma-payment-authorization/1` statement and its digest.
3. The module (`src/`): authorization checks, nonce, expiry, per-period
   cap, owner-managed accepted keys, deployment without an AdaSouls key.
4. External audit before any mainnet funds.

Branch from `develop`; changes land through pull requests.
