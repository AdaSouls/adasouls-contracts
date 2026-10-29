# adasouls-contracts

On-chain contracts for AdaSouls. The first: a Safe module that pays out
only what AdaSouls authorized, so an agent can't make a payment on-chain
that AdaSouls didn't authorize. Design note:
https://claude.ai/artifact/EAvZ7VQunmxVJaNCUDrmFb

**Status: written and tested, not audited, not deployed.** Don't put real
funds behind it until it is audited.

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
| `src/AdaSoulsPaymentModule.sol` | The module |
| `src/Ed25519Key.sol` | An Ed25519 public key in the verifier's form, from the public key alone |
| `test/AdaSoulsPaymentModule.t.sol` | The module against a real Safe v1.4.1 |
| `test/AlmaCoreInterop.t.sol` | Same digest as alma-core, and its signature accepted (`test/vectors/`) |
| `lib/safe-smart-account` | [Safe](https://github.com/safe-global/safe-smart-account) v1.4.1, for the tests |
| `src/spike/SclEd25519Verifier.sol` | Ed25519 check with Smooth Crypto Lib, and the key setup from a public key alone |
| `src/spike/Eip712Verifier.sol` | The fallback: secp256k1, EIP-712 |
| `test/spike/Ed25519Gas.t.sol` | Correctness and gas |
| `spike/` | Test vectors (`vectors.json`) and their generator |
| `lib/crypto-lib` | [Smooth Crypto Lib](https://github.com/get-smooth/crypto-lib), pinned at `d714e98` |

## The module

One deployment per chain serves every Safe, with no admin and no upgrade.
Each Safe's owners set it up with ordinary Safe transactions:

1. `enableModule(module)` on the Safe.
2. `setAgent(agent)`: the one address that may submit payments.
3. `acceptKey(publicKey)`: an AdaSouls issuer key (raw Ed25519, 32 bytes).
   AdaSouls announces a new key 30 days before it signs with it.
4. `setCap(token, cap, period)`: at most `cap` per `period` seconds. A token
   without a cap can't be paid at all, so this is also the token allowlist.

The agent then calls `pay(authorization, publicKey, signature)` with what
AdaSouls signed (`signPaymentAuthorization` in alma-core). It pays only if
every check passes: the Safe's agent is calling, the chain and module
match, the authorization hasn't expired, its nonce is unused, the key is
accepted, the signature is valid and the cap has room. The nonce and the
spending are recorded before the Safe is called. Then the Safe transfers
exactly that amount of that token to that address, and `Paid` is emitted
for adasouls-worker to match.

Owners can stop the agent (`setAgent(address(0))`), drop a key, set a
token's cap to 0, or disable the module at any time, and they can always
move funds directly.

Gas, through a real Safe, under Osaka rules: `pay` costs about 595k (about
$0.008 at 0.006 gwei); `acceptKey` costs about 147k, once per key per Safe.

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

The full module call, through a real Safe, is measured above. Not measured:
Base's L1 data fee.

## Next

1. Deterministic deployment that anyone can run, with no AdaSouls key: CREATE2
   for Smooth Crypto Lib's `SCL_EIP6565` library (the module links to it),
   then for the module.
2. Confirm what the Veridise audit of Smooth Crypto Lib covered: commit and
   files, `libSCL_EIP6565` in particular.
3. External audit of this repo (the module and `Ed25519Key`) before any
   mainnet funds.

Known limits, for the audit:
- Smooth Crypto Lib notes 16 weak (small-order) keys its verifier doesn't
  handle. Keys are accepted by each Safe's owners, and AdaSouls' key isn't
  one of them.
- A fee-on-transfer token delivers less than the authorized amount; owners
  choose which tokens get a cap.

Branch from `develop`; changes land through pull requests.
