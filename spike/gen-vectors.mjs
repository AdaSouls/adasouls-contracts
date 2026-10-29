// Test vectors for the gas spike: one Ed25519 key (RFC 8032, the scheme AWS KMS ED25519_SHA_512 signs with) and one secp256k1 key (EIP-712).
// Usage (from spike/): npm ci && node gen-vectors.mjs vectors.json
import crypto from "node:crypto";
import { writeFileSync } from "node:fs";
import { privateKeyToAccount } from "viem/accounts";

const seed = crypto.randomBytes(32);
const key = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" });
const pub = crypto.createPublicKey(key).export({ format: "der", type: "spki" }).subarray(-32);

const auth = {
  action: "0x" + crypto.randomBytes(32).toString("hex"),
  chainId: 8453n,
  safe: "0x" + "11".repeat(20),
  module: "0x" + "22".repeat(20),
  token: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
  to: "0x" + "33".repeat(20),
  amount: 25_000_000n,
  nonce: "0x" + crypto.randomBytes(32).toString("hex"),
  expiresAt: 1_800_000_000n,
};
// Two message shapes: the authorization's fields ABI-packed (what the module would hash anyway), and only a 32-byte digest of them.
const packed = Buffer.concat([
  Buffer.from("alma-payment-authorization/1"),
  Buffer.from(auth.action.slice(2), "hex"),
  Buffer.from(auth.chainId.toString(16).padStart(64, "0"), "hex"),
  ...[auth.safe, auth.module, auth.token, auth.to].map((a) => Buffer.from(a.slice(2), "hex")),
  Buffer.from(auth.amount.toString(16).padStart(64, "0"), "hex"),
  Buffer.from(auth.nonce.slice(2), "hex"),
  Buffer.from(auth.expiresAt.toString(16).padStart(16, "0"), "hex"),
]);
const digest = crypto.createHash("sha256").update(packed).digest();
const ed = (m) => { const sig = crypto.sign(null, m, key); if (!crypto.verify(null, m, crypto.createPublicKey(key), sig)) throw new Error("bad"); return "0x" + sig.toString("hex"); };

const account = privateKeyToAccount("0x" + crypto.randomBytes(32).toString("hex"));
const sig712 = await account.signTypedData({
  domain: { name: "AdaSouls", version: "1", chainId: 8453, verifyingContract: auth.module },
  types: { PaymentAuthorization: [
    { name: "action", type: "bytes32" }, { name: "safe", type: "address" }, { name: "token", type: "address" },
    { name: "to", type: "address" }, { name: "amount", type: "uint256" }, { name: "nonce", type: "bytes32" }, { name: "expiresAt", type: "uint64" } ] },
  primaryType: "PaymentAuthorization",
  message: { action: auth.action, safe: auth.safe, token: auth.token, to: auth.to, amount: auth.amount, nonce: auth.nonce, expiresAt: auth.expiresAt },
});

writeFileSync(process.argv[2], JSON.stringify({
  seed: "0x" + seed.toString("hex"),
  pub: "0x" + pub.toString("hex"),
  packed: "0x" + packed.toString("hex"),
  packedSig: ed(packed),
  digest: "0x" + digest.toString("hex"),
  digestSig: ed(digest),
  ecdsa: { signer: account.address, sig: sig712, ...Object.fromEntries(Object.entries(auth).map(([k, v]) => [k, typeof v === "bigint" ? Number(v) : v])) },
}, null, 2));
console.log(`packed message: ${packed.length} bytes`);
