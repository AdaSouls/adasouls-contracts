// An authorization signed by @adasouls/alma-core's signPaymentAuthorization, for test/AlmaCoreInterop.t.sol:
// the module must rebuild the same digest and accept the same signature.
// Usage: node gen-alma-core-vector.mjs <path to alma-core's dist/index.js> ../test/vectors/alma-core-authorization.json
// (until @adasouls/alma-core with payment authorizations is published; then import it from npm).
import crypto from "node:crypto";
import { writeFileSync } from "node:fs";

const core = await import(process.argv[2]);
const seed = crypto.randomBytes(32);
const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
const signer = await core.LocalSigner.fromPkcs8(new Uint8Array(pkcs8));
const authorization = {
  chainId: 8453,
  module: `0x${"22".repeat(20)}`,
  safe: `0x${"11".repeat(20)}`,
  token: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
  to: `0x${"33".repeat(20)}`,
  amount: "25000000",
  nonce: `0x${"ab".repeat(32)}`,
  expiresAt: 1_800_000_000,
};
const signed = await core.signPaymentAuthorization(signer, authorization);
writeFileSync(process.argv[3], JSON.stringify({ publicKey: `0x${Buffer.from(signer.publicKey).toString("hex")}`, kid: signed.kid, digest: signed.digest, sig: signed.sig, ...authorization }, null, 2) + "\n");
console.log("digest", signed.digest);
