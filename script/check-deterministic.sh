#!/usr/bin/env bash
# The deployment is deterministic: two chains with different ids, deployed from different
# accounts, get the same module address, and a second run changes nothing. Local anvil chains
# and anvil's built-in test accounts only; nothing here touches a real network.
set -euo pipefail

# anvil's well-known test accounts (public, local only).
KEY_A=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
KEY_B=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d

anvil --port 18545 --chain-id 8453 --silent & A=$!
anvil --port 18546 --chain-id 84532 --silent & B=$!
# Broadcast logs go to a temporary folder: these local runs must never look like real deployments.
export FOUNDRY_BROADCAST=$(mktemp -d)
trap 'kill $A $B 2>/dev/null; rm -rf "$FOUNDRY_BROADCAST"' EXIT
sleep 2

deploy() { forge script script/Deploy.s.sol --rpc-url "http://127.0.0.1:$1" --broadcast --private-key "$2" 2>&1; }
address() { grep -oE "AdaSoulsPaymentModule: 0x[0-9a-fA-F]{40}" <<<"$1" | awk '{print $2}'; }

first=$(deploy 18545 "$KEY_A")
second=$(deploy 18546 "$KEY_B")
again=$(deploy 18545 "$KEY_B")

a=$(address "$first"); b=$(address "$second")
[[ -n "$a" && "$a" == "$b" ]] || { echo "different addresses: '$a' on 8453, '$b' on 84532"; echo "$first"; echo "$second"; exit 1; }
grep -q "already deployed" <<<"$again" || { echo "a second run did not recognize the deployment:"; echo "$again"; exit 1; }
[[ -n "$(cast code "$a" --rpc-url http://127.0.0.1:18546)" && "$(cast code "$a" --rpc-url http://127.0.0.1:18546)" != "0x" ]] || { echo "no code at $a"; exit 1; }

echo "AdaSoulsPaymentModule deploys deterministically at $a"
