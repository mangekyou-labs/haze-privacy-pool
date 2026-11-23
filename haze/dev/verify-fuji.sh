#!/bin/bash
# Verify a Haze Fuji deployment on Routescan (Snowtrace) through the etherscan-compatible API.
#
# Usage:
#   haze/dev/verify-fuji.sh [--dry-run] <deployment.json>
#
# <deployment.json> is either:
#   - a curated map with an `.addresses` object (e.g. haze/deployments/fuji-v1.live.json), or
#   - a forge broadcast file (e.g. haze/contracts/broadcast/DeployFujiPoseidonV2.s.sol/43113/run-latest.json).
#
# Constructor arguments are not taken from the JSON. They are read back from the deployed
# contracts' public immutables with `cast call` and re-encoded with `cast abi-encode`.
#
# Env:
#   FUJI_RPC_URL       RPC to read immutables from (default: public Fuji C-chain RPC).
#   ROUTESCAN_API_KEY  Routescan key. Routescan accepts the placeholder "verifyContract".
#
# Groth16Verifier and HazeOperatorGroth16Adapter(Poseidon) come from the tracked
# haze/dev/artifacts/operator-verifier/HazeGroth16Verifier.generated.sol. They are skipped unless
# that file exists. See operator-verifier/PROVENANCE.md for the bytecode match.
#
# This script only reads chain state and submits source to the explorer. It never signs or
# broadcasts a transaction.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTRACTS_DIR="$SCRIPT_DIR/../contracts"
GENERATED_SRC="$SCRIPT_DIR/artifacts/operator-verifier/HazeGroth16Verifier.generated.sol"

CHAIN_ID=43113
VERIFIER_URL="https://api.routescan.io/v2/network/testnet/evm/43113/etherscan"
RPC_URL="${FUJI_RPC_URL:-https://api.avax-test.network/ext/bc/C/rpc}"
API_KEY="${ROUTESCAN_API_KEY:-verifyContract}"

DRY_RUN=0
if [ "${1:-}" = "--dry-run" ]; then
    DRY_RUN=1
    shift
fi
if [ $# -ne 1 ] || [ ! -f "$1" ]; then
    echo "usage: $0 [--dry-run] <deployment.json>" >&2
    exit 64
fi
DEPLOYMENT_JSON="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"

for bin in jq cast forge; do
    command -v "$bin" >/dev/null || { echo "missing dependency: $bin" >&2; exit 69; }
done

# addr <ContractName> -> address or empty string
addr() {
    jq -r --arg n "$1" '
        if has("addresses") then (.addresses[$n] // "")
        else ([.transactions[]? | select(.transactionType == "CREATE" and .contractName == $n)
               | .contractAddress] | last // "")
        end' "$DEPLOYMENT_JSON"
}

# read <address> <signature> -> first return value, with cast's " [1e18]" style suffix removed
read_call() {
    cast call --rpc-url "$RPC_URL" "$1" "$2" | awk '{print $1}'
}

verify() {
    local address="$1" target="$2" args="${3:-}"
    local cmd=(forge verify-contract "$address" "$target"
        --root "$CONTRACTS_DIR"
        --chain "$CHAIN_ID"
        --verifier etherscan
        --verifier-url "$VERIFIER_URL"
        --etherscan-api-key "$API_KEY"
        --watch)
    if [ -n "$args" ]; then
        cmd+=(--constructor-args "$args")
    fi
    echo "==> $target at $address"
    if [ "$DRY_RUN" = 1 ]; then
        printf '%q ' "${cmd[@]}" | sed "s/$API_KEY/\$ROUTESCAN_API_KEY/"
        echo
    else
        "${cmd[@]}"
    fi
}

ACCESS="$(addr HazeAccess)"
APPS="$(addr ApplicationRegistry)"
POLICIES="$(addr PolicyRegistry)"
VERSIONS="$(addr VersionRegistry)"
DEV_EQ="$(addr DevelopmentEqualityVerifier)"
GROTH16="$(addr Groth16Verifier)"
ADAPTER="$(addr HazeOperatorGroth16Adapter)"
[ -n "$ADAPTER" ] || ADAPTER="$(addr HazeOperatorGroth16AdapterPoseidon)"
SPEND_PAIRING="$(addr HazeSpendVerifierPairing)"
SPEND_GROTH16="$(addr HazeSpendVerifierGroth16)"
POOL="$(addr HazePoolPoseidon)"
ROUTER="$(addr SwapAndShieldRouter)"
EXIT="$(addr EmergencyExit)"

# Forge broadcast files omit contracts the script only referenced (v2 reuses the operator
# Groth16 verifier and adapter). Recover them on-chain from the spend verifier.
if [ -z "$ADAPTER" ] && [ -n "$SPEND_GROTH16" ]; then
    ADAPTER="$(read_call "$SPEND_GROTH16" 'pairingBackend()(address)')"
fi
if [ -z "$GROTH16" ] && [ -n "$ADAPTER" ]; then
    GROTH16="$(read_call "$ADAPTER" 'impl()(address)')"
fi

if [ -n "$ACCESS" ]; then
    gov="$(read_call "$ACCESS" 'governance()(address)')"
    pause="$(read_call "$ACCESS" 'pauseRole()(address)')"
    delay="$(read_call "$ACCESS" 'minDelay()(uint48)')"
    verify "$ACCESS" src/HazeAccess.sol:HazeAccess \
        "$(cast abi-encode 'constructor(address,address,uint48)' "$gov" "$pause" "$delay")"
fi

access_arg() { cast abi-encode 'constructor(address)' "$1"; }
for pair in "ApplicationRegistry:$APPS" "PolicyRegistry:$POLICIES" "VersionRegistry:$VERSIONS"; do
    name="${pair%%:*}"
    a="${pair#*:}"
    [ -n "$a" ] || continue
    verify "$a" "src/$name.sol:$name" "$(access_arg "$(read_call "$a" 'access()(address)')")"
done

if [ -n "$DEV_EQ" ]; then
    verify "$DEV_EQ" ../dev/artifacts/DevelopmentEqualityVerifier.sol:DevelopmentEqualityVerifier
fi

if [ -n "$GROTH16" ] || [ -n "$ADAPTER" ]; then
    if [ -f "$GENERATED_SRC" ]; then
        echo "NOTE: Groth16Verifier/adapter verification uses $GENERATED_SRC."
        echo "      The adapter wrapper lives in a deploy script; verify it manually if the"
        echo "      explorer rejects the script path."
        [ -z "$GROTH16" ] || verify "$GROTH16" \
            ../dev/artifacts/operator-verifier/HazeGroth16Verifier.generated.sol:Groth16Verifier
        [ -z "$ADAPTER" ] || verify "$ADAPTER" \
            script/DeployFujiPoseidonLive.s.sol:HazeOperatorGroth16AdapterPoseidon \
            "$(cast abi-encode 'constructor(address)' "$GROTH16")"
    else
        echo "SKIP: Groth16Verifier ${GROTH16:-?} and adapter ${ADAPTER:-?}: generated source"
        echo "      $GENERATED_SRC is absent. Restore it from git (see PROVENANCE.md)"
        echo "      and re-run."
    fi
fi

if [ -n "$SPEND_PAIRING" ]; then
    dev="$(read_call "$SPEND_PAIRING" 'developmentBackend()(address)')"
    pair_backend="$(read_call "$SPEND_PAIRING" 'pairingBackend()(address)')"
    verify "$SPEND_PAIRING" src/HazeSpendVerifierPairing.sol:HazeSpendVerifierPairing \
        "$(cast abi-encode 'constructor(address,address)' "$dev" "$pair_backend")"
fi

if [ -n "$SPEND_GROTH16" ]; then
    verify "$SPEND_GROTH16" src/HazeSpendVerifierGroth16.sol:HazeSpendVerifierGroth16 \
        "$(cast abi-encode 'constructor(address)' "$(read_call "$SPEND_GROTH16" 'pairingBackend()(address)')")"
fi

if [ -n "$POOL" ]; then
    args="$(cast abi-encode \
        'constructor(address,address,address,address,address,address,address,bytes32,uint256)' \
        "$(read_call "$POOL" 'access()(address)')" \
        "$(read_call "$POOL" 'applications()(address)')" \
        "$(read_call "$POOL" 'policies()(address)')" \
        "$(read_call "$POOL" 'verifier()(address)')" \
        "$(read_call "$POOL" 'usdc()(address)')" \
        "$(read_call "$POOL" 'approvedRouter()(address)')" \
        "$(read_call "$POOL" 'approvedExit()(address)')" \
        "$(read_call "$POOL" 'poolVersion()(bytes32)')" \
        "$(read_call "$POOL" 'rootHistorySize()(uint256)')")"
    verify "$POOL" src/HazePoolPoseidon.sol:HazePoolPoseidon "$args"
fi

if [ -n "$ROUTER" ]; then
    # The router does not expose its constructor allowlist. Both Fuji deploy scripts pass empty
    # token/adapter arrays; if a deployment passed non-empty ones, edit this call.
    args="$(cast abi-encode 'constructor(address,address,address,address[],address[])' \
        "$(read_call "$ROUTER" 'access()(address)')" \
        "$(read_call "$ROUTER" 'pool()(address)')" \
        "$(read_call "$ROUTER" 'usdc()(address)')" \
        '[]' '[]')"
    verify "$ROUTER" src/SwapAndShieldRouter.sol:SwapAndShieldRouter "$args"
fi

if [ -n "$EXIT" ]; then
    args="$(cast abi-encode 'constructor(address,address,address,address)' \
        "$(read_call "$EXIT" 'access()(address)')" \
        "$(read_call "$EXIT" 'pool()(address)')" \
        "$(read_call "$EXIT" 'versions()(address)')" \
        "$(read_call "$EXIT" 'policies()(address)')")"
    verify "$EXIT" src/EmergencyExit.sol:EmergencyExit "$args"
fi
