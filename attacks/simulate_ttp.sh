#!/usr/bin/env bash
# ==============================================================================
# Script: simulate_ttp.sh
# Purpose: Emulate adversary tactics, techniques, and procedures (MITRE ATT&CK)
#          to validate Falco eBPF runtime detection and K8s API audit logging.
# Target: k8s-guard / k8s-detection-lab
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

VICTIM_POD="payment-service"
BREAKOUT_MANIFEST="${SCRIPT_DIR}/payloads/breakout-pod.yaml"
ROGUE_RBAC_MANIFEST="${SCRIPT_DIR}/payloads/rogue-rbac.yaml"

log_info() {
    echo "[*] $1"
}

log_pass() {
    echo "[+] $1"
}

log_warn() {
    echo "[!] $1"
}

log_fail() {
    echo "[-] $1"
}

ensure_victim_pod() {
    if ! kubectl get pod "${VICTIM_POD}" -n default >/dev/null 2>&1; then
        log_info "Spawning victim workload pod '${VICTIM_POD}' (image: nginx:alpine)..."
        kubectl run "${VICTIM_POD}" --image=nginx:alpine --restart=Never -n default
        log_info "Waiting for '${VICTIM_POD}' to enter Running state..."
        kubectl wait --for=condition=Ready pod/"${VICTIM_POD}" -n default --timeout=60s
        log_pass "Victim workload pod '${VICTIM_POD}' is ready."
    else
        log_info "Victim pod '${VICTIM_POD}' is already running."
    fi
}

scenario_1_shell_spawn() {
    echo ""
    log_info "============================================================"
    log_info "SCENARIO 1: Interactive Shell in Workload (MITRE T1609)"
    log_info "Target Detection: Falco rule 'Unauthorized Interactive Shell in Workload Container'"
    log_info "============================================================"
    ensure_victim_pod

    log_info "Executing interactive shell command in '${VICTIM_POD}'..."
    kubectl exec "${VICTIM_POD}" -n default -- /bin/sh -c "whoami && uname -a && id"
    log_pass "Scenario 1 executed successfully."
}

scenario_2_token_access() {
    echo ""
    log_info "============================================================"
    log_info "SCENARIO 2: Service Account Token Harvesting (MITRE T1613)"
    log_info "Target Detection: Falco rule 'Access to Service Account Token by Untrusted Binary'"
    log_info "============================================================"
    ensure_victim_pod

    log_info "Attempting unauthorized read of service account token file..."
    kubectl exec "${VICTIM_POD}" -n default -- /bin/sh -c \
        "cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || true"
    log_pass "Scenario 2 executed successfully."
}

scenario_3_container_escape() {
    echo ""
    log_info "============================================================"
    log_info "SCENARIO 3: Container HostPath Escape Surface (MITRE T1611)"
    log_info "Target Detection: Falco rule 'Sensitive Host Path Mounted in Pod Spec'"
    log_info "============================================================"

    log_info "Deploying breakout simulation pod from ${BREAKOUT_MANIFEST}..."
    kubectl apply -f "${BREAKOUT_MANIFEST}"
    log_info "Waiting for breakout-pod to schedule and trigger host access..."
    kubectl wait --for=condition=Ready pod/breakout-pod -n default --timeout=60s || true

    log_info "Triggering file read on mounted /host/proc filesystem..."
    kubectl exec breakout-pod -n default -- /bin/sh -c \
        "head -n 2 /host/proc/version 2>/dev/null || true" || true
    log_pass "Scenario 3 executed successfully."
}

scenario_4_rogue_rbac() {
    echo ""
    log_info "============================================================"
    log_info "SCENARIO 4: Unauthorized ClusterRoleBinding via API (MITRE T1098.004)"
    log_info "Target Detection: K8s Audit Rule 'Rogue ClusterRoleBinding to cluster-admin'"
    log_info "============================================================"

    log_info "Applying rogue ClusterRoleBinding manifest: ${ROGUE_RBAC_MANIFEST}..."
    kubectl apply -f "${ROGUE_RBAC_MANIFEST}"
    log_pass "Scenario 4 executed successfully. Check control-plane audit log for detection."
}

cleanup() {
    echo ""
    log_info "============================================================"
    log_info "CLEANUP: Removing simulated attack artifacts"
    log_info "============================================================"

    log_info "Deleting victim pod '${VICTIM_POD}'..."
    kubectl delete pod "${VICTIM_POD}" -n default --ignore-not-found=true --grace-period=0 --force 2>/dev/null || true

    log_info "Deleting breakout pod 'breakout-pod'..."
    kubectl delete pod breakout-pod -n default --ignore-not-found=true --grace-period=0 --force 2>/dev/null || true

    log_info "Deleting rogue ClusterRoleBinding 'rogue-admin'..."
    kubectl delete clusterrolebinding rogue-admin --ignore-not-found=true 2>/dev/null || true

    log_pass "Cleanup completed."
}

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --all              Execute all 4 attack emulation scenarios sequentially"
    echo "  --scenario <1..4>  Execute a specific attack emulation scenario:"
    echo "                       1: Interactive shell in container (T1609)"
    echo "                       2: Service account token theft (T1613)"
    echo "                       3: Container hostPath escape surface (T1611)"
    echo "                       4: Rogue ClusterRoleBinding escalation (T1098.004)"
    echo "  --cleanup          Delete all simulation pods and RBAC objects"
    echo "  --help, -h         Show this help message"
    echo ""
}

main() {
    if [ $# -eq 0 ]; then
        usage
        exit 1
    fi

    while [ $# -gt 0 ]; do
        case "$1" in
            --all)
                scenario_1_shell_spawn
                scenario_2_token_access
                scenario_3_container_escape
                scenario_4_rogue_rbac
                shift
                ;;
            --scenario)
                if [ -z "${2:-}" ]; then
                    log_fail "Error: --scenario requires a number (1, 2, 3, or 4)"
                    exit 1
                fi
                case "$2" in
                    1) scenario_1_shell_spawn ;;
                    2) scenario_2_token_access ;;
                    3) scenario_3_container_escape ;;
                    4) scenario_4_rogue_rbac ;;
                    *) log_fail "Unknown scenario '$2'. Valid: 1, 2, 3, 4"; exit 1 ;;
                esac
                shift 2
                ;;
            --cleanup)
                cleanup
                shift
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                log_fail "Unknown argument: $1"
                usage
                exit 1
                ;;
        esac
    done
}

main "$@"
