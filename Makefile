# ==============================================================================
# Makefile: k8s-guard / k8s-detection-lab
# Threat Detection & Defense Engineering Automation
# ==============================================================================

CLUSTER_NAME ?= k8s-detection-lab
FALCO_NAMESPACE ?= falco
KIND_CONFIG ?= cluster/kind-config.yaml
AUDIT_POLICY ?= cluster/audit-policy.yaml
FALCO_VALUES ?= detections/falco_values.yaml

.PHONY: all setup create-cluster deploy-falco status simulate simulate-s1 simulate-s2 simulate-s3 simulate-s4 clean test-live test-offline audit-tail falco-logs destroy-cluster

all: test-offline

# ------------------------------------------------------------------------------
# Cluster Management
# ------------------------------------------------------------------------------

check-docker:
	@if ! docker info >/dev/null 2>&1; then \
		CURRENT_CTX=$$(docker context show 2>/dev/null || echo "unknown"); \
		echo "[!] Error: Docker daemon is unreachable (active context: $${CURRENT_CTX})."; \
		echo "    Remediation steps:"; \
		echo "    1. If using OrbStack:"; \
		echo "       Run 'orb start' in your terminal or launch /Applications/OrbStack.app"; \
		echo "    2. If using Docker Desktop:"; \
		echo "       Switch context: 'docker context use desktop-linux'"; \
		echo "       Launch /Applications/Docker.app"; \
		echo "    3. If using standard daemon socket:"; \
		echo "       Switch context: 'docker context use default'"; \
		exit 1; \
	fi

setup:
	@mkdir -p logs/audit
	@chmod 755 attacks/simulate_ttp.sh validation/test_coverage.py detections/k8s_audit_rules.py

create-cluster: setup check-docker
	@echo "[*] Launching Kind cluster '$(CLUSTER_NAME)' with API audit logging..."
	kind create cluster --name $(CLUSTER_NAME) --config $(KIND_CONFIG)
	@echo "[+] Verifying cluster connectivity..."
	kubectl cluster-info --context kind-$(CLUSTER_NAME)

destroy-cluster:
	@echo "[*] Tearing down Kind cluster '$(CLUSTER_NAME)'..."
	kind delete cluster --name $(CLUSTER_NAME)

# ------------------------------------------------------------------------------
# Falco Deployment
# ------------------------------------------------------------------------------

deploy-falco:
	@echo "[*] Adding Falco Helm repository..."
	helm repo add falcosecurity https://falcosecurity.github.io/charts
	helm repo update
	@echo "[*] Installing/Upgrading Falco with modern_ebpf driver and custom rules..."
	helm upgrade --install falco falcosecurity/falco \
		--namespace $(FALCO_NAMESPACE) --create-namespace \
		-f $(FALCO_VALUES)
	@echo "[*] Waiting for Falco daemonset rollout..."
	kubectl rollout status daemonset/falco -n $(FALCO_NAMESPACE) --timeout=120s
	@echo "[+] Falco runtime engine deployed successfully."

status:
	@echo "=== Node Status ==="
	@kubectl get nodes -o wide
	@echo "\n=== Falco Pods ==="
	@kubectl get pods -n $(FALCO_NAMESPACE) -o wide
	@echo "\n=== Workload Pods ==="
	@kubectl get pods -n default -o wide

# ------------------------------------------------------------------------------
# Attack Emulation & Purple Teaming
# ------------------------------------------------------------------------------

simulate:
	@attacks/simulate_ttp.sh --all

simulate-s1:
	@attacks/simulate_ttp.sh --scenario 1

simulate-s2:
	@attacks/simulate_ttp.sh --scenario 2

simulate-s3:
	@attacks/simulate_ttp.sh --scenario 3

simulate-s4:
	@attacks/simulate_ttp.sh --scenario 4

clean:
	@attacks/simulate_ttp.sh --cleanup

# ------------------------------------------------------------------------------
# Detection Telemetry & Analysis
# ------------------------------------------------------------------------------

falco-logs:
	@kubectl logs -l app.kubernetes.io/name=falco -n $(FALCO_NAMESPACE) -c falco -f

audit-tail:
	@python3 detections/k8s_audit_rules.py --kind-cluster $(CLUSTER_NAME) --follow

# ------------------------------------------------------------------------------
# Validation & Test Verification
# ------------------------------------------------------------------------------

test-offline:
	@python3 validation/test_coverage.py --offline

test-live:
	@python3 validation/test_coverage.py --live --cluster-name $(CLUSTER_NAME)
