# k8s-guard: Kubernetes Runtime & Control-Plane Threat Detection Lab

## 1. Executive Overview

`k8s-guard` is a production-grade Kubernetes threat detection lab designed to validate, test, and operationalize security telemetry across both the **Runtime Plane** (kernel syscalls via eBPF) and the **Control Plane** (Kubernetes API server audit logs).

Modern Kubernetes environments face multi-vector attacks spanning container breakouts, token theft, living-off-the-land interactive shell executions, and privilege escalation via API RBAC manipulation. Single-layer defenses fail to provide complete visibility. `k8s-guard` provides a dual-telemetry detection architecture:

1. **Runtime Threat Detection**: CNCF Falco (v0.37+) utilizing the **Modern eBPF** probe architecture (`driver.kind=modern_ebpf`) to detect hostile process execution, credential theft, and container escape surfaces in real time.
2. **Control-Plane Audit Detection**: Kubernetes API Server Audit Policy coupled with an automated audit parser and detection engine (`detections/k8s_audit_rules.py`) to detect unauthorized RBAC bindings, suspicious pod creation, and administrative exec calls.
3. **Automated Emulation & Verification Harness**: Purple-team attack emulation scripts (`attacks/simulate_ttp.sh`) and an automated test suite (`validation/test_coverage.py`) asserting detection rules fire with zero manual guesswork.

```
================================================================================
SYSTEM ARCHITECTURE & DATA FLOW
================================================================================

  +-----------------------------------------------------------------------+
  | HOST SYSTEM (Docker Engine / macOS / Linux)                           |
  |                                                                       |
  |  +-----------------------------------------------------------------+  |
  |  | KIND CLUSTER (Kubernetes-in-Docker Node Container)              |  |
  |  |                                                                 |  |
  |  |  [K8s API Server] <----------> [Audit Policy: audit-policy.yaml]|  |
  |  |         |                                    |                  |  |
  |  |         | (Webhook / Log Mount)              |                  |  |
  |  |         v                                    v                  |  |
  |  |  /var/log/kubernetes/kube-audit.log   (Control Plane Telemetry) |  |
  |  |                                                                 |  |
  |  |  [Host Kernel / vHost] <--- [eBPF Probe: modern_ebpf]           |  |
  |  |                                      |                          |  |
  |  |                                      v                          |  |
  |  |  +-----------------------------------------------------------+  |  |
  |  |  | FALCO DAEMONSET (Namespace: falco)                        |  |  |
  |  |  |  - Default Rules Engine (Syscall events)                  |  |  |
  |  |  |  - Custom Rules: falco_custom_rules.yaml                  |  |  |
  |  |  |  - Output: Structured JSON to stdout / file / webhook     |  |  |
  |  |  +-----------------------------+-----------------------------+  |  |
  |  |                                |                                |  |
  |  |  +-----------------------------v-----------------------------+  |  |
  |  |  | TEST & PRODUCTION WORKLOADS                               |  |  |
  |  |  |  - Pod: payment-service (simulated victim)                |  |  |
  |  |  |  - Pod: breakout-pod (privileged escape simulation)       |  |  |
  |  |  +-----------------------------------------------------------+  |  |
  |  +-----------------------------------------------------------------+  |
  |                                                                       |
  |  +-----------------------------------------------------------------+  |
  |  | VALIDATION & ATTACK EMULATION RUNNER (Host Python / Bash)       |  |
  |  |  - attacks/simulate_ttp.sh (Executes T1609, T1613, T1611, etc.) |  |
  |  |  - detections/k8s_audit_rules.py (API Server Audit Engine)      |  |
  |  |  - validation/test_coverage.py (Automated Detection Assertions) |  |
  |  +-----------------------------------------------------------------+  |
  +-----------------------------------------------------------------------+
```

---

## 2. Repository Structure

```
k8s-guard/
├── Makefile                        # Unified lifecycle management and test commands
├── README.md                       # Architectural guide, runbook, and design decisions
├── cluster/
│   ├── kind-config.yaml            # Kind cluster manifest with audit-log volume mounts
│   └── audit-policy.yaml           # K8s API server audit filtering policy
├── detections/
│   ├── falco_custom_rules.yaml     # Production Falco eBPF detection rules
│   ├── falco_values.yaml           # Helm override values enabling modern_ebpf & JSON
│   └── k8s_audit_rules.py          # Control plane audit log parser & detector
├── attacks/
│   ├── simulate_ttp.sh             # Automated MITRE ATT&CK emulation runner
│   └── payloads/
│       ├── breakout-pod.yaml       # HostPath escape container manifest (T1611)
│       └── rogue-rbac.yaml         # Privilege escalation ClusterRoleBinding (T1098.004)
└── validation/
    ├── test_coverage.py            # Automated test suite asserting detection firing
    └── sample_alerts.json          # Verified sample JSON alert outputs
```

---

## 3. Technical Stack & Prerequisites

| Component | Target Version | Purpose |
|---|---|---|
| Host Container Runtime | Docker Engine 24.0+, OrbStack, or Docker Desktop | Base execution container runtime |
| Kubernetes Engine | Kind (Kubernetes-in-Docker) v0.22+ | Local isolated multi-node or single-node cluster |
| Kubernetes Version | v1.29+ / v1.30+ | Target cluster control-plane and worker |
| Runtime Threat Engine | Falco v0.37+ (CNCF Graduated) | Real-time kernel syscall detection via eBPF |
| eBPF Probe | Modern eBPF (`driver.kind=modern_ebpf`) | Kernel probe with BPF CO-RE (no header compile) |
| Package Manager | Helm v3.12+ | Falco deployment and configuration |
| Test Harness | Python 3.10+, Bash 4+, Kubectl CLI | Adversary emulation and detection validation |

### Host Prerequisites Installation (macOS / Linux)

```bash
# macOS (via Homebrew)
brew install kind kubectl helm

# Linux (Debian/Ubuntu/RHEL)
# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl && sudo mv kubectl /usr/local/bin/

# Install kind
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.22.0/kind-linux-amd64
chmod +x ./kind && sudo mv ./kind /usr/local/bin/

# Install helm
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

---

## 4. Threat Matrix & MITRE ATT&CK Alignment

The following threat scenarios are modeled, emulated, and detected across both runtime and control-plane layers:

| Scenario | MITRE ID | Threat Technique | Telemetry Source | Primary Rule ID / Name |
|---|---|---|---|---|
| **Scenario 1** | **T1609** | Interactive Shell in Container | Runtime (eBPF syscall) | `Unauthorized Interactive Shell in Workload Container` |
| **Scenario 1 (API)** | **T1609** | Workload Exec via API Server | Control Plane (Audit Log) | `K8S-AUDIT-002: Container Exec Command Executed via API` |
| **Scenario 2** | **T1613** | Service Account Token Harvesting | Runtime (eBPF syscall) | `Access to Service Account Token by Untrusted Binary` |
| **Scenario 2 (API)** | **T1613** | Direct Secret Access via API | Control Plane (Audit Log) | `K8S-AUDIT-003: Direct Secret Credential Access via API` |
| **Scenario 3** | **T1611** | HostPath Container Escape Surface | Runtime (eBPF syscall) & Control Plane | `Sensitive Host Path Mounted in Pod Spec` / `K8S-AUDIT-004` |
| **Scenario 4** | **T1098.004** | Rogue ClusterRoleBinding Escalation | Control Plane (Audit Log) | `K8S-AUDIT-001: Rogue ClusterRoleBinding to cluster-admin` |

---

## 5. Step-by-Step Deployment Runbook

### Step 1: Initialize Workspace & Setup

Create the local log storage directories:

```bash
make setup
# OR:
mkdir -p logs/audit
```

### Step 2: Provision Kind Cluster with API Server Audit Logging

Deploy the Kind cluster with custom volume mounts and audit log flags applied to `kube-apiserver`:

```bash
make create-cluster
# OR:
kind create cluster --name k8s-detection-lab --config cluster/kind-config.yaml
```

Verify that the API server is actively emitting audit logs:

```bash
# Verify cluster context
kubectl cluster-info

# Check that the audit log file exists inside the control-plane container
docker exec k8s-detection-lab-control-plane head -n 5 /var/log/kubernetes/kube-audit.log
```

### Step 3: Deploy Falco with Modern eBPF via Helm

Install Falco using the official Helm chart, configuring JSON output and custom rules:

```bash
make deploy-falco
# OR:
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
helm upgrade --install falco falcosecurity/falco \
  --namespace falco --create-namespace \
  -f detections/falco_values.yaml
```

### Step 4: Verify Deployment Health

Ensure Falco is running and the modern eBPF driver successfully attached:

```bash
kubectl get pods -n falco -o wide

# Verify that modern eBPF probe loaded without errors:
kubectl logs -l app.kubernetes.io/name=falco -n falco -c falco | grep -i "modern bpf"
```

---

## 6. Threat Emulation & Detection Validation

### 6.1 Attack Emulation Script (`attacks/simulate_ttp.sh`)

The emulation runner executes safe, atomic attacks directly mapped to our MITRE ATT&CK scenarios.

```bash
# Execute all attack scenarios:
./attacks/simulate_ttp.sh --all

# Execute individual scenarios:
./attacks/simulate_ttp.sh --scenario 1   # T1609: Interactive Shell
./attacks/simulate_ttp.sh --scenario 2   # T1613: SA Token Access
./attacks/simulate_ttp.sh --scenario 3   # T1611: HostPath Escape Surface
./attacks/simulate_ttp.sh --scenario 4   # T1098.004: Rogue ClusterRoleBinding

# Teardown simulation workloads:
./attacks/simulate_ttp.sh --cleanup
```

### 6.2 Control-Plane Audit Detection Engine (`detections/k8s_audit_rules.py`)

Run the audit log detector in real time or over existing logs:

```bash
# Stream and analyze events directly from the Kind control-plane container:
python3 detections/k8s_audit_rules.py --kind-cluster k8s-detection-lab

# Continuously tail audit events in human-readable SOC format:
python3 detections/k8s_audit_rules.py --kind-cluster k8s-detection-lab --follow --output-format text

# Analyze audit logs from local file:
python3 detections/k8s_audit_rules.py --file logs/audit/kube-audit.log
```

### 6.3 Automated Test Suite (`validation/test_coverage.py`)

Run automated assertions to guarantee alert generation:

```bash
# Offline verification (validates rules, parsers, and sample schemas without cluster):
python3 validation/test_coverage.py --offline

# Live cluster verification (executes attacks and asserts telemetry firing):
python3 validation/test_coverage.py --live --cluster-name k8s-detection-lab
```

---

## 7. Technical Design Decisions & Controversial Choices

The following design decisions were made to guarantee production fidelity, performance stability, and operational usability:

### Decision 1: Modern eBPF (`modern_ebpf`) vs Kernel Modules or Legacy eBPF
- **Rationale**: Older Falco deployments relied on kernel module compilation (`falco-driver-loader`), which requires compiling C code against the exact kernel headers of the host node. On macOS (Docker VM) and ephemeral cloud instances, kernel header compilation frequently breaks. Modern eBPF leverages BPF CO-RE (Compile Once, Run Everywhere) and BTF (`/sys/kernel/btf/vmlinux`), bundling the probe directly inside the Falco binary.
- **Trade-off / Controversy**: Modern eBPF requires a minimum Linux kernel version of 5.8+. Older legacy kernels (<5.8) cannot run modern eBPF. For local developer environments running Docker Desktop, OrbStack, or modern Linux distributions (kernel 5.15+ or 6.x), this is the optimal and recommended configuration.

### Decision 2: Kind `extraMounts` Schema (`containerPath` vs `mountPath`)
- **Rationale**: In the Kind `kind.x-k8s.io/v1alpha4` configuration API, node extra mounts use `containerPath` to specify the destination path inside the Kind node container (`hostPath` -> `containerPath`). In contrast, kubeadm API patches use `mountPath`. Specifying `mountPath` under Kind's `extraMounts` causes a YAML unmarshal failure during cluster creation.
- **Implementation**: `cluster/kind-config.yaml` explicitly adheres to `containerPath: /etc/kubernetes/audit-policy.yaml`.

### Decision 3: Syscall Scoping on File Paths in Falco Rules
- **Rationale**: In standard Falco syntax, conditions matching file paths (e.g., `fd.name startswith "/host/proc"`) without an event type restriction evaluate against **every syscall** referencing that file descriptor (including `read`, `write`, `close`, `fstat`, `lseek`, `poll`). If a container accesses `/host/proc`, thousands of syscall events can be generated within seconds, causing ring buffer drops and alerting floods.
- **Implementation**: The custom rule scopes evaluation to file open operations: `(evt.type in (open, openat, openat2) or open_read)`. This captures the exact moment the sensitive host path is accessed while preventing event storms.

### Decision 4: Audit Log Dual-Access Architecture (Mount + Docker Exec Fallback)
- **Rationale**: On macOS, Docker VM volume mounts can occasionally encounter file synchronization delays or UID/GID permission isolation when root services inside the VM write to `/var/log/kubernetes`.
- **Implementation**: `k8s_audit_rules.py` and `test_coverage.py` implement dual retrieval: they attempt direct disk access first (via `./logs/audit/kube-audit.log`), and automatically fall back to executing `docker exec <cluster>-control-plane cat /var/log/kubernetes/kube-audit.log` if local mount synchronization is delayed.

### Decision 5: Atomic Red Team Emulation vs Destructive Payloads
- **Rationale**: Security validation scripts must be safe to execute in CI/CD pipelines, shared developer environments, and automated test runners. Emulating T1611 (container escape) using destructive host-compromise exploits or rootkits introduces operational risk.
- **Implementation**: `attacks/payloads/breakout-pod.yaml` safely defines the dangerous hostPath mount (`/proc` and `/etc`) and triggers an inspection command (`head -n 1 /host/proc/version`). This triggers the exact detection signature without destabilizing the host system or altering host state.

---

## 8. Troubleshooting Guide

### Issue 0: Docker Daemon Unreachable (`connect: no such file or directory`)
- **Cause**: Kind executes `docker info --format '{{json .}}'` during cluster initialization. If the active Docker context points to a stopped daemon (such as OrbStack or Docker Desktop), Kind fails immediately with:
  `failed to connect to the docker API at unix:///Users/<user>/.orbstack/run/docker.sock: connect: no such file or directory`
- **Diagnosis**:
  ```bash
  docker context show
  docker info
  ```
- **Resolution**:
  - **If using OrbStack**: Start the engine by running `orb start` in your terminal or opening `/Applications/OrbStack.app`.
  - **If using Docker Desktop**: Switch to the Docker Desktop context and launch Docker:
    ```bash
    docker context use desktop-linux
    open /Applications/Docker.app
    ```
  - **If using standard Docker socket**:
    ```bash
    docker context use default
    ```

### Issue 1: Falco Pod Enters `CrashLoopBackOff`
- **Cause**: The host kernel lacks BTF support or is running a kernel version below 5.8.
- **Diagnosis**:
  ```bash
  kubectl logs -n falco -l app.kubernetes.io/name=falco -c falco --tail=50
  ```
- **Resolution**:
  Verify BTF availability inside the Kind node:
  ```bash
  docker exec -it k8s-detection-lab-control-plane ls -la /sys/kernel/btf/vmlinux
  ```
  If BTF is missing, upgrade Docker Desktop/OrbStack to the latest version, or fall back to `driver.kind=ebpf` with an appropriate driver loader.

### Issue 2: Audit Logs are Not Being Written
- **Cause**: The API server failed to mount `audit-policy.yaml` or cannot write to `/var/log/kubernetes`.
- **Diagnosis**:
  ```bash
  docker exec -it k8s-detection-lab-control-plane cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep audit
  docker exec -it k8s-detection-lab-control-plane crictl logs $(docker exec k8s-detection-lab-control-plane crictl ps --name kube-apiserver -q)
  ```
- **Resolution**: Ensure `cluster/kind-config.yaml` has `containerPath: /etc/kubernetes/audit-policy.yaml` and `./cluster/audit-policy.yaml` exists relative to the execution root.

### Issue 3: Falco Events Lag or Buffer
- **Cause**: Modern eBPF buffers events in kernel ring buffers before flushing to userspace.
- **Resolution**: Falco buffers events by default to optimize CPU. In automated testing, wait 2 to 5 seconds after running an attack command, or configure `output_timeout: 100` in Falco values for real-time flush during testing.
# k8-guard
