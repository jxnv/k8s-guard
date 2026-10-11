#!/usr/bin/env python3
"""Kubernetes Control Plane Audit Log Detection Engine.

Analyzes Kubernetes API server audit events (audit.k8s.io/v1) for runtime
threats, policy violations, and adversary techniques aligned with MITRE ATT&CK
for Containers and Kubernetes.

Supported Scenarios & Detections:
- T1098.004: Rogue ClusterRoleBinding (cluster-admin privilege escalation)
- T1609: Workload Container Exec via API Server (pods/exec)
- T1613: Secret Credential Harvesting via API Server
- T1611: Pod creation with hostPath escape surfaces or privileged containers
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from typing import Any, Callable, Dict, Generator, Iterable, List, Optional


@dataclass
class AuditAlert:
    """Represents a structured security detection emitted from audit log analysis."""
    timestamp: str
    rule_id: str
    rule_name: str
    severity: str
    mitre_technique: str
    mitre_tactic: str
    actor_username: str
    actor_groups: List[str]
    source_ips: List[str]
    user_agent: str
    resource: str
    resource_name: Optional[str]
    resource_namespace: Optional[str]
    verb: str
    audit_id: str
    details: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Convert dataclass to dictionary representation."""
        return asdict(self)

    def to_json(self) -> str:
        """Serialize alert to JSON formatted string."""
        return json.dumps(self.to_dict())


class AuditRule:
    """Base class defining a detection rule interface for audit events."""

    rule_id: str
    rule_name: str
    severity: str
    mitre_technique: str
    mitre_tactic: str

    def evaluate(self, event: Dict[str, Any]) -> Optional[AuditAlert]:
        """Evaluate an audit event and return an AuditAlert if triggered."""
        raise NotImplementedError


class RogueClusterRoleBindingRule(AuditRule):
    """Detects creation or modification of ClusterRoleBindings granting cluster-admin.

    MITRE ATT&CK: T1098.004 (Account Manipulation: SSH/ClusterRoleBinding)
    """

    rule_id = "K8S-AUDIT-001"
    rule_name = "Rogue ClusterRoleBinding to cluster-admin"
    severity = "CRITICAL"
    mitre_technique = "T1098.004"
    mitre_tactic = "Privilege Escalation / Persistence"

    # Known standard control plane bindings to ignore if created by system bootstrap
    TRUSTED_BINDING_NAMES = {
        "cluster-admin",
        "system:controller:bootstrap-signer",
    }

    def evaluate(self, event: Dict[str, Any]) -> Optional[AuditAlert]:
        object_ref = event.get("objectRef") or {}
        resource = object_ref.get("resource", "")
        api_group = object_ref.get("apiGroup", "")

        if api_group != "rbac.authorization.k8s.io" or resource != "clusterrolebindings":
            return None

        verb = event.get("verb", "")
        if verb not in ("create", "update", "patch"):
            return None

        stage = event.get("stage", "")
        if stage not in ("ResponseComplete", ""):
            return None

        binding_name = object_ref.get("name", "")
        if binding_name in self.TRUSTED_BINDING_NAMES:
            return None

        # Inspect requestObject and responseObject for roleRef
        request_obj = event.get("requestObject") or {}
        response_obj = event.get("responseObject") or {}

        role_ref = request_obj.get("roleRef") or response_obj.get("roleRef") or {}
        role_name = role_ref.get("name", "")

        subjects = request_obj.get("subjects") or response_obj.get("subjects") or []

        # Trigger if bound to cluster-admin
        if role_name == "cluster-admin":
            user = event.get("user") or {}
            return AuditAlert(
                timestamp=event.get("stageTimestamp") or event.get("requestReceivedTimestamp") or "",
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                mitre_technique=self.mitre_technique,
                mitre_tactic=self.mitre_tactic,
                actor_username=user.get("username", "unknown"),
                actor_groups=user.get("groups", []),
                source_ips=event.get("sourceIPs", []),
                user_agent=event.get("userAgent", "unknown"),
                resource=resource,
                resource_name=binding_name,
                resource_namespace=object_ref.get("namespace"),
                verb=verb,
                audit_id=event.get("auditID", ""),
                details={
                    "roleRef": role_name,
                    "subjects": subjects,
                    "binding_name": binding_name,
                },
            )
        return None


class PodExecRule(AuditRule):
    """Detects interactive exec requests dispatched to workload pods.

    MITRE ATT&CK: T1609 (Execution: Container Administration Command)
    """

    rule_id = "K8S-AUDIT-002"
    rule_name = "Container Exec Command Executed via API Server"
    severity = "HIGH"
    mitre_technique = "T1609"
    mitre_tactic = "Execution"

    SYSTEM_NAMESPACES = {"kube-system"}

    def evaluate(self, event: Dict[str, Any]) -> Optional[AuditAlert]:
        object_ref = event.get("objectRef") or {}
        resource = object_ref.get("resource", "")
        subresource = object_ref.get("subresource", "")

        if resource == "pods" and subresource in ("exec", "attach"):
            namespace = object_ref.get("namespace", "default")
            if namespace in self.SYSTEM_NAMESPACES:
                return None

            user = event.get("user") or {}
            pod_name = object_ref.get("name", "")
            verb = event.get("verb", "")

            return AuditAlert(
                timestamp=event.get("stageTimestamp") or event.get("requestReceivedTimestamp") or "",
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                mitre_technique=self.mitre_technique,
                mitre_tactic=self.mitre_tactic,
                actor_username=user.get("username", "unknown"),
                actor_groups=user.get("groups", []),
                source_ips=event.get("sourceIPs", []),
                user_agent=event.get("userAgent", "unknown"),
                resource=f"{resource}/{subresource}",
                resource_name=pod_name,
                resource_namespace=namespace,
                verb=verb,
                audit_id=event.get("auditID", ""),
                details={
                    "pod": pod_name,
                    "namespace": namespace,
                    "subresource": subresource,
                    "uri": event.get("requestURI", ""),
                },
            )
        return None


class SecretAccessRule(AuditRule):
    """Detects access to sensitive secret resources by unexpected actors.

    MITRE ATT&CK: T1613 (Credential Access: Container and Resource Discovery)
    """

    rule_id = "K8S-AUDIT-003"
    rule_name = "Direct Secret Credential Access via API"
    severity = "HIGH"
    mitre_technique = "T1613"
    mitre_tactic = "Credential Access"

    TRUSTED_USERS_PREFIX = (
        "system:node:",
        "system:kube-controller-manager",
        "system:serviceaccount:kube-system:",
    )

    def evaluate(self, event: Dict[str, Any]) -> Optional[AuditAlert]:
        object_ref = event.get("objectRef") or {}
        resource = object_ref.get("resource", "")

        if resource != "secrets":
            return None

        verb = event.get("verb", "")
        if verb not in ("get", "list"):
            return None

        user = event.get("user") or {}
        username = user.get("username", "")

        # Ignore trusted infrastructure system accounts
        if any(username.startswith(prefix) for prefix in self.TRUSTED_USERS_PREFIX):
            return None

        secret_name = object_ref.get("name", "*")
        namespace = object_ref.get("namespace", "default")

        return AuditAlert(
            timestamp=event.get("stageTimestamp") or event.get("requestReceivedTimestamp") or "",
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            mitre_technique=self.mitre_technique,
            mitre_tactic=self.mitre_tactic,
            actor_username=username,
            actor_groups=user.get("groups", []),
            source_ips=event.get("sourceIPs", []),
            user_agent=event.get("userAgent", "unknown"),
            resource=resource,
            resource_name=secret_name,
            resource_namespace=namespace,
            verb=verb,
            audit_id=event.get("auditID", ""),
            details={
                "secret_name": secret_name,
                "namespace": namespace,
                "uri": event.get("requestURI", ""),
            },
        )


class PrivilegedHostEscapePodRule(AuditRule):
    """Detects creation of Pods configured with hostPath volume mounts or privileged mode.

    MITRE ATT&CK: T1611 (Privilege Escalation: Escape to Host)
    """

    rule_id = "K8S-AUDIT-004"
    rule_name = "Pod Spec Declares Sensitive HostPath or Privileged SecurityContext"
    severity = "CRITICAL"
    mitre_technique = "T1611"
    mitre_tactic = "Privilege Escalation"

    SENSITIVE_HOST_PATHS = ("/proc", "/etc", "/var/run/docker.sock", "/sys", "/")

    def evaluate(self, event: Dict[str, Any]) -> Optional[AuditAlert]:
        object_ref = event.get("objectRef") or {}
        resource = object_ref.get("resource", "")

        if resource != "pods":
            return None

        verb = event.get("verb", "")
        if verb not in ("create", "update"):
            return None

        req_obj = event.get("requestObject") or {}
        spec = req_obj.get("spec") or {}

        reasons = []

        # Check hostPath volumes
        volumes = spec.get("volumes") or []
        for v in volumes:
            host_path_info = v.get("hostPath")
            if host_path_info:
                path = host_path_info.get("path", "")
                for sensitive in self.SENSITIVE_HOST_PATHS:
                    if path == sensitive or path.startswith(f"{sensitive}/"):
                        reasons.append(f"hostPath volume '{v.get('name')}' mounts sensitive host path '{path}'")

        # Check privileged containers
        containers = (spec.get("containers") or []) + (spec.get("initContainers") or [])
        for c in containers:
            sec_ctx = c.get("securityContext") or {}
            if sec_ctx.get("privileged") is True:
                reasons.append(f"container '{c.get('name')}' runs in privileged mode")

        if not reasons:
            return None

        user = event.get("user") or {}
        pod_name = object_ref.get("name") or req_obj.get("metadata", {}).get("name", "unknown")
        namespace = object_ref.get("namespace", "default")

        return AuditAlert(
            timestamp=event.get("stageTimestamp") or event.get("requestReceivedTimestamp") or "",
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            mitre_technique=self.mitre_technique,
            mitre_tactic=self.mitre_tactic,
            actor_username=user.get("username", "unknown"),
            actor_groups=user.get("groups", []),
            source_ips=event.get("sourceIPs", []),
            user_agent=event.get("userAgent", "unknown"),
            resource=resource,
            resource_name=pod_name,
            resource_namespace=namespace,
            verb=verb,
            audit_id=event.get("auditID", ""),
            details={
                "pod_name": pod_name,
                "reasons": reasons,
            },
        )


class AuditLogDetector:
    """Detection engine managing registered rules and event evaluation."""

    def __init__(self, rules: Optional[List[AuditRule]] = None) -> None:
        self.rules: List[AuditRule] = rules or [
            RogueClusterRoleBindingRule(),
            PodExecRule(),
            SecretAccessRule(),
            PrivilegedHostEscapePodRule(),
        ]

    def evaluate_line(self, line: str) -> List[AuditAlert]:
        """Evaluate a raw JSON string line from the audit log."""
        line = line.strip()
        if not line:
            return []
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return []

        alerts: List[AuditAlert] = []
        for rule in self.rules:
            try:
                alert = rule.evaluate(event)
                if alert:
                    alerts.append(alert)
            except Exception as exc:
                # Isolate rule evaluation failure to prevent breaking the detector
                print(f"[!] Warning: Rule {rule.rule_id} raised exception: {exc}", file=sys.stderr)
        return alerts

    def process_stream(self, lines: Iterable[str]) -> Generator[AuditAlert, None, None]:
        """Process an iterable stream of JSON log lines, yielding alerts as detected."""
        for line in lines:
            for alert in self.evaluate_line(line):
                yield alert


def stream_from_kind_container(cluster_name: str, log_path: str = "/var/log/kubernetes/kube-audit.log") -> Generator[str, None, None]:
    """Retrieve audit log content directly from the Kind control-plane container via docker exec."""
    container_name = f"{cluster_name}-control-plane"
    cmd = ["docker", "exec", container_name, "cat", log_path]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if proc.stdout is not None:
            for line in proc.stdout:
                yield line
        proc.wait()
    except FileNotFoundError:
        print("[!] Error: Docker CLI binary not found in PATH", file=sys.stderr)
    except Exception as exc:
        print(f"[!] Error reading from Kind container {container_name}: {exc}", file=sys.stderr)


def stream_from_file(file_path: str, follow: bool = False) -> Generator[str, None, None]:
    """Stream audit log lines from local disk, optionally following file appends."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Audit log file not found at: {file_path}")

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        if not follow:
            for line in f:
                yield line
            return

        # Follow mode
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Kubernetes API Server Audit Log Threat Detection Engine"
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--file", "-f",
        type=str,
        help="Path to local kube-audit.log file",
    )
    group.add_argument(
        "--kind-cluster", "-k",
        type=str,
        default=None,
        help="Kind cluster name to stream audit logs directly from control-plane container",
    )
    group.add_argument(
        "--stdin",
        action="store_true",
        help="Read audit log events from standard input",
    )
    parser.add_argument(
        "--follow",
        action="store_true",
        help="Continuously tail the audit log for new events",
    )
    parser.add_argument(
        "--output-format",
        choices=["json", "text"],
        default="json",
        help="Format for emitted alerts (default: json)",
    )
    return parser.parse_args()


def format_alert_text(alert: AuditAlert) -> str:
    """Format alert as human-readable SOC analyst text."""
    return (
        f"[{alert.severity}] [{alert.mitre_technique}] {alert.rule_name}\n"
        f"  Actor:    {alert.actor_username} (IPs: {', '.join(alert.source_ips) or 'N/A'})\n"
        f"  Action:   {alert.verb} on {alert.resource} -> {alert.resource_name or 'N/A'}\n"
        f"  Time:     {alert.timestamp}\n"
        f"  Details:  {json.dumps(alert.details)}\n"
    )


def main() -> int:
    args = parse_args()
    detector = AuditLogDetector()

    lines_stream: Iterable[str]

    if args.stdin or (not args.file and not args.kind_cluster and not sys.stdin.isatty()):
        lines_stream = sys.stdin
    elif args.kind_cluster:
        lines_stream = stream_from_kind_container(args.kind_cluster)
    elif args.file:
        lines_stream = stream_from_file(args.file, follow=args.follow)
    else:
        # Check standard default locations
        default_candidates = [
            "logs/audit/kube-audit.log",
            "/var/log/kubernetes/kube-audit.log",
        ]
        found_file = next((p for p in default_candidates if os.path.exists(p)), None)
        if found_file:
            print(f"[*] Reading audit logs from detected path: {found_file}", file=sys.stderr)
            lines_stream = stream_from_file(found_file, follow=args.follow)
        else:
            print("[!] Error: No audit log source provided. Use --file, --kind-cluster, or pipe via stdin.", file=sys.stderr)
            return 1

    alert_count = 0
    try:
        for alert in detector.process_stream(lines_stream):
            alert_count += 1
            if args.output_format == "json":
                print(alert.to_json(), flush=True)
            else:
                print(format_alert_text(alert), flush=True)
    except KeyboardInterrupt:
        pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
