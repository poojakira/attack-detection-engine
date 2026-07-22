"""
Behavior detection engine.
Analyzes process trees, API call sequences, and behavioral patterns.
"""

from typing import List, Dict, Any
from .base import BaseDetector, DetectionFinding
from .pattern_library import BEHAVIOR_PATTERNS


class BehaviorDetector(BaseDetector):
    def detect(self, data: List[Dict[str, Any]]) -> List[DetectionFinding]:
        """
        data: list of behavioral telemetry records with keys:
              - process_tree: dict of parent->children relationships
              - api_calls: list of API call sequences
              - process_info: dict with pid, ppid, cmdline, image_path, user
              - timestamp, host
        """
        findings = []
        for record in data:
            findings.extend(self._analyze_process_tree(record))
            findings.extend(self._analyze_api_calls(record))
            findings.extend(self._analyze_process_anomalies(record))
        return findings

    def _analyze_process_tree(self, record: Dict) -> List[DetectionFinding]:
        findings = []
        tree = record.get("process_tree", {})
        suspicious_parent_child = [
            ("winword.exe", "powershell.exe"),
            ("excel.exe", "powershell.exe"),
            ("outlook.exe", "cmd.exe"),
            ("wordpad.exe", "powershell.exe"),
            ("notepad.exe", "powershell.exe"),
            ("iexplore.exe", "cmd.exe"),
            ("excel.exe", "wscript.exe"),
            ("winword.exe", "cscript.exe"),
            ("powershell.exe", "cmd.exe"),
            ("cmd.exe", "powershell.exe"),
            ("mshta.exe", "powershell.exe"),
            ("rundll32.exe", "powershell.exe"),
            ("regsvr32.exe", "powershell.exe"),
            ("certutil.exe", "cmd.exe"),
            ("msbuild.exe", "cmd.exe"),
        ]

        for parent, children in tree.items():
            parent_name = parent.lower()
            for child in children:
                child_name = child.get("name", "").lower()
                for sus_parent, sus_child in suspicious_parent_child:
                    if sus_parent in parent_name and sus_child in child_name:
                        findings.append(self._make_finding(
                            "T1059.001", "Suspicious Process Spawn",
                            "HIGH", 0.85, record, "behavior",
                            f"{parent_name} spawned {child_name}"
                        ))
        return findings

    def _analyze_api_calls(self, record: Dict) -> List[DetectionFinding]:
        findings = []
        api_calls = record.get("api_calls", [])

        injection_apis = [
            "WriteProcessMemory", "CreateRemoteThread", "VirtualAllocEx",
            "NtWriteVirtualMemory", "NtCreateThreadEx", "QueueUserAPC",
            "SetThreadContext", "NtQueueApcThread"
        ]

        injection_sequence = []
        for call in api_calls:
            if call.get("api") in injection_apis:
                injection_sequence.append(call)

        if len(injection_sequence) >= 3:
            findings.append(self._make_finding(
                "T1055", "Process Injection API Sequence",
                "CRITICAL", 0.9, record, "behavior",
                f"Injection APIs: {[c['api'] for c in injection_sequence]}"
            ))

        return findings

    def _analyze_process_anomalies(self, record: Dict) -> List[DetectionFinding]:
        findings = []
        proc = record.get("process_info", {})
        image_path = proc.get("image_path", "").lower()
        cmdline = proc.get("cmdline", "").lower()
        parent = proc.get("parent_image", "").lower()

        if "temp" in image_path or "appdata" in image_path:
            if any(x in cmdline for x in ["powershell", "cmd", "wscript", "cscript", "rundll32"]):
                findings.append(self._make_finding(
                    "T1059", "Script Execution from Temp/AppData",
                    "HIGH", 0.8, record, "behavior",
                    f"Process: {image_path} CMD: {cmdline[:200]}"
                ))

        if "system32" not in image_path and "syswow64" not in image_path:
            system_binaries = ["svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe"]
            for sys_bin in system_binaries:
                if sys_bin in image_path:
                    findings.append(self._make_finding(
                        "T1036", "System Binary in Non-Standard Path",
                        "HIGH", 0.9, record, "behavior",
                        f"{sys_bin} running from {image_path}"
                    ))

        return findings

    def _make_finding(self, tech_id: str, rule_name: str, severity: str, confidence: float,
                      evidence: Dict, source_type: str, description: str) -> DetectionFinding:
        return DetectionFinding(
            rule_id=f"BEH-{tech_id.replace('.', '-')}",
            rule_name=rule_name,
            severity=severity,
            confidence=confidence,
            source_type=source_type,
            raw_evidence=evidence,
            mappings=[self._build_mapping(tech_id, confidence)],
            timestamp=str(evidence.get("timestamp", "")),
            host=evidence.get("host", ""),
            description=description,
        )