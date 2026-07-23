"""
Central pattern library for all detection engines.
Each pattern maps to one or more ATT&CK technique IDs.
"""

LOG_PATTERNS = [
    {
        "rule_id": "LOG-T1003-001",
        "rule_name": "Credential Dumping - LSASS Access",
        "description": "Detects access to LSASS process memory indicative of credential dumping",
        "severity": "CRITICAL",
        "confidence": 0.9,
        "technique_ids": ["T1003", "T1003.001"],
        "conditions": [
            {"type": "event_id", "values": [4688, 4624]},
            {"type": "field_regex", "field": "Image", "pattern": r"(lsass\.exe|sekurlsa|mimikatz|procdump|comsvcs\.dll)"},
        ],
    },
    {
        "rule_id": "LOG-T1021-001",
        "rule_name": "Remote Services - RDP Logon",
        "description": "Detects successful RDP logons from non-standard sources",
        "severity": "HIGH",
        "confidence": 0.8,
        "technique_ids": ["T1021", "T1021.001"],
        "conditions": [
            {"type": "event_id", "values": [4624]},
            {"type": "field_regex", "field": "LogonType", "pattern": r"^10$"},
        ],
    },
    {
        "rule_id": "LOG-T1047-001",
        "rule_name": "WMI Execution",
        "description": "Detects WMI command execution via wmic or PowerShell",
        "severity": "HIGH",
        "confidence": 0.85,
        "technique_ids": ["T1047"],
        "conditions": [
            {"type": "event_id", "values": [4688]},
            {"type": "message_contains", "keywords": ["wmic", "Get-WmiObject", "Invoke-WmiMethod", "wmi"]},
        ],
    },
    {
        "rule_id": "LOG-T1053-001",
        "rule_name": "Scheduled Task Creation",
        "description": "Detects creation of scheduled tasks via schtasks or Task Scheduler API",
        "severity": "HIGH",
        "confidence": 0.85,
        "technique_ids": ["T1053", "T1053.005"],
        "conditions": [
            {"type": "event_id", "values": [4698, 4702]},
        ],
    },
    {
        "rule_id": "LOG-T1059-001",
        "rule_name": "PowerShell Execution",
        "description": "Detects PowerShell execution with suspicious parameters",
        "severity": "MEDIUM",
        "confidence": 0.75,
        "technique_ids": ["T1059", "T1059.001"],
        "conditions": [
            {"type": "event_id", "values": [4688, 4104]},
            {"type": "message_contains", "keywords": ["powershell", "pwsh", "-enc", "-encoded", "-nop", "-w hidden"]},
        ],
    },
    {
        "rule_id": "LOG-T1059-002",
        "rule_name": "Command Shell Execution",
        "description": "Detects cmd.exe execution with suspicious arguments",
        "severity": "MEDIUM",
        "confidence": 0.7,
        "technique_ids": ["T1059", "T1059.003"],
        "conditions": [
            {"type": "event_id", "values": [4688]},
            {"type": "field_regex", "field": "Image", "pattern": r"cmd\.exe"},
            {"type": "message_contains", "keywords": ["/c", "/k", "&&", "||", "powershell", "wscript", "cscript"]},
        ],
    },
    {
        "rule_id": "LOG-T1070-001",
        "rule_name": "Security Log Cleared",
        "description": "Detects clearing of Windows Security event log",
        "severity": "CRITICAL",
        "confidence": 0.95,
        "technique_ids": ["T1070", "T1070.001"],
        "conditions": [
            {"type": "event_id", "values": [1102]},
        ],
    },
    {
        "rule_id": "LOG-T1078-001",
        "rule_name": "Brute Force - Failed Logons Followed by Success",
        "description": "Detects multiple failed logons followed by successful logon",
        "severity": "HIGH",
        "confidence": 0.8,
        "technique_ids": ["T1078", "T1110"],
        "conditions": [
            {"type": "event_id", "values": [4625, 4624]},
        ],
    },
    {
        "rule_id": "LOG-T1082-001",
        "rule_name": "System Information Discovery",
        "description": "Detects systeminfo, whoami, hostname commands",
        "severity": "LOW",
        "confidence": 0.6,
        "technique_ids": ["T1082"],
        "conditions": [
            {"type": "event_id", "values": [4688]},
            {"type": "message_contains", "keywords": ["systeminfo", "whoami", "hostname", "ipconfig", "net config"]},
        ],
    },
    {
        "rule_id": "LOG-T1083-001",
        "rule_name": "File and Directory Discovery",
        "description": "Detects dir, ls, tree, find commands",
        "severity": "LOW",
        "confidence": 0.6,
        "technique_ids": ["T1083"],
        "conditions": [
            {"type": "event_id", "values": [4688]},
            {"type": "message_contains", "keywords": ["dir ", "ls ", "tree ", "find ", "gci ", "Get-ChildItem"]},
        ],
    },
    {
        "rule_id": "LOG-T1105-001",
        "rule_name": "Ingress Tool Transfer",
        "description": "Detects file download via certutil, bitsadmin, curl, wget, powershell",
        "severity": "HIGH",
        "confidence": 0.85,
        "technique_ids": ["T1105"],
        "conditions": [
            {"type": "event_id", "values": [4688]},
            {"type": "message_contains", "keywords": ["certutil -urlcache", "bitsadmin /transfer", "curl ", "wget ", "Invoke-WebRequest", "Start-BitsTransfer", "System.Net.WebClient"]},
        ],
    },
    {
        "rule_id": "LOG-T1136-001",
        "rule_name": "Account Creation",
        "description": "Detects local or domain account creation",
        "severity": "HIGH",
        "confidence": 0.9,
        "technique_ids": ["T1136", "T1136.001", "T1136.002"],
        "conditions": [
            {"type": "event_id", "values": [4720, 4722, 4723, 4724]},
        ],
    },
    {
        "rule_id": "LOG-T1543-001",
        "rule_name": "Service Creation",
        "description": "Detects new service installation",
        "severity": "HIGH",
        "confidence": 0.85,
        "technique_ids": ["T1543", "T1543.003"],
        "conditions": [
            {"type": "event_id", "values": [7045, 4697]},
        ],
    },
    {
        "rule_id": "LOG-T1562-001",
        "rule_name": "Defender Disabled",
        "description": "Detects Windows Defender being disabled",
        "severity": "CRITICAL",
        "confidence": 0.95,
        "technique_ids": ["T1562", "T1562.001"],
        "conditions": [
            {"type": "event_id", "values": [4688]},
            {"type": "message_contains", "keywords": ["Set-MpPreference -DisableRealtimeMonitoring", "Disable-WindowsDefender", "sc stop WinDefend"]},
        ],
    },
    {
        "rule_id": "LOG-T1566-001",
        "rule_name": "Phishing Email Detected",
        "description": "Detects phishing indicators in email logs",
        "severity": "HIGH",
        "confidence": 0.75,
        "technique_ids": ["T1566", "T1566.001"],
        "conditions": [
            {"type": "source_type", "values": ["email", "exchange", "o365"]},
            {"type": "message_contains", "keywords": ["phish", "malware", "credential", "verify account", "urgent action"]},
        ],
    },
]

TRAFFIC_PATTERNS = [
    {
        "rule_id": "NET-T1041-001",
        "rule_name": "Exfiltration Over C2 Channel",
        "description": "Large outbound data transfer to rare destination",
        "severity": "CRITICAL",
        "confidence": 0.8,
        "technique_ids": ["T1041"],
    },
    {
        "rule_id": "NET-T1048-001",
        "rule_name": "DNS Tunneling",
        "description": "High entropy DNS queries or excessive query length",
        "severity": "HIGH",
        "confidence": 0.85,
        "technique_ids": ["T1048", "T1048.003"],
    },
    {
        "rule_id": "NET-T1071-001",
        "rule_name": "HTTP C2 Beaconing",
        "description": "Regular interval HTTP requests to same destination",
        "severity": "HIGH",
        "confidence": 0.8,
        "technique_ids": ["T1071", "T1071.001"],
    },
    {
        "rule_id": "NET-T1090-001",
        "rule_name": "Proxy/Tor Connection",
        "description": "Connections to known Tor exit nodes or proxy services",
        "severity": "HIGH",
        "confidence": 0.9,
        "technique_ids": ["T1090"],
    },
    {
        "rule_id": "NET-T1102-001",
        "rule_name": "Web Service C2",
        "description": "Communication with GitHub, Pastebin, or similar as C2",
        "severity": "MEDIUM",
        "confidence": 0.7,
        "technique_ids": ["T1102"],
    },
    {
        "rule_id": "NET-T1219-001",
        "rule_name": "Remote Access Tool Traffic",
        "description": "RDP, VNC, TeamViewer, AnyDesk traffic patterns",
        "severity": "MEDIUM",
        "confidence": 0.75,
        "technique_ids": ["T1219"],
    },
    {
        "rule_id": "NET-T1572-001",
        "rule_name": "Protocol Tunneling",
        "description": "DNS over HTTPS, ICMP tunneling, SSH over HTTP",
        "severity": "HIGH",
        "confidence": 0.8,
        "technique_ids": ["T1572"],
    },
]

BEHAVIOR_PATTERNS = [
    {
        "rule_id": "BEH-T1055-001",
        "rule_name": "Process Injection",
        "description": "Cross-process memory writes, thread creation, APC queueing",
        "severity": "CRITICAL",
        "confidence": 0.9,
        "technique_ids": ["T1055", "T1055.001", "T1055.002", "T1055.004"],
    },
    {
        "rule_id": "BEH-T1059-003",
        "rule_name": "Script Interpreter Spawning",
        "description": "Office apps spawning powershell, cmd, wscript, cscript",
        "severity": "HIGH",
        "confidence": 0.85,
        "technique_ids": ["T1059", "T1059.001", "T1059.005", "T1059.007"],
    },
    {
        "rule_id": "BEH-T1106-001",
        "rule_name": "Native API Execution",
        "description": "Direct syscalls, NtCreateThread, NtWriteVirtualMemory",
        "severity": "HIGH",
        "confidence": 0.8,
        "technique_ids": ["T1106"],
    },
]

EVENT_PATTERNS = [
    {
        "rule_id": "EDR-T1003-001",
        "rule_name": "EDR Credential Dumping Alert",
        "description": "EDR detection of LSASS access or credential dumping",
        "severity": "CRITICAL",
        "confidence": 0.95,
        "technique_ids": ["T1003"],
    },
    {
        "rule_id": "EDR-T1562-001",
        "rule_name": "EDR Tampering Detection",
        "description": "EDR agent stopped, uninstalled, or configuration modified",
        "severity": "CRITICAL",
        "confidence": 0.95,
        "technique_ids": ["T1562"],
    },
]

CODE_PATTERNS = [
    {
        "rule_id": "CODE-T1027-001",
        "rule_name": "Obfuscated Script - Base64",
        "pattern": r"[A-Za-z0-9+/]{50,}={0,2}",
        "description": "Base64 encoded payloads in scripts",
        "severity": "HIGH",
        "confidence": 0.8,
        "technique_ids": ["T1027", "T1027.001"],
    },
    {
        "rule_id": "CODE-T1059-001",
        "rule_name": "Dynamic Code Execution",
        "pattern": r"(eval|exec|os\.system|subprocess\.call|subprocess\.run|subprocess\.Popen)\s*\(",
        "description": "eval, exec, os.system, subprocess with user input",
        "severity": "HIGH",
        "confidence": 0.85,
        "technique_ids": ["T1059", "T1059.006"],
    },
    {
        "rule_id": "CODE-T1059-002",
        "rule_name": "PowerShell IEX/DownloadString",
        "pattern": r"(IEX|Invoke-Expression)\s+\(|\.DownloadString\s*\(",
        "description": "PowerShell IEX or WebClient DownloadString",
        "severity": "HIGH",
        "confidence": 0.9,
        "technique_ids": ["T1059", "T1059.001"],
    },
    {
        "rule_id": "CODE-T1202-001",
        "rule_name": "Indirect Command Execution",
        "pattern": r"(certutil|mshta|rundll32|regsvr32|regasm|installutil|msbuild|csc|vbc)\.exe",
        "description": "certutil, mshta, rundll32, regsvr32 execution",
        "severity": "HIGH",
        "confidence": 0.9,
        "technique_ids": ["T1202", "T1218"],
    },
    {
        "rule_id": "CODE-T1553-001",
        "rule_name": "Unsigned/Invalid Signature",
        "pattern": r"",
        "description": "Binary with invalid signature",
        "severity": "MEDIUM",
        "confidence": 0.7,
        "technique_ids": ["T1553", "T1553.002"],
    },
]

# =============================================================================
# ATT&CK v19 AI-SPECIFIC DETECTION PATTERNS
# New techniques in v19: T1682 (Query Public AI Services), T1683 (Generate Content),
# T1684 (Social Engineering), T1685 (Disable or Modify Tools), T1689 (Downgrade Attack),
# T1027/018 (Invisible Unicode)
# =============================================================================

AI_TECHNIQUE_PATTERNS = [
    {
        "rule_id":       "ATK-V19-T1682-001",
        "rule_name":     "Query Public AI Services — Suspicious LLM API Call in Process",
        "severity":      "MEDIUM",
        "confidence":    0.70,
        "technique_ids": ["T1682"],
        "description":   "Process making outbound calls to public AI API endpoints (OpenAI, Anthropic, Gemini, Mistral, Cohere). LAMEHUG (S9035/APT28) used this pattern in live operations per ATT&CK v19.",
        "conditions": [
            {"type": "message_contains", "keywords": [
                "api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com",
                "api.mistral.ai", "api.cohere.com", "api.together.xyz"
            ]},
            {"type": "field_regex", "field": "process_name",
             "pattern": r"(cmd\.exe|powershell|bash|python|node|curl|wget)"},
        ],
    },
    {
        "rule_id":       "ATK-V19-T1682-002",
        "rule_name":     "Query Public AI Services — LLM API Key in Environment or CLI",
        "severity":      "HIGH",
        "confidence":    0.85,
        "technique_ids": ["T1682", "T1552.001"],
        "description":   "AI API key passed via CLI argument or environment variable — credential exposure enabling unauthorized AI querying.",
        "conditions": [
            {"type": "field_regex", "field": "cmdline",
             "pattern": r"(OPENAI_API_KEY|ANTHROPIC_API_KEY|GEMINI_API_KEY|sk-[A-Za-z0-9]{32,})"},
        ],
    },
    {
        "rule_id":       "ATK-V19-T1683-001",
        "rule_name":     "Generate Content — AI-Generated Written Content for Phishing",
        "severity":      "HIGH",
        "confidence":    0.65,
        "technique_ids": ["T1683/001", "T1566"],
        "description":   "Automated high-volume content generation via LLM API for use in phishing or disinformation. Pattern: rapid sequential LLM completions with variable substitution.",
        "conditions": [
            {"type": "message_contains", "keywords": ["completion", "generate", "prompt"]},
            {"type": "field_regex", "field": "request_count_per_min", "pattern": r"[5-9]\d|[1-9]\d{2,}"},
        ],
    },
    {
        "rule_id":       "ATK-V19-T1683-002",
        "rule_name":     "Generate Content — Deepfake Audio-Visual Generation Detected",
        "severity":      "CRITICAL",
        "confidence":    0.75,
        "technique_ids": ["T1683/002", "T1684"],
        "description":   "Process invoking voice-cloning or video synthesis libraries (TTS, Wav2Lip, ElevenLabs API). Maps to T1683/002 Audio-Visual Content — new in ATT&CK v19.",
        "conditions": [
            {"type": "message_contains", "keywords": [
                "elevenlabs", "wav2lip", "so-vits-svc", "rvc", "coqui",
                "tortoisetcc", "styletts", "f5-tts", "voice_clone"
            ]},
        ],
    },
    {
        "rule_id":       "ATK-V19-T1684-001",
        "rule_name":     "Social Engineering — Impersonation Pattern in Outbound Communication",
        "severity":      "HIGH",
        "confidence":    0.72,
        "technique_ids": ["T1684/001", "T1566"],
        "description":   "Email or message headers show display-name/domain mismatch with AI-generated body content. T1684/001 Social Engineering: Impersonation — new in ATT&CK v19.",
        "conditions": [
            {"type": "field_regex", "field": "from_header",
             "pattern": r"([Cc][Ee][Oo]|[Cc][Ff][Oo]|[Hh][Rr]|[Ii][Tt] [Ss]upport)"},
            {"type": "field_regex", "field": "reply_to",
             "pattern": r"@(?!yourdomain\.com)"},
        ],
    },
    {
        "rule_id":       "ATK-V19-T1684-002",
        "rule_name":     "Social Engineering — Email Spoofing via DMARC Failure",
        "severity":      "HIGH",
        "confidence":    0.90,
        "technique_ids": ["T1684/002"],
        "description":   "Inbound email failed DMARC check with spoofed From: domain. T1684/002 Email Spoofing — new sub-technique in ATT&CK v19 (previously standalone T1566.003).",
        "conditions": [
            {"type": "field_regex", "field": "dmarc_result", "pattern": r"fail"},
            {"type": "message_contains", "keywords": ["Authentication-Results", "dmarc=fail"]},
        ],
    },
    {
        "rule_id":       "ATK-V19-T1027-018-001",
        "rule_name":     "Invisible Unicode Obfuscation in Source Code or Script",
        "severity":      "HIGH",
        "confidence":    0.88,
        "technique_ids": ["T1027/018"],
        "description":   "Source file contains invisible Unicode characters (zero-width space U+200B, ZWSP, RLO U+202E, tag characters U+E0000-U+E007F). T1027/018 Invisible Unicode — new sub-technique in ATT&CK v19.",
        "conditions": [
            {"type": "field_regex", "field": "file_content_hex",
             "pattern": r"(e2 80 8b|e2 80 ab|e2 80 ae|ef a3 b0|f3 a0 80)"},
        ],
    },
    {
        "rule_id":       "ATK-V19-T1689-001",
        "rule_name":     "Downgrade Attack — TLS/SSL Downgrade Negotiation",
        "severity":      "HIGH",
        "confidence":    0.82,
        "technique_ids": ["T1689"],
        "description":   "Network connection negotiated TLS 1.0 or SSL 3.0 after initial higher-version offer. T1689 Downgrade Attack — new in ATT&CK v19.",
        "conditions": [
            {"type": "field_regex", "field": "tls_version", "pattern": r"(TLSv1\.0|SSLv3|TLSv1$)"},
            {"type": "field_regex", "field": "tls_negotiation_log",
             "pattern": r"downgrad|version_fallback|legacy_renegotiation"},
        ],
    },
    {
        "rule_id":       "ATK-V19-T1685-001",
        "rule_name":     "Disable or Modify Tools — Security Tool Process Termination",
        "severity":      "CRITICAL",
        "confidence":    0.92,
        "technique_ids": ["T1685"],
        "description":   "Process termination targeting known security tools. T1685 replaces revoked T1562.001 (Impair Defenses: Disable or Modify Tools) in ATT&CK v19.",
        "conditions": [
            {"type": "field_regex", "field": "target_process",
             "pattern": r"(MsMpEng|cb\.exe|CylanceSvc|CSFalconService|SentinelAgent|CrowdStrike|cylancesvc|bdagent)"},
            {"type": "message_contains", "keywords": ["TerminateProcess", "taskkill", "sc stop", "net stop"]},
        ],
    },
    {
        "rule_id":       "ATK-V19-T1685-005-001",
        "rule_name":     "Disable or Modify Tools — Clear Windows Event Logs",
        "severity":      "HIGH",
        "confidence":    0.95,
        "technique_ids": ["T1685/005"],
        "description":   "Windows Event Log cleared via wevtutil or Clear-EventLog. T1685/005 replaces revoked T1070.001 in ATT&CK v19.",
        "conditions": [
            {"type": "event_id", "values": ["1102", "104"]},
        ],
    },
]

# Merge into LOG_PATTERNS at end of file
LOG_PATTERNS.extend(AI_TECHNIQUE_PATTERNS)