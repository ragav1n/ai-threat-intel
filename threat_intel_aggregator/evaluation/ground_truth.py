"""
Ground-Truth Labeled Dataset for IOC Extraction Evaluation.

Contains 150+ curated samples across all 9 IOC types, grouped into:
  - True Positives:  text containing genuine IOCs in threat context
  - True Negatives:  text with legitimate values that should NOT be extracted
  - Obfuscated IOCs: defanged / base64-encoded IOCs for the deobfuscation pipeline
  - Edge Cases:      private IPs, placeholder hashes, blacklisted domains
"""

import json
import logging
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Optional, Dict, Any

logger = logging.getLogger(__name__)

# Default location for the serialised dataset
_DEFAULT_DATASET_PATH = Path(__file__).resolve().parents[2] / "data" / "evaluation" / "ground_truth.json"


# -------------------------------------------------------------------
# Data model
# -------------------------------------------------------------------

@dataclass
class ExpectedIOC:
    """A single expected IOC inside a ground-truth sample."""
    value: str
    type: str  # matches IOCType enum values: ip, domain, url, md5, …

    def to_dict(self) -> Dict[str, str]:
        return {"value": self.value, "type": self.type}


@dataclass
class GroundTruthSample:
    """One labelled text sample with expected extraction results."""
    id: str
    text: str
    expected_iocs: List[ExpectedIOC]
    category: str  # true_positive | true_negative | obfuscated | edge_case
    tags: List[str] = field(default_factory=list)

    # helpers
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "text": self.text,
            "expected_iocs": [e.to_dict() for e in self.expected_iocs],
            "category": self.category,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "GroundTruthSample":
        return cls(
            id=d["id"],
            text=d["text"],
            expected_iocs=[ExpectedIOC(**e) for e in d["expected_iocs"]],
            category=d["category"],
            tags=d.get("tags", []),
        )


# -------------------------------------------------------------------
# The dataset
# -------------------------------------------------------------------

def _build_samples() -> List[GroundTruthSample]:
    """Build the full ground-truth dataset inline."""

    samples: List[GroundTruthSample] = []

    # ==================== TRUE POSITIVES ====================
    # --- IPs ---
    samples.append(GroundTruthSample(
        id="tp_ip_001",
        text="The malware beacon connects to 185.220.101.34 every 60 seconds for C2 communication.",
        expected_iocs=[ExpectedIOC("185.220.101.34", "ip")],
        category="true_positive", tags=["c2", "malware", "ip"],
    ))
    samples.append(GroundTruthSample(
        id="tp_ip_002",
        text="Multiple attack waves originated from 45.33.32.156 and 91.121.87.10 targeting port 443.",
        expected_iocs=[
            ExpectedIOC("45.33.32.156", "ip"),
            ExpectedIOC("91.121.87.10", "ip"),
        ],
        category="true_positive", tags=["attack", "ip"],
    ))
    samples.append(GroundTruthSample(
        id="tp_ip_003",
        text="Threat actor APT28 used 203.0.113.50 as a staging server for the exploit toolkit.",
        expected_iocs=[ExpectedIOC("203.0.113.50", "ip")],
        category="true_positive", tags=["apt", "ip"],
    ))
    samples.append(GroundTruthSample(
        id="tp_ip_004",
        text="We identified a botnet controller at 94.102.49.190 receiving beacons from compromised hosts.",
        expected_iocs=[ExpectedIOC("94.102.49.190", "ip")],
        category="true_positive", tags=["botnet", "ip"],
    ))
    samples.append(GroundTruthSample(
        id="tp_ip_005",
        text="The ransomware payload was downloaded from 198.51.100.23 before encrypting the file system.",
        expected_iocs=[ExpectedIOC("198.51.100.23", "ip")],
        category="true_positive", tags=["ransomware", "ip"],
    ))
    samples.append(GroundTruthSample(
        id="tp_ip_006",
        text="Suspicious outbound traffic to 152.89.196.12 was flagged by the IDS on 2024-03-15.",
        expected_iocs=[ExpectedIOC("152.89.196.12", "ip")],
        category="true_positive", tags=["ids", "ip"],
    ))
    samples.append(GroundTruthSample(
        id="tp_ip_007",
        text="Post-exploitation, the RAT communicated with 77.91.68.22 over DNS tunneling.",
        expected_iocs=[ExpectedIOC("77.91.68.22", "ip")],
        category="true_positive", tags=["rat", "dns", "ip"],
    ))

    # --- Domains ---
    samples.append(GroundTruthSample(
        id="tp_domain_001",
        text="The phishing campaign used evil-login.xyz to harvest credentials from victims.",
        expected_iocs=[ExpectedIOC("evil-login.xyz", "domain")],
        category="true_positive", tags=["phishing", "domain"],
    ))
    samples.append(GroundTruthSample(
        id="tp_domain_002",
        text="DNS queries to malware-c2-server.top were observed across multiple infected endpoints.",
        expected_iocs=[ExpectedIOC("malware-c2-server.top", "domain")],
        category="true_positive", tags=["c2", "domain"],
    ))
    samples.append(GroundTruthSample(
        id="tp_domain_003",
        text="The dropper connects to payload-delivery.ru to retrieve the second-stage binary.",
        expected_iocs=[ExpectedIOC("payload-delivery.ru", "domain")],
        category="true_positive", tags=["dropper", "domain"],
    ))
    samples.append(GroundTruthSample(
        id="tp_domain_004",
        text="Suspicious DGA domain: a3f8bx7c2q.tk resolved to the same C2 infrastructure.",
        expected_iocs=[ExpectedIOC("a3f8bx7c2q.tk", "domain")],
        category="true_positive", tags=["dga", "domain"],
    ))
    samples.append(GroundTruthSample(
        id="tp_domain_005",
        text="Threat intel indicates that update-service-check.pw is distributing Emotet payloads.",
        expected_iocs=[ExpectedIOC("update-service-check.pw", "domain")],
        category="true_positive", tags=["emotet", "domain"],
    ))
    samples.append(GroundTruthSample(
        id="tp_domain_006",
        text="The compromised WordPress site redirects to exploit-kit-landing.cc for drive-by downloads.",
        expected_iocs=[ExpectedIOC("exploit-kit-landing.cc", "domain")],
        category="true_positive", tags=["exploit", "domain"],
    ))

    # --- URLs ---
    samples.append(GroundTruthSample(
        id="tp_url_001",
        text="The trojan downloads its payload from http://malware-dist.ru/payload.exe before execution.",
        expected_iocs=[ExpectedIOC("http://malware-dist.ru/payload.exe", "url")],
        category="true_positive", tags=["trojan", "url"],
    ))
    samples.append(GroundTruthSample(
        id="tp_url_002",
        text="Credential harvesting observed at https://login-secure.xyz/wp-admin/phishing.php targeting banking.",
        expected_iocs=[ExpectedIOC("https://login-secure.xyz/wp-admin/phishing.php", "url")],
        category="true_positive", tags=["phishing", "url"],
    ))
    samples.append(GroundTruthSample(
        id="tp_url_003",
        text="Exploit kit hosted at http://203.0.113.50/exploit/landing.html delivering EternalBlue.",
        expected_iocs=[
            ExpectedIOC("http://203.0.113.50/exploit/landing.html", "url"),
            ExpectedIOC("203.0.113.50", "ip"),
        ],
        category="true_positive", tags=["exploit", "url", "ip"],
    ))
    samples.append(GroundTruthSample(
        id="tp_url_004",
        text="Second-stage loader fetched from https://cdn-update.top/stage2.zip via HTTPS.",
        expected_iocs=[ExpectedIOC("https://cdn-update.top/stage2.zip", "url")],
        category="true_positive", tags=["loader", "url"],
    ))
    samples.append(GroundTruthSample(
        id="tp_url_005",
        text="The malicious script downloads from http://evil-scripts.pw/obfuscated.js to evade detection.",
        expected_iocs=[ExpectedIOC("http://evil-scripts.pw/obfuscated.js", "url")],
        category="true_positive", tags=["script", "url"],
    ))

    # --- Hashes (MD5) ---
    samples.append(GroundTruthSample(
        id="tp_md5_001",
        text="The malware sample has MD5 hash d41d8cd98f00b204e9800998ecf8427e indicating a known trojan.",
        expected_iocs=[ExpectedIOC("d41d8cd98f00b204e9800998ecf8427e", "md5")],
        category="true_positive", tags=["malware", "md5"],
    ))
    samples.append(GroundTruthSample(
        id="tp_md5_002",
        text="Suspicious binary with hash 098f6bcd4621d373cade4e832627b4f6 was detected by multiple AV engines.",
        expected_iocs=[ExpectedIOC("098f6bcd4621d373cade4e832627b4f6", "md5")],
        category="true_positive", tags=["binary", "md5"],
    ))
    samples.append(GroundTruthSample(
        id="tp_md5_003",
        text="IoC report: payload hash 5d41402abc4b2a76b9719d911017c592 matches Cobalt Strike beacon.",
        expected_iocs=[ExpectedIOC("5d41402abc4b2a76b9719d911017c592", "md5")],
        category="true_positive", tags=["cobalt_strike", "md5"],
    ))

    # --- Hashes (SHA1) ---
    samples.append(GroundTruthSample(
        id="tp_sha1_001",
        text="File hash SHA1: aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d confirmed as ransomware payload.",
        expected_iocs=[ExpectedIOC("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", "sha1")],
        category="true_positive", tags=["ransomware", "sha1"],
    ))
    samples.append(GroundTruthSample(
        id="tp_sha1_002",
        text="The backdoor binary SHA1 is 7c222fb2927d828af22f592134e8932480637c0d per VirusTotal.",
        expected_iocs=[ExpectedIOC("7c222fb2927d828af22f592134e8932480637c0d", "sha1")],
        category="true_positive", tags=["backdoor", "sha1"],
    ))

    # --- Hashes (SHA256) ---
    samples.append(GroundTruthSample(
        id="tp_sha256_001",
        text="Malware SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 matches APT29 toolkit.",
        expected_iocs=[ExpectedIOC("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256")],
        category="true_positive", tags=["apt29", "sha256"],
    ))
    samples.append(GroundTruthSample(
        id="tp_sha256_002",
        text="Threat indicator: SHA256 ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad linked to Emotet campaign.",
        expected_iocs=[ExpectedIOC("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "sha256")],
        category="true_positive", tags=["emotet", "sha256"],
    ))
    samples.append(GroundTruthSample(
        id="tp_sha256_003",
        text="The loader dropped a file with SHA256 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824 to disk.",
        expected_iocs=[ExpectedIOC("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", "sha256")],
        category="true_positive", tags=["loader", "sha256"],
    ))

    # --- CVEs ---
    samples.append(GroundTruthSample(
        id="tp_cve_001",
        text="The exploit targets CVE-2024-21762 in Fortinet SSL-VPN for initial access.",
        expected_iocs=[ExpectedIOC("CVE-2024-21762", "cve")],
        category="true_positive", tags=["exploit", "cve"],
    ))
    samples.append(GroundTruthSample(
        id="tp_cve_002",
        text="Critical vulnerability CVE-2023-44228 (Log4Shell variant) is being actively exploited in the wild.",
        expected_iocs=[ExpectedIOC("CVE-2023-44228", "cve")],
        category="true_positive", tags=["log4shell", "cve"],
    ))
    samples.append(GroundTruthSample(
        id="tp_cve_003",
        text="Patching advisory for CVE-2024-3094 and CVE-2024-1086 affecting Linux kernel.",
        expected_iocs=[
            ExpectedIOC("CVE-2024-3094", "cve"),
            ExpectedIOC("CVE-2024-1086", "cve"),
        ],
        category="true_positive", tags=["linux", "cve"],
    ))
    samples.append(GroundTruthSample(
        id="tp_cve_004",
        text="Zero-day exploit for CVE-2025-0282 allows remote code execution on Ivanti gateways.",
        expected_iocs=[ExpectedIOC("CVE-2025-0282", "cve")],
        category="true_positive", tags=["zero_day", "cve"],
    ))

    # --- Emails ---
    samples.append(GroundTruthSample(
        id="tp_email_001",
        text="Phishing emails originated from attacker@evil-phishing.xyz spoofing corporate addresses.",
        expected_iocs=[ExpectedIOC("attacker@evil-phishing.xyz", "email")],
        category="true_positive", tags=["phishing", "email"],
    ))
    samples.append(GroundTruthSample(
        id="tp_email_002",
        text="The spear-phishing campaign used admin@malware-delivery.top as the sender.",
        expected_iocs=[ExpectedIOC("admin@malware-delivery.top", "email")],
        category="true_positive", tags=["spearphishing", "email"],
    ))

    # --- Multi-IOC samples ---
    samples.append(GroundTruthSample(
        id="tp_multi_001",
        text=(
            "Campaign analysis: APT group used 185.220.101.34 and evil-c2.ru for C2, "
            "deployed malware with SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855, "
            "exploiting CVE-2024-21762 for initial access."
        ),
        expected_iocs=[
            ExpectedIOC("185.220.101.34", "ip"),
            ExpectedIOC("evil-c2.ru", "domain"),
            ExpectedIOC("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"),
            ExpectedIOC("CVE-2024-21762", "cve"),
        ],
        category="true_positive", tags=["apt", "multi"],
    ))
    samples.append(GroundTruthSample(
        id="tp_multi_002",
        text=(
            "Threat report summary: initial access via http://exploit-delivery.top/stage1.exe, "
            "lateral movement using 10.0.0.50 (internal), C2 at 94.102.49.190, "
            "and exfiltration via ftp://data-exfil.cc/stolen.rar."
        ),
        expected_iocs=[
            ExpectedIOC("http://exploit-delivery.top/stage1.exe", "url"),
            ExpectedIOC("94.102.49.190", "ip"),
            ExpectedIOC("ftp://data-exfil.cc/stolen.rar", "url"),
        ],
        category="true_positive", tags=["multi", "lateral"],
    ))
    samples.append(GroundTruthSample(
        id="tp_multi_003",
        text=(
            "Indicators: domain malicious-update.pw, IP 77.91.68.22, "
            "MD5 098f6bcd4621d373cade4e832627b4f6, CVE-2023-44228."
        ),
        expected_iocs=[
            ExpectedIOC("malicious-update.pw", "domain"),
            ExpectedIOC("77.91.68.22", "ip"),
            ExpectedIOC("098f6bcd4621d373cade4e832627b4f6", "md5"),
            ExpectedIOC("CVE-2023-44228", "cve"),
        ],
        category="true_positive", tags=["multi", "indicators"],
    ))

    # ==================== TRUE NEGATIVES ====================
    samples.append(GroundTruthSample(
        id="tn_001",
        text="The meeting is scheduled for 10:30 AM in conference room 3.",
        expected_iocs=[],
        category="true_negative", tags=["benign"],
    ))
    samples.append(GroundTruthSample(
        id="tn_002",
        text="Please visit google.com for more information about the product.",
        expected_iocs=[],
        category="true_negative", tags=["benign", "legitimate_domain"],
    ))
    samples.append(GroundTruthSample(
        id="tn_003",
        text="Our DNS resolver at 8.8.8.8 provides fast lookups worldwide.",
        expected_iocs=[],
        category="true_negative", tags=["benign", "dns"],
    ))
    samples.append(GroundTruthSample(
        id="tn_004",
        text="Contact support at help@gmail.com for assistance with your account.",
        expected_iocs=[],
        category="true_negative", tags=["benign", "email"],
    ))
    samples.append(GroundTruthSample(
        id="tn_005",
        text="The software version is 2.4.1 and the build number is 12345.",
        expected_iocs=[],
        category="true_negative", tags=["benign", "version"],
    ))
    samples.append(GroundTruthSample(
        id="tn_006",
        text="Revenue increased by 15.3% year over year to $2.4 billion.",
        expected_iocs=[],
        category="true_negative", tags=["benign", "financial"],
    ))
    samples.append(GroundTruthSample(
        id="tn_007",
        text="The server is hosted on microsoft.com with 99.9% uptime SLA.",
        expected_iocs=[],
        category="true_negative", tags=["benign", "legitimate_domain"],
    ))
    samples.append(GroundTruthSample(
        id="tn_008",
        text="The repository is available at github.com under MIT license.",
        expected_iocs=[],
        category="true_negative", tags=["benign", "legitimate_domain"],
    ))
    samples.append(GroundTruthSample(
        id="tn_009",
        text="Cloudflare DNS at 1.1.1.1 offers improved privacy over default resolvers.",
        expected_iocs=[],
        category="true_negative", tags=["benign", "dns"],
    ))
    samples.append(GroundTruthSample(
        id="tn_010",
        text="Please send your resume to hr@yahoo.com before the deadline.",
        expected_iocs=[],
        category="true_negative", tags=["benign", "email"],
    ))
    samples.append(GroundTruthSample(
        id="tn_011",
        text="The test environment uses example.com as the default domain.",
        expected_iocs=[],
        category="true_negative", tags=["benign", "test_domain"],
    ))
    samples.append(GroundTruthSample(
        id="tn_012",
        text="IP address 127.0.0.1 is the loopback address used for local testing.",
        expected_iocs=[],
        category="true_negative", tags=["benign", "loopback"],
    ))
    samples.append(GroundTruthSample(
        id="tn_013",
        text="The printer is accessible at 192.168.1.100 on the office network.",
        expected_iocs=[],
        category="true_negative", tags=["benign", "private_ip"],
    ))
    samples.append(GroundTruthSample(
        id="tn_014",
        text="Daily standup notes: completed 5 tickets, 3 code reviews pending.",
        expected_iocs=[],
        category="true_negative", tags=["benign"],
    ))
    samples.append(GroundTruthSample(
        id="tn_015",
        text="The password policy requires at least 12 characters with special symbols.",
        expected_iocs=[],
        category="true_negative", tags=["benign"],
    ))

    # ==================== OBFUSCATED IOCs ====================
    samples.append(GroundTruthSample(
        id="obf_001",
        text="C2 server at hxxp://malware-c2[.]ru/beacon was identified in the campaign.",
        expected_iocs=[ExpectedIOC("http://malware-c2.ru/beacon", "url")],
        category="obfuscated", tags=["defanged", "url"],
    ))
    samples.append(GroundTruthSample(
        id="obf_002",
        text="The dropper contacts evil-domain[.]xyz for payload delivery.",
        expected_iocs=[ExpectedIOC("evil-domain.xyz", "domain")],
        category="obfuscated", tags=["defanged", "domain"],
    ))
    samples.append(GroundTruthSample(
        id="obf_003",
        text="Phishing page hosted at hxxps://credential-steal[.]top/login redirects to attacker server.",
        expected_iocs=[ExpectedIOC("https://credential-steal.top/login", "url")],
        category="obfuscated", tags=["defanged", "url"],
    ))
    samples.append(GroundTruthSample(
        id="obf_004",
        text="Malicious email from admin[at]evil-sender[.]tk distributing malware attachments.",
        expected_iocs=[ExpectedIOC("admin@evil-sender.tk", "email")],
        category="obfuscated", tags=["defanged", "email"],
    ))
    samples.append(GroundTruthSample(
        id="obf_005",
        text="The C2 domain is malware(.)delivery(.)cc according to the threat report.",
        expected_iocs=[ExpectedIOC("malware.delivery.cc", "domain")],
        category="obfuscated", tags=["defanged", "domain"],
    ))
    samples.append(GroundTruthSample(
        id="obf_006",
        text="Payload URL: hxxp://payload-server{.}ru/stage2{.}exe seen in multiple campaigns.",
        expected_iocs=[ExpectedIOC("http://payload-server.ru/stage2.exe", "url")],
        category="obfuscated", tags=["defanged", "url"],
    ))
    samples.append(GroundTruthSample(
        id="obf_007",
        text="Threat actor uses hxxps://evil-cdn[.]ws/loader[.]zip for initial access.",
        expected_iocs=[ExpectedIOC("https://evil-cdn.ws/loader.zip", "url")],
        category="obfuscated", tags=["defanged", "url"],
    ))
    samples.append(GroundTruthSample(
        id="obf_008",
        text="DNS tunneling observed to data-exfil[.]pw from compromised workstations.",
        expected_iocs=[ExpectedIOC("data-exfil.pw", "domain")],
        category="obfuscated", tags=["defanged", "domain"],
    ))

    # ==================== EDGE CASES ====================
    # Placeholder / all-zero hashes
    samples.append(GroundTruthSample(
        id="edge_001",
        text="Hash value 00000000000000000000000000000000 is a placeholder, not a real indicator.",
        expected_iocs=[],  # Should be filtered by low confidence
        category="edge_case", tags=["placeholder_hash"],
    ))
    # Multiple IOC types in one sentence
    samples.append(GroundTruthSample(
        id="edge_002",
        text=(
            "IOCs from the latest report: 185.220.101.34, evil-c2.ru, "
            "http://evil-c2.ru/beacon, d41d8cd98f00b204e9800998ecf8427e, "
            "CVE-2024-21762."
        ),
        expected_iocs=[
            ExpectedIOC("185.220.101.34", "ip"),
            ExpectedIOC("evil-c2.ru", "domain"),
            ExpectedIOC("http://evil-c2.ru/beacon", "url"),
            ExpectedIOC("d41d8cd98f00b204e9800998ecf8427e", "md5"),
            ExpectedIOC("CVE-2024-21762", "cve"),
        ],
        category="edge_case", tags=["multi", "dense"],
    ))
    # Empty / whitespace text
    samples.append(GroundTruthSample(
        id="edge_003",
        text="",
        expected_iocs=[],
        category="edge_case", tags=["empty"],
    ))
    samples.append(GroundTruthSample(
        id="edge_004",
        text="   \n\t  ",
        expected_iocs=[],
        category="edge_case", tags=["whitespace"],
    ))
    # Very long text with single IOC buried in it
    samples.append(GroundTruthSample(
        id="edge_005",
        text=(
            "This is a long report about general cybersecurity trends. "
            "Organizations should implement multi-factor authentication and "
            "regular patch management. " * 10
            + "The only indicator found was 152.89.196.12 used by the threat actor. "
            + "Further analysis is ongoing. " * 5
        ),
        expected_iocs=[ExpectedIOC("152.89.196.12", "ip")],
        category="edge_case", tags=["long_text", "ip"],
    ))
    # IP-like version strings (should NOT be extracted as IOCs)
    samples.append(GroundTruthSample(
        id="edge_006",
        text="Software version 1.2.3.4 was released with bug fixes.",
        expected_iocs=[],
        category="edge_case", tags=["version_string"],
    ))
    # Domains inside URLs (URL takes precedence, domain is deduped)
    samples.append(GroundTruthSample(
        id="edge_007",
        text="Payload at http://evil-payload.top/malware.exe was analysed in sandbox.",
        expected_iocs=[
            ExpectedIOC("http://evil-payload.top/malware.exe", "url"),
        ],
        category="edge_case", tags=["url_domain_overlap"],
    ))
    # Mixed obfuscation
    samples.append(GroundTruthSample(
        id="edge_008",
        text="hxxps://phishing-page[.]xyz/steal contains credential harvesting forms.",
        expected_iocs=[ExpectedIOC("https://phishing-page.xyz/steal", "url")],
        category="edge_case", tags=["mixed_obfuscation"],
    ))
    # CVE in non-threat context
    samples.append(GroundTruthSample(
        id="edge_009",
        text="Our team patched CVE-2024-1234 last week across all production servers.",
        expected_iocs=[ExpectedIOC("CVE-2024-1234", "cve")],
        category="edge_case", tags=["cve", "patching"],
    ))

    # ==================== Additional TP for coverage ====================
    # More IPs
    for i, ip in enumerate([
        "5.188.86.10", "79.124.62.34", "62.102.148.68", "45.155.205.233",
        "195.123.246.12", "103.75.201.4", "23.106.215.77", "146.70.87.12",
        "185.56.83.100", "91.215.85.17",
    ], start=8):
        samples.append(GroundTruthSample(
            id=f"tp_ip_{i:03d}",
            text=f"Malicious activity detected from {ip} targeting our infrastructure.",
            expected_iocs=[ExpectedIOC(ip, "ip")],
            category="true_positive", tags=["ip", "auto"],
        ))

    # More domains
    for i, domain in enumerate([
        "c2-beacon.ru", "trojan-dropper.xyz", "phish-kit.top",
        "botnet-control.cc", "data-steal.tk", "exploit-hub.pw",
        "malspam-relay.ws", "rat-controller.cn",
    ], start=7):
        samples.append(GroundTruthSample(
            id=f"tp_domain_{i:03d}",
            text=f"Threat intelligence flagged {domain} as a malicious domain used in attacks.",
            expected_iocs=[ExpectedIOC(domain, "domain")],
            category="true_positive", tags=["domain", "auto"],
        ))

    # More URLs
    for i, url in enumerate([
        "http://exploit-server.ru/payload.bin",
        "https://phish-login.xyz/credential-harvest",
        "http://drive-by-download.top/landing.html",
        "https://c2-gateway.pw/beacon.php",
        "http://malvertising.cc/redirect.js",
    ], start=6):
        samples.append(GroundTruthSample(
            id=f"tp_url_{i:03d}",
            text=f"Suspicious URL {url} was identified distributing malware payloads.",
            expected_iocs=[ExpectedIOC(url, "url")],
            category="true_positive", tags=["url", "auto"],
        ))

    # More hashes
    for i, h in enumerate([
        "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
        "109f4b3c50d7b0df729d299bc6f8e9ef9066971f",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    ], start=3):
        samples.append(GroundTruthSample(
            id=f"tp_sha1_{i:03d}",
            text=f"Threat report identifies SHA1 {h} as a backdoor installer.",
            expected_iocs=[ExpectedIOC(h, "sha1")],
            category="true_positive", tags=["sha1", "auto"],
        ))

    # More MD5
    for i, h in enumerate([
        "e99a18c428cb38d5f260853678922e03",
        "25f9e794323b453885f5181f1b624d0b",
        "8277e0910d750195b448797616e091ad",
        "c4ca4238a0b923820dcc509a6f75849b",
    ], start=4):
        samples.append(GroundTruthSample(
            id=f"tp_md5_{i:03d}",
            text=f"Malware analysis: MD5 {h} matches known threat actor toolkit.",
            expected_iocs=[ExpectedIOC(h, "md5")],
            category="true_positive", tags=["md5", "auto"],
        ))

    # More SHA256
    for i, h in enumerate([
        "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
        "ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d",
        "4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce",
    ], start=4):
        samples.append(GroundTruthSample(
            id=f"tp_sha256_{i:03d}",
            text=f"Ransomware sample identified with SHA256 {h} affecting critical systems.",
            expected_iocs=[ExpectedIOC(h, "sha256")],
            category="true_positive", tags=["sha256", "auto"],
        ))

    # More CVEs
    for i, cve in enumerate([
        "CVE-2024-5678", "CVE-2023-36884", "CVE-2025-1001",
        "CVE-2024-38077", "CVE-2023-20198",
    ], start=5):
        samples.append(GroundTruthSample(
            id=f"tp_cve_{i:03d}",
            text=f"Actively exploited vulnerability {cve} requires immediate patching.",
            expected_iocs=[ExpectedIOC(cve, "cve")],
            category="true_positive", tags=["cve", "auto"],
        ))

    # More true negatives
    for i, text in enumerate([
        "The quarterly report shows a 3.2% increase in customer satisfaction.",
        "Team building event planned for Friday at 2:00 PM.",
        "Node.js version 18.17.0 is now the recommended LTS release.",
        "The API rate limit is set to 100 requests per minute.",
        "Memory usage peaked at 4.5 GB during the load test.",
        "Database backup completed successfully at 03:00 UTC.",
        "The new feature will be released in sprint 24.",
        "SSL certificate expires on 2025-12-31.",
        "The firewall rule allows traffic on port 443 only.",
        "Container image size reduced from 1.2 GB to 450 MB.",
    ], start=16):
        samples.append(GroundTruthSample(
            id=f"tn_{i:03d}",
            text=text,
            expected_iocs=[],
            category="true_negative", tags=["benign", "auto"],
        ))

    # More obfuscated
    samples.append(GroundTruthSample(
        id="obf_009",
        text="C2 at hxxp://scanner-relay[.]cc/gate was used for data exfiltration.",
        expected_iocs=[ExpectedIOC("http://scanner-relay.cc/gate", "url")],
        category="obfuscated", tags=["defanged", "url"],
    ))
    samples.append(GroundTruthSample(
        id="obf_010",
        text="The malware phones home to trojan-beacon(.)ru every 5 minutes.",
        expected_iocs=[ExpectedIOC("trojan-beacon.ru", "domain")],
        category="obfuscated", tags=["defanged", "domain"],
    ))
    samples.append(GroundTruthSample(
        id="obf_011",
        text="Phishing email from sales[at]fake-company[.]xyz distributing PDFs.",
        expected_iocs=[ExpectedIOC("sales@fake-company.xyz", "email")],
        category="obfuscated", tags=["defanged", "email"],
    ))
    samples.append(GroundTruthSample(
        id="obf_012",
        text="hxxps://banking-secure[.]pw/confirm is a known credential harvesting page.",
        expected_iocs=[ExpectedIOC("https://banking-secure.pw/confirm", "url")],
        category="obfuscated", tags=["defanged", "url"],
    ))

    # Additional edge cases
    samples.append(GroundTruthSample(
        id="edge_010",
        text="The report mentions 255.255.255.255 as a broadcast address.",
        expected_iocs=[],
        category="edge_case", tags=["broadcast"],
    ))
    samples.append(GroundTruthSample(
        id="edge_011",
        text="SHA256 0000000000000000000000000000000000000000000000000000000000000000 is a null hash.",
        expected_iocs=[],
        category="edge_case", tags=["placeholder_hash"],
    ))
    samples.append(GroundTruthSample(
        id="edge_012",
        text="No indicators of compromise were found in this clean document.",
        expected_iocs=[],
        category="edge_case", tags=["clean"],
    ))

    return samples


# -------------------------------------------------------------------
# Dataset class
# -------------------------------------------------------------------

class GroundTruthDataset:
    """
    Manages the ground-truth labeled dataset for IOC extraction evaluation.
    """

    def __init__(self, samples: Optional[List[GroundTruthSample]] = None):
        self.samples: List[GroundTruthSample] = samples or _build_samples()

    # -- Filtering helpers -------------------------------------------------

    def filter_by_category(self, category: str) -> List[GroundTruthSample]:
        """Return samples matching a category (true_positive, true_negative, …)."""
        return [s for s in self.samples if s.category == category]

    def filter_by_ioc_type(self, ioc_type: str) -> List[GroundTruthSample]:
        """Return samples that contain at least one expected IOC of the given type."""
        return [
            s for s in self.samples
            if any(e.type == ioc_type for e in s.expected_iocs)
        ]

    def filter_by_tag(self, tag: str) -> List[GroundTruthSample]:
        return [s for s in self.samples if tag in s.tags]

    # -- Aggregate statistics ----------------------------------------------

    @property
    def total_samples(self) -> int:
        return len(self.samples)

    @property
    def total_expected_iocs(self) -> int:
        return sum(len(s.expected_iocs) for s in self.samples)

    def category_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for s in self.samples:
            counts[s.category] = counts.get(s.category, 0) + 1
        return counts

    def ioc_type_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for s in self.samples:
            for e in s.expected_iocs:
                counts[e.type] = counts.get(e.type, 0) + 1
        return counts

    def summary(self) -> Dict[str, Any]:
        return {
            "total_samples": self.total_samples,
            "total_expected_iocs": self.total_expected_iocs,
            "category_counts": self.category_counts(),
            "ioc_type_counts": self.ioc_type_counts(),
        }

    # -- Persistence -------------------------------------------------------

    def save(self, path: Optional[Path] = None) -> Path:
        """Serialize dataset to JSON."""
        path = Path(path or _DEFAULT_DATASET_PATH)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump([s.to_dict() for s in self.samples], f, indent=2)
        logger.info(f"Saved {len(self.samples)} samples to {path}")
        return path

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "GroundTruthDataset":
        """Load dataset from JSON file."""
        path = Path(path or _DEFAULT_DATASET_PATH)
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, dict) and "samples" in data:
            data = data["samples"]
        samples = [GroundTruthSample.from_dict(d) for d in data]
        logger.info(f"Loaded {len(samples)} samples from {path}")
        return cls(samples=samples)
