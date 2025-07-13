import re

IOC_PATTERNS = {
    "ip": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
    "ipv6": r"\b(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{1,4}\b",
    "domain": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
    "url": r"https?://[^\s\"'<>]+",
    "md5": r"\b[a-fA-F\d]{32}\b",
    "sha1": r"\b[a-fA-F\d]{40}\b",
    "sha256": r"\b[a-fA-F\d]{64}\b"
}

def extract_iocs(text):
    matches = []
    for ioc_type, pattern in IOC_PATTERNS.items():
        found = re.findall(pattern, text)
        for item in found:
            matches.append((item, ioc_type))
    return matches
