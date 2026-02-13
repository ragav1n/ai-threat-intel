"""
IOC Deobfuscation Module.

Handles common IOC defanging/obfuscation techniques found in threat intel reports:
- hxxp/hxxps URL defanging
- Bracket-wrapped dots [.] and (.)
- Base64-encoded IOCs
- Email defanging [at] / (at)
- Other bracket notation like [://]

This runs BEFORE regex extraction to maximize IOC recovery.
"""
import re
import base64
import logging
from typing import List, Tuple

logger = logging.getLogger(__name__)


def defang_url(text: str) -> str:
    """
    Convert defanged URL schemes back to normal.
    
    Handles:
    - hxxp:// → http://
    - hxxps:// → https://
    - hXXp:// → http:// (case-insensitive)
    - fxp:// → ftp://
    """
    # hxxp/hxxps variants (case-insensitive)
    text = re.sub(r'hxxps?://', lambda m: m.group().replace('hxxp', 'http').replace('hXXp', 'http'), text, flags=re.IGNORECASE)
    text = re.sub(r'hxxp', 'http', text, flags=re.IGNORECASE)
    
    # fxp → ftp
    text = re.sub(r'\bfxp://', 'ftp://', text, flags=re.IGNORECASE)
    
    return text


def defang_dots(text: str) -> str:
    """
    Convert bracket-wrapped dots back to actual dots.
    
    Handles:
    - [.] → .
    - (.) → .
    - {.} → .
    - [dot] → .
    - (dot) → .
    """
    # Bracket-wrapped dots
    text = re.sub(r'\[\.\]', '.', text)
    text = re.sub(r'\(\.\)', '.', text)
    text = re.sub(r'\{\.\}', '.', text)
    
    # Bracket-wrapped "dot" word
    text = re.sub(r'\[dot\]', '.', text, flags=re.IGNORECASE)
    text = re.sub(r'\(dot\)', '.', text, flags=re.IGNORECASE)
    
    return text


def defang_at(text: str) -> str:
    """
    Convert defanged @ symbols back to normal.
    
    Handles:
    - [at] → @
    - (at) → @
    - [@] → @
    - [AT] → @ (case-insensitive)
    """
    text = re.sub(r'\[at\]', '@', text, flags=re.IGNORECASE)
    text = re.sub(r'\(at\)', '@', text, flags=re.IGNORECASE)
    text = re.sub(r'\[@\]', '@', text)
    
    return text


def normalize_brackets(text: str) -> str:
    """
    Remove common bracket-based obfuscation patterns.
    
    Handles:
    - [://] → ://
    - hxxp[://] → http://
    - hxxp[:]// → http://
    """
    text = re.sub(r'\[://\]', '://', text)
    text = re.sub(r'\[:\]//', '://', text)
    text = re.sub(r'\[://', '://', text)
    text = re.sub(r'://\]', '://', text)
    
    return text


def decode_base64_iocs(text: str) -> str:
    """
    Detect and decode base64-encoded strings that look like IOCs.
    
    Searches for base64-encoded blobs and attempts to decode them.
    If the decoded content looks like an IOC (contains IP, URL, domain patterns),
    it is appended to the text for extraction.
    
    Returns the original text with any decoded IOCs appended.
    """
    # Match potential base64 strings (at least 16 chars, proper base64 charset)
    b64_pattern = re.compile(r'(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])')
    
    MAX_B64_DECODE_SIZE = 2048  # 2KB max decoded size to prevent memory attacks
    decoded_iocs: List[str] = []
    
    for match in b64_pattern.finditer(text):
        candidate = match.group()
        
        # Skip overly long base64 candidates (prevent decode of huge blobs)
        if len(candidate) > MAX_B64_DECODE_SIZE * 2:
            continue
        
        try:
            # Attempt decode
            decoded = base64.b64decode(candidate).decode('utf-8', errors='strict')
            
            # Enforce size limit on decoded content
            if len(decoded) > MAX_B64_DECODE_SIZE:
                continue
            
            # Check if decoded content looks like an IOC
            ioc_indicators = [
                re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', decoded),           # IP
                re.search(r'https?://', decoded),                              # URL
                re.search(r'\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b', decoded),      # Domain
                re.search(r'\b[a-fA-F0-9]{32,64}\b', decoded),               # Hash
                re.search(r'\bCVE-\d{4}-\d{4,}\b', decoded),                 # CVE
            ]
            
            if any(ioc_indicators):
                decoded_iocs.append(decoded)
                logger.info(f"🔓 Decoded base64 IOC: {decoded[:80]}...")
                
        except (ValueError, UnicodeDecodeError):
            # Not valid base64 or not UTF-8 — skip
            continue
    
    # Append decoded IOCs to the original text for extraction
    if decoded_iocs:
        text = text + "\n\n[DECODED_BASE64_IOCS]\n" + "\n".join(decoded_iocs)
    
    return text


def deobfuscate_text(text: str) -> Tuple[str, bool]:
    """
    Master deobfuscation function. Applies all deobfuscation rules in order.
    
    Args:
        text: Raw text potentially containing obfuscated IOCs.
        
    Returns:
        Tuple of (deobfuscated_text, was_modified).
        was_modified is True if any deobfuscation was applied.
    """
    original = text
    
    # Apply deobfuscation in optimal order
    text = normalize_brackets(text)  # Fix bracket notation first
    text = defang_url(text)          # Fix URL schemes
    text = defang_dots(text)         # Fix dots (after URLs to avoid breaking schemes)
    text = defang_at(text)           # Fix email @ symbols
    text = decode_base64_iocs(text)  # Decode base64 last (appends to text)
    
    was_modified = text != original
    
    if was_modified:
        logger.info("🔧 IOC deobfuscation applied to text")
    
    return text, was_modified
