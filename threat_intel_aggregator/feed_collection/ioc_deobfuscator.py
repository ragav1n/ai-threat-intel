"""
Advanced IOC Deobfuscation Module.

Handles exotic and emerging IOC masking techniques found in threat intelligence:
- Base64, Hex, Octal, Unicode escapes
- Zero-width characters & Homoglyphs
- URL schemes (h**p, hXXp, meow://)
- IP encodings (Hex, Decimal, Splitting)
- Markdown/HTML artifacts
- Complex bracket/paren obfuscation
"""
import re
import base64
import logging
import html
import unicodedata
from typing import List, Tuple

logger = logging.getLogger(__name__)

# --- Phase 1: Encoding & Character Normalization ---

def decode_unicode_escapes(text: str) -> str:
    """Decode \\uXXXX, \\xXX, and octal escapes."""
    def replace_u(match):
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)
    text = re.sub(r'\\u([0-9a-fA-F]{4})', replace_u, text)
    
    def replace_x(match):
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)
    text = re.sub(r'\\x([0-9a-fA-F]{2})', replace_x, text)
    
    def replace_o(match):
        try:
            return chr(int(match.group(1), 8))
        except ValueError:
            return match.group(0)
    text = re.sub(r'\\([0-3][0-7]{2})', replace_o, text)
    return text

def normalize_unicode(text: str) -> str:
    """Normalize fullwidth characters and obvious homoglyphs using NFKC."""
    text = unicodedata.normalize('NFKC', text)
    
    # Explicit homoglyph map for common Cyrillic abuse
    homoglyphs = {
        'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 
        'р': 'p', 'х': 'x', 'у': 'y', 'і': 'i', 'ј': 'j'
    }
    for cyrillic, latin in homoglyphs.items():
        text = text.replace(cyrillic, latin)
    return text

def strip_zero_width(text: str) -> str:
    """Remove invisible zero-width characters and null bytes."""
    return re.sub(r'[\u200b\u200c\u200d\u200e\u200f\ufeff\x00]', '', text)

def decode_html_entities(text: str) -> str:
    """Decode HTML entities like &#104; or &#x68;."""
    return html.unescape(text)

def decode_base64_iocs(text: str) -> str:
    """Detect and decode Base64 strings resembling IOCs."""
    b64_pattern = re.compile(r'(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])')
    
    MAX_B64_DECODE_SIZE = 4096 
    decoded_iocs: List[str] = []
    
    for match in b64_pattern.finditer(text):
        candidate = match.group()
        if len(candidate) > MAX_B64_DECODE_SIZE * 2:
            continue
        try:
            pad_len = 4 - (len(candidate) % 4)
            if pad_len != 4:
                candidate += '=' * pad_len
            
            decoded = base64.urlsafe_b64decode(candidate).decode('utf-8', errors='ignore')
            
            if len(decoded) > MAX_B64_DECODE_SIZE:
                 continue
                 
            ioc_indicators = [
                re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', decoded),           # IP
                re.search(r'https?://', decoded, re.IGNORECASE),              # URL
                re.search(r'\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b', decoded),      # Domain
                re.search(r'\b[a-fA-F0-9]{32,64}\b', decoded),               # Hash
                re.search(r'\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b', decoded), # MAC
            ]
            
            if any(ioc_indicators):
                decoded_iocs.append(decoded)
                
        except Exception:
            pass
            
    if decoded_iocs:
        text = text + "\n\n[DECODED_BASE64_IOCS]\n" + "\n".join(decoded_iocs)
    return text

# --- Phase 2: Structural Cleanups ---

def strip_markdown_artifacts(text: str) -> str:
    """Remove Markdown/RST artifacts commonly mangling IOCs."""
    text = re.sub(r'\[([^\]]+)\]\((https?://[^\)]+)\)', r'\1', text)
    text = re.sub(r'<([^>]+)>', r'\1', text)
    text = re.sub(r'(?<!\w)`([^`\s]+)`(?!\w)', r'\1', text)
    text = re.sub(r'(?<!\w)\*\*([^\*\s]+)\*\*(?!\w)', r'\1', text)
    text = re.sub(r'(?<!\w)_([^\_\s]+)_(?!\w)', r'\1', text)
    return text

def rejoin_split_iocs(text: str) -> str:
    """Rejoin IOCs split across newlines (common in PDFs)."""
    text = re.sub(r'([a-zA-Z0-9-])[ \t]*\r?\n[ \t]*\.([a-zA-Z]{2,})\b', r'\1.\2', text)
    text = re.sub(r'(\b\d{1,3}\.\d{1,3})[ \t]*\r?\n[ \t]*(\.\d{1,3}\.\d{1,3}\b)', r'\1\2', text)
    text = re.sub(r'(\b\d{1,3}\.\d{1,3}\.\d{1,3})?[ \t]*\r?\n[ \t]*(\.\d{1,3}\b)', r'\1\2', text)
    text = re.sub(r'(https?://[a-zA-Z0-9\.-]+)[ \t]*\r?\n[ \t]*([a-zA-Z0-9/_\.-]+)', r'\1\2', text)
    return text

# --- Phase 3: Punctuation & Brackets ---

def normalize_brackets(text: str) -> str:
    """Normalize and remove defanging brackets."""
    text = text.replace('%5B', '[').replace('%5D', ']')
    text = text.replace('%5b', '[').replace('%5d', ']')
    text = text.replace('%28', '(').replace('%29', ')')
    text = text.replace('%7B', '{').replace('%7D', '}')
    
    text = re.sub(r'\[://\]', '://', text)
    text = re.sub(r'\[:\]//', '://', text)
    text = re.sub(r'\[://', '://', text)
    text = re.sub(r'://\]', '://', text)
    text = re.sub(r'\(://\)', '://', text)
    text = re.sub(r'\{://\}', '://', text)
    
    text = re.sub(r'http\[s\]://', 'https://', text, flags=re.IGNORECASE)
    text = re.sub(r'http\(s\)://', 'https://', text, flags=re.IGNORECASE)
    
    text = re.sub(r'\[([a-zA-Z0-9_-])\]', r'\1', text)
    text = re.sub(r'\(([a-zA-Z0-9_-])\)', r'\1', text)
    text = re.sub(r'\{([a-zA-Z0-9_-])\}', r'\1', text)
    return text

def defang_dots(text: str) -> str:
    """Normalize varied dot obfuscations."""
    unicode_dots = ['․', '﹒', '·', '∙', '｡', '。']
    for d in unicode_dots:
        text = text.replace(d, '.')
        
    text = text.replace('%2E', '.').replace('%2e', '.')
    
    text = re.sub(r'\[\.\]', '.', text)
    text = re.sub(r'\(\.\)', '.', text)
    text = re.sub(r'\{\.\}', '.', text)
    
    text = re.sub(r'\[d0t\]', '.', text, flags=re.IGNORECASE)
    text = re.sub(r'\[dt\]', '.', text, flags=re.IGNORECASE)
    text = re.sub(r'\[dot\]', '.', text, flags=re.IGNORECASE)
    text = re.sub(r'\(dot\)', '.', text, flags=re.IGNORECASE)
    text = re.sub(r'\{dot\}', '.', text, flags=re.IGNORECASE)
    text = re.sub(r'<dot>', '.', text, flags=re.IGNORECASE)
    text = re.sub(r'\bDOT\b', '.', text)
    
    text = re.sub(r'\b([a-zA-Z0-9_.-]+)\s+\.\s+([a-zA-Z0-9_-]+)\b', r'\1.\2', text)
    return text

def defang_slashes(text: str) -> str:
    """Normalize slashed paths and schemes."""
    text = text.replace(r'\/', '/') 
    text = re.sub(r'\[/\]', '/', text) 
    text = text.replace('&#47;', '/')
    text = text.replace('%252F', '%2F').replace('%252f', '%2f')
    return text

def defang_email(text: str) -> str:
    """Normalize at signs."""
    text = re.sub(r'\s*\[at\]\s*', '@', text, flags=re.IGNORECASE)
    text = re.sub(r'\s*\(\s*at\s*\)\s*', '@', text, flags=re.IGNORECASE)
    text = re.sub(r'\s*\[@\]\s*', '@', text)
    text = re.sub(r'\s*\bAT\b\s*', '@', text)
    text = text.replace('＠', '@') 
    return text

# --- Phase 4: Encodings & Formats ---

def defang_url(text: str) -> str:
    """Normalize URL schemes."""
    def scheme_repl(m):
        base = 'https' if 's' in m.group(0).lower() else 'http'
        sep = '://' if '%3' not in m.group(1).lower() else m.group(1)
        return base + sep
        
    text = re.sub(r'h[a-zA-Z*_-]{1,2}ps?(://|%3A%2F%2F|%3a%2f%2f)', scheme_repl, text, flags=re.IGNORECASE)
    text = re.sub(r'\bfxp(://)', r'ftp\1', text, flags=re.IGNORECASE)
    text = re.sub(r'\bmeow(://)', r'http\1', text, flags=re.IGNORECASE)
    
    text = text.replace('%253A', '%3A').replace('%253a', '%3a')
    return text

def defang_ips(text: str) -> str:
    """Normalize exotic IP obfuscations."""
    import socket
    import struct
    
    text = re.sub(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', r'\1', text)
    text = re.sub(r'\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)', r'\1', text)
    text = re.sub(r'\{(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\}', r'\1', text)
    
    text = re.sub(r'\b(\d{1,3})\s+\.\s+(\d{1,3})\s+\.\s+(\d{1,3})\s+\.\s+(\d{1,3})\b', r'\1.\2.\3.\4', text)
    
    def decode_ip(match):
        val = match.group(0)
        try:
            if val.startswith('0x') or val.startswith('0X'):
                num = int(val, 16)
            elif val.startswith('0') and len(val) > 1 and '.' not in val:
                num = int(val, 8)
            else:
                num = int(val)
                
            if 0 <= num <= 0xFFFFFFFF:
                return socket.inet_ntoa(struct.pack('!L', num))
        except Exception:
            pass
        return val

    # Full Dec/Hex standalones
    text = re.sub(r'\b0[xX][0-9a-fA-F]{8}\b', decode_ip, text)
    text = re.sub(r'\b[1-3]\d{9}\b|\b\d{8,9}\b', decode_ip, text)
    
    # Mixed dotted
    def decode_mixed_ip(match):
        try:
            parts = []
            for p in match.groups():
                if p.startswith('0x') or p.startswith('0X'):
                    parts.append(str(int(p, 16)))
                elif p.startswith('0') and len(p) > 1:
                    parts.append(str(int(p, 8)))
                else:
                    parts.append(p)
            return ".".join(parts)
        except Exception:
            return match.group(0)
            
    text = re.sub(r'\b(0[xX][0-9a-fA-F]+|0[0-7]*|\d{1,3})\.(0[xX][0-9a-fA-F]+|0[0-7]*|\d{1,3})\.(0[xX][0-9a-fA-F]+|0[0-7]*|\d{1,3})\.(0[xX][0-9a-fA-F]+|0[0-7]*|\d{1,3})\b', decode_mixed_ip, text)
    
    return text

def normalize_cve(text: str) -> str:
    """Normalize CVE formats to standard CVE-YYYY-NNNN."""
    def repl_cve(m):
        return f"CVE-{m.group(1)}-{m.group(2)}"
    text = re.sub(r'(?i)\bcve[_\.#\-\s]+(\d{4})[_\.#\-\s]+(\d{4,})\b', repl_cve, text)
    return text

def decode_punycode(text: str) -> str:
    """Decode xn-- punycode strings."""
    def repl_puny(m):
        try:
            return m.group(0).encode('utf-8').decode('idna')
        except Exception:
            return m.group(0)
    return re.sub(r'\bxn--[a-zA-Z0-9-]+\b', repl_puny, text, flags=re.IGNORECASE)


def deobfuscate_text(text: str) -> Tuple[str, bool]:
    """
    Master pipeline executing deobfuscation rules in strict priority order.
    Returns (cleaned_text, was_modified).
    """
    original = text
    
    # 1. Encoding
    text = decode_unicode_escapes(text)
    text = normalize_unicode(text)
    text = strip_zero_width(text)
    text = decode_html_entities(text)
    text = decode_base64_iocs(text)
    
    # 2. Structural
    text = strip_markdown_artifacts(text)
    text = rejoin_split_iocs(text)
    
    # 3. Brackets & Punctuation
    text = normalize_brackets(text)
    text = defang_dots(text)
    text = defang_slashes(text)
    text = defang_email(text)
    
    # 4. Formats
    text = defang_url(text)
    text = defang_ips(text)
    text = normalize_cve(text)
    text = decode_punycode(text)
    
    was_modified = text != original
    if was_modified:
        logger.info("🔧 IOC deobfuscation applied to text")
        
    return text, was_modified
