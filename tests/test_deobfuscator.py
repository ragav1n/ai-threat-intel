import pytest
from threat_intel_aggregator.feed_collection.ioc_deobfuscator import (
    defang_url,
    defang_dots,
    normalize_brackets,
    defang_slashes,
    defang_ips,
    deobfuscate_text,
    decode_unicode_escapes,
    normalize_unicode,
    strip_zero_width,
    decode_html_entities,
    strip_markdown_artifacts,
    defang_email,
    normalize_cve,
    decode_punycode,
    rejoin_split_iocs
)

def test_defang_url():
    # Protcols & Schemes
    assert defang_url("hxxp://example.com") == "http://example.com"
    assert defang_url("hXXp://example.com") == "http://example.com"
    assert defang_url("HXXP://example.com") == "http://example.com"
    assert defang_url("fxp://example.com") == "ftp://example.com"
    assert defang_url("meow://example.com") == "http://example.com"
    assert defang_url("h**p://example.com") == "http://example.com"
    assert defang_url("h--p://example.com") == "http://example.com"
    assert defang_url("h__ps://example.com") == "https://example.com"
    
    # Brackets in protocols
    assert normalize_brackets("hxxp[s]://example.com") == "hxxps://example.com"
    assert normalize_brackets("http[:]//example.com") == "http://example.com"
    assert normalize_brackets("http[://]example.com") == "http://example.com"

def test_defang_dots():
    # Parentheses, braces, brackets
    assert defang_dots("example(.)com") == "example.com"
    assert defang_dots("example{.}com") == "example.com"
    assert defang_dots("example[/]com") == "example[/]com" # Not defang_dots job
    assert defang_dots("example%2Ecom") == "example.com"
    
    # Leetspeak / words
    assert defang_dots("example[d0t]com") == "example.com"
    assert defang_dots("example[dt]com") == "example.com"
    assert defang_dots("example<dot>com") == "example.com"
    
    # Unicode dots
    assert defang_dots("example·com") == "example.com" # U+00B7
    assert defang_dots("example∙com") == "example.com" # U+2219
    assert defang_dots("example｡com") == "example.com" # U+FF61
    assert defang_dots("example。com") == "example.com" # CJK

def test_defang_ips():
    # IP Brackets
    assert defang_ips("[192.168.1.1]") == "192.168.1.1"
    assert defang_ips("192 . 168 . 1 . 1") == "192.168.1.1"
    
    # Encoding & Fragmented
    assert defang_ips("0x7f000001") == "127.0.0.1"
    assert defang_ips("2130706433") == "127.0.0.1"
    assert defang_ips("0177.0.0.1") == "127.0.0.1"
    assert defang_ips("127.0x0.0.1") == "127.0.0.1"

def test_defang_email():
    assert defang_email("user[@]evil.com") == "user@evil.com"
    assert defang_email("user[at]evil.com") == "user@evil.com"
    assert defang_email("user(at)evil.com") == "user@evil.com"
    assert defang_email("user AT evil.com") == "user@evil.com"
    assert defang_email("user＠evil.com") == "user@evil.com" # U+FF20

def test_advanced_string_cleanups():
    # Unicode Homoglyphs
    assert normalize_unicode("evіl.com") == "evil.com" # Cyrillic і
    assert normalize_unicode("goоgle.com") == "google.com" # Cyrillic о
    assert normalize_unicode("pаypal.com") == "paypal.com" # Cyrillic а

    # Zero Width
    assert strip_zero_width("evil\u200B.com") == "evil.com"
    assert strip_zero_width("evil\u200C.com") == "evil.com"
    assert strip_zero_width("e\x00vil.com") == "evil.com"
    
    # HTML / URL / Unicode Escapes
    assert decode_unicode_escapes("\u0068xxp://") == "hxxp://"
    assert decode_html_entities("&#x68;xxp://") == "hxxp://"
    assert decode_html_entities("&#104;xxp://") == "hxxp://"
    
    # Punycode
    assert decode_punycode("xn--pple-43d.com") == "аpple.com"

def test_split_and_markdown():
    # Markdown
    assert strip_markdown_artifacts("`evil.com`") == "evil.com"
    assert strip_markdown_artifacts("**evil.com**") == "evil.com"
    assert strip_markdown_artifacts("_evil.com_") == "evil.com"
    assert strip_markdown_artifacts("<evil.com>") == "evil.com"
    
    # Rejoin Splits
    split_domain = "evil\n.com"
    assert rejoin_split_iocs(split_domain) == "evil.com"

def test_cve_normalize():
    assert normalize_cve("CVE_2026_1234") == "CVE-2026-1234"
    assert normalize_cve("CVE 2026 1234") == "CVE-2026-1234"
    assert normalize_cve("cve-2026-1234") == "CVE-2026-1234"
    assert normalize_cve("CVE#2026#1234") == "CVE-2026-1234"
