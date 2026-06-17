import re
import math
import socket
import urllib.parse
from datetime import datetime

import tldextract

# ---------------------------------------------------------------------------
# Shortener domains (lexical check, no network call)
# ---------------------------------------------------------------------------
SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "buff.ly",
    "rebrand.ly", "short.io", "bl.ink", "cutt.ly", "is.gd", "clck.ru",
}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "update", "secure",
    "account", "banking", "confirm", "password", "alert",
    "webscr", "cmd=", "ebayisapi", "suspend", "unusual-activity",
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_parts(url: str):
    parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    ext = tldextract.extract(url)
    return parsed, ext


def _is_ip(hostname: str) -> bool:
    try:
        socket.inet_aton(hostname)
        return True
    except OSError:
        return False


def _entropy(s: str) -> float:
    """Shannon entropy — high value means random/gibberish string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _consonant_ratio(s: str) -> float:
    """Ratio of consonants to total letters — gibberish domains have very few vowels."""
    vowels = set('aeiou')
    letters = [c for c in s.lower() if c.isalpha()]
    if not letters:
        return 0.0
    consonants = [c for c in letters if c not in vowels]
    return round(len(consonants) / len(letters), 4)


def _longest_consonant_streak(s: str) -> int:
    """Longest consecutive consonant run — real words rarely exceed 4."""
    vowels = set('aeiou')
    max_streak = streak = 0
    for c in s.lower():
        if c.isalpha() and c not in vowels:
            streak += 1
            max_streak = max(max_streak, streak)
        else:
            streak = 0
    return max_streak


# ---------------------------------------------------------------------------
# Tier 1 — Lexical features (URL string only, zero network I/O)
# ---------------------------------------------------------------------------

def lexical_features(url: str) -> dict:
    parsed, ext = _extract_parts(url)
    hostname = parsed.netloc.split(":")[0]
    path     = parsed.path
    full     = url

    subdomain = ext.subdomain
    domain    = ext.domain
    suffix    = ext.suffix

    # Basic counts
    url_length           = len(full)
    hostname_length      = len(hostname)
    path_length          = len(path)
    num_dots             = full.count(".")
    num_hyphens          = full.count("-")
    num_underscores      = full.count("_")
    num_slashes          = full.count("/")
    num_question_marks   = full.count("?")
    num_at_signs         = full.count("@")
    num_ampersands       = full.count("&")
    num_equals           = full.count("=")
    num_percent          = full.count("%")
    num_digits_in_url    = sum(c.isdigit() for c in full)
    digit_ratio          = round(num_digits_in_url / max(url_length, 1), 4)

    # Structural signals
    has_ip_hostname      = int(_is_ip(hostname))
    has_at_sign          = int("@" in full)
    has_double_slash     = int("//" in path)
    has_dash_in_domain   = int("-" in domain)
    subdomain_depth      = len(subdomain.split(".")) if subdomain else 0
    uses_https = int(parsed.scheme == "https")
    has_only_https_as_safety = int(parsed.scheme == "https" and "-" not in domain)
    has_port             = int(":" in parsed.netloc and not parsed.netloc.endswith(":443"))
    is_shortener         = int(f"{domain}.{suffix}".lower() in SHORTENERS)

    # Suspicious keywords
    url_lower = full.lower()
    has_suspicious_keyword   = int(any(kw in url_lower for kw in SUSPICIOUS_KEYWORDS))
    suspicious_keyword_count = sum(kw in url_lower for kw in SUSPICIOUS_KEYWORDS)

    # Encoding tricks
    has_hex_encoding = int("%2" in full or "%3" in full)
    has_punycode     = int("xn--" in hostname.lower())

    # TLD signals
    tld_length = len(suffix)

    # ── Entropy / randomness features (catches gibberish domains) ──
    domain_entropy           = round(_entropy(domain), 4)
    hostname_entropy         = round(_entropy(hostname.replace(".", "")), 4)
    has_high_entropy         = int(domain_entropy > 3.5)
    consonant_ratio          = _consonant_ratio(domain)
    has_high_consonant_ratio = int(consonant_ratio > 0.72)
    longest_consonant_streak = _longest_consonant_streak(domain)
    has_long_consonant_streak= int(longest_consonant_streak > 4)

    # Domain length signal (very long domains are suspicious)
    domain_length            = len(domain)
    has_long_domain          = int(domain_length > 20)

    return {
        "url_length":               url_length,
        "hostname_length":          hostname_length,
        "path_length":              path_length,
        "num_dots":                 num_dots,
        "num_hyphens":              num_hyphens,
        "num_underscores":          num_underscores,
        "num_slashes":              num_slashes,
        "num_question_marks":       num_question_marks,
        "num_at_signs":             num_at_signs,
        "num_ampersands":           num_ampersands,
        "num_equals":               num_equals,
        "num_percent":              num_percent,
        "digit_ratio":              digit_ratio,
        "subdomain_depth":          subdomain_depth,
        "tld_length":               tld_length,
        "has_ip_hostname":          has_ip_hostname,
        "has_at_sign":              has_at_sign,
        "has_double_slash_in_path": has_double_slash,
        "has_dash_in_domain":       has_dash_in_domain,
        "uses_https":               uses_https,
        "has_port":                 has_port,
        "is_shortener":             is_shortener,
        "has_suspicious_keyword":   has_suspicious_keyword,
        "suspicious_keyword_count": suspicious_keyword_count,
        "has_hex_encoding":         has_hex_encoding,
        "has_punycode":             has_punycode,
        # Entropy features
        "domain_entropy":           domain_entropy,
        "hostname_entropy":         hostname_entropy,
        "has_high_entropy":         has_high_entropy,
        "consonant_ratio":          consonant_ratio,
        "has_high_consonant_ratio": has_high_consonant_ratio,
        "longest_consonant_streak": longest_consonant_streak,
        "has_long_consonant_streak":has_long_consonant_streak,
        "domain_length":            domain_length,
        "has_long_domain":          has_long_domain,
    }


# ---------------------------------------------------------------------------
# Tier 2 — Host-based features (DNS / WHOIS — needs network)
# ---------------------------------------------------------------------------

def host_features(url: str) -> dict:
    parsed, ext = _extract_parts(url)
    hostname = parsed.netloc.split(":")[0]

    # DNS resolve check
    try:
        socket.setdefaulttimeout(3)
        socket.getaddrinfo(hostname, None)
        dns_resolves = 1
    except (socket.gaierror, OSError):
        dns_resolves = 0

    # WHOIS domain age
    domain_age_days = -1
    try:
        import whois
        w = whois.whois(hostname)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            domain_age_days = (datetime.utcnow() - creation).days
    except Exception:
        pass

    is_new_domain = int(0 <= domain_age_days < 180)

    return {
        "dns_resolves":    dns_resolves,
        "domain_age_days": domain_age_days,
        "is_new_domain":   is_new_domain,
    }


# ---------------------------------------------------------------------------
# Tier 3 — Page/content features (HTTP fetch — slowest tier)
# ---------------------------------------------------------------------------

def page_features(url: str, timeout: int = 5) -> dict:
    defaults = {
        "num_redirects":     0,
        "final_url_changed": 0,
        "num_external_links":0,
        "num_forms":         0,
        "has_password_field":0,
        "favicon_external":  0,
        "title_domain_mismatch": 0,
    }

    try:
        import requests
        from bs4 import BeautifulSoup

        resp = requests.get(
            url if "://" in url else "http://" + url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"},
        )

        num_redirects     = len(resp.history)
        final_url         = resp.url
        final_url_changed = int(final_url.rstrip("/") != url.rstrip("/"))

        soup = BeautifulSoup(resp.text, "html.parser")
        _, ext_orig = _extract_parts(url)
        orig_domain = f"{ext_orig.domain}.{ext_orig.suffix}".lower()

        # External links
        external_links = 0
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.startswith("http"):
                _, ext_link = _extract_parts(href)
                link_domain = f"{ext_link.domain}.{ext_link.suffix}".lower()
                if link_domain and link_domain != orig_domain:
                    external_links += 1

        # Forms
        num_forms    = len(soup.find_all("form"))
        has_password = int(bool(soup.find("input", {"type": "password"})))

        # Favicon
        favicon_ext = 0
        favicon_tag = soup.find("link", rel=lambda r: r and "icon" in r)
        if favicon_tag and favicon_tag.get("href", "").startswith("http"):
            _, fav_ext = _extract_parts(favicon_tag["href"])
            fav_domain = f"{fav_ext.domain}.{fav_ext.suffix}".lower()
            if fav_domain and fav_domain != orig_domain:
                favicon_ext = 1

        # Title mismatch
        title_mismatch = 0
        title_tag = soup.find("title")
        if title_tag and title_tag.string:
            if ext_orig.domain.lower() not in title_tag.string.lower():
                title_mismatch = 1

        return {
            "num_redirects":      num_redirects,
            "final_url_changed":  final_url_changed,
            "num_external_links": external_links,
            "num_forms":          num_forms,
            "has_password_field": has_password,
            "favicon_external":   favicon_ext,
            "title_domain_mismatch": title_mismatch,
        }

    except Exception:
        return defaults


# ---------------------------------------------------------------------------
# Combined extractor
# ---------------------------------------------------------------------------

def extract_features(url: str, include_host: bool = True, include_page: bool = False) -> dict:
    features = lexical_features(url)
    if include_host:
        features.update(host_features(url))
    if include_page:
        features.update(page_features(url))
    return features


# ---------------------------------------------------------------------------
# Feature name lists
# ---------------------------------------------------------------------------

LEXICAL_FEATURE_NAMES = list(lexical_features("http://example.com").keys())
HOST_FEATURE_NAMES    = ["dns_resolves", "domain_age_days", "is_new_domain"]
PAGE_FEATURE_NAMES    = [
    "num_redirects", "final_url_changed", "num_external_links",
    "num_forms", "has_password_field", "favicon_external", "title_domain_mismatch",
]
ALL_FEATURE_NAMES = LEXICAL_FEATURE_NAMES + HOST_FEATURE_NAMES + PAGE_FEATURE_NAMES


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "https://ldhxyvxxbrujbrtyjbunnjbtbxa.com",   # gibberish
        "http://paypa1-secure-login.com/verify?user=test@gmail.com",
        "http://192.168.1.1/admin/login",
        "https://bit.ly/3xYzAbC",
    ]

    for u in test_urls:
        feats = extract_features(u, include_host=False, include_page=False)
        print(f"\n{u}")
        print(f"  domain_entropy           : {feats['domain_entropy']}")
        print(f"  has_high_entropy         : {feats['has_high_entropy']}")
        print(f"  consonant_ratio          : {feats['consonant_ratio']}")
        print(f"  has_high_consonant_ratio : {feats['has_high_consonant_ratio']}")
        print(f"  longest_consonant_streak : {feats['longest_consonant_streak']}")
        print(f"  domain_length            : {feats['domain_length']}")