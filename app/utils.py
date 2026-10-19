import re
from urllib.parse import urlparse

# Trusted domains list for safe known platforms
TRUSTED_DOMAINS = {
    'google.com', 'google.co.in', 'google.co.uk', 'google.ca', 'google.de',
    'youtube.com', 'gmail.com',
    'github.com', 'gitlab.com', 'bitbucket.org',
    'wikipedia.org', 'wikimedia.org',
    'microsoft.com', 'live.com', 'office.com', 'bing.com',
    'apple.com', 'icloud.com',
    'amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de', 'amazon.ca', 'amazon.fr',
    'linkedin.com', 'reddit.com', 'twitter.com', 'x.com',
    'facebook.com', 'instagram.com', 'whatsapp.com',
    'stackoverflow.com', 'stackexchange.com',
    'python.org', 'pypi.org',
    'netflix.com', 'spotify.com', 'medium.com',
    'yahoo.com', 'paypal.com',
    # Modern AI, Cloud & Developer Services
    'chatgpt.com', 'openai.com',
    'claude.ai', 'anthropic.com',
    'notion.so', 'notion.site',
    'huggingface.co', 'cloudflare.com',
    'figma.com', 'canva.com',
    'discord.com', 'slack.com', 'zoom.us',
    'adobe.com', 'dropbox.com', 'duckduckgo.com'
}

POPULAR_BRANDS = {
    'paypal': ['paypal.com'],
    'amazon': ['amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de', 'amazon.ca', 'amazon.fr', 'amazon.es', 'amazon.it'],
    'google': ['google.com', 'google.co.in', 'google.co.uk', 'google.de', 'google.ca'],
    'apple': ['apple.com', 'icloud.com'],
    'microsoft': ['microsoft.com', 'live.com', 'office.com', 'bing.com'],
    'netflix': ['netflix.com'],
    'instagram': ['instagram.com'],
    'facebook': ['facebook.com', 'fb.com'],
    'twitter': ['twitter.com', 'x.com'],
    'chatgpt': ['chatgpt.com', 'openai.com'],
    'openai': ['openai.com', 'chatgpt.com'],
    'claude': ['claude.ai', 'anthropic.com'],
    'anthropic': ['anthropic.com', 'claude.ai']
}

SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.club', '.work', '.buzz', '.fit',
    '.tk', '.ml', '.ga', '.cf', '.gq', '.surf', '.cam'
}

# Legally restricted domains allocated exclusively to verified government, military, and educational entities
RESTRICTED_GOV_EDU_REGEX = re.compile(
    r'(?:^|\.)(?:gov|nic|mil|edu|ac)\.[a-z]{2,3}$|(?:^|\.)(?:gov|mil|edu)$',
    re.IGNORECASE
)


def validate_url(url: str):
    """Validates whether the user-provided string looks like a website URL."""
    if not url or not url.strip():
        return False, "Please enter a website URL."
    
    cleaned = url.strip()
    if len(cleaned) < 3:
        return False, "The entered URL is too short to be valid."
    
    if "." not in cleaned:
        return False, "Please enter a valid website URL (must contain a domain extension like .com, .org, etc.)."
    
    if re.search(r"\s", cleaned):
        return False, "A URL cannot contain whitespace characters."
        
    return True, ""


def normalize_url(raw_url: str) -> str:
    """
    Normalizes user input to match the training dataset distribution:
    - Strips protocol (http:// or https://)
    - Lowercases domain
    - Ensures trailing slash for root domains (since dataset good URLs overwhelmingly feature '/')
    """
    url = raw_url.strip()
    # Strip protocol
    url = re.sub(r"^https?://", "", url, flags=re.IGNORECASE)
    # Split domain and path
    parts = url.split("/", 1)
    domain = parts[0].lower()
    path = parts[1] if len(parts) > 1 else ""
    
    if not path:
        return f"{domain}/"
    return f"{domain}/{path}"


def is_trusted_root_domain(url: str) -> bool:
    """
    Checks if the root domain belongs to a verified trusted authority/service,
    or a legally restricted government/educational TLD (.gov, .gov.in, .nic.in, .edu, .ac.in).
    """
    cleaned = re.sub(r"^https?://", "", url.strip(), flags=re.IGNORECASE)
    host = cleaned.split("/")[0].split(":")[0].lower()
    if host.startswith("www."):
        host = host[4:]
        
    # Check official restricted Government, Military, and Higher-Education TLDs
    if RESTRICTED_GOV_EDU_REGEX.search(host):
        return True
        
    if host in TRUSTED_DOMAINS:
        return True
        
    parts = host.split(".")
    if len(parts) > 2:
        parent = ".".join(parts[-2:])
        if parent in TRUSTED_DOMAINS:
            # Check for form phishing hosted on docs.google.com
            if "docs.google.com" in host and "viewform" in url.lower():
                return False
            return True
            
    return False


def detect_brand_spoofing(url: str):
    """
    Detects if a known brand keyword is used inside an unauthorized domain (typo-squatting / impersonation).
    """
    cleaned = re.sub(r"^https?://", "", url.strip(), flags=re.IGNORECASE)
    host = cleaned.split("/")[0].split(":")[0].lower()
    if host.startswith("www."):
        host = host[4:]
        
    for brand, valid_domains in POPULAR_BRANDS.items():
        if brand in host:
            is_valid = any(host == d or host.endswith("." + d) for d in valid_domains)
            if not is_valid:
                return True, brand
    return False, None


def extract_url_features(url: str) -> dict:
    """
    Extracts lexical indicators for user explainability and heuristic scoring.
    """
    cleaned = url.strip()
    has_ip = bool(re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", cleaned))
    has_at = "@" in cleaned
    has_double_slash = "//" in re.sub(r"^https?://", "", cleaned)
    length = len(cleaned)
    dot_count = cleaned.count(".")
    hyphen_count = cleaned.count("-")
    
    host = re.sub(r"^https?://", "", cleaned).split("/")[0].lower()
    suspicious_tld = any(host.endswith(tld) for tld in SUSPICIOUS_TLDS)
    is_institutional = bool(RESTRICTED_GOV_EDU_REGEX.search(host))
    is_spoofed, spoofed_brand = detect_brand_spoofing(cleaned)
    
    # Calculate simple heuristic risk factor
    risk_points = 0
    if is_spoofed:
        risk_points += 50
    if has_ip:
        risk_points += 40
    if has_at:
        risk_points += 25
    if has_double_slash:
        risk_points += 20
    if suspicious_tld:
        risk_points += 20
    if hyphen_count >= 3:
        risk_points += 15
    if length > 75:
        risk_points += 10
        
    return {
        "length": length,
        "dot_count": dot_count,
        "hyphen_count": hyphen_count,
        "has_ip": has_ip,
        "has_at": has_at,
        "has_redirect": has_double_slash,
        "suspicious_tld": suspicious_tld,
        "is_institutional": is_institutional,
        "is_brand_spoofed": is_spoofed,
        "spoofed_brand": spoofed_brand,
        "heuristic_risk_score": min(100, risk_points)
    }
