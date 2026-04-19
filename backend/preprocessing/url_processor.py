import re
import requests
import tldextract

URL_REGEX = r'(https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:\/[^\s]*)?)'

def extract_urls(text: str) -> list:
    """Extract all URLs from text, stripping trailing punctuation."""
    urls = re.findall(URL_REGEX, text)
    cleaned_urls = []
    for url in urls:
        url = url.rstrip('.,;:!?)')
        cleaned_urls.append(url)
    return cleaned_urls

def normalize_url(url: str) -> str:
    """
    Extract the true registrable domain (eTLD+1) from a URL using tldextract.
    
    Examples:
        delivery.fedex.com.parcel-track.xyz  ->  parcel-track.xyz
        https://www.amazon.com/orders        ->  amazon.com
        bit.ly/abc                           ->  bit.ly
        paypa1.com                           ->  paypa1.com
    """
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    extracted = tldextract.extract(url)
    
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}".lower()
    
    # Fallback: strip scheme and www manually
    url = re.sub(r'^https?://', '', url)
    url = re.sub(r'^www\.', '', url)
    domain = url.split('/')[0].split('?')[0]
    return domain.lower()

def expand_short_url(url: str) -> str:
    """Expand shortened URLs using HEAD request."""
    short_domains = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"]
    domain = normalize_url(url)
    if any(short == domain for short in short_domains):
        try:
            full_url = url if url.startswith('http') else 'http://' + url
            resp = requests.head(full_url, allow_redirects=True, timeout=3)
            return resp.url
        except Exception:
            return url
    return url
