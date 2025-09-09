import unicodedata
import difflib
import re

WHITELIST = [
    "google.com", "facebook.com", "youtube.com",
    "twitter.com", "github.com", "linkedin.com",
    "amazon.com", "microsoft.com", "apple.com"
]

# Sample homoglyph map (expand as needed)
HOMOGLYPHS = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
    'і': 'i', 'ј': 'j', 'ӏ': 'l', 'ԁ': 'd', 'һ': 'h',
    'ԛ': 'q', 'ѕ': 's', 'ᴜ': 'u', 'ѵ': 'v', 'ԝ': 'w',
    'х': 'x', 'у': 'y', 'ᴢ': 'z'
}

def normalize_unicode(text):
    return unicodedata.normalize('NFKC', text)

def replace_homoglyphs(domain):
    return ''.join(HOMOGLYPHS.get(char, char) for char in domain)

def extract_domain(url):
    match = re.search(r"(?:https?://)?(?:www\.)?([^/]+)", url)
    return match.group(1).lower() if match else url.lower()

def is_similar_to_whitelist(domain):
    for legit in WHITELIST:
        similarity = difflib.SequenceMatcher(None, domain, legit).ratio()
        if similarity > 0.85:  # Tune threshold if needed
            return True, legit, similarity
    return False, None, None

def detect_homoglyph_attack(url):
    domain = extract_domain(url)
    norm = normalize_unicode(domain)
    replaced = replace_homoglyphs(norm)
    
    is_similar, matched, score = is_similar_to_whitelist(replaced)
    
    if domain != replaced and is_similar:
        return {
            "status": "⚠️ Suspicious",
            "input": domain,
            "normalized": replaced,
            "matched": matched,
            "similarity": round(score, 2)
        }
    else:
        return {
            "status": "✅ Clean",
            "input": domain,
            "normalized": replaced
        }

# Example URLs
urls = [
    "https://www.ɡoogle.com " # suspicious ('а' from Cyrillic)
]

for u in urls:
    print(detect_homoglyph_attack(u))
