"""
generate_extra.py — Generate synthetic phishing and legitimate URLs
to supplement the training dataset with patterns the model misses.
"""
import random
import string
import pandas as pd

random.seed(42)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

VOWELS     = "aeiou"
CONSONANTS = "bcdfghjklmnpqrstvwxyz"
TLDS       = [".com", ".net", ".org", ".info", ".xyz", ".top", ".site", ".online"]
PHISH_TLDS = [".com", ".net", ".xyz", ".top", ".site", ".online", ".club", ".tk"]

def random_gibberish(min_len=8, max_len=22):
    """High entropy domain — mostly consonants, no real words."""
    length = random.randint(min_len, max_len)
    # 80% consonants to mimic real gibberish
    chars = random.choices(CONSONANTS, k=int(length * 0.82)) + \
            random.choices(VOWELS,     k=int(length * 0.18))
    random.shuffle(chars)
    return "".join(chars)

def random_word(min_len=4, max_len=10):
    """Pronounceable word — alternating consonant/vowel."""
    length = random.randint(min_len, max_len)
    word = ""
    for i in range(length):
        word += random.choice(CONSONANTS if i % 2 == 0 else VOWELS)
    return word

def random_path():
    parts = random.randint(0, 3)
    return "/" + "/".join(random_word(3, 8) for _ in range(parts)) if parts else ""

def random_query():
    if random.random() < 0.3:
        params = random.randint(1, 3)
        return "?" + "&".join(f"{random_word(2,5)}={random_word(2,8)}" for _ in range(params))
    return ""

LEGIT_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "twitter.com",
    "instagram.com", "linkedin.com", "github.com", "microsoft.com",
    "apple.com", "amazon.com", "wikipedia.org", "reddit.com",
    "netflix.com", "yahoo.com", "stackoverflow.com", "paypal.com",
    "dropbox.com", "slack.com", "zoom.us", "notion.so",
    "medium.com", "wordpress.com", "blogger.com", "tumblr.com",
    "pinterest.com", "quora.com", "twitch.tv", "discord.com",
    "shopify.com", "stripe.com", "heroku.com", "digitalocean.com",
    "cloudflare.com", "aws.amazon.com", "azure.microsoft.com",
    "letsupgrade.in", "internshala.com", "nptel.ac.in",
    "geeksforgeeks.org", "hackerrank.com", "leetcode.com",
    "coursera.org", "udemy.com", "edx.org", "khan academy.org",
    "khanacademy.org", "codecademy.com", "freecodecamp.org",
    "claude.ai", "anthropic.com", "openai.com", "huggingface.co",
]

SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "confirm", "banking", "password", "alert", "suspend", "unusual",
    "webscr", "checkout", "wallet", "recover", "unlock", "validate",
]

BRANDS = [
    "paypal", "amazon", "google", "apple", "microsoft", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "dropbox",
    "wellsfargo", "chase", "bankofamerica", "citibank", "hsbc",
]

phishing_urls = []
legit_urls    = []

# ── 1. Gibberish high-entropy phishing domains ──────────────────────────────
for _ in range(8000):
    domain = random_gibberish(10, 25)
    tld    = random.choice(PHISH_TLDS)
    path   = random_path()
    query  = random_query()
    scheme = random.choice(["http://", "https://"])
    phishing_urls.append(f"{scheme}{domain}{tld}{path}{query}")

# ── 2. Brand impersonation (typosquat) ──────────────────────────────────────
for _ in range(5000):
    brand  = random.choice(BRANDS)
    suffix = random_gibberish(3, 8)
    sep    = random.choice(["-", ""])
    tld    = random.choice(PHISH_TLDS)
    kw     = random.choice(SUSPICIOUS_WORDS)
    path   = f"/{kw}/{random_word()}"
    scheme = random.choice(["http://", "https://"])
    phishing_urls.append(f"{scheme}{brand}{sep}{suffix}{tld}{path}")

# ── 3. Suspicious keyword phishing ──────────────────────────────────────────
for _ in range(5000):
    kw1    = random.choice(SUSPICIOUS_WORDS)
    kw2    = random.choice(SUSPICIOUS_WORDS)
    brand  = random.choice(BRANDS)
    domain = f"{brand}-{kw1}-{kw2}"
    tld    = random.choice(PHISH_TLDS)
    query  = f"?user={random_word()}@gmail.com&token={random_gibberish(8,12)}"
    phishing_urls.append(f"http://{domain}{tld}/{kw1}{query}")

# ── 4. IP-based phishing ─────────────────────────────────────────────────────
for _ in range(2000):
    ip   = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
    kw   = random.choice(SUSPICIOUS_WORDS)
    path = f"/{kw}/{random_word()}.php"
    phishing_urls.append(f"http://{ip}{path}")

# ── 5. Hex-encoded phishing ──────────────────────────────────────────────────
for _ in range(2000):
    brand  = random.choice(BRANDS)
    kw     = random.choice(SUSPICIOUS_WORDS)
    domain = f"{brand}-{kw}"
    tld    = random.choice(PHISH_TLDS)
    query  = f"?redirect=%2F{random_word()}%2F{random_word()}&id=%3D{random_gibberish(4,8)}"
    phishing_urls.append(f"https://{domain}{tld}/{kw}{query}")

# ── 6. Legitimate URLs ───────────────────────────────────────────────────────
for domain in LEGIT_DOMAINS:
    for _ in range(60):
        scheme = "https://"
        subdomain = random.choice(["www.", ""])
        path   = random_path()
        query  = random_query()
        legit_urls.append(f"{scheme}{subdomain}{domain}{path}{query}")

# Extra clean domains
for _ in range(8000):
    word1  = random_word(4, 8)
    word2  = random_word(3, 6)
    tld    = random.choice([".com", ".org", ".net", ".io", ".co"])
    scheme = "https://"
    path   = random_path()
    legit_urls.append(f"{scheme}www.{word1}{word2}{tld}{path}")

# ---------------------------------------------------------------------------
# Combine and save
# ---------------------------------------------------------------------------

print(f"Generated {len(phishing_urls)} phishing URLs")
print(f"Generated {len(legit_urls)} legitimate URLs")

rows = (
    [{"url": u, "label": 1} for u in phishing_urls] +
    [{"url": u, "label": 0} for u in legit_urls]
)

df_new = pd.DataFrame(rows).sample(frac=1, random_state=42).reset_index(drop=True)

# Load existing dataset and append
df_existing = pd.read_csv("data/dataset.csv")
print(f"Existing dataset: {len(df_existing)} rows")

df_combined = pd.concat([df_existing, df_new], ignore_index=True).sample(frac=1, random_state=42)
df_combined.to_csv("data/dataset.csv", index=False)

print(f"\nFinal dataset: {len(df_combined)} rows")
print(df_combined["label"].value_counts())
print("\nSaved to data/dataset.csv")