import re
import unicodedata

# Zero-width and invisible Unicode characters commonly injected to evade regex
_ZERO_WIDTH = re.compile(
    r'[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad]'
)

def clean_text(text: str) -> str:
    """
    Prepare text for CNN input:
    1. Strip zero-width / invisible Unicode characters.
    2. Normalise unicode (NFKC) to collapse look-alike characters.
    3. Lowercase.
    4. Remove everything except a-z and spaces.
    5. Collapse multiple spaces.
    """
    text = str(text)

    # Step 1: Remove zero-width characters
    text = _ZERO_WIDTH.sub('', text)

    # Step 2: Unicode normalisation (e.g. fullwidth letters -> ASCII)
    text = unicodedata.normalize('NFKC', text)

    # Step 3: Lowercase
    text = text.lower()

    # Step 4: Remove non-alphabetic characters
    text = re.sub(r'[^a-z\s]', ' ', text)

    # Step 5: Collapse spaces
    text = re.sub(r'\s+', ' ', text).strip()

    return text


def tokenize(text: str) -> list:
    return text.split()
