"""
Export the Keras Tokenizer's vocabulary from pickle to JSON
for consumption by the Android app.
"""
import os
import pickle
import json

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TOKENIZER_PATH = os.path.join(SCRIPT_DIR, "model", "tokenizer.pkl")
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "..", "android_app", "app", "src", "main", "assets")
OUTPUT_PATH = os.path.join(OUTPUT_DIR, "vocab.json")

MAX_VOCAB_SIZE = 10000

def export():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print(f"Loading tokenizer from {TOKENIZER_PATH}...")
    with open(TOKENIZER_PATH, 'rb') as f:
        tokenizer = pickle.load(f)

    # word_index is a dict: word -> integer index (1-indexed, sorted by frequency)
    # Keras reserves 0 for padding and 1 for OOV when oov_token is set
    word_index = tokenizer.word_index

    # Filter to top MAX_VOCAB_SIZE entries
    vocab = {word: idx for word, idx in word_index.items() if idx < MAX_VOCAB_SIZE}

    # Ensure OOV token is present
    vocab['<OOV>'] = 1

    with open(OUTPUT_PATH, 'w', encoding='utf-8') as f:
        json.dump(vocab, f, ensure_ascii=False)

    print(f"Vocabulary exported: {len(vocab)} words -> {OUTPUT_PATH}")

if __name__ == "__main__":
    export()
