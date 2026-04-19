import os
import pandas as pd
import numpy as np
import pickle
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from tf_keras.preprocessing.text import Tokenizer
from tf_keras.preprocessing.sequence import pad_sequences
from cnn_model import build_cnn_model

import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from preprocessing.text_processor import clean_text

DATA_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "spam.csv"))
MODEL_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "smishing_cnn.keras"))
TOKENIZER_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "tokenizer.pkl"))

MAX_VOCAB_SIZE = 10000
MAX_LENGTH = 100
EMBEDDING_DIM = 50

def train_model():
    print(f"Loading data from {DATA_PATH}...")
    try:
        df = pd.read_csv(DATA_PATH, encoding='latin-1')
    except Exception as e:
        print(f"Error loading csv: {e}")
        return

    df = df[['v1', 'v2']].dropna()
    df.columns = ['label', 'message']
    df['label'] = df['label'].map({'spam': 1, 'ham': 0})
    
    print("Preprocessing text...")
    df['cleaned_message'] = df['message'].apply(clean_text)

    tokenizer = Tokenizer(num_words=MAX_VOCAB_SIZE, oov_token='<OOV>')
    tokenizer.fit_on_texts(df['cleaned_message'])
    
    with open(TOKENIZER_PATH, 'wb') as f:
        pickle.dump(tokenizer, f)

    sequences = tokenizer.texts_to_sequences(df['cleaned_message'])
    X = pad_sequences(sequences, maxlen=MAX_LENGTH, padding='post', truncating='post')
    y = df['label'].values

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    print("Building model...")
    vocab_size = min(len(tokenizer.word_index) + 1, MAX_VOCAB_SIZE)
    model = build_cnn_model(vocab_size, EMBEDDING_DIM, MAX_LENGTH)
    
    print("Training model...")
    model.fit(X_train, y_train, epochs=5, batch_size=32, validation_split=0.1, verbose=1)
    
    print("Evaluating model...")
    y_pred_probs = model.predict(X_test)
    y_pred = (y_pred_probs > 0.5).astype(int).flatten()
    
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print(f"Precision: {precision_score(y_test, y_pred):.4f}")
    print(f"Recall: {recall_score(y_test, y_pred):.4f}")
    print(f"F1 Score: {f1_score(y_test, y_pred):.4f}")

    print(f"Saving model to {MODEL_PATH}...")
    model.save(MODEL_PATH)
    print("Training completed successfully!")

if __name__ == "__main__":
    train_model()
