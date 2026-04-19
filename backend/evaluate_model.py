"""
Generate model evaluation metrics and visualizations for the smishing CNN model.
Outputs: confusion matrix, classification report, training accuracy/loss curves.
"""
import os, sys
import numpy as np
import pandas as pd
import pickle
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, confusion_matrix, classification_report,
                             roc_curve, auc)

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import tf_keras as keras
from tf_keras.preprocessing.sequence import pad_sequences
from preprocessing.text_processor import clean_text
from sklearn.model_selection import train_test_split

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(SCRIPT_DIR, "data", "spam.csv")
MODEL_PATH = os.path.join(SCRIPT_DIR, "model", "smishing_cnn.keras")
TOKENIZER_PATH = os.path.join(SCRIPT_DIR, "model", "tokenizer.pkl")
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "evaluation_results")

MAX_VOCAB_SIZE = 10000
MAX_LENGTH = 100

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Load data
    print("Loading data...")
    df = pd.read_csv(DATA_PATH, encoding='latin-1')
    df = df[['v1', 'v2']].dropna()
    df.columns = ['label', 'message']
    df['label_int'] = df['label'].map({'spam': 1, 'ham': 0})
    df['cleaned_message'] = df['message'].apply(clean_text)

    # Load tokenizer and model
    print("Loading model and tokenizer...")
    model = keras.models.load_model(MODEL_PATH)
    with open(TOKENIZER_PATH, 'rb') as f:
        tokenizer = pickle.load(f)

    # Prepare sequences
    sequences = tokenizer.texts_to_sequences(df['cleaned_message'])
    X = pad_sequences(sequences, maxlen=MAX_LENGTH, padding='post', truncating='post')
    y = df['label_int'].values

    # Train/test split (same seed as training)
    _, X_test, _, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # Predictions
    print("Making predictions...")
    y_pred_probs = model.predict(X_test, verbose=0).flatten()
    y_pred = (y_pred_probs > 0.5).astype(int)

    # ── Metrics ──────────────────────────────────────────────────────────────
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    report = classification_report(y_test, y_pred, target_names=['Ham', 'Spam'], digits=4)
    print(f"\nAccuracy:  {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall:    {rec:.4f}")
    print(f"F1 Score:  {f1:.4f}")
    print(f"\n{report}")

    with open(os.path.join(OUTPUT_DIR, "classification_report.txt"), "w") as f:
        f.write(f"Accuracy:  {acc:.4f}\nPrecision: {prec:.4f}\nRecall:    {rec:.4f}\nF1 Score:  {f1:.4f}\n\n")
        f.write(report)

    # ── 1. Confusion Matrix ──────────────────────────────────────────────────
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=['Ham (Safe)', 'Spam (Smishing)'],
                yticklabels=['Ham (Safe)', 'Spam (Smishing)'])
    plt.title('Confusion Matrix — Smishing Detection CNN', fontsize=14, fontweight='bold')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "confusion_matrix.png"), dpi=150)
    plt.close()
    print("Saved: confusion_matrix.png")

    # ── 2. ROC Curve ─────────────────────────────────────────────────────────
    fpr, tpr, _ = roc_curve(y_test, y_pred_probs)
    roc_auc = auc(fpr, tpr)

    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, color='#1976D2', lw=2, label=f'ROC Curve (AUC = {roc_auc:.4f})')
    plt.plot([0, 1], [0, 1], color='gray', lw=1, linestyle='--')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('ROC Curve — Smishing Detection CNN', fontsize=14, fontweight='bold')
    plt.legend(loc='lower right')
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "roc_curve.png"), dpi=150)
    plt.close()
    print("Saved: roc_curve.png")

    # ── 3. Prediction Distribution ───────────────────────────────────────────
    plt.figure(figsize=(8, 6))
    plt.hist(y_pred_probs[y_test == 0], bins=50, alpha=0.7, label='Ham (Safe)', color='#43A047')
    plt.hist(y_pred_probs[y_test == 1], bins=50, alpha=0.7, label='Spam (Smishing)', color='#E53935')
    plt.axvline(x=0.5, color='black', linestyle='--', linewidth=1, label='Threshold (0.5)')
    plt.xlabel('Model Prediction Probability')
    plt.ylabel('Count')
    plt.title('Prediction Score Distribution', fontsize=14, fontweight='bold')
    plt.legend()
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "prediction_distribution.png"), dpi=150)
    plt.close()
    print("Saved: prediction_distribution.png")

    # ── 4. Metrics Bar Chart ─────────────────────────────────────────────────
    metrics = {'Accuracy': acc, 'Precision': prec, 'Recall': rec, 'F1 Score': f1}
    colors = ['#1976D2', '#43A047', '#FB8C00', '#E53935']

    plt.figure(figsize=(8, 5))
    bars = plt.bar(metrics.keys(), metrics.values(), color=colors, width=0.5, edgecolor='white')
    for bar, val in zip(bars, metrics.values()):
        plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                 f'{val:.4f}', ha='center', va='bottom', fontweight='bold', fontsize=12)
    plt.ylim(0, 1.1)
    plt.ylabel('Score')
    plt.title('Model Performance Metrics', fontsize=14, fontweight='bold')
    plt.grid(axis='y', alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "metrics_bar_chart.png"), dpi=150)
    plt.close()
    print("Saved: metrics_bar_chart.png")

    # ── 5. Training History (re-train briefly to capture curves) ─────────────
    print("\nTraining model briefly to capture learning curves...")
    _, X_train, _, y_train = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    X_t, X_v, y_t, y_v = train_test_split(X_train, y_train, test_size=0.1, random_state=42)

    from model.cnn_model import build_cnn_model
    vocab_size = min(len(tokenizer.word_index) + 1, MAX_VOCAB_SIZE)
    fresh_model = build_cnn_model(vocab_size, 50, MAX_LENGTH)
    history = fresh_model.fit(X_t, y_t, epochs=5, batch_size=32,
                              validation_data=(X_v, y_v), verbose=1)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

    ax1.plot(history.history['accuracy'], label='Train Accuracy', color='#1976D2', linewidth=2)
    ax1.plot(history.history['val_accuracy'], label='Val Accuracy', color='#E53935', linewidth=2)
    ax1.set_title('Model Accuracy Over Epochs', fontsize=13, fontweight='bold')
    ax1.set_xlabel('Epoch')
    ax1.set_ylabel('Accuracy')
    ax1.legend()
    ax1.grid(alpha=0.3)

    ax2.plot(history.history['loss'], label='Train Loss', color='#1976D2', linewidth=2)
    ax2.plot(history.history['val_loss'], label='Val Loss', color='#E53935', linewidth=2)
    ax2.set_title('Model Loss Over Epochs', fontsize=13, fontweight='bold')
    ax2.set_xlabel('Epoch')
    ax2.set_ylabel('Loss')
    ax2.legend()
    ax2.grid(alpha=0.3)

    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "training_curves.png"), dpi=150)
    plt.close()
    print("Saved: training_curves.png")

    print(f"\n✅ All evaluation results saved to: {OUTPUT_DIR}")

if __name__ == "__main__":
    main()
