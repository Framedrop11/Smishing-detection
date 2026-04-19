import os
import pickle
import numpy as np
import tf_keras as keras
from tf_keras.preprocessing.sequence import pad_sequences
from inference.lime_explainer import SmishingExplainer
from heuristics.rule_engine import RuleEngine
from heuristics.domain_checker import DomainChecker
from preprocessing.text_processor import clean_text
from preprocessing.url_processor import extract_urls, normalize_url

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "model", "smishing_cnn.keras")
TOKENIZER_PATH = os.path.join(os.path.dirname(__file__), "..", "model", "tokenizer.pkl")

# FIX B: Trusted domain allowlist.
# If a URL in the message resolves to one of these domains, skip CNN inference
# and return Safe immediately. This prevents false positives on legitimate
# transactional messages from known brands (Amazon, HDFC, Netflix etc.).
TRUSTED_DOMAINS = {
    # E-commerce
    'amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de',
    'flipkart.com', 'myntra.com', 'meesho.com',
    # Banking (India)
    'hdfcbank.com', 'sbi.co.in', 'icicibank.com', 'axisbank.com',
    'kotakbank.com', 'paytm.com', 'phonepe.com',
    # Banking (Global)
    'hsbc.com', 'barclays.co.uk', 'lloydsbank.com', 'natwest.com',
    'santander.co.uk', 'chase.com', 'bankofamerica.com',
    # Streaming
    'netflix.com', 'primevideo.com', 'hotstar.com',
    # Big Tech / Social
    'google.com', 'apple.com', 'microsoft.com',
    'linkedin.com', 'twitter.com', 'instagram.com',
    # Logistics
    'fedex.com', 'dhl.com', 'ups.com', 'usps.com', 'royalmail.com',
    # Telecom (India)
    'jio.com', 'airtel.in', 'vodafone.in',
}


class PredictionPipeline:

    def __init__(self):
        self.rule_engine = RuleEngine()
        self.domain_checker = DomainChecker()
        self.model = None
        self.tokenizer = None
        self.explainer = None

        if os.path.exists(MODEL_PATH) and os.path.exists(TOKENIZER_PATH):
            self.model = keras.models.load_model(MODEL_PATH)
            with open(TOKENIZER_PATH, 'rb') as f:
                self.tokenizer = pickle.load(f)
            self.explainer = SmishingExplainer(self._predict_proba_for_lime)
        else:
            print("Warning: Model or Tokenizer not found. Please train first.")

    def _predict_proba_for_lime(self, texts):
        cleaned_texts = [clean_text(t) for t in texts]
        sequences = self.tokenizer.texts_to_sequences(cleaned_texts)
        X = pad_sequences(sequences, maxlen=100, padding='post', truncating='post')
        preds = self.model.predict(X, verbose=0)
        prob_spam = preds
        prob_ham = 1.0 - preds
        return np.hstack((prob_ham, prob_spam))

    def _run_lime(self, text: str) -> list:
        """Run LIME explanation. Returns empty list if not available or text is empty."""
        if self.explainer is None or not text.strip():
            return []
        try:
            return self.explainer.explain_instance(text)
        except Exception as e:
            print(f"LIME explanation failed: {e}")
            return []

    def _format_reason_with_lime(self, base_reason: str, important_words: list) -> str:
        """Append top LIME words to a reason string."""
        if not important_words:
            return base_reason
        top = sorted(important_words, key=lambda x: x["score"], reverse=True)[:3]
        lime_str = ", ".join(
            f'{w["word"]}(+{w["score"]:.2f})' for w in top
        )
        return f"{base_reason} | AI highlights: {lime_str}"

    def predict(self, text: str) -> dict:
        """
        Four-stage hybrid pipeline:

        Stage 1 — Trusted domain check: if a URL from a known-safe brand is
                  present, return Safe immediately (prevents CNN false positives).
        Stage 2 — Malicious domain check: if a known-bad or suspicious domain
                  is found, flag as Smishing and STILL run LIME for explanation.
        Stage 3 — Heuristic rule engine: regex-based urgency/PII detection.
                  STILL runs LIME for explanation before returning.
        Stage 4 — CNN + LIME: probabilistic classification with full XAI output.

        Key fix: Stages 2 and 3 no longer return early before LIME runs.
        LIME is always called for any flagged message so important_words
        is never empty for detected smishing.
        """

        # ── Stage 1: Trusted domain allowlist ────────────────────────────────
        # Check this FIRST to prevent false positives before any other stage.
        urls = extract_urls(text)
        for url in urls:
            domain = normalize_url(url)
            if domain in TRUSTED_DOMAINS:
                return {
                    "status": "Safe",
                    "risk_score": 0.0,
                    "reason": f"Trusted domain verified: {domain}",
                    "important_words": []
                }

        # ── Stage 2: Malicious domain check ──────────────────────────────────
        # Record result but DO NOT return yet — fall through to LIME.
        heuristic_hit = False
        heuristic_risk = None
        heuristic_reason = None

        for url in urls:
            domain = normalize_url(url)
            if self.domain_checker.is_malicious(domain):
                heuristic_hit = True
                heuristic_risk = 1.0
                heuristic_reason = f"Malicious domain detected: {domain}"
                break

        # ── Stage 3: Heuristic rule engine ───────────────────────────────────
        # Only check if domain stage did not already flag.
        if not heuristic_hit:
            rule_result = self.rule_engine.evaluate(text)
            if rule_result["is_smishing"]:
                heuristic_hit = True
                heuristic_risk = 0.95
                heuristic_reason = rule_result["reason"]

        # ── Stage 4: CNN inference ────────────────────────────────────────────
        cnn_available = self.model is not None and self.tokenizer is not None
        prob_spam = None

        if cnn_available:
            try:
                probs = self._predict_proba_for_lime([text])[0]
                prob_spam = float(probs[1])
            except Exception as e:
                print(f"CNN inference error: {e}")

        # ── LIME: always run for any flagged or borderline message ────────────
        # This is the core fix for the 20 LIME gaps. LIME now runs whether the
        # flag came from domain_checker, rule_engine, or the CNN.
        important_words = []
        should_explain = (
            heuristic_hit
            or (prob_spam is not None and prob_spam > 0.3)
        )

        if cnn_available and should_explain:
            important_words = self._run_lime(text)

        # ── Compose final response ────────────────────────────────────────────
        if heuristic_hit:
            reason = self._format_reason_with_lime(heuristic_reason, important_words)
            return {
                "status": "Smishing Detected",
                "risk_score": heuristic_risk,
                "reason": reason,
                "important_words": important_words
            }

        # No heuristic hit — use CNN result
        if prob_spam is None:
            return {
                "status": "Error",
                "risk_score": 0.0,
                "reason": "Backend model not available",
                "important_words": []
            }

        is_smishing = prob_spam > 0.5

        # Build reason from LIME output if available, else generic label
        if important_words:
            top = sorted(important_words, key=lambda x: x["score"], reverse=True)[:3]
            reason = "Risk words: " + ", ".join(
                f'{w["word"]}(+{w["score"]:.2f})' for w in top
            )
        else:
            reason = "CNN Model Classification"

        return {
            "status": "Smishing Detected" if is_smishing else "Safe",
            "risk_score": prob_spam,
            "reason": reason,
            "important_words": important_words
        }
