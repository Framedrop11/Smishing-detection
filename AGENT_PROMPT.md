# Smishing Detection — Offline Migration Agent Prompt

**Role & Context:**
You are an expert Senior Android Developer specializing in On-Device Machine Learning and Python-to-Mobile model conversion. You have deep expertise in TensorFlow Lite, Java Android development, and text-classification NLP pipelines.

**Project Location:** `f:\Sem 6\R&D\Project\Final Project`

---

## Project Overview

We have a working **SMS Phishing (Smishing) Detection Engine** split into two parts:

1. **Android App** (`android_app/`): Java-based app that intercepts incoming SMS via `SmsReceiver.java`, sends the raw text over HTTP to a Python backend, and shows a warning notification if phishing is detected.
2. **Python Backend** (`backend/`): A FastAPI server running a Keras CNN model (`smishing_cnn.keras`) with a LIME explainer, heuristic rule engine, and domain checker.

**The Goal:** Completely eliminate the Python backend and network layer. Move ALL inference, preprocessing, heuristics, and explainability logic onto the Android device so the app runs 100% offline with zero data leakage. The user's private SMS messages must **never leave the device**.

---

## Existing Backend Architecture (What You Must Port)

### Model Details (`backend/model/`)
- **Architecture**: `Embedding(10000, 50, input_length=100) → Conv1D(64, kernel=5, relu) → GlobalMaxPooling1D → Dense(32, relu) → Dense(1, sigmoid)`
- **Output**: Single float (sigmoid) — probability of spam. Threshold: `> 0.5 = spam`.
- **Training file**: `backend/model/ml_train.py`
- **Saved model**: `backend/model/smishing_cnn.keras`
- **Saved tokenizer**: `backend/model/tokenizer.pkl` (Python pickle of `tf_keras.preprocessing.text.Tokenizer`)

### Critical Training Parameters (from `ml_train.py`)
```
MAX_VOCAB_SIZE = 10000
MAX_LENGTH = 100
EMBEDDING_DIM = 50
padding = 'post'
truncating = 'post'
OOV_TOKEN = '<OOV>'
```

### Text Preprocessing (`backend/preprocessing/text_processor.py`)
The `clean_text()` function does exactly this, in order:
1. Strip zero-width Unicode characters: `\u200b`, `\u200c`, `\u200d`, `\u200e`, `\u200f`, `\ufeff`, `\u00ad`
2. NFKC Unicode normalization
3. Lowercase
4. Replace `[^a-z\s]` with space
5. Collapse multiple spaces
6. Trim

### URL Processing (`backend/preprocessing/url_processor.py`)
- `extract_urls()`: regex `(https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:\/[^\s]*)?)` with trailing punctuation strip
- `normalize_url()`: Uses `tldextract` to get registrable domain (eTLD+1). For Android, implement a simpler version: strip scheme, strip `www.`, take hostname.

### Heuristic Rule Engine (`backend/heuristics/rule_engine.py`)
Checks in order, returns on first match:
1. **Shortened URL detection**: bit.ly, tinyurl.com, is.gd, goo.gl, t.co, ow.ly
2. **13 Urgency regex patterns**: `\burgent\b`, `\bverif(y|ication|ied)\b`, `\bclick\s+now\b`, `\baccount\b.{0,20}\bsuspended\b`, `\bbeen\s+suspended\b`, `\baction\s+required\b`, `\bwinner\b`, `\bwon\b`, `\bclaim\s+your\s+prize\b`, `\bimmediate\s+action\b`, `\bsecurity\s+alert\b`, `\bupdate\s+now\b`, `\bpassword\s+reset\b`
3. **10 PII harvesting regex patterns**: `\bdate\s+of\s+birth\b`, `\bcard\b.{0,15}\bnumber\b`, `\bcredit\s+card\b`, `\bdebit\s+card\b`, `\bsocial\s+security\b`, `\baccount\s+number\b`, `\bsort\s+code\b`, `\bcvv\b|\bcvc\b`, `\bfull\s+name\b.{0,40}\bdate\s+of\s+birth\b`, `\bpin\s+(number|code)\b`
4. **Multiple suspicious phone numbers** (≥2 matches)

### Domain Checker (`backend/heuristics/domain_checker.py`)
- **Known malicious domains**: `free-iphone-winner.com`, `login-paypal-verify.com`, `update-your-bank.us`, `secure-msg.net`, `parcel-track.xyz`, `prize-claim.ml`, `bit.ly`, `tinyurl.com`, `t.co`, `goo.gl`, `ow.ly`, `is.gd`
- **Malicious TLDs**: `.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.xyz`, `.top`, `.click`, `.loan`, `.work`, `.us`
- **Homograph detection**: Confusable mapping (`0→o, 1→l, 3→e, 4→a, 5→s, 6→g, 7→t, 8→b, |→l, @→a`), checks if normalized domain matches known brands: paypal, amazon, google, apple, microsoft, netflix, facebook, instagram, whatsapp, twitter, hsbc, barclays, lloyds, natwest, santander, hdfc, sbi, icici, axis, kotak, fedex, dhl, ups, usps, royalmail

### Trusted Domain Allowlist (`backend/inference/predict_pipeline.py`)
Messages containing URLs from these domains are immediately classified as Safe:
```
amazon.com, amazon.in, amazon.co.uk, amazon.de, flipkart.com, myntra.com, meesho.com,
hdfcbank.com, sbi.co.in, icicibank.com, axisbank.com, kotakbank.com, paytm.com, phonepe.com,
hsbc.com, barclays.co.uk, lloydsbank.com, natwest.com, santander.co.uk, chase.com, bankofamerica.com,
netflix.com, primevideo.com, hotstar.com, google.com, apple.com, microsoft.com,
linkedin.com, twitter.com, instagram.com, fedex.com, dhl.com, ups.com, usps.com, royalmail.com,
jio.com, airtel.in, vodafone.in
```

### Four-Stage Prediction Pipeline (`backend/inference/predict_pipeline.py`)
```
Stage 1: Trusted domain check → if match, return Safe immediately
Stage 2: Malicious domain check → flag (risk=1.0) but don't return yet
Stage 3: Heuristic rule engine → flag (risk=0.95) but don't return yet
Stage 4: CNN inference → get probability
Then: If flagged (Stage 2/3 or CNN > 0.3), run Explainability
Finally: Compose response with status, risk_score, reason, important_words
```

### LIME Explainer (`backend/inference/lime_explainer.py`)
Returns top words that contribute positively to the "Spam" classification. For the native Android port, implement **Leave-One-Out Perturbation** instead:
- For each word in the message, remove it, re-tokenize, re-predict
- `importance = original_probability - probability_without_word`
- Return top 5 words with `importance > 0`, sorted descending

---

## Your Tasks (Execute in Order)

### Task 1: Python Asset Conversion Scripts

**1a. Create `backend/convert_to_tflite.py`:**
```python
import tensorflow as tf
import tf_keras as keras

model = keras.models.load_model('backend/model/smishing_cnn.keras')
converter = tf.lite.TFLiteConverter.from_keras_model(model)
tflite_model = converter.convert()
with open('android_app/app/src/main/assets/model.tflite', 'wb') as f:
    f.write(tflite_model)
```

**1b. Create `backend/export_vocab.py`:**
```python
import pickle, json

with open('backend/model/tokenizer.pkl', 'rb') as f:
    tokenizer = pickle.load(f)

# word_index is already sorted by frequency (most frequent = lowest index)
# Keras reserves index 0 for padding, index 1 for OOV
vocab = {word: idx for word, idx in tokenizer.word_index.items() if idx < 10000}
vocab['<OOV>'] = 1  # ensure OOV token exists

with open('android_app/app/src/main/assets/vocab.json', 'w') as f:
    json.dump(vocab, f)
```

**1c. Run both scripts** to generate `model.tflite` and `vocab.json` in `android_app/app/src/main/assets/`.

### Task 2: Update Android Dependencies

**2a. Update `android_app/app/build.gradle`:**
- Add `implementation 'org.tensorflow:tensorflow-lite:2.14.0'`
- Add `implementation 'com.google.code.gson:gson:2.10.1'`
- Add `aaptOptions { noCompress "tflite" }` inside the `android` block

### Task 3: Create Native Java Classes

All under `android_app/app/src/main/java/com/example/smishingdetector/`:

**3a. `TextCleaner.java`** — Exact port of `text_processor.py`'s `clean_text()`.

**3b. `VocabLoader.java`** — Singleton that reads `assets/vocab.json` into `HashMap<String, Integer>`. Method `int getIndex(String word)` returns the word's index or 1 (OOV).

**3c. `TextTokenizer.java`** — Uses TextCleaner + VocabLoader. Method `int[] tokenize(String rawText)` returns a post-padded `int[100]` array.

**3d. `TFLiteManager.java`** — Singleton wrapping the TFLite `Interpreter`. Method `float predict(int[] tokens)` returns spam probability (0.0-1.0). Input shape `[1][100]`, output shape `[1][1]`.

**3e. `HeuristicEngine.java`** — Ports ALL rules from `rule_engine.py` + `domain_checker.py` + the trusted domain allowlist. Methods:
- `boolean isTrustedDomain(String text)` — Stage 1
- `HeuristicResult checkMaliciousDomain(String text)` — Stage 2
- `HeuristicResult evaluateRules(String text)` — Stage 3
Returns `{ boolean isSmishing, float riskScore, String reason }`

**3f. `ExplainabilityEngine.java`** — Leave-One-Out perturbation. Method `List<ImportantWord> explain(String text, float originalScore)`. Each `ImportantWord` has `String word` and `double score`.

### Task 4: Rewrite `ApiService.java`

**Completely strip all HTTP/network code.** Replace with:

```java
public static void analyzeSms(Context context, String message, SmsCallback callback) {
    new Thread(() -> {
        try {
            HeuristicEngine heuristics = HeuristicEngine.getInstance(context);
            
            // Stage 1: Trusted domain
            if (heuristics.isTrustedDomain(message)) {
                callback.onResult("Safe", 0.0, "Trusted domain verified");
                return;
            }
            
            // Stage 2: Malicious domain
            HeuristicResult domainResult = heuristics.checkMaliciousDomain(message);
            
            // Stage 3: Rule engine  
            HeuristicResult ruleResult = null;
            if (!domainResult.isSmishing) {
                ruleResult = heuristics.evaluateRules(message);
            }
            
            // Stage 4: CNN
            TFLiteManager model = TFLiteManager.getInstance(context);
            TextTokenizer tokenizer = TextTokenizer.getInstance(context);
            int[] tokens = tokenizer.tokenize(message);
            float probSpam = model.predict(tokens);
            
            // Determine if we should explain
            boolean heuristicHit = domainResult.isSmishing || 
                                   (ruleResult != null && ruleResult.isSmishing);
            boolean shouldExplain = heuristicHit || probSpam > 0.3;
            
            List<ImportantWord> importantWords = new ArrayList<>();
            if (shouldExplain) {
                ExplainabilityEngine xai = new ExplainabilityEngine(model, tokenizer);
                importantWords = xai.explain(message, probSpam);
            }
            
            // Compose response
            if (heuristicHit) {
                float risk = domainResult.isSmishing ? 1.0f : 0.95f;
                String reason = domainResult.isSmishing ? domainResult.reason : ruleResult.reason;
                // Append XAI words to reason
                reason = appendXaiWords(reason, importantWords);
                callback.onResult("Smishing Detected", risk, reason);
            } else if (probSpam > 0.5) {
                String reason = formatXaiReason(importantWords);
                callback.onResult("Smishing Detected", probSpam, reason);
            } else {
                callback.onResult("Safe", probSpam, "CNN Model Classification");
            }
        } catch (Exception e) {
            callback.onResult("Error", 0.0, "Analysis failed: " + e.getMessage());
        }
    }).start();
}
```

### Task 5: Update `SmsReceiver.java`

Change the call from:
```java
ApiService.analyzeSms(message, callback);
```
To:
```java
ApiService.analyzeSms(context, message, callback);
```

### Task 6: AndroidManifest.xml Cleanup

- **Remove**: `android.permission.INTERNET`  
- **Remove**: `android:usesCleartextTraffic="true"`
- Keep: `RECEIVE_SMS`, `READ_SMS`, `POST_NOTIFICATIONS`

---

## STRICT CONSTRAINTS

1. **NO network requests.** Zero HTTP calls, no Retrofit, no HttpURLConnection, no OkHttp. The app must work in airplane mode.
2. **Exact text preprocessing match.** The Java `TextCleaner` must produce identical output to `text_processor.py`'s `clean_text()` for the model to work correctly.
3. **Post-padding with zeros to length 100.** Not 120. Not pre-padding. The model was trained with `pad_sequences(maxlen=100, padding='post')`.
4. **Sigmoid output** — the model outputs `float[1][1]`, NOT `float[1][3]`. This is binary classification (ham vs spam), not 3-class.
5. **OOV index = 1** (Keras convention with `oov_token='<OOV>'`).
6. **Thread safety** — all TFLite and VocabLoader instances must be singletons, initialized lazily, thread-safe.
7. **Background thread** — all inference and XAI work runs on `new Thread()` to never block the main/UI thread.

---

## Verification

After implementation:
1. Run `convert_to_tflite.py` and `export_vocab.py` — verify `model.tflite` and `vocab.json` exist in `assets/`
2. Build: `./gradlew assembleDebug` — must succeed
3. Test on emulator in **airplane mode**:
   - Send `"Urgent! Claim your prize at bit.ly/123"` → expect "Smishing Detected" notification with AI highlights
   - Send `"Your Amazon order has shipped"` → expect "Safe"
   - Send `"Hey, are we still meeting for lunch?"` → expect "Safe"
   - Send `"Verify your identity at paypa1.com/secure"` → expect "Smishing Detected" (homograph detection)
