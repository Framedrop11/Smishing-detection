package com.example.smishingdetector;

import android.content.Context;
import android.util.Log;

import java.util.ArrayList;
import java.util.List;

/**
 * On-device SMS analysis pipeline — ZERO network requests.
 *
 * Replaces the old HTTP-based ApiService with a fully local pipeline:
 *   Stage 1: Trusted domain allowlist   → Safe immediately
 *   Stage 2: Malicious domain check     → flag (risk=1.0)
 *   Stage 3: Heuristic rule engine      → flag (risk=0.95)
 *   Stage 4: CNN (TFLite) inference     → probabilistic classification
 *   XAI:     Leave-One-Out perturbation → important_words
 *   Alert:   AlertMessageBuilder        → human-readable awareness message
 */
public class ApiService {

    private static final String TAG = "ApiService";

    /**
     * Analyse an SMS message entirely on-device.
     * Runs on a background thread and delivers results via callback.
     *
     * @param context  Application context (needed for assets access)
     * @param message  Raw SMS text
     * @param callback Results callback
     */
    public static void analyzeSms(Context context, String message, SmsCallback callback) {
        new Thread(() -> {
            try {
                HeuristicEngine heuristics = HeuristicEngine.getInstance(context);

                // ── Stage 1: Trusted domain ─────────────────────────────
                if (heuristics.isTrustedDomain(message)) {
                    String alert = AlertMessageBuilder.buildAlert(
                            "Safe", 0.0, "Trusted domain verified", null);
                    callback.onResult("Safe", 0.0, "Trusted domain verified",
                            alert, null);
                    return;
                }

                // ── Stage 2: Malicious domain ───────────────────────────
                HeuristicEngine.HeuristicResult domainResult =
                        heuristics.checkMaliciousDomain(message);

                // ── Stage 3: Rule engine (only if domain didn't flag) ───
                HeuristicEngine.HeuristicResult ruleResult = null;
                if (!domainResult.isSmishing) {
                    ruleResult = heuristics.evaluateRules(message);
                }

                // ── Stage 4: CNN inference ──────────────────────────────
                TFLiteManager model = TFLiteManager.getInstance(context);
                TextTokenizer tokenizer = TextTokenizer.getInstance(context);
                int[] tokens = tokenizer.tokenize(message);
                float probSpam = model.predict(tokens);

                Log.d(TAG, "CNN prob=" + probSpam
                        + " domainHit=" + domainResult.isSmishing
                        + " ruleHit=" + (ruleResult != null && ruleResult.isSmishing));

                // ── XAI: explain if flagged ──────────────────────────────
                boolean heuristicHit = domainResult.isSmishing
                        || (ruleResult != null && ruleResult.isSmishing);
                boolean shouldExplain = heuristicHit || probSpam > 0.3f;

                List<ExplainabilityEngine.ImportantWord> importantWords = new ArrayList<>();
                if (shouldExplain) {
                    ExplainabilityEngine xai = new ExplainabilityEngine(model, tokenizer);
                    importantWords = xai.explain(message, probSpam);
                }

                // ── Compose response + awareness message ────────────────
                if (heuristicHit) {
                    float risk = domainResult.isSmishing
                            ? domainResult.riskScore
                            : ruleResult.riskScore;
                    String reason = domainResult.isSmishing
                            ? domainResult.reason
                            : ruleResult.reason;

                    String alert = AlertMessageBuilder.buildAlert(
                            "Smishing Detected", risk, reason, importantWords);
                    callback.onResult("Smishing Detected", risk, reason,
                            alert, importantWords);

                } else if (probSpam > 0.5f) {
                    String reason = "CNN Model Classification";
                    String alert = AlertMessageBuilder.buildAlert(
                            "Smishing Detected", probSpam, reason, importantWords);
                    callback.onResult("Smishing Detected", probSpam, reason,
                            alert, importantWords);

                } else {
                    String alert = AlertMessageBuilder.buildAlert(
                            "Safe", probSpam, "CNN Model Classification", null);
                    callback.onResult("Safe", probSpam, "CNN Model Classification",
                            alert, null);
                }

            } catch (Exception e) {
                Log.e(TAG, "Analysis failed", e);
                callback.onResult("Error", 0.0, "Analysis failed: " + e.getMessage(),
                        "Analysis could not be completed. Please try again.", null);
            }
        }).start();
    }

    // ── Callback interface ──────────────────────────────────────────────────

    /**
     * @param status          "Smishing Detected", "Safe", or "Error"
     * @param riskScore       0.0 – 1.0
     * @param reason          Short technical reason (for the reason label)
     * @param alertMessage    Full human-readable awareness message from AlertMessageBuilder
     * @param importantWords  XAI word list (nullable, for notification use)
     */
    public interface SmsCallback {
        void onResult(String status, double riskScore, String reason,
                      String alertMessage,
                      List<ExplainabilityEngine.ImportantWord> importantWords);
    }
}