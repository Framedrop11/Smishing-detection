package com.example.smishingdetector;

import java.util.List;

/**
 * Crafts human-friendly, educational awareness messages from raw
 * analysis data + XAI (Leave-One-Out) explainability results.
 *
 * Instead of showing cryptic technical output like
 *   "Urgency keyword detected: 'urgent' | AI highlights: claim(+0.18), prize(+0.12)"
 * the user sees:
 *   "This message was flagged because it uses pressure tactics like 'urgent'
 *    to make you act without thinking. Our AI also found that the words
 *    'claim' and 'prize' are strong indicators of a phishing attempt.
 *    Tip: Legitimate organisations never rush you into clicking a link."
 */
public class AlertMessageBuilder {

    /**
     * Build a complete user-facing awareness message.
     *
     * @param status          "Smishing Detected", "Safe", or "Error"
     * @param riskScore       0.0 – 1.0
     * @param technicalReason Raw reason string from the pipeline
     * @param importantWords  XAI Leave-One-Out results (may be empty)
     * @return A structured, human-readable alert string
     */
    public static String buildAlert(String status, double riskScore,
                                     String technicalReason,
                                     List<ExplainabilityEngine.ImportantWord> importantWords) {

        if ("Safe".equals(status)) {
            return buildSafeMessage(riskScore, technicalReason);
        } else if ("Smishing Detected".equals(status)) {
            return buildDangerMessage(riskScore, technicalReason, importantWords);
        } else {
            return "Analysis could not be completed. Please try again.";
        }
    }

    // ── SAFE message ────────────────────────────────────────────────────────

    private static String buildSafeMessage(double riskScore, String reason) {
        StringBuilder sb = new StringBuilder();

        sb.append("This message appears to be safe.");

        if (reason != null && reason.contains("Trusted domain")) {
            sb.append("\n\nThe message contains a link to a verified, trusted domain. ")
              .append("Our system recognised it as a legitimate source.");
        } else {
            sb.append("\n\nOur AI model analysed the text and found no suspicious patterns. ")
              .append("The risk score is very low (")
              .append(String.format("%.0f%%", riskScore * 100))
              .append(").");
        }

        sb.append("\n\nTip: Always stay cautious with messages that ask for personal information, ")
          .append("even if they appear safe.");

        return sb.toString();
    }

    // ── DANGER message ──────────────────────────────────────────────────────

    private static String buildDangerMessage(double riskScore, String technicalReason,
                                              List<ExplainabilityEngine.ImportantWord> xaiWords) {
        StringBuilder sb = new StringBuilder();

        // ── Header: severity level ──
        if (riskScore >= 0.9) {
            sb.append("HIGH RISK — This message is very likely a phishing attempt.");
        } else if (riskScore >= 0.7) {
            sb.append("ELEVATED RISK — This message shows strong signs of a scam.");
        } else {
            sb.append("SUSPICIOUS — This message contains patterns commonly used in scams.");
        }

        // ── WHY it was flagged (from heuristic reason) ──
        sb.append("\n\nWhy was this flagged?\n");
        sb.append(explainReason(technicalReason));

        // ── XAI word explanations ──
        if (xaiWords != null && !xaiWords.isEmpty()) {
            sb.append("\n\nAI Word Analysis:\n");
            sb.append("Our AI examined each word in the message. ");
            sb.append("Removing these words caused the biggest drop in the threat score, ");
            sb.append("confirming they are key indicators of a phishing attempt:\n");

            for (int i = 0; i < Math.min(xaiWords.size(), 5); i++) {
                ExplainabilityEngine.ImportantWord w = xaiWords.get(i);
                sb.append("\n  • \"").append(w.word).append("\"");
                sb.append(" — contributes ").append(String.format("%.0f%%", w.score * 100));
                sb.append(" to the threat score");
            }
        }

        // ── Safety tips ──
        sb.append("\n\nWhat you should do:\n");
        sb.append(getSafetyTips(technicalReason));

        return sb.toString();
    }

    // ── Human-readable reason translator ────────────────────────────────────

    private static String explainReason(String reason) {
        if (reason == null || reason.isEmpty()) {
            return "Our AI model detected suspicious language patterns in this message.";
        }

        String lower = reason.toLowerCase();
        StringBuilder sb = new StringBuilder();

        // Malicious domain
        if (lower.contains("malicious domain")) {
            sb.append("The link in this message points to a known malicious website ")
              .append("that has been reported for phishing or scam activity.");
        }
        // Homograph attack
        else if (lower.contains("homograph")) {
            sb.append("The link in this message uses look-alike characters to impersonate ")
              .append("a trusted brand (e.g., using '1' instead of 'l', or '0' instead of 'o'). ")
              .append("This is a common trick called a homograph attack.");
        }
        // Shortened URL
        else if (lower.contains("shortened url")) {
            sb.append("This message contains a shortened URL (like bit.ly) which hides ")
              .append("the real destination. Scammers use URL shorteners to disguise ")
              .append("malicious links.");
        }
        // Urgency keywords
        else if (lower.contains("urgency")) {
            String keyword = extractQuoted(reason);
            sb.append("This message uses pressure tactics");
            if (keyword != null) {
                sb.append(" like '").append(keyword).append("'");
            }
            sb.append(" to make you act quickly without thinking. ")
              .append("Legitimate organisations rarely create this kind of urgency over SMS.");
        }
        // PII harvesting
        else if (lower.contains("pii") || lower.contains("harvesting")) {
            String keyword = extractQuoted(reason);
            sb.append("This message is attempting to collect your personal information");
            if (keyword != null) {
                sb.append(" (").append(keyword).append(")");
            }
            sb.append(". Sharing sensitive details like card numbers, PINs, or dates of birth ")
              .append("via SMS is extremely dangerous.");
        }
        // Phone numbers
        else if (lower.contains("phone number")) {
            sb.append("This message contains multiple suspicious phone numbers, ")
              .append("which is a common pattern in scam campaigns that try to ")
              .append("redirect you to fraudulent call centres.");
        }
        // CNN model classification (no heuristic hit, pure model)
        else if (lower.contains("risk words") || lower.contains("cnn")) {
            sb.append("Our AI model detected language patterns that are statistically ")
              .append("associated with phishing messages.");
        }
        // Default
        else {
            sb.append(reason);
        }

        return sb.toString();
    }

    // ── Context-aware safety tips ───────────────────────────────────────────

    private static String getSafetyTips(String reason) {
        String lower = (reason != null) ? reason.toLowerCase() : "";
        StringBuilder sb = new StringBuilder();

        sb.append("  • Do NOT click any links in this message.\n");
        sb.append("  • Do NOT reply or share any personal details.\n");

        if (lower.contains("domain") || lower.contains("url") || lower.contains("link")) {
            sb.append("  • If you need to visit the site, type the URL directly in your browser.\n");
            sb.append("  • Check for subtle character tricks in the URL (e.g., paypa1.com vs paypal.com).\n");
        }
        if (lower.contains("pii") || lower.contains("card") || lower.contains("pin") || lower.contains("harvesting")) {
            sb.append("  • Banks and services will NEVER ask for your PIN, CVV, or full card number via SMS.\n");
        }
        if (lower.contains("urgency") || lower.contains("suspend") || lower.contains("prize") || lower.contains("winner")) {
            sb.append("  • Take a moment to think — scammers rely on panic to bypass your judgement.\n");
            sb.append("  • Contact the organisation directly using their official website or app.\n");
        }

        sb.append("  • Report this number to your network provider.");

        return sb.toString();
    }

    // ── Notification summary (shorter version for system notifications) ─────

    /**
     * Build a concise notification body (max ~3 lines).
     */
    public static String buildNotificationSummary(double riskScore, String reason,
                                                   List<ExplainabilityEngine.ImportantWord> xaiWords) {
        StringBuilder sb = new StringBuilder();

        // Severity
        if (riskScore >= 0.9) {
            sb.append("HIGH RISK phishing attempt detected!\n");
        } else if (riskScore >= 0.7) {
            sb.append("Suspicious message detected.\n");
        } else {
            sb.append("Potentially unsafe message detected.\n");
        }

        // Short reason
        sb.append(explainReasonShort(reason));

        // Top XAI word
        if (xaiWords != null && !xaiWords.isEmpty()) {
            sb.append("\nKey word: \"").append(xaiWords.get(0).word).append("\"");
        }

        return sb.toString();
    }

    private static String explainReasonShort(String reason) {
        if (reason == null) return "";
        String lower = reason.toLowerCase();

        if (lower.contains("malicious domain")) return "Contains a known malicious link.";
        if (lower.contains("homograph")) return "Link impersonates a trusted brand.";
        if (lower.contains("shortened url")) return "Uses a hidden/shortened link.";
        if (lower.contains("urgency")) return "Uses pressure tactics to rush you.";
        if (lower.contains("pii") || lower.contains("harvesting")) return "Tries to steal your personal data.";
        if (lower.contains("phone number")) return "Contains suspicious phone numbers.";
        return "AI detected phishing language patterns.";
    }

    // ── Utility ─────────────────────────────────────────────────────────────

    /** Extract a quoted keyword like 'urgent' from a reason string. */
    private static String extractQuoted(String text) {
        int start = text.indexOf('\'');
        if (start >= 0) {
            int end = text.indexOf('\'', start + 1);
            if (end > start) {
                return text.substring(start + 1, end);
            }
        }
        return null;
    }
}
