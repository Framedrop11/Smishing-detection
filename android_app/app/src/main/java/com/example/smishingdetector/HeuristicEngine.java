package com.example.smishingdetector;

import android.content.Context;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Complete port of the Python backend's heuristic pipeline:
 *   - backend/heuristics/rule_engine.py
 *   - backend/heuristics/domain_checker.py
 *   - backend/inference/predict_pipeline.py (trusted domain allowlist)
 *   - backend/preprocessing/url_processor.py (URL extraction / normalisation)
 */
public class HeuristicEngine {

    private static volatile HeuristicEngine instance;

    // ── URL extraction regex (from url_processor.py) ────────────────────────
    private static final Pattern URL_REGEX = Pattern.compile(
            "(https?://[^\\s]+|www\\.[^\\s]+|[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}(?:/[^\\s]*)?)",
            Pattern.CASE_INSENSITIVE
    );

    // ── Trusted domain allowlist (Stage 1) ──────────────────────────────────
    private static final Set<String> TRUSTED_DOMAINS = new HashSet<>(Arrays.asList(
            "amazon.com", "amazon.in", "amazon.co.uk", "amazon.de",
            "flipkart.com", "myntra.com", "meesho.com",
            "hdfcbank.com", "sbi.co.in", "icicibank.com", "axisbank.com",
            "kotakbank.com", "paytm.com", "phonepe.com",
            "hsbc.com", "barclays.co.uk", "lloydsbank.com", "natwest.com",
            "santander.co.uk", "chase.com", "bankofamerica.com",
            "netflix.com", "primevideo.com", "hotstar.com",
            "google.com", "apple.com", "microsoft.com",
            "linkedin.com", "twitter.com", "instagram.com",
            "fedex.com", "dhl.com", "ups.com", "usps.com", "royalmail.com",
            "jio.com", "airtel.in", "vodafone.in"
    ));

    // ── Known malicious domains (Stage 2) ───────────────────────────────────
    private static final Set<String> MALICIOUS_DOMAINS = new HashSet<>(Arrays.asList(
            "free-iphone-winner.com", "login-paypal-verify.com",
            "update-your-bank.us", "secure-msg.net",
            "parcel-track.xyz", "prize-claim.ml",
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"
    ));

    private static final String[] MALICIOUS_TLDS = {
            ".tk", ".ml", ".ga", ".cf", ".gq",
            ".xyz", ".top", ".click", ".loan", ".work", ".us"
    };

    // ── Homograph detection (Stage 2) ───────────────────────────────────────
    private static final Map<Character, Character> CONFUSABLES = new HashMap<>();
    static {
        CONFUSABLES.put('0', 'o');
        CONFUSABLES.put('1', 'l');
        CONFUSABLES.put('3', 'e');
        CONFUSABLES.put('4', 'a');
        CONFUSABLES.put('5', 's');
        CONFUSABLES.put('6', 'g');
        CONFUSABLES.put('7', 't');
        CONFUSABLES.put('8', 'b');
        CONFUSABLES.put('|', 'l');
        CONFUSABLES.put('@', 'a');
    }

    private static final Set<String> BRAND_DOMAINS = new HashSet<>(Arrays.asList(
            "paypal", "amazon", "google", "apple", "microsoft",
            "netflix", "facebook", "instagram", "whatsapp", "twitter",
            "hsbc", "barclays", "lloyds", "natwest", "santander",
            "hdfc", "sbi", "icici", "axis", "kotak",
            "fedex", "dhl", "ups", "usps", "royalmail"
    ));

    // ── Shortened URL domains (Stage 3 - rule engine) ───────────────────────
    private static final Set<String> SHORT_URL_DOMAINS = new HashSet<>(Arrays.asList(
            "bit.ly", "tinyurl.com", "is.gd", "goo.gl", "t.co", "ow.ly"
    ));

    // ── Urgency patterns (Stage 3) ──────────────────────────────────────────
    private static final PatternReason[] URGENCY_PATTERNS = {
            new PatternReason(Pattern.compile("\\burgent\\b", Pattern.CASE_INSENSITIVE),
                    "Urgency keyword detected: 'urgent'"),
            new PatternReason(Pattern.compile("\\bverif(y|ication|ied)\\b", Pattern.CASE_INSENSITIVE),
                    "Urgency keyword detected: 'verify'"),
            new PatternReason(Pattern.compile("\\bclick\\s+now\\b", Pattern.CASE_INSENSITIVE),
                    "Urgency keyword detected: 'click now'"),
            new PatternReason(Pattern.compile("\\baccount\\b.{0,20}\\bsuspended\\b", Pattern.CASE_INSENSITIVE),
                    "Urgency keyword detected: 'account suspended'"),
            new PatternReason(Pattern.compile("\\bbeen\\s+suspended\\b", Pattern.CASE_INSENSITIVE),
                    "Urgency keyword detected: 'account suspended'"),
            new PatternReason(Pattern.compile("\\baction\\s+required\\b", Pattern.CASE_INSENSITIVE),
                    "Urgency keyword detected: 'action required'"),
            new PatternReason(Pattern.compile("\\bwinner\\b", Pattern.CASE_INSENSITIVE),
                    "Urgency keyword detected: 'winner'"),
            new PatternReason(Pattern.compile("\\bwon\\b", Pattern.CASE_INSENSITIVE),
                    "Urgency keyword detected: 'won'"),
            new PatternReason(Pattern.compile("\\bclaim\\s+your\\s+prize\\b", Pattern.CASE_INSENSITIVE),
                    "Urgency keyword detected: 'claim your prize'"),
            new PatternReason(Pattern.compile("\\bimmediate\\s+action\\b", Pattern.CASE_INSENSITIVE),
                    "Urgency keyword detected: 'immediate action'"),
            new PatternReason(Pattern.compile("\\bsecurity\\s+alert\\b", Pattern.CASE_INSENSITIVE),
                    "Urgency keyword detected: 'security alert'"),
            new PatternReason(Pattern.compile("\\bupdate\\s+now\\b", Pattern.CASE_INSENSITIVE),
                    "Urgency keyword detected: 'update now'"),
            new PatternReason(Pattern.compile("\\bpassword\\s+reset\\b", Pattern.CASE_INSENSITIVE),
                    "Urgency keyword detected: 'password reset'"),
    };

    // ── PII harvesting patterns (Stage 3) ───────────────────────────────────
    private static final PatternReason[] PII_PATTERNS = {
            new PatternReason(Pattern.compile("\\bdate\\s+of\\s+birth\\b", Pattern.CASE_INSENSITIVE),
                    "PII harvesting detected: 'date of birth'"),
            new PatternReason(Pattern.compile("\\bcard\\b.{0,15}\\bnumber\\b", Pattern.CASE_INSENSITIVE),
                    "PII harvesting detected: 'card number'"),
            new PatternReason(Pattern.compile("\\bcredit\\s+card\\b", Pattern.CASE_INSENSITIVE),
                    "PII harvesting detected: 'credit card'"),
            new PatternReason(Pattern.compile("\\bdebit\\s+card\\b", Pattern.CASE_INSENSITIVE),
                    "PII harvesting detected: 'debit card'"),
            new PatternReason(Pattern.compile("\\bsocial\\s+security\\b", Pattern.CASE_INSENSITIVE),
                    "PII harvesting detected: 'social security'"),
            new PatternReason(Pattern.compile("\\baccount\\s+number\\b", Pattern.CASE_INSENSITIVE),
                    "PII harvesting detected: 'account number'"),
            new PatternReason(Pattern.compile("\\bsort\\s+code\\b", Pattern.CASE_INSENSITIVE),
                    "PII harvesting detected: 'sort code'"),
            new PatternReason(Pattern.compile("\\bcvv\\b|\\bcvc\\b", Pattern.CASE_INSENSITIVE),
                    "PII harvesting detected: 'cvv'"),
            new PatternReason(Pattern.compile("\\bfull\\s+name\\b.{0,40}\\bdate\\s+of\\s+birth\\b", Pattern.CASE_INSENSITIVE),
                    "PII harvesting detected: personal data request"),
            new PatternReason(Pattern.compile("\\bpin\\s+(number|code)\\b", Pattern.CASE_INSENSITIVE),
                    "PII harvesting detected: 'PIN'"),
    };

    // ── Phone number pattern (Stage 3) ──────────────────────────────────────
    private static final Pattern PHONE_PATTERN = Pattern.compile(
            "(\\+?\\d{1,3}[\\s-]?)?\\(?\\d{3}\\)?[\\s.-]?\\d{3}[\\s.-]?\\d{4}"
    );

    // ────────────────────────────────────────────────────────────────────────

    private HeuristicEngine() { /* singleton */ }

    public static HeuristicEngine getInstance(Context context) {
        if (instance == null) {
            synchronized (HeuristicEngine.class) {
                if (instance == null) {
                    instance = new HeuristicEngine();
                }
            }
        }
        return instance;
    }

    // ── URL helpers ─────────────────────────────────────────────────────────

    private List<String> extractUrls(String text) {
        List<String> urls = new ArrayList<>();
        Matcher m = URL_REGEX.matcher(text);
        while (m.find()) {
            String url = m.group();
            // Strip trailing punctuation
            url = url.replaceAll("[.,;:!?)]+$", "");
            urls.add(url);
        }
        return urls;
    }

    /**
     * Simplified normalize_url: strip scheme, strip www., take host, lowercase.
     */
    private String normalizeUrl(String url) {
        String u = url.toLowerCase();
        u = u.replaceFirst("^https?://", "");
        u = u.replaceFirst("^www\\.", "");
        // Take the host part (before first / or ?)
        int slashIdx = u.indexOf('/');
        if (slashIdx > 0) u = u.substring(0, slashIdx);
        int qIdx = u.indexOf('?');
        if (qIdx > 0) u = u.substring(0, qIdx);
        return u;
    }

    // ── STAGE 1: Trusted domain check ───────────────────────────────────────

    public boolean isTrustedDomain(String text) {
        List<String> urls = extractUrls(text);
        for (String url : urls) {
            String domain = normalizeUrl(url);
            if (TRUSTED_DOMAINS.contains(domain)) {
                return true;
            }
        }
        return false;
    }

    // ── STAGE 2: Malicious domain check ─────────────────────────────────────

    public HeuristicResult checkMaliciousDomain(String text) {
        List<String> urls = extractUrls(text);
        for (String url : urls) {
            String domain = normalizeUrl(url);

            // Direct lookup
            if (MALICIOUS_DOMAINS.contains(domain)) {
                return new HeuristicResult(true, 1.0f, "Malicious domain detected: " + domain);
            }

            // Malicious TLD check
            for (String tld : MALICIOUS_TLDS) {
                if (domain.endsWith(tld)) {
                    return new HeuristicResult(true, 1.0f, "Malicious domain detected: " + domain);
                }
            }

            // Homograph detection
            if (isHomographAttack(domain)) {
                return new HeuristicResult(true, 1.0f, "Homograph attack detected: " + domain);
            }
        }
        return new HeuristicResult(false, 0f, "");
    }

    private boolean isHomographAttack(String domain) {
        // Extract domain root (everything before the last dot)
        int lastDot = domain.lastIndexOf('.');
        if (lastDot <= 0) return false;
        String root = domain.substring(0, lastDot);

        // If it already exactly matches a brand, it's not a homograph attack
        if (BRAND_DOMAINS.contains(root)) return false;

        // Translate confusable characters
        StringBuilder sb = new StringBuilder();
        for (char c : root.toCharArray()) {
            Character replacement = CONFUSABLES.get(c);
            sb.append(replacement != null ? replacement : c);
        }
        String normalised = sb.toString();

        return BRAND_DOMAINS.contains(normalised);
    }

    // ── STAGE 3: Heuristic rule engine ──────────────────────────────────────

    public HeuristicResult evaluateRules(String text) {
        // 1. Shortened URL detection
        List<String> urls = extractUrls(text);
        for (String url : urls) {
            String domain = normalizeUrl(url);
            if (SHORT_URL_DOMAINS.contains(domain)) {
                return new HeuristicResult(true, 0.95f, "Shortened URL detected");
            }
        }

        // 2. Urgency patterns
        for (PatternReason pr : URGENCY_PATTERNS) {
            if (pr.pattern.matcher(text).find()) {
                return new HeuristicResult(true, 0.95f, pr.reason);
            }
        }

        // 3. PII harvesting patterns
        for (PatternReason pr : PII_PATTERNS) {
            if (pr.pattern.matcher(text).find()) {
                return new HeuristicResult(true, 0.95f, pr.reason);
            }
        }

        // 4. Multiple suspicious phone numbers (>=2)
        Matcher phoneMatcher = PHONE_PATTERN.matcher(text);
        int phoneCount = 0;
        while (phoneMatcher.find()) phoneCount++;
        if (phoneCount >= 2) {
            return new HeuristicResult(true, 0.95f, "Multiple suspicious phone numbers detected");
        }

        return new HeuristicResult(false, 0f, "");
    }

    // ── Helper classes ──────────────────────────────────────────────────────

    public static class HeuristicResult {
        public final boolean isSmishing;
        public final float riskScore;
        public final String reason;

        public HeuristicResult(boolean isSmishing, float riskScore, String reason) {
            this.isSmishing = isSmishing;
            this.riskScore = riskScore;
            this.reason = reason;
        }
    }

    private static class PatternReason {
        final Pattern pattern;
        final String reason;

        PatternReason(Pattern pattern, String reason) {
            this.pattern = pattern;
            this.reason = reason;
        }
    }
}
