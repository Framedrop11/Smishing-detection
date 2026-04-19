package com.example.smishingdetector;

import java.text.Normalizer;
import java.util.regex.Pattern;

/**
 * Exact port of backend/preprocessing/text_processor.py's clean_text().
 * The cleaning steps MUST match the Python pipeline exactly for the
 * TFLite model to produce correct predictions.
 */
public class TextCleaner {

    // Zero-width and invisible Unicode characters commonly injected to evade regex
    private static final Pattern ZERO_WIDTH = Pattern.compile(
            "[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad]"
    );

    // Keep only a-z and whitespace
    private static final Pattern NON_ALPHA = Pattern.compile("[^a-z\\s]");

    // Collapse multiple spaces
    private static final Pattern MULTI_SPACE = Pattern.compile("\\s+");

    /**
     * Clean text for CNN input, replicating the Python pipeline exactly:
     * 1. Strip zero-width / invisible Unicode characters
     * 2. NFKC Unicode normalisation
     * 3. Lowercase
     * 4. Remove everything except a-z and spaces
     * 5. Collapse multiple spaces
     * 6. Trim
     */
    public static String cleanText(String text) {
        if (text == null) return "";

        // Step 1: Remove zero-width characters
        text = ZERO_WIDTH.matcher(text).replaceAll("");

        // Step 2: NFKC Unicode normalisation (e.g. fullwidth letters -> ASCII)
        text = Normalizer.normalize(text, Normalizer.Form.NFKC);

        // Step 3: Lowercase
        text = text.toLowerCase();

        // Step 4: Remove non-alphabetic characters
        text = NON_ALPHA.matcher(text).replaceAll(" ");

        // Step 5: Collapse spaces
        text = MULTI_SPACE.matcher(text).replaceAll(" ");

        // Step 6: Trim
        return text.trim();
    }
}
