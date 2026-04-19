package com.example.smishingdetector;

import android.content.Context;

/**
 * Converts raw SMS text into a fixed-length integer token array
 * suitable for the TFLite CNN model.
 *
 * Pipeline: raw text -> TextCleaner -> split on whitespace -> VocabLoader lookup
 *           -> post-pad/truncate to MAX_LENGTH=100
 *
 * Matches the Python training pipeline:
 *   clean_text() -> tokenizer.texts_to_sequences() -> pad_sequences(maxlen=100, padding='post')
 */
public class TextTokenizer {

    private static final int MAX_LENGTH = 100;

    private static volatile TextTokenizer instance;
    private final VocabLoader vocabLoader;

    private TextTokenizer(Context context) {
        vocabLoader = VocabLoader.getInstance(context);
    }

    public static TextTokenizer getInstance(Context context) {
        if (instance == null) {
            synchronized (TextTokenizer.class) {
                if (instance == null) {
                    instance = new TextTokenizer(context.getApplicationContext());
                }
            }
        }
        return instance;
    }

    /**
     * Tokenize raw text into a post-padded int[100] array.
     */
    public int[] tokenize(String rawText) {
        // Step 1: Clean text (exact match to Python clean_text())
        String cleaned = TextCleaner.cleanText(rawText);

        // Step 2: Split on whitespace
        String[] words;
        if (cleaned.isEmpty()) {
            words = new String[0];
        } else {
            words = cleaned.split("\\s+");
        }

        // Step 3: Map words to integer indices
        int[] tokens = new int[MAX_LENGTH]; // initialized to 0 (padding)

        int len = Math.min(words.length, MAX_LENGTH);
        for (int i = 0; i < len; i++) {
            tokens[i] = vocabLoader.getIndex(words[i]);
        }
        // Remaining positions are already 0 (post-padding)

        return tokens;
    }

    /**
     * Get the VocabLoader (needed by ExplainabilityEngine).
     */
    public VocabLoader getVocabLoader() {
        return vocabLoader;
    }
}
