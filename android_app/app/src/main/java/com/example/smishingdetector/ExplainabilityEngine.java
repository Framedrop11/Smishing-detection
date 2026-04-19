package com.example.smishingdetector;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * Native Leave-One-Out Perturbation engine replacing Python LIME.
 *
 * Algorithm:
 * 1. Clean and tokenize the original message → get base prediction P_original
 * 2. For each word in the cleaned message:
 *    a. Remove that word
 *    b. Re-tokenize the modified text
 *    c. Re-predict → P_without_word
 *    d. importance = P_original - P_without_word
 * 3. Return top 5 words with importance > 0, sorted descending
 */
public class ExplainabilityEngine {

    private static final int TOP_K = 5;

    private final TFLiteManager model;
    private final TextTokenizer tokenizer;

    public ExplainabilityEngine(TFLiteManager model, TextTokenizer tokenizer) {
        this.model = model;
        this.tokenizer = tokenizer;
    }

    /**
     * Explain which words contribute most to the spam prediction.
     *
     * @param rawText       The original raw SMS text
     * @param originalScore The spam probability from the full message
     * @return List of important words sorted by contribution, max TOP_K
     */
    public List<ImportantWord> explain(String rawText, float originalScore) {
        // Clean the text the same way the tokenizer does
        String cleaned = TextCleaner.cleanText(rawText);
        if (cleaned.isEmpty()) return Collections.emptyList();

        String[] words = cleaned.split("\\s+");
        if (words.length == 0) return Collections.emptyList();

        List<ImportantWord> scores = new ArrayList<>();

        for (int i = 0; i < words.length; i++) {
            // Build text with word[i] removed
            StringBuilder sb = new StringBuilder();
            for (int j = 0; j < words.length; j++) {
                if (j == i) continue;
                if (sb.length() > 0) sb.append(' ');
                sb.append(words[j]);
            }

            String perturbedText = sb.toString();

            // Re-tokenize and re-predict
            int[] tokens = tokenizer.tokenize(perturbedText);
            float newScore = model.predict(tokens);

            float importance = originalScore - newScore;

            if (importance > 0) {
                scores.add(new ImportantWord(words[i], importance));
            }
        }

        // Sort by importance descending
        Collections.sort(scores, new Comparator<ImportantWord>() {
            @Override
            public int compare(ImportantWord a, ImportantWord b) {
                return Float.compare(b.score, a.score);
            }
        });

        // Return top K
        if (scores.size() > TOP_K) {
            return scores.subList(0, TOP_K);
        }
        return scores;
    }

    /**
     * Data class for a word and its importance score.
     */
    public static class ImportantWord {
        public final String word;
        public final float score;

        public ImportantWord(String word, float score) {
            this.word = word;
            this.score = score;
        }
    }
}
