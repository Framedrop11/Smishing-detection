package com.example.smishingdetector;

import android.content.Context;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.Map;

/**
 * Thread-safe singleton that reads vocab.json from assets into memory.
 * Provides word -> integer index lookups matching the Keras Tokenizer.
 *
 * Keras convention:  index 0 = padding, index 1 = OOV (<OOV>).
 */
public class VocabLoader {

    private static final String VOCAB_FILENAME = "vocab.json";
    private static final int OOV_INDEX = 1;

    private static volatile VocabLoader instance;
    private final Map<String, Integer> vocab;

    private VocabLoader(Context context) {
        vocab = loadVocab(context);
    }

    /**
     * Double-checked locking singleton.
     */
    public static VocabLoader getInstance(Context context) {
        if (instance == null) {
            synchronized (VocabLoader.class) {
                if (instance == null) {
                    instance = new VocabLoader(context.getApplicationContext());
                }
            }
        }
        return instance;
    }

    private Map<String, Integer> loadVocab(Context context) {
        try {
            InputStream is = context.getAssets().open(VOCAB_FILENAME);
            InputStreamReader reader = new InputStreamReader(is, "UTF-8");
            Type type = new TypeToken<Map<String, Integer>>() {}.getType();
            Map<String, Integer> loaded = new Gson().fromJson(reader, type);
            reader.close();
            return loaded != null ? loaded : new HashMap<>();
        } catch (Exception e) {
            e.printStackTrace();
            return new HashMap<>();
        }
    }

    /**
     * Returns the integer index for a word, or OOV_INDEX (1) if unknown.
     */
    public int getIndex(String word) {
        Integer idx = vocab.get(word);
        return idx != null ? idx : OOV_INDEX;
    }

    public int size() {
        return vocab.size();
    }
}
