package com.example.smishingdetector;

import android.content.Context;
import android.util.Log;

import org.tensorflow.lite.Interpreter;

import java.io.FileInputStream;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;

/**
 * Thread-safe singleton wrapping the TFLite Interpreter.
 *
 * Model shape:
 *   Input:  int[1][100]   (batch=1, sequence_length=100)
 *   Output: float[1][1]   (sigmoid probability of spam)
 */
public class TFLiteManager {

    private static final String TAG = "TFLiteManager";
    private static final String MODEL_FILENAME = "model.tflite";

    private static volatile TFLiteManager instance;
    private Interpreter interpreter;

    private TFLiteManager(Context context) {
        try {
            MappedByteBuffer modelBuffer = loadModelFile(context);
            interpreter = new Interpreter(modelBuffer);
            Log.i(TAG, "TFLite model loaded successfully");
        } catch (Exception e) {
            Log.e(TAG, "Error loading TFLite model", e);
            interpreter = null;
        }
    }

    public static TFLiteManager getInstance(Context context) {
        if (instance == null) {
            synchronized (TFLiteManager.class) {
                if (instance == null) {
                    instance = new TFLiteManager(context.getApplicationContext());
                }
            }
        }
        return instance;
    }

    private MappedByteBuffer loadModelFile(Context context) throws Exception {
        android.content.res.AssetFileDescriptor afd = context.getAssets().openFd(MODEL_FILENAME);
        FileInputStream fis = new FileInputStream(afd.getFileDescriptor());
        FileChannel fileChannel = fis.getChannel();
        long startOffset = afd.getStartOffset();
        long declaredLength = afd.getDeclaredLength();
        return fileChannel.map(FileChannel.MapMode.READ_ONLY, startOffset, declaredLength);
    }

    /**
     * Run inference on a tokenized input array.
     *
     * @param tokens int[100] — post-padded token indices
     * @return spam probability (0.0 to 1.0)
     */
    public float predict(int[] tokens) {
        if (interpreter == null) {
            Log.e(TAG, "Model not loaded — returning 0");
            return 0f;
        }

        // Input: [1][100] — TFLite Embedding expects FLOAT32 even for token indices
        float[][] input = new float[1][100];
        for (int i = 0; i < Math.min(tokens.length, 100); i++) {
            input[0][i] = (float) tokens[i];
        }

        // Output: [1][1]
        float[][] output = new float[1][1];

        long start = System.currentTimeMillis();
        interpreter.run(input, output);
        long elapsed = System.currentTimeMillis() - start;

        Log.d(TAG, "Inference: " + elapsed + "ms, prob=" + output[0][0]);

        return output[0][0];
    }

    public boolean isModelLoaded() {
        return interpreter != null;
    }
}
