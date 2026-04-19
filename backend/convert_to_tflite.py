"""
Convert the Keras CNN model to TensorFlow Lite format for on-device inference.
"""
import os
import tensorflow as tf
import tf_keras as keras

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(SCRIPT_DIR, "model", "smishing_cnn.keras")
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "..", "android_app", "app", "src", "main", "assets")
OUTPUT_PATH = os.path.join(OUTPUT_DIR, "model.tflite")

def convert():
    # Ensure output directory exists
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print(f"Loading Keras model from {MODEL_PATH}...")
    model = keras.models.load_model(MODEL_PATH)
    model.summary()

    print("Converting to TFLite...")
    converter = tf.lite.TFLiteConverter.from_keras_model(model)
    tflite_model = converter.convert()

    with open(OUTPUT_PATH, 'wb') as f:
        f.write(tflite_model)

    size_kb = os.path.getsize(OUTPUT_PATH) / 1024
    print(f"TFLite model saved to {OUTPUT_PATH} ({size_kb:.1f} KB)")

if __name__ == "__main__":
    convert()
