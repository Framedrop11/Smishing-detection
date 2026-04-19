import tensorflow as tf
from tf_keras.models import Sequential
from tf_keras.layers import Embedding, Conv1D, Dense, GlobalMaxPooling1D

def build_cnn_model(vocab_size: int, embedding_dim: int, max_length: int) -> Sequential:
    """
    Builds the CNN model for text classification.
    Architecture: Embedding -> Conv1D -> ReLU -> MaxPooling -> Dense -> Sigmoid
    """
    model = Sequential([
        Embedding(input_dim=vocab_size, output_dim=embedding_dim, input_length=max_length),
        Conv1D(filters=64, kernel_size=5, padding='valid', activation='relu'),
        GlobalMaxPooling1D(),
        Dense(32, activation='relu'),
        Dense(1, activation='sigmoid') # Binary classification
    ])
    
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    return model
