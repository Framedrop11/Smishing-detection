from lime.lime_text import LimeTextExplainer
import numpy as np

class SmishingExplainer:
    def __init__(self, predict_func):
        """
        predict_func is a function that takes a list of strings
        and returns a numpy array of shape (n_samples, 2) giving 
        the probability of [ham, spam].
        """
        self.explainer = LimeTextExplainer(class_names=['Ham', 'Spam'])
        self.predict_func = predict_func
        
    def explain_instance(self, text: str, num_features=5):
        """
        Returns the top contributing words for 'Spam' class (class index 1).
        """
        if not text.strip():
            return []
            
        exp = self.explainer.explain_instance(text, self.predict_func, num_features=num_features)
        
        important_words = []
        for word, weight in exp.as_list():
            if weight > 0:
                important_words.append({"word": word, "score": float(weight)})
                
        return important_words
