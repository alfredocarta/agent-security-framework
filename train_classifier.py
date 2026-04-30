import pickle
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.model_selection import cross_val_score
from training_data import TRAINING_DATA

# Load the realistic dataset
texts = [item[0] for item in TRAINING_DATA]
labels = [item[1] for item in TRAINING_DATA]

# Build the ML Pipeline: TF-IDF + Random Forest
pipeline = Pipeline([
    ("tfidf", TfidfVectorizer(ngram_range=(1, 3), max_features=1000)),
    ("clf", RandomForestClassifier(n_estimators=100, random_state=42, class_weight="balanced"))
])

# Evaluate using 5-fold cross-validation
scores = cross_val_score(pipeline, texts, labels, cv=5, scoring='f1_macro')
print(f"Cross-Validation F1 Macro Score: {np.mean(scores):.2f}")

# Train the final model on all data
pipeline.fit(texts, labels)

# Save the trained model
with open("classifier.pkl", "wb") as f:
    pickle.dump(pipeline, f)

print("Classifier successfully trained and saved as classifier.pkl")
