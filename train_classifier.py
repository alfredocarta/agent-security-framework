import json
import pickle
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.model_selection import cross_val_score

# Load the realistic dataset
with open("training_data.json", "r") as f:
    data = json.load(f)

texts = [item["text"] for item in data]
labels = [item["label"] for item in data]

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
