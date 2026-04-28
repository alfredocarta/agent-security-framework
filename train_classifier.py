# train_classifier.py
# Trains the TF-IDF + Logistic Regression security classifier.
# Runs 5-fold cross-validation, prints per-class metrics, and saves classifier.pkl.
# Run this script whenever TRAINING_DATA in training_data.py is updated.

import os
import pickle
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.metrics import classification_report, confusion_matrix

from training_data import TRAINING_DATA

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CLASSIFIER_PATH = os.path.join(BASE_DIR, "classifier.pkl")

LABEL_NAMES = ["SAFE", "DANGEROUS"]


def build_pipeline():
    return Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), lowercase=True)),
        ("clf", LogisticRegression(max_iter=1000, class_weight="balanced")),
    ])


def evaluate(texts, labels):
    print(f"\n{'='*50}")
    print("DATASET STATISTICS")
    print(f"{'='*50}")
    print(f"Total examples : {len(labels)}")
    print(f"  SAFE         : {labels.count(0)}")
    print(f"  DANGEROUS    : {labels.count(1)}")

    print(f"\n{'='*50}")
    print("5-FOLD CROSS-VALIDATION")
    print(f"{'='*50}")

    pipeline = build_pipeline()
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scoring = ["accuracy", "precision_macro", "recall_macro", "f1_macro"]
    results = cross_validate(pipeline, texts, labels, cv=cv, scoring=scoring)

    for metric in scoring:
        scores = results[f"test_{metric}"]
        print(f"  {metric:<20} {scores.mean():.4f} (+/- {scores.std():.4f})")

    print(f"\n{'='*50}")
    print("FINAL MODEL - FULL DATASET REPORT")
    print(f"{'='*50}")

    pipeline.fit(texts, labels)
    preds = pipeline.predict(texts)
    print(classification_report(labels, preds, target_names=LABEL_NAMES))

    cm = confusion_matrix(labels, preds)
    print("Confusion matrix (rows=actual, cols=predicted):")
    print(f"             {LABEL_NAMES[0]:<12} {LABEL_NAMES[1]:<12}")
    for i, row in enumerate(cm):
        print(f"  {LABEL_NAMES[i]:<12} {row[0]:<12} {row[1]:<12}")

    print(f"\n{'='*50}")
    print("CONFIDENCE THRESHOLD ANALYSIS")
    print(f"{'='*50}")
    print("  Recommendation: set CONFIDENCE_THRESHOLD in interceptor.py")
    print("  to the lowest value where uncertain% is acceptable (<20%).\n")
    probas = pipeline.predict_proba(texts)
    for threshold in [0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90]:
        certain = np.sum(np.max(probas, axis=1) >= threshold)
        uncertain = len(texts) - certain
        pct_certain = 100 * certain / len(texts)
        print(f"  threshold={threshold:.2f}  certain={certain}/{len(texts)} ({pct_certain:.1f}%)  uncertain={uncertain}")

    return pipeline


def save(pipeline):
    with open(CLASSIFIER_PATH, "wb") as f:
        pickle.dump(pipeline, f)
    print(f"\n[OK] Classifier saved to {CLASSIFIER_PATH}")


if __name__ == "__main__":
    texts = [t for t, _ in TRAINING_DATA]
    labels = [l for _, l in TRAINING_DATA]
    pipeline = evaluate(texts, labels)
    save(pipeline)
