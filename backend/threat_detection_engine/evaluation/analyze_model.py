import pandas as pd
import joblib


MODEL_PATH = "ml_models/content_classifier.joblib"


print("Loading trained model...")

model = joblib.load(MODEL_PATH)

vectorizer = model.named_steps["tfidf"]
classifier = model.named_steps["classifier"]


feature_names = vectorizer.get_feature_names_out()
coefficients = classifier.coef_[0]


# Highest positive coefficients = strongest Threat indicators
threat_indices = coefficients.argsort()[-30:][::-1]

# Highest negative coefficients = strongest Legitimate indicators
legitimate_indices = coefficients.argsort()[:30]


print("\n" + "=" * 60)
print("TOP THREAT INDICATORS")
print("=" * 60)

for index in threat_indices:
    print(
        f"{feature_names[index]:40s}"
        f"{coefficients[index]:.4f}"
    )


print("\n" + "=" * 60)
print("TOP LEGITIMATE INDICATORS")
print("=" * 60)

for index in legitimate_indices:
    print(
        f"{feature_names[index]:40s}"
        f"{coefficients[index]:.4f}"
    )