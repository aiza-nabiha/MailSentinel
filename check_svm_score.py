import numpy as np

from backend.threat_detection_engine.core.content_analysis import (
    get_content_analyzer,
)
from backend.threat_detection_engine.core.email_content_extractor import (
    extract_email_content,
)
from backend.threat_detection_engine.core.email_features import (
    extract_email_features,
)
from scipy.sparse import hstack, csr_matrix

analyzer = get_content_analyzer()

content = extract_email_content(
    "data/test_emails/example.eml"
)

subject = content.get("subject", "")
body = content.get("combined_text", "")

features = extract_email_features(
    subject=subject,
    body=body,
    urls=content.get("urls", []),
    attachments=content.get("attachments", []),
    html_source=content.get("html_source", ""),
    mailto_links=content.get("mailto_links", []),
    html_links=content.get("html_links", []),
)

text = analyzer._prepare_text(subject, body)
text_vector = analyzer.vectorizer.transform([text])

numeric = analyzer._prepare_numeric_features(features)
scaled = analyzer.scaler.transform(numeric)

X = hstack(
    [text_vector, csr_matrix(scaled)],
    format="csr",
)

model = analyzer.classifier

print("\nClassifier:", type(model).__name__)
print("Classes:", model.classes_)
print("Feature shape:", X.shape)

print("\nCalibrated probabilities:")
print(model.predict_proba(X))

print("\nUnderlying SVM decision scores:")

for i, calibrated in enumerate(model.calibrated_classifiers_):
    estimator = calibrated.estimator
    print(
        f"Fold {i}:",
        estimator.decision_function(X)
    )

print("\nFinite probabilities:",
      np.isfinite(model.predict_proba(X)).all())

print("Probability sum:",
      model.predict_proba(X).sum(axis=1))
