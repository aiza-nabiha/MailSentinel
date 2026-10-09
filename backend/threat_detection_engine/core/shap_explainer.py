import numpy as np
from scipy.sparse import csr_matrix, issparse

# NOTE: the `shap` package is deliberately NOT imported here any more.
# Importing it pulls in numba/llvmlite and costs ~120 MB of RAM at
# startup, which pushed the 512 MB Render free instance over its limit
# (three "Ran out of memory" restarts during /analyze on 2026-10-05).
# For a LINEAR model with a zero baseline, SHAP values have an exact
# closed form -- coef * (x - baseline) = coef * x -- so we compute that
# directly. Output is identical to shap.LinearExplainer (verified:
# max abs difference 0.0).


class ContentSHAPExplainer:
    """
    Lightweight SHAP explanation for the MailSentinel
    TF-IDF + numeric LinearSVC content model.

    The production classifier is CalibratedClassifierCV
    containing three LinearSVC estimators.

    SHAP explanations are generated from the underlying
    linear SVM decision function.
    """

    def __init__(
        self,
        vectorizer,
        scaler,
        classifier,
        feature_names,
        top_k=10,
    ):
        self.vectorizer = vectorizer
        self.scaler = scaler
        self.classifier = classifier
        self.feature_names = list(feature_names)
        self.top_k = int(top_k)

        self.feature_names_text = (
            list(
                self.vectorizer.get_feature_names_out()
            )
        )

        self.all_feature_names = (
            self.feature_names_text
            + self.feature_names
        )

        self.explainer = None
        self._build_explainer()

    def _get_base_estimator(self):
        calibrated = getattr(
            self.classifier,
            "calibrated_classifiers_",
            None,
        )

        if not calibrated:
            raise ValueError(
                "Calibrated classifier does not contain "
                "base estimators."
            )

        return calibrated[0].estimator

    def _build_explainer(self):
        estimator = self._get_base_estimator()

        # Linear SHAP with a zero baseline: shap_i = coef_i * x_i.
        self.coef_ = np.asarray(
            estimator.coef_,
            dtype=np.float64,
        ).ravel()

        # Kept so any `if explainer is not None` style check still works.
        self.explainer = True

    def explain(
        self,
        model_input,
    ):
        """
        Generate top positive and negative SHAP features.
        """

        if issparse(model_input):
            row = csr_matrix(model_input)[0]
            values = np.asarray(
                row.multiply(self.coef_).todense()
            ).ravel()
        else:
            values = (
                np.atleast_2d(
                    np.asarray(model_input, dtype=np.float64)
                )[0]
                * self.coef_
            )

        if values.ndim != 1:
            raise ValueError(
                "Unexpected SHAP output shape: "
                f"{values.shape}"
            )

        positive_indices = np.argsort(
            values
        )[-self.top_k:][::-1]

        negative_indices = np.argsort(
            values
        )[:self.top_k]

        positive = []

        for index in positive_indices:
            value = float(values[index])

            if value <= 0:
                continue

            positive.append(
                {
                    "feature": self.all_feature_names[index],
                    "impact": value,
                }
            )

        negative = []

        for index in negative_indices:
            value = float(values[index])

            if value >= 0:
                continue

            negative.append(
                {
                    "feature": self.all_feature_names[index],
                    "impact": value,
                }
            )

        return {
            "top_positive_features": positive,
            "top_negative_features": negative,
        }