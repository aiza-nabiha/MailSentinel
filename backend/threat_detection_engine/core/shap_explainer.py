import numpy as np
import shap


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

        # Use a sparse zero baseline.
        # This keeps the 150,023-feature representation sparse
        # instead of creating a huge dense background matrix.
        from scipy.sparse import csr_matrix

        background = csr_matrix(
            (1, len(self.all_feature_names)),
            dtype=np.float64,
        )

        self.explainer = shap.LinearExplainer(
            estimator,
            background,
        )

    def explain(
        self,
        model_input,
    ):
        """
        Generate top positive and negative SHAP features.
        """

        shap_values = self.explainer(
            model_input
        )

        values = np.asarray(
            shap_values.values
        )

        if values.ndim == 2:
            values = values[0]

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