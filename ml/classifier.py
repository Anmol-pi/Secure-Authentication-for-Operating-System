#!/usr/bin/env python3
"""
LinuxAuthGuard - ML Sensitivity Classifier
Random Forest classifier that learns which files are sensitive
based on access patterns, sudo usage, file attributes, and path features.
"""

from __future__ import annotations

import logging
import os
import pickle
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("linuxauthguard.ml.classifier")

MODEL_PATH = "/var/lib/linuxauthguard/model.pkl"
MIN_CONFIDENCE = 0.80  # Threshold for flagging as sensitive


class SensitivityClassifier:
    """
    Wraps a scikit-learn RandomForestClassifier with save/load, incremental
    retraining, and confidence-threshold flagging.

    Imports scikit-learn lazily to avoid loading it at daemon startup.
    """

    LABEL_SENSITIVE     = 1
    LABEL_NOT_SENSITIVE = 0

    def __init__(self, model_path: str = MODEL_PATH) -> None:
        self._model_path = model_path
        self._model: Optional[Any] = None
        self._feature_names: Optional[List[str]] = None
        self._trained = False
        Path(model_path).parent.mkdir(parents=True, exist_ok=True)

    # ── Model lifecycle ─────────────────────────────────────────────────────

    def load(self) -> bool:
        """Load model from disk. Returns True on success."""
        if not Path(self._model_path).exists():
            logger.info("No saved model at %s; will train fresh", self._model_path)
            return False
        try:
            with open(self._model_path, "rb") as f:
                bundle = pickle.load(f)
            self._model = bundle["model"]
            self._feature_names = bundle.get("feature_names", [])
            self._trained = True
            logger.info("Loaded model from %s", self._model_path)
            return True
        except Exception as e:
            logger.error("Failed to load model: %s", e)
            return False

    def save(self) -> bool:
        """Persist model to disk. Returns True on success."""
        if not self._trained or self._model is None:
            return False
        try:
            bundle = {
                "model": self._model,
                "feature_names": self._feature_names or [],
                "saved_at": time.time(),
            }
            tmp_path = self._model_path + ".tmp"
            with open(tmp_path, "wb") as f:
                pickle.dump(bundle, f, protocol=pickle.HIGHEST_PROTOCOL)
            os.replace(tmp_path, self._model_path)
            logger.info("Model saved to %s", self._model_path)
            return True
        except Exception as e:
            logger.error("Failed to save model: %s", e)
            return False

    # ── Training ─────────────────────────────────────────────────────────────

    def train(
        self,
        X: List[List[float]],
        y: List[int],
        feature_names: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Train the Random Forest classifier.
        Returns a dict with training metrics.
        """
        # Lazy import
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import cross_val_score
        import numpy as np

        if len(X) < 5:
            logger.warning("Not enough samples to train (%d). Need at least 5.", len(X))
            return {"error": "insufficient_data", "samples": len(X)}

        X_arr = np.array(X, dtype=float)
        y_arr = np.array(y, dtype=int)

        self._model = RandomForestClassifier(
            n_estimators=100,
            max_depth=8,
            min_samples_split=2,
            min_samples_leaf=1,
            class_weight="balanced",  # Handle imbalanced labels
            random_state=42,
            n_jobs=1,
            max_features="sqrt",
        )

        # Cross-validate if we have enough samples
        metrics: Dict[str, Any] = {}
        if len(X) >= 10:
            try:
                cv_scores = cross_val_score(
                    self._model, X_arr, y_arr,
                    cv=min(5, len(X) // 2),
                    scoring="f1_macro",
                )
                metrics["cv_f1_mean"] = float(cv_scores.mean())
                metrics["cv_f1_std"]  = float(cv_scores.std())
                logger.info(
                    "CV F1: %.3f ± %.3f", cv_scores.mean(), cv_scores.std()
                )
            except Exception as e:
                logger.warning("Cross-validation failed: %s", e)

        self._model.fit(X_arr, y_arr)
        self._feature_names = feature_names or []
        self._trained = True

        metrics["samples"]   = len(X)
        metrics["trained_at"] = time.time()
        logger.info("Model trained on %d samples", len(X))
        return metrics

    # ── Prediction ───────────────────────────────────────────────────────────

    def predict(self, features: List[float]) -> Tuple[int, float]:
        """
        Classify a single file feature vector.
        Returns (label, confidence) where label is 0 (safe) or 1 (sensitive).
        """
        if not self._trained or self._model is None:
            return self.LABEL_NOT_SENSITIVE, 0.0

        import numpy as np
        X = np.array([features], dtype=float)
        try:
            proba = self._model.predict_proba(X)[0]
            label = int(self._model.predict(X)[0])
            # Confidence = probability of the predicted class
            confidence = float(proba[label])
            return label, confidence
        except Exception as e:
            logger.warning("Prediction error: %s", e)
            return self.LABEL_NOT_SENSITIVE, 0.0

    def predict_batch(
        self,
        feature_matrix: List[List[float]],
    ) -> List[Tuple[int, float]]:
        """Classify a batch of feature vectors."""
        if not self._trained or self._model is None:
            return [(self.LABEL_NOT_SENSITIVE, 0.0)] * len(feature_matrix)

        import numpy as np
        X = np.array(feature_matrix, dtype=float)
        try:
            probas = self._model.predict_proba(X)
            labels = self._model.predict(X)
            return [
                (int(lbl), float(proba[lbl]))
                for lbl, proba in zip(labels, probas)
            ]
        except Exception as e:
            logger.warning("Batch prediction error: %s", e)
            return [(self.LABEL_NOT_SENSITIVE, 0.0)] * len(feature_matrix)

    def is_sensitive(self, features: List[float]) -> Tuple[bool, float]:
        """
        Returns (is_sensitive, confidence).
        File is flagged sensitive if confidence > MIN_CONFIDENCE.
        """
        label, confidence = self.predict(features)
        return (label == self.LABEL_SENSITIVE and confidence >= MIN_CONFIDENCE,
                confidence)

    # ── Feature importance ────────────────────────────────────────────────────

    def get_feature_importance(self) -> Dict[str, float]:
        """Return feature importance scores (requires fitted model)."""
        if not self._trained or self._model is None:
            return {}
        try:
            importances = self._model.feature_importances_
            names = self._feature_names or [
                f"feature_{i}" for i in range(len(importances))
            ]
            return dict(zip(names, (float(v) for v in importances)))
        except Exception:
            return {}

    def get_feature_names(self) -> List[str]:
        return list(self._feature_names or [])

    @property
    def is_trained(self) -> bool:
        return self._trained


class FolderSensitivityAggregator:
    """
    Flags folders as sensitive zones when they contain many sensitive files.
    """

    FOLDER_SENSITIVE_THRESHOLD = 0.30  # 30% of files are sensitive

    def __init__(self, classifier: SensitivityClassifier) -> None:
        self._clf = classifier

    def flag_sensitive_folders(
        self,
        file_results: List[Tuple[str, int, float]],
    ) -> List[str]:
        """
        Given a list of (path, label, confidence) for files,
        return folders that contain >= threshold% sensitive files.
        """
        folder_counts: Dict[str, Dict[str, int]] = {}

        for file_path, label, confidence in file_results:
            folder = str(Path(file_path).parent)
            if folder not in folder_counts:
                folder_counts[folder] = {"total": 0, "sensitive": 0}
            folder_counts[folder]["total"] += 1
            if label == SensitivityClassifier.LABEL_SENSITIVE and confidence >= MIN_CONFIDENCE:
                folder_counts[folder]["sensitive"] += 1

        sensitive_folders = []
        for folder, counts in folder_counts.items():
            if counts["total"] == 0:
                continue
            ratio = counts["sensitive"] / counts["total"]
            if ratio >= self.FOLDER_SENSITIVE_THRESHOLD:
                sensitive_folders.append(folder)
                logger.info(
                    "Folder flagged as sensitive zone: %s (%.0f%% sensitive files)",
                    folder,
                    ratio * 100,
                )
        return sensitive_folders
