"""AI-Generated Content Detector Module.

Uses TF-IDF Vectorization and Logistic Regression for binary classification
of text as either Human-written (0) or AI-generated (1).
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import unicodedata
from typing import Any, Dict, List, Optional, Union
import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


def normalize_text_preprocessing(text: Any) -> str:
    """Normalize input text for consistent ML vectorization.

    - Coerces input to string safely
    - Normalizes Unicode characters (NFKC)
    - Normalizes multiple whitespace, tabs, and newlines into single spaces
    - Strips leading and trailing whitespace
    """
    if text is None:
        return ""
    text_str = str(text)
    if not text_str.strip():
        return ""
    # Unicode canonical decomposition + compatibility composition
    text_norm = unicodedata.normalize("NFKC", text_str)
    # Replace multiple whitespace characters (including newlines, tabs) with a single space
    text_cleaned = re.sub(r"\s+", " ", text_norm)
    return text_cleaned.strip()


class AIDetector:
    """Baseline classifier to detect whether text is AI-generated or human-written."""

    DEFAULT_MODEL_FILENAME = "detector_model.joblib"
    DEFAULT_REPORT_FILENAME = "evaluation_report.json"

    def __init__(
        self,
        model_path: Optional[Union[str, Path]] = None,
        dataset_path: Optional[Union[str, Path]] = None,
        report_path: Optional[Union[str, Path]] = None,
    ) -> None:
        """Initialize detector with cross-platform Path handling."""
        base_dir = Path(__file__).resolve().parent.parent

        self.model_path = (
            Path(model_path).resolve()
            if model_path is not None
            else Path(__file__).resolve().parent / self.DEFAULT_MODEL_FILENAME
        )
        self.dataset_path = (
            Path(dataset_path).resolve()
            if dataset_path is not None
            else base_dir / "data" / "dataset.csv"
        )
        self.report_path = (
            Path(report_path).resolve()
            if report_path is not None
            else Path(__file__).resolve().parent / self.DEFAULT_REPORT_FILENAME
        )
        self.pipeline: Optional[Pipeline] = None
        self.last_evaluation: Optional[Dict[str, Any]] = None

    def model_exists(self, model_path: Optional[Union[str, Path]] = None) -> bool:
        """Check if a serialized model file exists at the specified path."""
        target_path = Path(model_path).resolve() if model_path else self.model_path
        return target_path.exists() and target_path.is_file()

    def load_dataset(self, dataset_path: Optional[Union[str, Path]] = None) -> pd.DataFrame:
        """Load and validate the CSV training dataset."""
        target_path = Path(dataset_path).resolve() if dataset_path else self.dataset_path

        if not target_path.exists() or not target_path.is_file():
            raise FileNotFoundError(f"Dataset not found at path: {target_path}")

        try:
            df = pd.read_csv(target_path)
        except Exception as err:
            raise ValueError(f"Failed to parse CSV dataset at {target_path}: {err}") from err

        if df.empty:
            raise ValueError(f"Dataset at {target_path} is empty.")

        required_columns = {"text", "label"}
        if not required_columns.issubset(df.columns):
            raise ValueError(
                f"Dataset must contain columns {required_columns}. Found columns: {list(df.columns)}"
            )

        # Drop any null or empty text rows
        df = df.dropna(subset=["text", "label"]).copy()
        df["text"] = df["text"].astype(str).apply(normalize_text_preprocessing)
        df = df[df["text"].str.len() > 0]

        if df.empty:
            raise ValueError("Dataset contains no valid non-empty text rows after preprocessing.")

        # Ensure label column is numeric and contains only binary classes (0 and 1)
        try:
            df["label"] = df["label"].astype(int)
        except (ValueError, TypeError) as err:
            raise ValueError("Dataset labels must be convertible to integers (0 or 1).") from err

        unique_labels = set(df["label"].unique())
        if not unique_labels.issubset({0, 1}):
            raise ValueError(f"Dataset labels must only contain 0 and 1. Found: {unique_labels}")

        if len(unique_labels) < 2:
            raise ValueError("Dataset must contain samples for both classes (0 = Human, 1 = AI-generated).")

        return df

    def train(
        self,
        dataset_path: Optional[Union[str, Path]] = None,
        save_model: bool = True,
        model_path: Optional[Union[str, Path]] = None,
        report_path: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        """Train TF-IDF + Logistic Regression pipeline on the dataset and save evaluation report."""
        df = self.load_dataset(dataset_path)

        X = df["text"].values
        y = df["label"].values

        has_held_out_split = False
        # Split into train and test if sufficient samples exist (at least 10 samples total)
        if len(df) >= 10:
            try:
                X_train, X_test, y_train, y_test = train_test_split(
                    X, y, test_size=0.2, random_state=42, stratify=y
                )
                has_held_out_split = True
            except ValueError:
                try:
                    X_train, X_test, y_train, y_test = train_test_split(
                        X, y, test_size=0.2, random_state=42
                    )
                    has_held_out_split = True
                except Exception:
                    X_train, X_test, y_train, y_test = X, X, y, y
                    has_held_out_split = False
        else:
            X_train, X_test, y_train, y_test = X, X, y, y
            has_held_out_split = False

        # Build classical baseline ML pipeline
        self.pipeline = Pipeline([
            (
                "tfidf",
                TfidfVectorizer(
                    preprocessor=normalize_text_preprocessing,
                    ngram_range=(1, 2),
                    sublinear_tf=True,
                    strip_accents="unicode",
                    lowercase=True,
                    min_df=1,
                    max_df=0.98,
                ),
            ),
            (
                "clf",
                LogisticRegression(
                    C=1.0,
                    max_iter=1000,
                    random_state=42,
                    solver="lbfgs",
                    class_weight="balanced",
                ),
            ),
        ])

        self.pipeline.fit(X_train, y_train)

        # Evaluate performance on test split
        metrics = self.evaluate(
            X_test,
            y_test,
            is_held_out=has_held_out_split,
            total_dataset_size=len(df),
            train_size=len(X_train),
            test_size=len(X_test),
        )
        self.last_evaluation = metrics

        if save_model:
            target_model_path = Path(model_path).resolve() if model_path else self.model_path
            self.save_model(target_model_path)

            target_report_path = Path(report_path).resolve() if report_path else self.report_path
            self.save_evaluation_report(metrics, target_report_path)

        return metrics

    def evaluate(
        self,
        X_test: Any,
        y_test: Any,
        is_held_out: bool = True,
        total_dataset_size: Optional[int] = None,
        train_size: Optional[int] = None,
        test_size: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Evaluate model performance on test data."""
        if self.pipeline is None:
            raise RuntimeError("Cannot evaluate: Model is not trained or loaded.")

        test_count = len(y_test)
        unique_test_classes = set(y_test)

        if not is_held_out or test_count < 2 or len(unique_test_classes) < 2:
            y_pred = self.pipeline.predict(X_test)
            return {
                "evaluation_status": "insufficient_data_for_standalone_evaluation",
                "accuracy": float(accuracy_score(y_test, y_pred)),
                "precision": float(precision_score(y_test, y_pred, zero_division=0)),
                "recall": float(recall_score(y_test, y_pred, zero_division=0)),
                "f1_score": float(f1_score(y_test, y_pred, zero_division=0)),
                "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
                "total_samples": total_dataset_size or test_count,
                "test_samples": test_count,
                "note": "Dataset split is too small for held-out evaluation. Metrics computed on available samples.",
            }

        y_pred = self.pipeline.predict(X_test)
        cm = confusion_matrix(y_test, y_pred).tolist()

        return {
            "evaluation_status": "valid_test_split",
            "accuracy": float(accuracy_score(y_test, y_pred)),
            "precision": float(precision_score(y_test, y_pred, zero_division=0)),
            "recall": float(recall_score(y_test, y_pred, zero_division=0)),
            "f1_score": float(f1_score(y_test, y_pred, zero_division=0)),
            "confusion_matrix": cm,
            "total_samples": total_dataset_size or (train_size + test_size if train_size and test_size else test_count),
            "train_samples": train_size,
            "test_samples": test_count,
            "classes": [0, 1],
            "class_labels": {"0": "Human", "1": "AI-generated"},
        }

    def save_evaluation_report(
        self,
        metrics: Dict[str, Any],
        report_path: Optional[Union[str, Path]] = None,
    ) -> None:
        """Save evaluation report in human-readable JSON format."""
        target_path = Path(report_path).resolve() if report_path else self.report_path
        target_path.parent.mkdir(parents=True, exist_ok=True)

        report_data = {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "model_type": "TF-IDF (ngram_range=(1,2), sublinear_tf=True) + LogisticRegression (balanced, lbfgs)",
            "evaluation": metrics,
        }

        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

    def load_evaluation_report(
        self,
        report_path: Optional[Union[str, Path]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Load stored evaluation report if present."""
        target_path = Path(report_path).resolve() if report_path else self.report_path
        if target_path.exists() and target_path.is_file():
            try:
                with open(target_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return None
        return None

    def save_model(self, model_path: Optional[Union[str, Path]] = None) -> None:
        """Serialize and save the trained pipeline to disk."""
        if self.pipeline is None:
            raise RuntimeError("Cannot save model: No pipeline has been trained or loaded.")

        target_path = Path(model_path).resolve() if model_path else self.model_path
        target_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.pipeline, str(target_path))

    def load_model(self, model_path: Optional[Union[str, Path]] = None) -> None:
        """Load a serialized pipeline from disk."""
        target_path = Path(model_path).resolve() if model_path else self.model_path
        if not target_path.exists() or not target_path.is_file():
            raise FileNotFoundError(f"Saved model file not found at: {target_path}")

        loaded_pipeline = joblib.load(str(target_path))
        if not isinstance(loaded_pipeline, Pipeline):
            raise ValueError(f"Loaded object from {target_path} is not a valid scikit-learn Pipeline.")

        self.pipeline = loaded_pipeline

    def _validate_input_text(self, text: Any) -> str:
        """Validate that input text is a non-empty, non-whitespace string."""
        if text is None:
            raise ValueError("Input text cannot be None.")
        if not isinstance(text, str):
            raise ValueError(f"Input text must be a string, got {type(text).__name__}.")
        cleaned = text.strip()
        if not cleaned:
            raise ValueError("Input text cannot be empty or whitespace-only.")
        return text

    def predict_proba(self, text: str) -> np.ndarray:
        """Predict class probabilities for the given text.

        Returns:
            np.ndarray: [human_probability, ai_probability]
        """
        validated_text = self._validate_input_text(text)

        if self.pipeline is None:
            if self.model_exists():
                self.load_model()
            else:
                raise RuntimeError("Model is not trained or loaded. Call train() or load_model() first.")

        probabilities = self.pipeline.predict_proba([validated_text])[0]
        return probabilities

    def predict(self, text: str) -> Dict[str, Union[str, float]]:
        """Predict whether text is AI-generated or Human-written.

        Returns exact standardized dictionary:
        {
            "label": "AI-generated" | "Human",
            "ai_probability": float,
            "human_probability": float,
            "confidence": float
        }
        """
        probs = self.predict_proba(text)

        # Explicitly map class indexes to ensure exact class probability assignment
        classes = list(self.pipeline.classes_)
        idx_human = classes.index(0) if 0 in classes else 0
        idx_ai = classes.index(1) if 1 in classes else 1

        human_prob = float(probs[idx_human])
        ai_prob = float(probs[idx_ai])

        # Binary label decision (threshold at 0.5)
        label = "AI-generated" if ai_prob >= 0.5 else "Human"
        confidence = float(max(ai_prob, human_prob))

        return {
            "label": label,
            "ai_probability": ai_prob,
            "human_probability": human_prob,
            "confidence": confidence,
        }
