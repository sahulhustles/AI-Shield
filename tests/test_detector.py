"""Unit tests for AIDetector model class."""

import json
import os
import tempfile
import pytest
import pandas as pd
from models.detector import AIDetector, normalize_text_preprocessing


@pytest.fixture
def sample_csv():
    """Create a temporary valid CSV dataset for testing."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8") as f:
        f.write("text,label\n")
        f.write('"I went to the store to buy some apples and oranges today.",0\n')
        f.write('"The integration of algorithmic paradigms enables optimized throughput.",1\n')
        f.write('"My brother helped me paint the fence behind our backyard.",0\n')
        f.write('"Furthermore, leveraging deep neural architectures maximizes performance.",1\n')
        f.write('"We cooked a hearty vegetable soup for dinner last night.",0\n')
        f.write('"In conclusion, comprehensive protocols facilitate operational resilience.",1\n')
        f.write('"I love reading fiction novels on rainy Sunday afternoons.",0\n')
        f.write('"Moreover, establishing structured governance models minimizes risk.",1\n')
        f.write('"The car wouldn\'t start because the battery was totally flat.",0\n')
        f.write('"Additionally, continuous refinement enhances predictive precision.",1\n')
        f.write('"My sister adopted a rescue puppy from the local animal shelter.",0\n')
        f.write('"Consequently, adopting decentralized ledgers optimizes transaction latency.",1\n')
        temp_path = f.name
    yield temp_path
    if os.path.exists(temp_path):
        os.remove(temp_path)


@pytest.fixture
def detector(sample_csv):
    """Instantiate and train an AIDetector using temporary paths."""
    with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as f_mod, \
         tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f_rep:
        model_path = f_mod.name
        report_path = f_rep.name

    det = AIDetector(model_path=model_path, dataset_path=sample_csv, report_path=report_path)
    det.train(save_model=True)
    yield det

    if os.path.exists(model_path):
        os.remove(model_path)
    if os.path.exists(report_path):
        os.remove(report_path)


def test_model_training_and_evaluation_report(sample_csv):
    """Test that training produces valid evaluation metrics and saves report."""
    with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as f_mod, \
         tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f_rep:
        model_path = f_mod.name
        report_path = f_rep.name

    try:
        det = AIDetector(model_path=model_path, dataset_path=sample_csv, report_path=report_path)
        metrics = det.train(save_model=True)

        assert isinstance(metrics, dict)
        assert "accuracy" in metrics
        assert "precision" in metrics
        assert "recall" in metrics
        assert "f1_score" in metrics
        assert "confusion_matrix" in metrics
        assert isinstance(metrics["confusion_matrix"], list)
        assert 0.0 <= metrics["accuracy"] <= 1.0
        assert os.path.exists(model_path)
        assert os.path.exists(report_path)

        # Verify report content
        report_data = det.load_evaluation_report()
        assert report_data is not None
        assert "generated_at_utc" in report_data
        assert "model_type" in report_data
        assert "evaluation" in report_data
        assert report_data["evaluation"]["accuracy"] == metrics["accuracy"]
    finally:
        if os.path.exists(model_path):
            os.remove(model_path)
        if os.path.exists(report_path):
            os.remove(report_path)


def test_small_dataset_evaluation_status():
    """Test evaluation reporting when dataset is too small for held-out split."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8") as f_csv, \
         tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as f_mod:
        f_csv.write("text,label\n")
        f_csv.write('"Sample human text",0\n')
        f_csv.write('"Sample AI text",1\n')
        f_csv.write('"Another human sentence",0\n')
        f_csv.write('"Another AI sentence",1\n')
        csv_path = f_csv.name
        mod_path = f_mod.name

    try:
        det = AIDetector(model_path=mod_path, dataset_path=csv_path)
        metrics = det.train(save_model=True)
        assert metrics["evaluation_status"] == "insufficient_data_for_standalone_evaluation"
        assert "note" in metrics
    finally:
        if os.path.exists(csv_path):
            os.remove(csv_path)
        if os.path.exists(mod_path):
            os.remove(mod_path)


def test_model_existence(detector):
    """Test model_exists accurately reflects file presence."""
    assert detector.model_exists() is True
    assert detector.model_exists("non_existent_model_12345.joblib") is False


def test_valid_prediction_structure(detector):
    """Test prediction output format and keys."""
    res = detector.predict("I had a great time walking in the park with my dog.")

    assert isinstance(res, dict)
    assert "label" in res
    assert res["label"] in ["AI-generated", "Human"]
    assert "ai_probability" in res
    assert "human_probability" in res
    assert "confidence" in res


def test_probability_range_and_sum(detector):
    """Test probability bounds and coherence."""
    res = detector.predict("The strategic deployment of AI optimizes workflows significantly.")

    ai_prob = res["ai_probability"]
    human_prob = res["human_probability"]
    confidence = res["confidence"]

    assert 0.0 <= ai_prob <= 1.0
    assert 0.0 <= human_prob <= 1.0
    assert 0.0 <= confidence <= 1.0
    assert pytest.approx(ai_prob + human_prob, rel=1e-3) == 1.0
    assert confidence == max(ai_prob, human_prob)


def test_robust_preprocessing_case_and_spacing(detector):
    """Test that casing, extra spaces, and newlines are preprocessed without error."""
    text_normal = "I love reading fiction novels on rainy Sunday afternoons."
    text_cased_and_spaced = "   I   LOVE  READING\n\nFICTION NOVELS  ON  rainy   Sunday afternoons.   "

    res1 = detector.predict(text_normal)
    res2 = detector.predict(text_cased_and_spaced)

    assert res1["label"] == res2["label"]
    assert pytest.approx(res1["ai_probability"], abs=1e-2) == res2["ai_probability"]


def test_normalize_text_function():
    """Test standalone normalize_text_preprocessing function."""
    assert normalize_text_preprocessing("  hello \n\n world\t!  ") == "hello world !"
    assert normalize_text_preprocessing("") == ""
    assert normalize_text_preprocessing(None) == ""


def test_invalid_empty_or_whitespace_text(detector):
    """Test detector rejects None, empty string, and whitespace-only text."""
    with pytest.raises(ValueError, match="Input text cannot be None."):
        detector.predict(None)

    with pytest.raises(ValueError, match="Input text cannot be empty or whitespace-only."):
        detector.predict("")

    with pytest.raises(ValueError, match="Input text cannot be empty or whitespace-only."):
        detector.predict("   \n\t  ")


def test_model_saving_and_loading(sample_csv):
    """Test that a saved model can be loaded and yields consistent predictions."""
    with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as f:
        model_path = f.name

    try:
        det1 = AIDetector(model_path=model_path, dataset_path=sample_csv)
        det1.train(save_model=True)
        pred1 = det1.predict("Testing model reproducibility across reload.")

        det2 = AIDetector(model_path=model_path)
        det2.load_model(model_path)
        pred2 = det2.predict("Testing model reproducibility across reload.")

        assert pred1["label"] == pred2["label"]
        assert pytest.approx(pred1["ai_probability"], abs=1e-5) == pred2["ai_probability"]
        assert pytest.approx(pred1["human_probability"], abs=1e-5) == pred2["human_probability"]
    finally:
        if os.path.exists(model_path):
            os.remove(model_path)


def test_dataset_validation_missing_file():
    """Test error when dataset file does not exist."""
    det = AIDetector(dataset_path="missing_file_xyz.csv")
    with pytest.raises(FileNotFoundError):
        det.load_dataset()


def test_dataset_validation_invalid_columns():
    """Test error when dataset is missing required columns."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
        f.write("wrong_col_1,wrong_col_2\nhello,world\n")
        path = f.name

    try:
        det = AIDetector(dataset_path=path)
        with pytest.raises(ValueError, match="must contain columns"):
            det.load_dataset()
    finally:
        if os.path.exists(path):
            os.remove(path)


def test_dataset_validation_invalid_labels():
    """Test error when dataset contains labels other than 0 and 1."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
        f.write("text,label\nSome text,2\nOther text,3\n")
        path = f.name

    try:
        det = AIDetector(dataset_path=path)
        with pytest.raises(ValueError, match="Dataset labels must only contain 0 and 1"):
            det.load_dataset()
    finally:
        if os.path.exists(path):
            os.remove(path)
