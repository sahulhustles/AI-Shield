"""Unit tests for TextAnalyzer service class."""

import pytest
from services.text_analyzer import TextAnalyzer


@pytest.fixture
def analyzer():
    """Fixture providing a TextAnalyzer instance."""
    return TextAnalyzer()


def test_normal_text_analysis(analyzer):
    """Test standard multi-sentence text metrics calculation."""
    text = "The quick brown fox jumps over the lazy dog. Did you see that? Wow!"
    metrics = analyzer.analyze(text)

    assert isinstance(metrics, dict)
    assert metrics["character_count"] == len(text)
    assert metrics["word_count"] == 14  # 9 + 4 + 1
    assert metrics["sentence_count"] == 3
    assert metrics["question_mark_count"] == 1
    assert metrics["exclamation_mark_count"] == 1
    assert metrics["punctuation_count"] == 3  # '.', '?', '!'
    assert 0.0 < metrics["vocabulary_richness"] <= 1.0
    assert metrics["average_word_length"] > 0
    assert metrics["average_sentence_length"] == pytest.approx(14 / 3, rel=1e-2)


def test_empty_and_none_text(analyzer):
    """Test that empty string or None returns zeroed metrics without throwing."""
    for empty_input in ["", None, "   ", "\n\t  "]:
        metrics = analyzer.analyze(empty_input)
        assert metrics["word_count"] == 0
        assert metrics["sentence_count"] == 0
        assert metrics["average_word_length"] == 0.0
        assert metrics["average_sentence_length"] == 0.0
        assert metrics["vocabulary_richness"] == 0.0
        assert metrics["repeated_word_count"] == 0


def test_punctuation_heavy_text(analyzer):
    """Test strings consisting primarily or exclusively of punctuation marks."""
    text = "???!!!... --- ***"
    metrics = analyzer.analyze(text)

    assert metrics["character_count"] == len(text)
    assert metrics["word_count"] == 0
    assert metrics["sentence_count"] == 0
    assert metrics["question_mark_count"] == 3
    assert metrics["exclamation_mark_count"] == 3
    assert metrics["punctuation_count"] > 0
    assert metrics["average_word_length"] == 0.0
    assert metrics["vocabulary_richness"] == 0.0


def test_single_word_text(analyzer):
    """Test single word input edge cases."""
    metrics = analyzer.analyze("Antigravity")

    assert metrics["word_count"] == 1
    assert metrics["sentence_count"] == 1
    assert metrics["average_word_length"] == 11.0
    assert metrics["average_sentence_length"] == 1.0
    assert metrics["vocabulary_richness"] == 1.0
    assert metrics["repeated_word_count"] == 0


def test_vocabulary_richness_and_repeated_words(analyzer):
    """Test repeated word counting and Type-Token Ratio calculation."""
    # 6 total words, 3 unique words ("data", "is", "great"), repeated words = 2 ("data", "is")
    text = "Data is data. Data is great!"
    metrics = analyzer.analyze(text)

    assert metrics["word_count"] == 6
    # Unique words (case-insensitive): {'data', 'is', 'great'} -> 3 / 6 = 0.5
    assert pytest.approx(metrics["vocabulary_richness"], rel=1e-2) == 0.5
    # Distinct words that appear > 1 time: 'data' (3x), 'is' (2x) -> 2
    assert metrics["repeated_word_count"] == 2


def test_multispace_and_newlines(analyzer):
    """Test text with irregular whitespace, tabs, and newlines."""
    text = "First   paragraph  line.\n\nSecond   paragraph  line!"
    metrics = analyzer.analyze(text)

    assert metrics["word_count"] == 6
    assert metrics["sentence_count"] == 2
    assert metrics["repeated_word_count"] == 2  # 'paragraph', 'line' appear twice
