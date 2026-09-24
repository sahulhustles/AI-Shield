"""Text analysis service for extracting structural and statistical text metrics."""

from collections import Counter
import re
import string
from typing import Any, Dict, List, Union


class TextAnalyzer:
    """Calculates linguistic, structural, and statistical metrics from text."""

    @staticmethod
    def _extract_words(text: str) -> List[str]:
        """Extract word tokens from text safely."""
        if not text:
            return []
        # Matches alphanumeric tokens including contractions (e.g. "don't")
        return re.findall(r"\b\w+(?:'\w+)?\b", text)

    @staticmethod
    def _extract_sentences(text: str) -> List[str]:
        """Extract sentence tokens from text safely."""
        if not text or not text.strip():
            return []
        # Split on sentence end marks (.!?) or newline boundaries
        raw_sentences = re.split(r"(?:[.!?]+(?:\s+|$))|\n+", text.strip())
        # Filter out empty or whitespace/punctuation-only segments
        sentences = []
        for s in raw_sentences:
            s_clean = s.strip()
            # Only count as a sentence if it contains at least one word character
            if re.search(r"\w", s_clean):
                sentences.append(s_clean)
        return sentences

    def analyze(self, text: Union[str, Any]) -> Dict[str, Union[int, float]]:
        """Analyze text and calculate comprehensive structural metrics.

        Returns:
            Dict containing:
            - character_count (int)
            - word_count (int)
            - sentence_count (int)
            - average_word_length (float)
            - average_sentence_length (float)
            - vocabulary_richness (float)
            - punctuation_count (int)
            - question_mark_count (int)
            - exclamation_mark_count (int)
            - repeated_word_count (int)
        """
        # Safe input coercion and validation
        if text is None:
            text = ""
        elif not isinstance(text, str):
            text = str(text)

        character_count = len(text)
        words = self._extract_words(text)
        word_count = len(words)

        sentences = self._extract_sentences(text)
        sentence_count = len(sentences)

        # If words exist but sentence regex yielded 0 (e.g. "Hello world" with no final period),
        # count it as at least 1 sentence.
        if word_count > 0 and sentence_count == 0:
            sentence_count = 1

        # Average word length
        if word_count > 0:
            total_word_chars = sum(len(w) for w in words)
            average_word_length = total_word_chars / word_count
        else:
            average_word_length = 0.0

        # Average sentence length (words per sentence)
        if sentence_count > 0 and word_count > 0:
            average_sentence_length = word_count / sentence_count
        else:
            average_sentence_length = 0.0

        # Vocabulary richness (Type-Token Ratio: unique words / total words)
        if word_count > 0:
            unique_words = {w.lower() for w in words}
            vocabulary_richness = len(unique_words) / word_count
        else:
            vocabulary_richness = 0.0

        # Punctuation metrics
        punctuation_count = sum(1 for char in text if char in string.punctuation)
        question_mark_count = text.count("?")
        exclamation_mark_count = text.count("!")

        # Repeated word count: number of distinct words that appear more than once
        if word_count > 0:
            word_frequencies = Counter(w.lower() for w in words)
            repeated_word_count = sum(1 for count in word_frequencies.values() if count > 1)
        else:
            repeated_word_count = 0

        return {
            "character_count": int(character_count),
            "word_count": int(word_count),
            "sentence_count": int(sentence_count),
            "average_word_length": float(average_word_length),
            "average_sentence_length": float(average_sentence_length),
            "vocabulary_richness": float(vocabulary_richness),
            "punctuation_count": int(punctuation_count),
            "question_mark_count": int(question_mark_count),
            "exclamation_mark_count": int(exclamation_mark_count),
            "repeated_word_count": int(repeated_word_count),
        }
