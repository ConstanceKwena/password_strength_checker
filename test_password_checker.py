import pytest
from password_checker import check_password, strength_label


def test_empty_password():
    result = check_password("")
    assert result["length_ok"] is False
    assert result["has_upper"] is False
    assert result["has_lower"] is False
    assert result["has_digit"] is False
    assert result["has_symbol"] is False
    assert result["score"] == 0


def test_password_shorter_than_8_characters():
    result = check_password("Abc123!")
    assert result["length_ok"] is False


def test_password_with_exactly_8_characters():
    result = check_password("Abc1234!")
    assert result["length_ok"] is True


def test_uppercase_requirement():
    assert check_password("abcdef1!")[ "has_upper"] is False
    assert check_password("Abcdef1!")[ "has_upper"] is True


def test_lowercase_requirement():
    assert check_password("ABCDEF1!")[ "has_lower"] is False
    assert check_password("Abcdef1!")[ "has_lower"] is True


def test_digit_requirement():
    assert check_password("Abcdefgh!")[ "has_digit"] is False
    assert check_password("Abcdefg1!")[ "has_digit"] is True


def test_symbol_requirement():
    assert check_password("Abcdefg1")[ "has_symbol"] is False
    assert check_password("Abcdefg1!")[ "has_symbol"] is True


def test_common_symbols_are_recognised():
    symbols = "!@#$%^&*()-_=+[]{};:'\",.<>?/\\|"
    for symbol in symbols:
        result = check_password(f"Abcdef1{symbol}")
        assert result["has_symbol"] is True


def test_strong_password_scores_5():
    result = check_password("Strong123!")
    assert result["score"] == 5


def test_score_counts_only_requirements():
    result = check_password("abc")
    assert result["score"] == 1


def test_strength_labels():
    assert strength_label(0) == "Weak"
    assert strength_label(1) == "Weak"
    assert strength_label(2) == "Weak"
    assert strength_label(3) == "Moderate"
    assert strength_label(4) == "Moderate"
    assert strength_label(5) == "Strong"


def test_non_string_password_is_rejected():
    with pytest.raises(TypeError):
        check_password(None)
