import math

import pytest

import password_checker as pc


# ---- blacklist ----

def test_load_blacklist_reads_file():
    blacklist = pc.load_blacklist()
    assert "password" in blacklist
    assert "123456" in blacklist


def test_load_blacklist_missing_file_returns_empty_set():
    blacklist = pc.load_blacklist("does_not_exist.txt")
    assert blacklist == set()


def test_is_blacklisted_case_insensitive():
    blacklist = {"password"}
    assert pc.is_blacklisted("Password", blacklist)
    assert pc.is_blacklisted("PASSWORD", blacklist)
    assert not pc.is_blacklisted("notinlist", blacklist)


# ---- entropy ----

def test_entropy_empty_password_is_zero():
    assert pc.calculate_entropy("") == 0.0


def test_entropy_increases_with_more_character_classes():
    lower_only = pc.calculate_entropy("aaaaaaaa")
    mixed = pc.calculate_entropy("aA1!aA1!")
    assert mixed > lower_only


def test_entropy_increases_with_length():
    short = pc.calculate_entropy("abcdef")
    longer = pc.calculate_entropy("abcdefabcdef")
    assert longer > short


def test_entropy_known_value():
    # 8 lowercase-only chars: pool size 26 -> 8 * log2(26)
    expected = 8 * math.log2(26)
    assert pc.calculate_entropy("abcdefgh") == pytest.approx(expected)


def test_entropy_label_boundaries():
    assert pc.entropy_label(10) == "Very Weak"
    assert pc.entropy_label(30) == "Weak"
    assert pc.entropy_label(45) == "Reasonable"
    assert pc.entropy_label(90) == "Strong"
    assert pc.entropy_label(150) == "Very Strong"


# ---- check_password ----

def test_check_password_all_criteria_met():
    results = pc.check_password("Abcdef1!", blacklist=set())
    assert results["length_ok"]
    assert results["has_upper"]
    assert results["has_lower"]
    assert results["has_digit"]
    assert results["has_symbol"]
    assert results["score"] == 5
    assert not results["is_blacklisted"]


def test_check_password_weak():
    results = pc.check_password("abc", blacklist=set())
    assert not results["length_ok"]
    assert results["score"] <= 2


def test_check_password_flags_blacklisted():
    results = pc.check_password("password", blacklist={"password"})
    assert results["is_blacklisted"]


def test_check_password_uses_default_blacklist_when_none_given():
    results = pc.check_password("password")
    assert results["is_blacklisted"]


# ---- strength_label ----

def test_strength_label_weak():
    assert pc.strength_label(1) == "Weak"


def test_strength_label_moderate():
    assert pc.strength_label(3) == "Moderate"


def test_strength_label_strong():
    assert pc.strength_label(5) == "Strong"


def test_strength_label_blacklisted_overrides_score():
    assert pc.strength_label(5, is_blacklisted_pw=True) == "Weak (common password)"


# ---- check_pwned (network mocked) ----

class FakeResponse:
    def __init__(self, text, status_code=200):
        self.text = text
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code != 200:
            raise pc.requests.HTTPError("bad status")


def test_check_pwned_found(monkeypatch):
    # SHA1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    # prefix = "5BAA6", suffix = everything after it
    fake_suffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
    fake_text = f"{fake_suffix}:3730471\nOTHERSUFFIX0000000000000000000000000:1"

    def fake_get(url, timeout=5):
        return FakeResponse(fake_text)

    monkeypatch.setattr(pc.requests, "get", fake_get)
    pwned, count = pc.check_pwned("password")
    assert pwned is True
    assert count == 3730471


def test_check_pwned_not_found(monkeypatch):
    def fake_get(url, timeout=5):
        return FakeResponse("SOMEOTHERSUFFIX00000000000000000000000:5")

    monkeypatch.setattr(pc.requests, "get", fake_get)
    pwned, count = pc.check_pwned("a-very-unique-password-xyz")
    assert pwned is False
    assert count == 0


def test_check_pwned_network_failure(monkeypatch):
    def fake_get(url, timeout=5):
        raise pc.requests.RequestException("network down")

    monkeypatch.setattr(pc.requests, "get", fake_get)
    pwned, count = pc.check_pwned("password")
    assert pwned is False
    assert count == -1
