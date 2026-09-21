from phishguard.core.obfuscation_intelligence import (
    detect_obfuscation,
)


def test_normal_domain():

    result = detect_obfuscation(
        "https://example.com",
        "example.com"
    )

    assert result["score"] == 0
    assert result["indicators"] == []


def test_unicode_hostname():

    result = detect_obfuscation(
        "https://еxample.com",
        "еxample.com"
    )

    assert result["score"] > 0

    assert any(
        "unicode" in indicator.lower()
        for indicator in result["indicators"]
    )


def test_punycode_hostname():

    result = detect_obfuscation(
        "https://xn--pple-43d.com",
        "xn--pple-43d.com"
    )

    assert result["score"] > 0

    assert any(
        "punycode" in indicator.lower()
        for indicator in result["indicators"]
    )


def test_confusable_character():

    result = detect_obfuscation(
        "https://раypal.com",
        "раypal.com"
    )

    assert result["score"] > 0

    assert any(
        "look-alike" in indicator.lower()
        for indicator in result["indicators"]
    )


def test_mixed_character_scripts():

    result = detect_obfuscation(
        "https://gооgle.com",
        "gооgle.com"
    )

    assert result["score"] > 0

    assert any(
        "mixed" in indicator.lower()
        or "unicode" in indicator.lower()
        for indicator in result["indicators"]
    )


def test_encoded_url():

    result = detect_obfuscation(
        "https://example.com/%41/%42/%43",
        "example.com"
    )

    assert result["score"] > 0

    assert any(
        "encoded" in indicator.lower()
        for indicator in result["indicators"]
    )


def test_normal_https_url():

    result = detect_obfuscation(
        "https://google.com",
        "google.com"
    )

    assert result["score"] == 0
