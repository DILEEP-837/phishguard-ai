from phishguard.core.redirect_intelligence import (
    analyze_redirect,
    detect_redirect_parameters,
    extract_redirect_targets,
    detect_encoded_redirect,
)


def test_normal_url():
    result = analyze_redirect("https://google.com")

    assert result["risk_level"] == "LOW"
    assert result["risk_score"] == 0


def test_redirect_parameter():
    result = analyze_redirect(
        "https://example.com/login?redirect=https://google.com"
    )

    assert "redirect" in result["redirect_parameters"]
    assert result["risk_score"] >= 20


def test_external_redirect():
    result = analyze_redirect(
        "https://example.com/login?next=https://evil.com"
    )

    assert "next" in result["redirect_parameters"]
    assert "https://evil.com" in result["redirect_targets"]
    assert result["risk_score"] >= 50


def test_multiple_redirect_parameters():
    result = analyze_redirect(
        "https://example.com/?url=https://evil.com&next=https://phish.com"
    )

    assert len(result["redirect_parameters"]) == 2
    assert len(result["redirect_targets"]) == 2


def test_redirect_parameter_detection():
    result = detect_redirect_parameters(
        "https://example.com/?redirect=https://evil.com"
    )

    assert "redirect" in result


def test_redirect_target_extraction():
    result = extract_redirect_targets(
        "https://example.com/?url=https://evil.com"
    )

    assert result == ["https://evil.com"]


def test_no_redirect_target():
    result = extract_redirect_targets(
        "https://example.com/?page=home"
    )

    assert result == []
from unittest.mock import Mock, patch

from phishguard.core.redirect_intelligence import (
    analyze_redirect_chain,
)


def test_no_redirect_chain():

    response = Mock()
    response.status_code = 200
    response.headers = {}

    with patch(
        "phishguard.core.redirect_intelligence.requests.Session"
    ) as mock_session:

        mock_session.return_value.get.return_value = response

        result = analyze_redirect_chain(
            "https://example.com"
        )

    assert result["redirect_count"] == 0
    assert result["final_url"] == "https://example.com"
    assert result["cross_domain_redirect"] is False
    assert result["error"] is None


def test_cross_domain_redirect():

    first_response = Mock()
    first_response.status_code = 302
    first_response.headers = {
        "Location": "https://evil.example/login"
    }

    second_response = Mock()
    second_response.status_code = 200
    second_response.headers = {}

    with patch(
        "phishguard.core.redirect_intelligence.requests.Session"
    ) as mock_session:

        mock_session.return_value.get.side_effect = [
            first_response,
            second_response,
        ]

        result = analyze_redirect_chain(
            "https://example.com"
        )

    assert result["redirect_count"] == 1
    assert result["cross_domain_redirect"] is True
    assert result["final_url"] == "https://evil.example/login"
    assert result["risk_score"] >= 25


def test_https_to_http_downgrade():

    first_response = Mock()
    first_response.status_code = 302
    first_response.headers = {
        "Location": "http://example.com/login"
    }

    second_response = Mock()
    second_response.status_code = 200
    second_response.headers = {}

    with patch(
        "phishguard.core.redirect_intelligence.requests.Session"
    ) as mock_session:

        mock_session.return_value.get.side_effect = [
            first_response,
            second_response,
        ]

        result = analyze_redirect_chain(
            "https://example.com"
        )

    assert result["https_to_http"] is True
    assert result["risk_score"] >= 30


def test_http_to_https_redirect():

    first_response = Mock()
    first_response.status_code = 301
    first_response.headers = {
        "Location": "https://example.com"
    }

    second_response = Mock()
    second_response.status_code = 200
    second_response.headers = {}

    with patch(
        "phishguard.core.redirect_intelligence.requests.Session"
    ) as mock_session:

        mock_session.return_value.get.side_effect = [
            first_response,
            second_response,
        ]

        result = analyze_redirect_chain(
            "http://example.com"
        )

    assert result["http_to_https"] is True
    assert result["error"] is None


def test_excessive_redirects():

    responses = []

    for i in range(6):

        response = Mock()
        response.status_code = 302
        response.headers = {
            "Location": f"https://example{i}.com"
        }

        responses.append(response)

    final_response = Mock()
    final_response.status_code = 200
    final_response.headers = {}

    responses.append(final_response)

    with patch(
        "phishguard.core.redirect_intelligence.requests.Session"
    ) as mock_session:

        mock_session.return_value.get.side_effect = responses

        result = analyze_redirect_chain(
            "https://start.example"
        )

    assert result["redirect_count"] == 6
    assert result["excessive_redirects"] is True
    assert result["risk_score"] >= 25
def test_redirect_loop():

    first_response = Mock()
    first_response.status_code = 302
    first_response.headers = {
        "Location": "https://second.example"
    }

    second_response = Mock()
    second_response.status_code = 302
    second_response.headers = {
        "Location": "https://first.example"
    }

    with patch(
        "phishguard.core.redirect_intelligence.requests.Session"
    ) as mock_session:

        mock_session.return_value.get.side_effect = [
            first_response,
            second_response,
        ]

        result = analyze_redirect_chain(
            "https://first.example"
        )

    assert result["redirect_loop"] is True
    assert result["risk_score"] >= 50


def test_final_destination_detection():

    first_response = Mock()
    first_response.status_code = 302
    first_response.headers = {
        "Location": "https://final.example/login"
    }

    second_response = Mock()
    second_response.status_code = 200
    second_response.headers = {}

    with patch(
        "phishguard.core.redirect_intelligence.requests.Session"
    ) as mock_session:

        mock_session.return_value.get.side_effect = [
            first_response,
            second_response,
        ]

        result = analyze_redirect_chain(
            "https://original.example"
        )

    assert result["final_url"] == (
        "https://final.example/login"
    )

    assert result["cross_domain_redirect"] is True
    assert result["redirect_count"] == 1


def test_multiple_redirect_chain():

    responses = []

    for domain in [
        "https://step1.example",
        "https://step2.example",
        "https://step3.example",
    ]:

        response = Mock()
        response.status_code = 302
        response.headers = {
            "Location": domain
        }

        responses.append(response)

    final_response = Mock()
    final_response.status_code = 200
    final_response.headers = {}

    responses.append(final_response)

    with patch(
        "phishguard.core.redirect_intelligence.requests.Session"
    ) as mock_session:

        mock_session.return_value.get.side_effect = responses

        result = analyze_redirect_chain(
            "https://start.example"
        )

    assert result["redirect_count"] == 3

    assert result["final_url"] == (
        "https://step3.example"
    )

    assert result["cross_domain_redirect"] is True
