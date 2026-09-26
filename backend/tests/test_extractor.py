import pytest

from analyzer.extractor import extract_indicators


def test_extracts_emails_urls_and_domains_in_encounter_order():
    content = (
        "Contact support@fake-bank.test or admin+alerts@mail.example.test. "
        "Visit https://login-alert.test/verify?token=abc#step "
        "and http://mail.example.test/help."
    )

    assert extract_indicators(content) == {
        "emails": ["support@fake-bank.test", "admin+alerts@mail.example.test"],
        "urls": [
            "https://login-alert.test/verify?token=abc#step",
            "http://mail.example.test/help",
        ],
        "domains": ["fake-bank.test", "mail.example.test", "login-alert.test"],
    }


def test_removes_duplicates_and_normalizes_domain_case():
    content = (
        "support@EXAMPLE.test support@example.test "
        "https://EXAMPLE.test/Login https://EXAMPLE.test/Login "
        "https://example.test/login"
    )

    assert extract_indicators(content) == {
        "emails": ["support@example.test"],
        "urls": ["https://EXAMPLE.test/Login", "https://example.test/login"],
        "domains": ["example.test"],
    }


@pytest.mark.parametrize(
    "content, expected",
    [
        ("Visit (https://example.test/login).", "https://example.test/login"),
        ("Visit <https://example.test/login>!", "https://example.test/login"),
        ("Visit \u201chttps://example.test/login\u201d.", "https://example.test/login"),
        (
            "See (https://example.test/wiki/Topic_(part)).",
            "https://example.test/wiki/Topic_(part)",
        ),
        ("[Help](https://example.test/login)", "https://example.test/login"),
    ],
)
def test_trims_prose_punctuation_but_preserves_balanced_parentheses(content, expected):
    assert extract_indicators(content)["urls"] == [expected]


def test_url_userinfo_does_not_hide_the_actual_host_or_create_a_fake_email():
    url = "https://trusted.test@actual-host.test:8443/login?next=/account#verify"

    assert extract_indicators(url) == {
        "emails": [],
        "urls": [url],
        "domains": ["actual-host.test"],
    }


def test_ip_urls_are_not_reported_as_domains():
    urls = ["https://192.0.2.1/login", "http://[2001:db8::1]:8080/verify"]

    assert extract_indicators(" ".join(urls)) == {
        "emails": [],
        "urls": urls,
        "domains": [],
    }


def test_accepts_uppercase_scheme_and_keeps_subdomain():
    assert extract_indicators("HTTPS://Login.Example.test/Account") == {
        "emails": [],
        "urls": ["HTTPS://Login.Example.test/Account"],
        "domains": ["login.example.test"],
    }


def test_malformed_urls_do_not_prevent_extracting_other_indicators():
    content = (
        "https://[broken http:///missing-host https://example.test:invalid "
        "https://example.test:99999 support@example.test https://valid.test/path"
    )

    assert extract_indicators(content) == {
        "emails": ["support@example.test"],
        "urls": ["https://valid.test/path"],
        "domains": ["example.test", "valid.test"],
    }


@pytest.mark.parametrize(
    "content", ["", " \n\t ", "Hello there!", "example.test", "name@", "@example.test"]
)
def test_returns_empty_lists_when_no_supported_indicators_are_found(content):
    assert extract_indicators(content) == {"emails": [], "urls": [], "domains": []}
