import logging

import pytest
import requests
import responses

from engines.darkeye import (
    BREACH_HOUSE_URL,
    HIBR_URL,
    DarkEyeEngine,
    clean,
    normalize_domain,
)
from models.observable import Observable, ObservableType
from utils.config import Secrets, read_secrets_from_env
from utils.load_engines import get_engine_instances

HIBR_KEY = "hibr-secret-key-0123456789"
BH_KEY = "bh-secret-key-9876543210"

HIBR_NAME = "Have I Been Ransomed?"
BH_NAME = "Breach House"

HIBR_DOMAIN_URL = f"{HIBR_URL}/example.com"


# ============================================================================
# Fixtures and helpers
# ============================================================================


def make_secrets(hibr: str = "", breach_house: str = "") -> Secrets:
    secrets = Secrets()
    secrets.darkeye_hibr_api_key = hibr
    secrets.darkeye_breach_house_api_key = breach_house
    return secrets


@pytest.fixture
def engine_both() -> DarkEyeEngine:
    return DarkEyeEngine(make_secrets(HIBR_KEY, BH_KEY), {}, True)


@pytest.fixture
def engine_hibr() -> DarkEyeEngine:
    return DarkEyeEngine(make_secrets(hibr=HIBR_KEY), {}, True)


@pytest.fixture
def engine_breach_house() -> DarkEyeEngine:
    return DarkEyeEngine(make_secrets(breach_house=BH_KEY), {}, True)


@pytest.fixture
def engine_no_key() -> DarkEyeEngine:
    return DarkEyeEngine(make_secrets(), {}, True)


@pytest.fixture
def fqdn_observable() -> Observable:
    return Observable(value="example.com", type=ObservableType.FQDN)


@pytest.fixture
def url_observable() -> Observable:
    return Observable(value="https://Example.com/some/path?x=1", type=ObservableType.URL)


def hibr_item(
    item_id: str = "1", leak_type: str = "traditional_breach", **extra: object
) -> dict[str, object]:
    item: dict[str, object] = {
        "id_source": item_id,
        "id": 9999,
        "leak_type": leak_type,
        "post_title": f"Title {item_id}",
        "website": "example.com",
        "group_name": "group-a",
        "country": "FR",
        "discovered": "2025-03-04T10:11:12Z",
    }
    item.update(extra)
    return item


def hibr_page(items: list[dict[str, object]], has_next: bool = False) -> dict[str, object]:
    return {"sources": items, "has_next": has_next, "page": 1}


def breach_house_payload() -> dict[str, object]:
    return {
        "ransomware": {
            "results": [{"victim_id": "v1", "post_title": "Victim", "group_name": "lockbit"}],
            "total": 1,
        },
        "breaches": [{"id": 7, "name": "Some breach", "discovered": "2024-01-02T00:00:00"}],
        "leads": {"results": [], "total": 0},
        "stealers": {"results": [{"id": "s1", "name": "Stealer pack"}], "total": 1},
    }


def mock_hibr(body: object = None, status: int = 200, url: str = HIBR_DOMAIN_URL) -> None:
    responses.add(
        responses.GET, url, json=hibr_page([hibr_item()]) if body is None else body, status=status
    )


def mock_breach_house(body: object = None, status: int = 200) -> None:
    responses.add(
        responses.GET,
        BREACH_HOUSE_URL,
        json=breach_house_payload() if body is None else body,
        status=status,
    )


def by_product(result: dict, product: str) -> list[dict]:
    return [r for r in result["records"] if r["product"] == product]


# ============================================================================
# Engine properties and registration
# ============================================================================


def test_engine_properties(engine_both: DarkEyeEngine) -> None:
    assert engine_both.name == "darkeye"
    assert engine_both.supported_types == ObservableType.FQDN | ObservableType.URL


def test_engine_is_registered() -> None:
    engines = get_engine_instances(make_secrets(), {}, True)
    assert isinstance(engines["darkeye"], DarkEyeEngine)


def test_keys_are_read_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DARKEYE_HIBR_API_KEY", HIBR_KEY)
    monkeypatch.setenv("DARKEYE_BREACH_HOUSE_API_KEY", BH_KEY)
    secrets = read_secrets_from_env(Secrets())
    assert secrets.darkeye_hibr_api_key == HIBR_KEY
    assert secrets.darkeye_breach_house_api_key == BH_KEY


# ============================================================================
# Keys
# ============================================================================


@responses.activate
def test_no_key_warns_and_returns_none(
    engine_no_key: DarkEyeEngine, fqdn_observable: Observable, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING):
        assert engine_no_key.analyze(fqdn_observable) is None
    assert "not configured" in caplog.text
    assert len(responses.calls) == 0


@responses.activate
def test_only_hibr_key_queries_only_hibr(
    engine_hibr: DarkEyeEngine, fqdn_observable: Observable
) -> None:
    mock_hibr()
    result = engine_hibr.analyze(fqdn_observable)
    assert result is not None
    assert result["products"] == [HIBR_NAME]
    assert result["errors"] == []
    assert result["found"] is True
    assert result["count"] == 1
    assert [call.request.url for call in responses.calls] == [HIBR_DOMAIN_URL]
    assert responses.calls[0].request.headers["Authorization"] == f"Bearer {HIBR_KEY}"
    assert "search_url" not in result


@responses.activate
def test_only_breach_house_key_queries_only_breach_house(
    engine_breach_house: DarkEyeEngine, fqdn_observable: Observable
) -> None:
    mock_breach_house()
    result = engine_breach_house.analyze(fqdn_observable)
    assert result is not None
    assert result["products"] == [BH_NAME]
    assert result["count"] == 3
    assert len(responses.calls) == 1
    request = responses.calls[0].request
    assert request.url is not None
    assert request.url.startswith(BREACH_HOUSE_URL)
    assert "q=example.com" in request.url
    assert "limit=25" in request.url
    assert request.headers["Authorization"] == f"Bearer {BH_KEY}"
    assert "search_url" not in result


@responses.activate
def test_both_keys_return_one_result_with_product_and_category(
    engine_both: DarkEyeEngine, fqdn_observable: Observable
) -> None:
    mock_hibr(hibr_page([hibr_item("1", "ransomware_leak"), hibr_item("2")]))
    mock_breach_house()
    result = engine_both.analyze(fqdn_observable)
    assert result is not None
    assert result["products"] == [HIBR_NAME, BH_NAME]
    assert result["count"] == 5
    assert result["errors"] == []
    assert result["truncated"] is False
    assert sorted((r["product"], r["category"]) for r in result["records"]) == [
        (BH_NAME, "breaches"),
        (BH_NAME, "ransomware"),
        (BH_NAME, "stealers"),
        (HIBR_NAME, "breaches"),
        (HIBR_NAME, "ransomware"),
    ]


@responses.activate
def test_not_found_is_a_result_not_none(
    engine_both: DarkEyeEngine, fqdn_observable: Observable
) -> None:
    mock_hibr(hibr_page([]))
    mock_breach_house({"ransomware": [], "breaches": [], "leads": [], "stealers": []})
    result = engine_both.analyze(fqdn_observable)
    assert result is not None
    assert result["found"] is False
    assert result["count"] == 0
    assert result["records"] == []
    assert result["errors"] == []


# ============================================================================
# Partial failures
# ============================================================================


@responses.activate
@pytest.mark.parametrize("failing", [HIBR_NAME, BH_NAME])
def test_one_product_failing_keeps_the_other_one(
    engine_both: DarkEyeEngine, fqdn_observable: Observable, failing: str
) -> None:
    mock_hibr(status=401 if failing == HIBR_NAME else 200)
    mock_breach_house(status=500 if failing == BH_NAME else 200)
    result = engine_both.analyze(fqdn_observable)
    assert result is not None
    assert [e["product"] for e in result["errors"]] == [failing]
    assert result["products"] == [p for p in (HIBR_NAME, BH_NAME) if p != failing]
    assert result["found"] is True
    assert {r["product"] for r in result["records"]} == set(result["products"])


@responses.activate
def test_hibr_failing_on_a_later_page_drops_only_hibr(
    engine_both: DarkEyeEngine, fqdn_observable: Observable
) -> None:
    mock_hibr(hibr_page([hibr_item("1")], has_next=True))
    mock_hibr(status=429, url=f"{HIBR_DOMAIN_URL}/2")
    mock_breach_house()
    result = engine_both.analyze(fqdn_observable)
    assert result is not None
    assert result["products"] == [BH_NAME]
    assert result["errors"][0]["product"] == HIBR_NAME
    assert "quota" in result["errors"][0]["error"]
    assert by_product(result, HIBR_NAME) == []


@responses.activate
def test_all_products_failing_returns_none(
    engine_both: DarkEyeEngine, fqdn_observable: Observable
) -> None:
    mock_hibr(status=500)
    mock_breach_house(status=403)
    assert engine_both.analyze(fqdn_observable) is None
    assert len(responses.calls) == 2


@responses.activate
def test_single_configured_product_failing_returns_none(
    engine_hibr: DarkEyeEngine, fqdn_observable: Observable
) -> None:
    mock_hibr(status=500)
    assert engine_hibr.analyze(fqdn_observable) is None


# ============================================================================
# Have I Been Ransomed? pagination
# ============================================================================


@responses.activate
def test_hibr_follows_has_next_and_dedupes(
    engine_hibr: DarkEyeEngine, fqdn_observable: Observable
) -> None:
    mock_hibr(hibr_page([hibr_item("1"), hibr_item("2")], has_next=True))
    # Item 2 is repeated on the next page, as leaks indexed while paging are.
    mock_hibr(
        hibr_page([hibr_item("2"), hibr_item("3")], has_next=False), url=f"{HIBR_DOMAIN_URL}/2"
    )
    result = engine_hibr.analyze(fqdn_observable)
    assert result is not None
    assert [r["id"] for r in result["records"]] == ["1", "2", "3"]
    assert result["truncated"] is False
    assert [call.request.url for call in responses.calls] == [
        HIBR_DOMAIN_URL,
        f"{HIBR_DOMAIN_URL}/2",
    ]


@responses.activate
def test_hibr_continues_after_an_empty_page_with_has_next(
    engine_hibr: DarkEyeEngine, fqdn_observable: Observable
) -> None:
    mock_hibr(hibr_page([], has_next=True))
    mock_hibr(hibr_page([hibr_item("5")]), url=f"{HIBR_DOMAIN_URL}/2")
    result = engine_hibr.analyze(fqdn_observable)
    assert result is not None
    assert [r["id"] for r in result["records"]] == ["5"]


@responses.activate
def test_hibr_documented_shape_results_and_pagination(
    engine_hibr: DarkEyeEngine, fqdn_observable: Observable
) -> None:
    mock_hibr({"results": [hibr_item("1")], "pagination": {"has_next": True}})
    mock_hibr(
        {"results": [{"id": "2", "leak_type": "ransomware_leak"}]}, url=f"{HIBR_DOMAIN_URL}/2"
    )
    result = engine_hibr.analyze(fqdn_observable)
    assert result is not None
    assert [(r["id"], r["category"]) for r in result["records"]] == [
        ("1", "breaches"),
        ("2", "ransomware"),
    ]


@responses.activate
def test_hibr_max_pages_truncates() -> None:
    engine = DarkEyeEngine(make_secrets(hibr=HIBR_KEY), {}, True, max_pages=2)
    mock_hibr(hibr_page([hibr_item("1")], has_next=True))
    mock_hibr(hibr_page([hibr_item("2")], has_next=True), url=f"{HIBR_DOMAIN_URL}/2")
    result = engine.analyze(Observable(value="example.com", type=ObservableType.FQDN))
    assert result is not None
    assert result["count"] == 2
    assert result["truncated"] is True
    assert len(responses.calls) == 2


@responses.activate
def test_hibr_default_max_pages_is_five(
    engine_hibr: DarkEyeEngine, fqdn_observable: Observable
) -> None:
    mock_hibr(hibr_page([hibr_item("1")], has_next=True))
    for page in range(2, 7):
        mock_hibr(hibr_page([hibr_item(str(page))], has_next=True), url=f"{HIBR_DOMAIN_URL}/{page}")
    result = engine_hibr.analyze(fqdn_observable)
    assert result is not None
    assert len(responses.calls) == 5
    assert result["truncated"] is True


@pytest.mark.parametrize("max_pages", [0, -3])
@responses.activate
def test_hibr_max_pages_has_a_floor_of_one(max_pages: int, fqdn_observable: Observable) -> None:
    engine = DarkEyeEngine(make_secrets(hibr=HIBR_KEY), {}, True, max_pages=max_pages)
    mock_hibr(hibr_page([hibr_item("1")], has_next=True))
    result = engine.analyze(fqdn_observable)
    assert result is not None
    assert len(responses.calls) == 1
    assert result["truncated"] is True


@pytest.mark.parametrize(
    ("leak_type", "category"),
    [
        ("ransomware_leak", "ransomware"),
        ("traditional_breach", "breaches"),
        ("stealer_log", "stealer_log"),
        (None, ""),
    ],
)
@responses.activate
def test_hibr_leak_type_mapping(
    engine_hibr: DarkEyeEngine,
    fqdn_observable: Observable,
    leak_type: str | None,
    category: str,
) -> None:
    mock_hibr(hibr_page([hibr_item("1", leak_type)]))  # pyright: ignore[reportArgumentType]
    result = engine_hibr.analyze(fqdn_observable)
    assert result is not None
    assert result["records"][0]["category"] == category


@responses.activate
def test_hibr_skips_invalid_and_idless_items(
    engine_hibr: DarkEyeEngine, fqdn_observable: Observable
) -> None:
    mock_hibr(hibr_page(["not-a-dict", {"post_title": "no id"}, hibr_item("1")]))  # pyright: ignore[reportArgumentType]
    result = engine_hibr.analyze(fqdn_observable)
    assert result is not None
    assert [r["id"] for r in result["records"]] == ["1"]


# ============================================================================
# Breach House shapes and truncation
# ============================================================================


@responses.activate
def test_breach_house_list_and_dict_shapes(
    engine_breach_house: DarkEyeEngine, fqdn_observable: Observable
) -> None:
    mock_breach_house(
        {
            "ransomware": [{"victim_id": "a"}],
            "breaches": {"results": [{"id": "b"}]},
            "leads": None,
            "stealers": "unexpected",
            "ignored": [{"id": "x"}],
        }
    )
    result = engine_breach_house.analyze(fqdn_observable)
    assert result is not None
    assert [(r["category"], r["id"]) for r in result["records"]] == [
        ("ransomware", "a"),
        ("breaches", "b"),
    ]
    assert result["truncated"] is False


@pytest.mark.parametrize("shape", ["list", "dict"])
@responses.activate
def test_breach_house_truncated_when_a_list_reaches_the_limit(
    fqdn_observable: Observable, shape: str
) -> None:
    engine = DarkEyeEngine(make_secrets(breach_house=BH_KEY), {}, True, limit=2)
    items = [{"id": "1"}, {"id": "2"}]
    mock_breach_house({"leads": items if shape == "list" else {"results": items}})
    result = engine.analyze(fqdn_observable)
    assert result is not None
    assert result["truncated"] is True
    assert result["count"] == 2


@pytest.mark.parametrize(
    ("limit", "expected"), [(1, "1"), (25, "25"), (500, "200"), (0, "1"), (-5, "1")]
)
@responses.activate
def test_breach_house_limit_is_clamped(
    fqdn_observable: Observable, limit: int, expected: str
) -> None:
    engine = DarkEyeEngine(make_secrets(breach_house=BH_KEY), {}, True, limit=limit)
    mock_breach_house({})
    assert engine.analyze(fqdn_observable) is not None
    request_url = responses.calls[0].request.url
    assert request_url is not None
    assert f"limit={expected}" in request_url


@responses.activate
def test_breach_house_skips_non_object_items(
    engine_breach_house: DarkEyeEngine, fqdn_observable: Observable
) -> None:
    mock_breach_house({"ransomware": ["text", 3, None, {"victim_id": "ok"}]})
    result = engine_breach_house.analyze(fqdn_observable)
    assert result is not None
    assert [r["id"] for r in result["records"]] == ["ok"]


# ============================================================================
# Records only keep listing metadata
# ============================================================================


@responses.activate
def test_records_keep_only_listing_metadata(
    engine_hibr: DarkEyeEngine, fqdn_observable: Observable
) -> None:
    mock_hibr(
        hibr_page(
            [
                hibr_item(
                    "1",
                    post_url="http://leaksite.onion/x",
                    description="leaked content",
                    download_url="https://example.net/dl",
                    proof_files=["a.png"],
                    **{"Identities Found": 12},
                )
            ]
        )
    )
    result = engine_hibr.analyze(fqdn_observable)
    assert result is not None
    assert set(result["records"][0]) == {
        "product",
        "category",
        "id",
        "title",
        "website",
        "group",
        "country",
        "discovered",
    }
    assert result["records"][0]["discovered"] == "2025-03-04"
    assert "leaksite" not in str(result)
    assert "leaked content" not in str(result)


@responses.activate
def test_record_strings_are_nfkc_normalized(
    engine_hibr: DarkEyeEngine, fqdn_observable: Observable
) -> None:
    mock_hibr(
        hibr_page(
            [
                hibr_item(
                    "1",
                    group_name="\uff2c\uff4f\uff43\uff4b  \uff22\uff49\uff54\n",
                    post_title="",
                )
            ]
        )
    )
    result = engine_hibr.analyze(fqdn_observable)
    assert result is not None
    assert result["records"][0]["group"] == "Lock Bit"
    # An empty title falls back to the website.
    assert result["records"][0]["title"] == "example.com"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("plain", "plain"),
        ("  spaced   out \n", "spaced out"),
        ("ﬁle", "file"),
        (42, "42"),
        (True, ""),
        (None, ""),
        (["x"], ""),
        ({"a": 1}, ""),
    ],
)
def test_clean(value: object, expected: str) -> None:
    assert clean(value) == expected


# ============================================================================
# Domain validation and URL handling
# ============================================================================


@pytest.mark.parametrize(
    "value",
    [
        "*.example.com",
        "exam?le.com",
        "example.*",
        "example",
        "localhost",
        "1.2.3.4",
        "example.com/path",
        "exa mple.com",
        "-",
        ".",
        "",
        "ex_ample.com",
    ],
)
@responses.activate
def test_invalid_domains_are_rejected_without_a_request(
    engine_both: DarkEyeEngine, value: str
) -> None:
    observable = Observable(value=value, type=ObservableType.FQDN)
    assert engine_both.analyze(observable) is None
    assert len(responses.calls) == 0


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("example.com", "example.com"),
        ("EXAMPLE.com.", "example.com"),
        ("  Sub.Example.CO.uk ", "sub.example.co.uk"),
        ("xn--bcher-kva.example", "xn--bcher-kva.example"),
        ("*.example.com", None),
        ("10.0.0.1", None),
        ("example.123", None),
    ],
)
def test_normalize_domain(value: str, expected: str | None) -> None:
    assert normalize_domain(value) == expected


@responses.activate
def test_url_is_reduced_to_its_domain(
    engine_both: DarkEyeEngine, url_observable: Observable
) -> None:
    mock_hibr()
    mock_breach_house()
    result = engine_both.analyze(url_observable)
    assert result is not None
    assert responses.calls[0].request.url == HIBR_DOMAIN_URL
    request_url = responses.calls[1].request.url
    assert request_url is not None
    assert "q=example.com" in request_url
    assert "some" not in request_url


@pytest.mark.parametrize(
    "value", ["http://1.2.3.4/path", "http://[2001:db8::1]/x", "not a url", "file:///etc/passwd"]
)
@responses.activate
def test_urls_without_a_domain_are_rejected(engine_both: DarkEyeEngine, value: str) -> None:
    observable = Observable(value=value, type=ObservableType.URL)
    assert engine_both.analyze(observable) is None
    assert len(responses.calls) == 0


@responses.activate
def test_fqdn_is_lowercased_and_trailing_dot_removed(engine_hibr: DarkEyeEngine) -> None:
    mock_hibr()
    observable = Observable(value="Example.COM", type=ObservableType.FQDN)
    result = engine_hibr.analyze(observable)
    assert result is not None
    assert responses.calls[0].request.url == HIBR_DOMAIN_URL


# ============================================================================
# HTTP failures
# ============================================================================


@pytest.mark.parametrize(
    ("status", "fragment"),
    [
        (401, "authentication failed"),
        (403, "authentication failed"),
        (429, "quota or rate limit"),
        (500, "HTTP 500"),
        (404, "HTTP 404"),
    ],
)
@pytest.mark.parametrize("product", [HIBR_NAME, BH_NAME])
@responses.activate
def test_http_errors_are_reported_per_product(
    fqdn_observable: Observable, product: str, status: int, fragment: str
) -> None:
    # The other product works, so the error is reported next to its records.
    engine = DarkEyeEngine(make_secrets(HIBR_KEY, BH_KEY), {}, True)
    mock_hibr(status=status if product == HIBR_NAME else 200)
    mock_breach_house(status=status if product == BH_NAME else 200)
    result = engine.analyze(fqdn_observable)
    assert result is not None
    assert len(result["errors"]) == 1
    assert result["errors"][0]["product"] == product
    assert fragment in result["errors"][0]["error"]
    assert product in result["errors"][0]["error"]


@pytest.mark.parametrize("body", ["<html>not json</html>", "", "{truncated"])
@responses.activate
def test_invalid_json_is_an_error(
    engine_hibr: DarkEyeEngine, fqdn_observable: Observable, body: str
) -> None:
    responses.add(responses.GET, HIBR_DOMAIN_URL, body=body, status=200)
    assert engine_hibr.analyze(fqdn_observable) is None


@pytest.mark.parametrize("body", ["[1, 2]", '"text"', "3", "null"])
@responses.activate
def test_non_object_json_is_an_error(
    engine_both: DarkEyeEngine, fqdn_observable: Observable, body: str
) -> None:
    responses.add(responses.GET, HIBR_DOMAIN_URL, body=body, status=200)
    responses.add(responses.GET, BREACH_HOUSE_URL, body=body, status=200)
    assert engine_both.analyze(fqdn_observable) is None


@responses.activate
def test_invalid_json_message(engine_both: DarkEyeEngine, fqdn_observable: Observable) -> None:
    responses.add(responses.GET, HIBR_DOMAIN_URL, body="oops", status=200)
    mock_breach_house()
    result = engine_both.analyze(fqdn_observable)
    assert result is not None
    assert result["errors"] == [
        {"product": HIBR_NAME, "error": f"{HIBR_NAME} returned invalid JSON."}
    ]


@responses.activate
def test_non_object_json_message(engine_both: DarkEyeEngine, fqdn_observable: Observable) -> None:
    mock_hibr([1, 2])
    mock_breach_house()
    result = engine_both.analyze(fqdn_observable)
    assert result is not None
    assert result["errors"][0]["error"] == f"{HIBR_NAME} returned an invalid response."


@pytest.mark.parametrize(
    "exception", [requests.ConnectionError, requests.Timeout, requests.exceptions.SSLError]
)
@responses.activate
def test_request_exceptions_are_reported_without_details(
    engine_both: DarkEyeEngine, fqdn_observable: Observable, exception: type[Exception]
) -> None:
    responses.add(responses.GET, HIBR_DOMAIN_URL, body=exception(f"boom {HIBR_KEY}"))
    mock_breach_house()
    result = engine_both.analyze(fqdn_observable)
    assert result is not None
    assert result["errors"] == [
        {"product": HIBR_NAME, "error": f"{HIBR_NAME} request failed or timed out."}
    ]


@responses.activate
def test_redirects_are_not_followed(
    engine_hibr: DarkEyeEngine, fqdn_observable: Observable
) -> None:
    responses.add(
        responses.GET,
        HIBR_DOMAIN_URL,
        status=302,
        headers={"Location": "https://attacker.example/steal"},
    )
    responses.add(responses.GET, "https://attacker.example/steal", json=hibr_page([hibr_item()]))
    assert engine_hibr.analyze(fqdn_observable) is None
    assert len(responses.calls) == 1


@responses.activate
def test_redirect_error_is_reported_when_the_other_product_works(
    engine_both: DarkEyeEngine, fqdn_observable: Observable
) -> None:
    responses.add(
        responses.GET, BREACH_HOUSE_URL, status=301, headers={"Location": "https://other.example/"}
    )
    mock_hibr()
    result = engine_both.analyze(fqdn_observable)
    assert result is not None
    assert result["errors"][0]["error"] == f"{BH_NAME} returned HTTP 301."
    assert all(
        call.request.url is not None and "other.example" not in call.request.url
        for call in responses.calls
    )


# ============================================================================
# Secrets never reach the logs or the result
# ============================================================================


@responses.activate
def test_keys_are_never_logged_or_returned(
    engine_both: DarkEyeEngine, fqdn_observable: Observable, caplog: pytest.LogCaptureFixture
) -> None:
    responses.add(responses.GET, HIBR_DOMAIN_URL, body=requests.ConnectionError(f"{HIBR_KEY}"))
    responses.add(
        responses.GET,
        BREACH_HOUSE_URL,
        body=requests.Timeout(f"Bearer {BH_KEY}"),
    )
    with caplog.at_level(logging.DEBUG):
        assert engine_both.analyze(fqdn_observable) is None
    assert HIBR_KEY not in caplog.text
    assert BH_KEY not in caplog.text
    assert "request failed" in caplog.text


@responses.activate
def test_keys_not_in_result_or_logs_on_success(
    engine_both: DarkEyeEngine, fqdn_observable: Observable, caplog: pytest.LogCaptureFixture
) -> None:
    mock_hibr()
    mock_breach_house(status=401)
    with caplog.at_level(logging.DEBUG):
        result = engine_both.analyze(fqdn_observable)
    assert result is not None
    assert HIBR_KEY not in str(result) + caplog.text
    assert BH_KEY not in str(result) + caplog.text


# ============================================================================
# Export row
# ============================================================================


EMPTY_ROW = {
    "darkeye_found": None,
    "darkeye_count": None,
    "darkeye_products": None,
    "darkeye_categories": None,
    "darkeye_groups": None,
}


@pytest.mark.parametrize("value", [None, {}, "", []])
def test_export_row_without_result(engine_both: DarkEyeEngine, value: object) -> None:
    assert engine_both.create_export_row(value) == EMPTY_ROW


@responses.activate
def test_export_row_with_records(engine_both: DarkEyeEngine, fqdn_observable: Observable) -> None:
    mock_hibr(hibr_page([hibr_item("1", "ransomware_leak", group_name="akira")]))
    mock_breach_house()
    result = engine_both.analyze(fqdn_observable)
    assert result is not None
    assert engine_both.create_export_row(result) == {
        "darkeye_found": True,
        "darkeye_count": 4,
        "darkeye_products": f"{HIBR_NAME}, {BH_NAME}",
        "darkeye_categories": "breaches, ransomware, stealers",
        "darkeye_groups": "akira, lockbit",
    }


def test_export_row_not_found(engine_both: DarkEyeEngine) -> None:
    row = engine_both.create_export_row(
        {"found": False, "count": 0, "products": [HIBR_NAME], "errors": [], "records": []}
    )
    assert row == {
        "darkeye_found": False,
        "darkeye_count": 0,
        "darkeye_products": HIBR_NAME,
        "darkeye_categories": None,
        "darkeye_groups": None,
    }
