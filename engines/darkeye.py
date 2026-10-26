"""DarkEye engine: ransomware, breach, lead and stealer log records for a domain.

DarkEye (https://darkeye.io) exposes this data through two APIs, each with its own
optional key: Have I Been Ransomed? (``DARKEYE_HIBR_API_KEY``) and Breach House
(``DARKEYE_BREACH_HOUSE_API_KEY``). The engine queries every product that has a key
and returns one combined result. A product that fails does not hide the records of the
other one: its failure is reported in ``errors``.

Only listing metadata is kept for each record. Leaked content, proof files, leak site
URLs and download URLs are never read from the responses.
"""

import logging
import re
import unicodedata
from dataclasses import asdict
from enum import StrEnum

import requests
from pydantic.dataclasses import dataclass
from requests.exceptions import RequestException
from typing_extensions import override

from models.base_engine import BaseEngine
from models.observable import Observable, ObservableType
from utils.config import Secrets

logger = logging.getLogger(__name__)

JsonObject = dict[str, object]

HIBR_URL = "https://haveibeenransom.com/api/metadata/domain"
HIBR_CATEGORIES: dict[str, str] = {
    "ransomware_leak": "ransomware",
    "traditional_breach": "breaches",
}
DEFAULT_MAX_PAGES = 5

BREACH_HOUSE_URL = "https://breach.house/api/v1/search"
BREACH_HOUSE_CATEGORIES: tuple[str, ...] = ("ransomware", "breaches", "leads", "stealers")
DEFAULT_LIMIT = 25
MAX_LIMIT = 200

REQUEST_TIMEOUT = 15

# The APIs treat * and ? as wildcards, so only plain domain names are queried.
DOMAIN_REGEX = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")


class Product(StrEnum):
    """DarkEye products wrapped by the engine."""

    HIBR = "Have I Been Ransomed?"
    BREACH_HOUSE = "Breach House"


class DarkEyeError(Exception):
    """A product lookup failed. The message is safe to log and to show to users."""


@dataclass
class Record:
    """Listing metadata of one record, the only data kept from the APIs."""

    product: str
    category: str
    id: str
    title: str
    website: str
    group: str
    country: str
    discovered: str


@dataclass
class ProductResult:
    """Records returned by one product, and whether a cap cut the list short."""

    records: list[Record]
    truncated: bool


def clean(value: object) -> str:
    """Return a NFKC-normalized single-line string, or "" for non-text values.

    Some group and source names use styled Unicode characters and irregular spacing.
    """
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return ""
    return " ".join(unicodedata.normalize("NFKC", str(value)).split())


def as_object(value: object) -> JsonObject:
    """Return value when it is a JSON object, else an empty one."""
    if not isinstance(value, dict):
        return {}
    return {str(key): item for key, item in value.items()}  # pyright: ignore[reportUnknownVariableType]


def as_list(value: object) -> list[object]:
    """Return value when it is a JSON array, else an empty list."""
    if not isinstance(value, list):
        return []
    return list(value)  # pyright: ignore[reportUnknownArgumentType]


def normalize_domain(value: str) -> str | None:
    """Return a lowercase plain domain name, or None when value is not one."""
    domain = value.strip().lower().rstrip(".")
    if not DOMAIN_REGEX.match(domain):
        return None
    # An IP address matches the pattern above; a TLD is never numeric.
    if domain.rsplit(".", 1)[-1].isdigit():
        return None
    return domain


def build_record(product: Product, category: str, item: JsonObject) -> Record:
    """Keep only listing metadata of an API item."""
    website = clean(item.get("website"))
    return Record(
        product=product.value,
        category=category,
        id=clean(item.get("victim_id") or item.get("id_source") or item.get("id")),
        title=clean(item.get("post_title")) or clean(item.get("name")) or website,
        website=website,
        group=clean(item.get("group_name")),
        country=clean(item.get("country")),
        discovered=clean(item.get("discovered"))[:10],
    )


def parse_hibr_page(data: JsonObject, seen: set[str]) -> list[Record]:
    """Parse the records of one Have I Been Ransomed? page, skipping seen ids.

    The API returns ``sources``; its documentation shows ``results``.
    """
    records: list[Record] = []
    for entry in as_list(data.get("sources") or data.get("results")):
        leak = as_object(entry)
        # A leak indexed while paging is repeated on a later page.
        leak_id = clean(leak.get("id_source") or leak.get("id"))
        if not leak_id or leak_id in seen:
            continue
        seen.add(leak_id)
        leak_type = clean(leak.get("leak_type"))
        category = HIBR_CATEGORIES.get(leak_type, leak_type)
        records.append(build_record(Product.HIBR, category, leak))
    return records


def hibr_has_next(data: JsonObject) -> bool:
    """Tell whether another page exists: top-level ``has_next`` or ``pagination``."""
    pagination = as_object(data.get("pagination"))
    return bool(data.get("has_next", pagination.get("has_next", False)))


def parse_breach_house(data: JsonObject, limit: int) -> ProductResult:
    """Parse the Breach House lists; each is a list or an object with ``results``."""
    records: list[Record] = []
    truncated = False
    for category in BREACH_HOUSE_CATEGORIES:
        section = data.get(category)
        items = as_list(as_object(section).get("results") if isinstance(section, dict) else section)
        if len(items) >= limit:
            truncated = True
        records.extend(
            build_record(Product.BREACH_HOUSE, category, as_object(item))
            for item in items
            if isinstance(item, dict)
        )
    return ProductResult(records=records, truncated=truncated)


def error_message(product: Product, status_code: int) -> str:
    """Return a user-facing message for a non-200 HTTP status."""
    if status_code in (401, 403):
        return f"{product.value} authentication failed; check its API key."
    if status_code == 429:
        return f"{product.value} quota or rate limit reached; retry later."
    return f"{product.value} returned HTTP {status_code}."


class DarkEyeEngine(BaseEngine):
    def __init__(
        self,
        secrets: Secrets,
        proxies: dict[str, str],
        ssl_verify: bool,
        max_pages: int = DEFAULT_MAX_PAGES,
        limit: int = DEFAULT_LIMIT,
    ):
        super().__init__(secrets, proxies, ssl_verify)
        self.max_pages: int = max(1, max_pages)
        self.limit: int = min(max(1, limit), MAX_LIMIT)

    @property
    @override
    def name(self) -> str:
        return "darkeye"

    @property
    @override
    def supported_types(self) -> ObservableType:
        return ObservableType.FQDN | ObservableType.URL

    @override
    def analyze(self, observable: Observable) -> dict[str, object] | None:
        keys = self._configured_keys()
        if not keys:
            logger.warning("DarkEye API keys are not configured.")
            return None

        domain = self._domain_of(observable)
        if domain is None:
            logger.error("DarkEye needs a plain domain name, got: %s", observable.value)
            return None

        results: dict[Product, ProductResult] = {}
        errors: list[dict[str, str]] = []
        for product, api_key in keys.items():
            try:
                results[product] = self._query(product, api_key, domain)
            except DarkEyeError as e:
                logger.error("Error querying DarkEye for '%s': %s", observable.value, e)
                errors.append({"product": product.value, "error": str(e)})

        if not results:
            # Every product failed: an empty result would read as "nothing found".
            return None
        return self._build_result(results, errors)

    def _configured_keys(self) -> dict[Product, str]:
        keys = {
            Product.HIBR: self.secrets.darkeye_hibr_api_key,
            Product.BREACH_HOUSE: self.secrets.darkeye_breach_house_api_key,
        }
        return {product: key for product, key in keys.items() if key}

    @staticmethod
    def _domain_of(observable: Observable) -> str | None:
        value = observable.value
        if observable.type is ObservableType.URL:
            value = observable._return_fqdn_from_url()
        return normalize_domain(value)

    def _query(self, product: Product, api_key: str, domain: str) -> ProductResult:
        if product is Product.HIBR:
            return self._fetch_hibr(domain, api_key)
        return self._fetch_breach_house(domain, api_key)

    def _fetch_hibr(self, domain: str, api_key: str) -> ProductResult:
        records: list[Record] = []
        seen: set[str] = set()
        for page in range(1, self.max_pages + 1):
            url = f"{HIBR_URL}/{domain}" if page == 1 else f"{HIBR_URL}/{domain}/{page}"
            data = self._get_json(Product.HIBR, url, api_key)
            records.extend(parse_hibr_page(data, seen))
            # A page can be short or empty and still have a next page.
            if not hibr_has_next(data):
                return ProductResult(records=records, truncated=False)
        return ProductResult(records=records, truncated=True)

    def _fetch_breach_house(self, domain: str, api_key: str) -> ProductResult:
        params = {"q": domain, "limit": str(self.limit)}
        data = self._get_json(Product.BREACH_HOUSE, BREACH_HOUSE_URL, api_key, params)
        return parse_breach_house(data, self.limit)

    def _get_json(
        self,
        product: Product,
        url: str,
        api_key: str,
        params: dict[str, str] | None = None,
    ) -> JsonObject:
        headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}
        try:
            response = requests.get(
                url,
                params=params,
                headers=headers,
                proxies=self.proxies,
                verify=self.ssl_verify,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
            )
        except RequestException:
            # Request exceptions can carry request details: never log or re-raise them.
            raise DarkEyeError(f"{product.value} request failed or timed out.") from None

        if response.status_code != 200:
            raise DarkEyeError(error_message(product, response.status_code))
        try:
            data: object = response.json()
        except ValueError:
            raise DarkEyeError(f"{product.value} returned invalid JSON.") from None
        if not isinstance(data, dict):
            raise DarkEyeError(f"{product.value} returned an invalid response.")
        return as_object(data)  # pyright: ignore[reportUnknownArgumentType]

    @staticmethod
    def _build_result(
        results: dict[Product, ProductResult],
        errors: list[dict[str, str]],
    ) -> dict[str, object]:
        records = [asdict(r) for result in results.values() for r in result.records]
        output: dict[str, object] = {
            "found": bool(records),
            "count": len(records),
            "products": [product.value for product in results],
            "truncated": any(result.truncated for result in results.values()),
            "errors": errors,
            "records": records,
        }
        return output

    @override
    def create_export_row(self, analysis_result: object) -> dict[str, object]:
        if not isinstance(analysis_result, dict) or not analysis_result:
            return {
                "darkeye_found": None,
                "darkeye_count": None,
                "darkeye_products": None,
                "darkeye_categories": None,
                "darkeye_groups": None,
            }

        result = as_object(analysis_result)  # pyright: ignore[reportUnknownArgumentType]
        records = [as_object(r) for r in as_list(result.get("records"))]
        products = [clean(p) for p in as_list(result.get("products"))]
        categories = sorted({clean(r.get("category")) for r in records} - {""})
        groups = sorted({clean(r.get("group")) for r in records} - {""})
        return {
            "darkeye_found": result.get("found"),
            "darkeye_count": result.get("count"),
            "darkeye_products": ", ".join(products) if products else None,
            "darkeye_categories": ", ".join(categories) if categories else None,
            "darkeye_groups": ", ".join(groups) if groups else None,
        }
