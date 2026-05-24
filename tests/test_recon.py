"""Comprehensive unit tests for the recon module (DNS, WHOIS, Subdomains, Portscan)."""

import time
import socket
from unittest.mock import MagicMock, Mock, patch, call, PropertyMock

import pytest

from src.modules.recon.dns import resolve_dns
from src.modules.recon.whois import lookup_whois
from src.modules.recon.subdomains import enumerate_subdomains, _resolve_subdomain, _query_crtsh, SUBDOMAIN_WORDLIST
from src.modules.recon.portscan import scan_ports, _scan_port, _grab_banner, _resolve_host
from src.core.scanner import Scanner


# =============================================================================
# Helper: Mock DNS records
# =============================================================================

class _MockRecord:
    """Mock DNS record that returns a string value when str()-ed."""
    def __init__(self, value: str):
        self._value = value

    def __str__(self):
        return self._value


class _MockMXRecord:
    """Mock MX record with an .exchange attribute."""
    def __init__(self, exchange: str):
        self._exchange = exchange

    @property
    def exchange(self):
        return _MockRecord(self._exchange)


def _dns_success_side_effect(domain, rtype):
    """Side effect factory for a successful DNS resolution (all types)."""
    # Import exceptions here so they are available in mock context
    import dns.resolver

    records = {
        "A": [_MockRecord("93.184.216.34")],
        "MX": [_MockMXRecord("mail.example.com.")],
        "NS": [_MockRecord("ns1.example.com."), _MockRecord("ns2.example.com.")],
        "TXT": [_MockRecord("v=spf1 include:_spf.example.com ~all")],
    }
    if rtype == "CNAME":
        raise dns.resolver.NoAnswer()
    if rtype in records:
        return records[rtype]
    return []


# =============================================================================
# DNS Tests
# =============================================================================

class TestDNS:
    """Tests for src.modules.recon.dns.resolve_dns."""

    # -- Fixtures -----------------------------------------------------------

    @pytest.fixture
    def mock_resolver(self):
        """Patch dns.resolver.Resolver and return the mock instance."""
        with patch("src.modules.recon.dns.dns.resolver.Resolver") as mock_cls:
            inst = MagicMock()
            mock_cls.return_value = inst
            yield inst

    # -- Tests --------------------------------------------------------------

    def test_resolve_dns_success(self, mock_resolver, mock_dns_results):
        """Successful resolution returns all expected record types."""
        mock_resolver.resolve.side_effect = _dns_success_side_effect

        result = resolve_dns("example.com")

        assert result["A"] == ["93.184.216.34"]
        assert result["MX"] == ["mail.example.com"]
        assert result["NS"] == ["ns1.example.com", "ns2.example.com"]
        assert result["TXT"] == ["v=spf1 include:_spf.example.com ~all"]
        assert result["CNAME"] == []
        # Verify resolver configuration
        assert mock_resolver.timeout == 5.0
        assert mock_resolver.lifetime == 5.0

    def test_resolve_dns_nxdomain(self, mock_resolver):
        """NXDOMAIN should return empty dict."""
        import dns.resolver
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN

        result = resolve_dns("nonexistent.example.com")
        assert result == {}

    def test_resolve_dns_timeout(self, mock_resolver):
        """DNS Timeout should return empty dict."""
        import dns.exception
        mock_resolver.resolve.side_effect = dns.exception.Timeout

        result = resolve_dns("slow.example.com")
        assert result == {}

    def test_resolve_dns_no_nameservers(self, mock_resolver):
        """NoNameservers should return empty dict."""
        import dns.resolver
        mock_resolver.resolve.side_effect = dns.resolver.NoNameservers

        result = resolve_dns("isolated.example.com")
        assert result == {}

    def test_resolve_dns_no_answer(self, mock_resolver):
        """NoAnswer for a record type should be silently skipped."""
        import dns.resolver

        # Return A record successfully, then raise NoAnswer for others
        def side_effect(domain, rtype):
            if rtype == "A":
                return [_MockRecord("93.184.216.34")]
            raise dns.resolver.NoAnswer()

        mock_resolver.resolve.side_effect = side_effect
        result = resolve_dns("example.com")

        assert result["A"] == ["93.184.216.34"]
        assert result["MX"] == []
        assert result["CNAME"] == []

    def test_resolve_dns_generic_exception(self, mock_resolver):
        """Generic exception on a record type should be logged and skipped."""
        mock_resolver.resolve.side_effect = RuntimeError("unexpected")

        result = resolve_dns("example.com")

        # The generic except catches RuntimeError, continues to next type.
        # Since side_effect raises every time, all types return empty.
        assert result["A"] == []
        assert result["MX"] == []
        assert result["NS"] == []
        assert result["TXT"] == []
        assert result["CNAME"] == []

    def test_resolve_dns_invalid_domain_empty(self):
        """Empty domain returns empty dict."""
        assert resolve_dns("") == {}

    def test_resolve_dns_invalid_domain_none(self):
        """None domain returns empty dict."""
        assert resolve_dns(None) == {}

    def test_resolve_dns_invalid_domain_not_string(self):
        """Non-string domain (int) returns empty dict."""
        assert resolve_dns(123) == {}

    def test_resolve_dns_no_dnspython(self, mock_resolver):
        """When dnspython is missing, return empty dict."""
        with patch("src.modules.recon.dns.HAS_DNSPYTHON", False):
            result = resolve_dns("example.com")
        assert result == {}
        # Resolver should NOT have been called
        mock_resolver.resolve.assert_not_called()

    def test_resolve_dns_return_format(self, mock_resolver):
        """Return dict has exactly the expected keys."""
        mock_resolver.resolve.side_effect = _dns_success_side_effect

        result = resolve_dns("example.com")

        assert set(result.keys()) == {"A", "MX", "NS", "TXT", "CNAME"}
        assert isinstance(result["A"], list)
        assert isinstance(result["MX"], list)
        assert isinstance(result["NS"], list)
        assert isinstance(result["TXT"], list)
        assert isinstance(result["CNAME"], list)

    def test_resolve_dns_mx_trailing_dot_stripped(self, mock_resolver):
        """MX exchange trailing dot is stripped."""
        import dns.resolver
        # Return an MX with trailing dot
        mock_resolver.resolve.side_effect = lambda d, r: (
            [_MockMXRecord("smtp.example.com.")] if r == "MX"
            else (_MockRecord("10.0.0.1") if r == "A" else (_ for _ in ()).throw(dns.resolver.NoAnswer()))
        )

        result = resolve_dns("example.com")
        assert result["MX"] == ["smtp.example.com"]
        assert not result["MX"][0].endswith(".")  # no trailing dot

    def test_resolve_dns_cname(self, mock_resolver):
        """CNAME records are returned correctly."""
        import dns.resolver

        def side_effect(domain, rtype):
            if rtype == "CNAME":
                return [_MockRecord("target.example.com.")]
            if rtype == "A":
                return [_MockRecord("10.0.0.1")]
            raise dns.resolver.NoAnswer()

        mock_resolver.resolve.side_effect = side_effect
        result = resolve_dns("alias.example.com")

        assert result["CNAME"] == ["target.example.com"]
        assert result["A"] == ["10.0.0.1"]

    def test_resolve_dns_timeout_parameter_passed(self, mock_resolver):
        """Custom timeout is passed to the resolver."""
        import dns.resolver

        mock_resolver.resolve.side_effect = lambda d, r: (
            [_MockRecord("10.0.0.1")] if r == "A" else (_ for _ in ()).throw(dns.resolver.NoAnswer())
        )

        resolve_dns("example.com", timeout=10.0)
        assert mock_resolver.timeout == 10.0
        assert mock_resolver.lifetime == 10.0

    def test_resolve_dns_txt_multiple_values(self, mock_resolver):
        """Multiple TXT records are all returned."""
        import dns.resolver

        def side_effect(domain, rtype):
            if rtype == "TXT":
                return [
                    _MockRecord("v=spf1 include:_spf.example.com ~all"),
                    _MockRecord("google-site-verification=abc123"),
                ]
            if rtype == "A":
                return [_MockRecord("10.0.0.1")]
            raise dns.resolver.NoAnswer()

        mock_resolver.resolve.side_effect = side_effect
        result = resolve_dns("example.com")

        assert "v=spf1 include:_spf.example.com ~all" in result["TXT"]
        assert "google-site-verification=abc123" in result["TXT"]
        assert len(result["TXT"]) == 2


# =============================================================================
# WHOIS Tests
# =============================================================================

class TestWHOIS:
    """Tests for src.modules.recon.whois.lookup_whois."""

    @pytest.fixture
    def mock_whois_call(self):
        """Patch only whois.whois() function, keeping whois.parser intact."""
        with patch("src.modules.recon.whois.whois.whois") as mock_w:
            yield mock_w

    # -- Helpers ------------------------------------------------------------

    def _make_whois_obj(self, **kwargs):
        """Create a mock WHOIS result object with the given attributes."""
        defaults = {
            "registrar": "Example Registrar Inc",
            "org": "Example Organization",
            "country": "US",
            "creation_date": "1995-08-14T00:00:00",
            "expiration_date": "2025-08-13T00:00:00",
            "updated_date": "2024-01-01T00:00:00",
            "name_servers": ["ns1.example.com", "ns2.example.com"],
            "text": "Raw WHOIS data here",
        }
        defaults.update(kwargs)

        class FakeWhoisResult:
            """Simulates a whois lookup result with attribute access and str()."""
            def __init__(self, data):
                for k, v in data.items():
                    if k != "text":
                        setattr(self, k, v)
                self._text = data.get("text", "")

            def __str__(self):
                return self._text

            @property
            def text(self):
                return self._text

        return FakeWhoisResult(defaults)

    # -- Tests --------------------------------------------------------------

    def test_lookup_whois_success(self, mock_whois_call, mock_whois_results):
        """Successful WHOIS lookup returns structured data."""
        mock_obj = self._make_whois_obj()
        mock_whois_call.return_value = mock_obj

        result = lookup_whois("example.com")

        assert result["registrar"] == "Example Registrar Inc"
        assert result["organization"] == "Example Organization"
        assert result["country"] == "US"
        assert result["name_servers"] == ["ns1.example.com", "ns2.example.com"]
        assert isinstance(result["raw"], str)
        assert "Raw WHOIS" in result["raw"]

    def test_lookup_whois_no_public_whois(self, mock_whois_call):
        """Domain without public WHOIS returns empty result."""
        mock_whois_call.side_effect = Exception("No WHOIS data")

        result = lookup_whois("local.domain")
        assert result["registrar"] is None
        assert result["name_servers"] == []
        assert result["raw"] is None

    def test_lookup_whois_pywhois_error(self, mock_whois_call):
        """A PywhoisError from the whois lib is handled by the specific except."""
        import whois.exceptions
        mock_whois_call.side_effect = whois.exceptions.PywhoisError("Parse error")

        result = lookup_whois("example.com")
        assert result["registrar"] is None
        assert result["name_servers"] == []

    def test_lookup_whois_generic_exception(self, mock_whois_call):
        """Generic exception during WHOIS lookup returns empty result."""
        mock_whois_call.side_effect = ConnectionError("Network error")

        result = lookup_whois("example.com")
        assert result["registrar"] is None
        assert result["organization"] is None

    def test_lookup_whois_invalid_domain_empty(self, mock_whois_call):
        """Empty domain returns empty result."""
        result = lookup_whois("")
        assert result["registrar"] is None
        assert result["name_servers"] == []
        mock_whois_call.assert_not_called()

    def test_lookup_whois_invalid_domain_none(self, mock_whois_call):
        """None domain returns empty result."""
        result = lookup_whois(None)
        assert result["registrar"] is None
        mock_whois_call.assert_not_called()

    def test_lookup_whois_invalid_domain_not_string(self, mock_whois_call):
        """Non-string domain returns empty result."""
        result = lookup_whois(42)
        assert result["registrar"] is None
        mock_whois_call.assert_not_called()

    def test_lookup_whois_no_whois_lib(self, mock_whois_call):
        """When python-whois is missing, return empty result."""
        with patch("src.modules.recon.whois.HAS_WHOIS", False):
            result = lookup_whois("example.com")
        assert result["registrar"] is None
        assert result["name_servers"] == []
        mock_whois_call.assert_not_called()

    def test_lookup_whois_return_format(self, mock_whois_call):
        """Return dict has exactly the expected keys."""
        mock_obj = self._make_whois_obj()
        mock_whois_call.return_value = mock_obj

        result = lookup_whois("example.com")

        expected_keys = {
            "registrar", "organization", "country",
            "creation_date", "expiration_date", "updated_date",
            "name_servers", "raw",
        }
        assert set(result.keys()) == expected_keys

    def test_lookup_whois_lists_as_values(self, mock_whois_call):
        """Fields that may be lists are handled (registrar as list)."""
        mock_obj = self._make_whois_obj(registrar=["Registrar A", "Registrar B"])
        mock_whois_call.return_value = mock_obj

        result = lookup_whois("example.com")
        # _first_str should take the first element
        assert result["registrar"] == "Registrar A"

    def test_lookup_whois_dates_as_datetime(self, mock_whois_call):
        """Datetime objects are formatted to ISO strings."""
        from datetime import datetime, timezone

        dt = datetime(2020, 6, 15, 10, 30, 0, tzinfo=timezone.utc)
        mock_obj = self._make_whois_obj(creation_date=dt)
        mock_whois_call.return_value = mock_obj

        result = lookup_whois("example.com")
        assert result["creation_date"] == "2020-06-15T10:30:00+00:00"

    def test_lookup_whois_dates_as_list(self, mock_whois_call):
        """Date as a list uses the first element."""
        from datetime import datetime, timezone

        dt1 = datetime(2020, 6, 15, 10, 30, 0, tzinfo=timezone.utc)
        dt2 = datetime(2021, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        mock_obj = self._make_whois_obj(creation_date=[dt1, dt2])
        mock_whois_call.return_value = mock_obj

        result = lookup_whois("example.com")
        assert "2020-06-15" in result["creation_date"]

    def test_lookup_whois_missing_attributes(self, mock_whois_call):
        """Missing attributes on the WHOIS object are handled gracefully."""
        # Create an object without the expected attributes
        mock_obj = MagicMock(spec=[])  # empty spec = no attributes
        # hasattr will return False for all
        mock_whois_call.return_value = mock_obj

        result = lookup_whois("example.com")
        assert result["registrar"] is None
        assert result["organization"] is None
        assert result["name_servers"] == []

    def test_lookup_whois_raw_truncated(self, mock_whois_call):
        """Raw WHOIS data is truncated to 500 chars."""
        long_text = "X" * 2000
        mock_obj = self._make_whois_obj(text=long_text)
        mock_whois_call.return_value = mock_obj

        result = lookup_whois("example.com")
        assert len(result["raw"]) == 500
        assert result["raw"] == "X" * 500

    def test_lookup_whois_raw_none(self, mock_whois_call):
        """When w.text is falsy, raw is None."""
        mock_obj = self._make_whois_obj(text="")
        mock_whois_call.return_value = mock_obj

        result = lookup_whois("example.com")
        assert result["raw"] is None

    def test_lookup_whois_date_as_plain_string(self, mock_whois_call):
        """When the whois lib returns a plain string date, it's passed through."""
        mock_obj = self._make_whois_obj(creation_date="1995-08-14")
        mock_whois_call.return_value = mock_obj

        result = lookup_whois("example.com")
        assert result["creation_date"] == "1995-08-14"

    def test_lookup_whois_org_as_list(self, mock_whois_call):
        """Organization as a list uses the first element."""
        mock_obj = self._make_whois_obj(org=["Org Alpha", "Org Beta"])
        mock_whois_call.return_value = mock_obj

        result = lookup_whois("example.com")
        assert result["organization"] == "Org Alpha"

    def test_lookup_whois_nameservers_single_string(self, mock_whois_call):
        """Name servers as a single string is normalized to a list."""
        mock_obj = self._make_whois_obj(name_servers="ns1.example.com")
        mock_whois_call.return_value = mock_obj

        result = lookup_whois("example.com")
        assert result["name_servers"] == ["ns1.example.com"]

    def test_lookup_whois_org_as_none(self, mock_whois_call):
        """Organization as None is handled correctly."""
        mock_obj = self._make_whois_obj(org=None)
        mock_whois_call.return_value = mock_obj

        result = lookup_whois("example.com")
        assert result["organization"] is None

    def test_lookup_whois_name_servers_none(self, mock_whois_call):
        """Name servers as None returns empty list."""
        mock_obj = self._make_whois_obj(name_servers=None)
        mock_whois_call.return_value = mock_obj

        result = lookup_whois("example.com")
        assert result["name_servers"] == []

    def test_lookup_whois_date_empty_list(self, mock_whois_call):
        """Date as an empty list returns None."""
        mock_obj = self._make_whois_obj(creation_date=[])
        mock_whois_call.return_value = mock_obj

        result = lookup_whois("example.com")
        assert result["creation_date"] is None

    def test_lookup_whois_all_dates_none(self, mock_whois_call):
        """All dates as None returns None for each."""
        mock_obj = self._make_whois_obj(
            creation_date=None, expiration_date=None, updated_date=None,
        )
        mock_whois_call.return_value = mock_obj

        result = lookup_whois("example.com")
        assert result["creation_date"] is None
        assert result["expiration_date"] is None
        assert result["updated_date"] is None


# =============================================================================
# Subdomain Tests
# =============================================================================

class TestSubdomains:
    """Tests for src.modules.recon.subdomains.enumerate_subdomains."""

    # -- Fixtures -----------------------------------------------------------

    @pytest.fixture(autouse=True)
    def mock_time_sleep(self):
        """Prevent actual time.sleep calls during tests."""
        with patch("src.modules.recon.subdomains.time.sleep") as mock:
            yield mock

    @pytest.fixture
    def mock_resolve_subdomain(self):
        """Patch _resolve_subdomain to return controlled IPs."""
        with patch("src.modules.recon.subdomains._resolve_subdomain") as mock:
            yield mock

    @pytest.fixture
    def mock_query_crtsh(self):
        """Patch _query_crtsh to return controlled results."""
        with patch("src.modules.recon.subdomains._query_crtsh") as mock:
            yield mock

    @pytest.fixture
    def short_wordlist(self):
        """Replace the subdomain wordlist with a short one for test speed."""
        test_list = ["www", "mail", "admin", "api", "dev"]
        with patch("src.modules.recon.subdomains.SUBDOMAIN_WORDLIST", test_list):
            yield test_list

    # -- Tests --------------------------------------------------------------

    def test_enumerate_subdomains_bruteforce(self, mock_time_sleep, mock_resolve_subdomain,
                                              mock_query_crtsh, short_wordlist):
        """Brute-force finds subdomains via DNS resolution."""
        def resolve_side_effect(fqdn):
            mapping = {
                "www.example.com": "93.184.216.34",
                "mail.example.com": "93.184.216.35",
                "admin.example.com": "93.184.216.36",
            }
            return mapping.get(fqdn)

        mock_resolve_subdomain.side_effect = resolve_side_effect
        mock_query_crtsh.return_value = set()

        results = enumerate_subdomains("example.com")

        assert len(results) == 3
        fqdns = {r["subdomain"] for r in results}
        assert "www.example.com" in fqdns
        assert "mail.example.com" in fqdns
        assert "admin.example.com" in fqdns
        # All should be from bruteforce source
        for r in results:
            assert r["source"] == "bruteforce"

    def test_enumerate_subdomains_crtsh(self, mock_time_sleep, mock_resolve_subdomain,
                                          mock_query_crtsh, short_wordlist):
        """crt.sh passive discovery finds additional subdomains."""
        # Only resolve www via bruteforce; the rest come from crt.sh
        def resolve_side_effect(fqdn):
            mapping = {
                "www.example.com": "93.184.216.34",
                "hidden.example.com": "10.0.0.1",
                "staging.example.com": "10.0.0.2",
            }
            return mapping.get(fqdn)

        mock_resolve_subdomain.side_effect = resolve_side_effect
        mock_query_crtsh.return_value = {"hidden.example.com", "staging.example.com"}

        results = enumerate_subdomains("example.com")

        assert len(results) == 3
        sources = {r["subdomain"]: r["source"] for r in results}
        assert sources["www.example.com"] == "bruteforce"
        assert sources["hidden.example.com"] == "crtsh"
        assert sources["staging.example.com"] == "crtsh"

    def test_enumerate_subdomains_no_results(self, mock_time_sleep, mock_resolve_subdomain,
                                               mock_query_crtsh, short_wordlist):
        """No resolvable subdomains returns empty list."""
        mock_resolve_subdomain.return_value = None
        mock_query_crtsh.return_value = set()

        results = enumerate_subdomains("example.com")
        assert results == []

    def test_enumerate_subdomains_deduplication(self, mock_time_sleep, mock_resolve_subdomain,
                                                  mock_query_crtsh, short_wordlist):
        """Same subdomain from both sources is not duplicated."""
        def resolve_side_effect(fqdn):
            mapping = {
                "www.example.com": "93.184.216.34",
                "mail.example.com": "93.184.216.35",
            }
            return mapping.get(fqdn)

        mock_resolve_subdomain.side_effect = resolve_side_effect
        # crt.sh returns same subdomains already found
        mock_query_crtsh.return_value = {"www.example.com"}

        results = enumerate_subdomains("example.com")

        assert len(results) == 2  # not 3
        # www should keep bruteforce source (first found)
        www_result = [r for r in results if r["subdomain"] == "www.example.com"][0]
        assert www_result["source"] == "bruteforce"

    def test_enumerate_subdomains_invalid_domain_empty(self):
        """Empty domain returns empty list."""
        assert enumerate_subdomains("") == []

    def test_enumerate_subdomains_invalid_domain_none(self):
        """None domain returns empty list."""
        assert enumerate_subdomains(None) == []

    def test_enumerate_subdomains_invalid_domain_not_string(self):
        """Non-string domain returns empty list."""
        assert enumerate_subdomains([]) == []

    def test_enumerate_subdomains_no_dnspython_no_requests(
            self, mock_time_sleep, short_wordlist):
        """Fallback to socket.gethostbyname when dnspython is missing."""
        with patch("src.modules.recon.subdomains.HAS_DNSPYTHON", False), \
             patch("src.modules.recon.subdomains.HAS_REQUESTS", False), \
             patch("src.modules.recon.subdomains.socket.gethostbyname") as mock_gethost:

            mock_gethost.side_effect = lambda fqdn: (
                "93.184.216.34" if fqdn == "www.example.com"
                else socket.gaierror() if fqdn == "mail.example.com"
                else (_ for _ in ()).throw(socket.gaierror())
            )

            results = enumerate_subdomains("example.com")

            # Only www should resolve via socket
            assert len(results) >= 1
            www_results = [r for r in results if r["subdomain"] == "www.example.com"]
            assert len(www_results) == 1
            assert www_results[0]["ip"] == "93.184.216.34"

    def test_enumerate_subdomains_no_dnspython_requests_fallback(
            self, mock_time_sleep, short_wordlist):
        """When dnspython is missing but requests available, crt.sh works."""
        with patch("src.modules.recon.subdomains.HAS_DNSPYTHON", False), \
             patch("src.modules.recon.subdomains.HAS_REQUESTS", True), \
             patch("src.modules.recon.subdomains.socket.gethostbyname") as mock_gethost, \
             patch("src.modules.recon.subdomains.requests.get") as mock_get:

            mock_gethost.side_effect = lambda fqdn: {
                "www.example.com": "93.184.216.34",
                "hidden.example.com": "10.0.0.1",
            }.get(fqdn) or (_ for _ in ()).throw(socket.gaierror())

            # Mock crt.sh response
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = [
                {"name_value": "hidden.example.com"},
            ]
            mock_get.return_value = mock_resp

            results = enumerate_subdomains("example.com")

            fqdns = {r["subdomain"] for r in results}
            assert "www.example.com" in fqdns
            assert "hidden.example.com" in fqdns

    def test_enumerate_subdomains_result_format(self, mock_time_sleep, mock_resolve_subdomain,
                                                  mock_query_crtsh, short_wordlist):
        """Each result dict has the expected keys."""
        mock_resolve_subdomain.return_value = "93.184.216.34"
        mock_query_crtsh.return_value = set()

        results = enumerate_subdomains("example.com")

        assert len(results) > 0
        for r in results:
            assert set(r.keys()) == {"subdomain", "ip", "source"}
            assert isinstance(r["subdomain"], str)
            assert isinstance(r["ip"], str)
            assert r["source"] in ("bruteforce", "crtsh")

    def test_enumerate_subdomains_delay_applied(self, mock_time_sleep, mock_resolve_subdomain,
                                                  mock_query_crtsh, short_wordlist):
        """Delay is applied between iterations."""
        mock_resolve_subdomain.side_effect = lambda fqdn: (
            "1.2.3.4" if fqdn == "www.example.com" else None
        )
        mock_query_crtsh.return_value = {"test.example.com"}

        enumerate_subdomains("example.com", delay=0.5)
        # Should have been called for each wordlist entry + crt.sh results
        # Reset wordlist has 5 entries + 1 crt.sh = 6 calls... but _resolve_subdomain
        # is called per entry in brute force AND per crt.sh result for validation
        # Actually sleep is called right after _resolve_subdomain in each phase
        # Brute force: 5 calls (one per wordlist entry)
        # crt.sh: 1 call (one returned result)
        # Total sleep calls: 5 + 1 = 6
        calls = mock_time_sleep.call_args_list
        # We just verify delay param was passed
        for call_args in calls:
            assert call_args == call(0.5)

    def test_enumerate_subdomains_crtsh_dns_failure(self, mock_time_sleep, mock_resolve_subdomain,
                                                      mock_query_crtsh, short_wordlist):
        """crt.sh subdomains that fail DNS resolution are excluded."""
        mock_resolve_subdomain.side_effect = lambda fqdn: (
            "93.184.216.34" if fqdn == "www.example.com" else None
        )
        # crt.sh returns a subdomain that can't be resolved
        mock_query_crtsh.return_value = {"dead.example.com"}

        results = enumerate_subdomains("example.com")

        assert len(results) == 1
        assert results[0]["subdomain"] == "www.example.com"

    def test_enumerate_subdomains_wordlist_order(self, mock_time_sleep, mock_resolve_subdomain,
                                                   mock_query_crtsh, short_wordlist):
        """Subdomains are found in wordlist order (first found = bruteforce)."""
        mock_resolve_subdomain.side_effect = lambda fqdn: "10.0.0.1"
        mock_query_crtsh.return_value = set()

        results = enumerate_subdomains("example.com")
        # Should find all 5 test subdomains
        assert len(results) == len(short_wordlist)
        for r in results:
            assert r["source"] == "bruteforce"


class TestResolveSubdomain:
    """Tests for src.modules.recon.subdomains._resolve_subdomain."""

    def test_resolve_with_dnspython(self):
        """DNS resolution via dnspython returns IP."""
        with patch("src.modules.recon.subdomains.HAS_DNSPYTHON", True), \
             patch("src.modules.recon.subdomains.dns.resolver.Resolver") as mock_cls:

            mock_resolver = MagicMock()
            mock_cls.return_value = mock_resolver
            mock_resolver.resolve.return_value = [_MockRecord("93.184.216.34")]

            ip = _resolve_subdomain("www.example.com")
            assert ip == "93.184.216.34"
            assert mock_resolver.timeout == 2
            assert mock_resolver.lifetime == 2

    def test_resolve_with_dnspython_fallback_socket(self):
        """DNS resolution falls back to socket when dnspython fails."""
        with patch("src.modules.recon.subdomains.HAS_DNSPYTHON", True), \
             patch("src.modules.recon.subdomains.dns.resolver.Resolver") as mock_cls, \
             patch("src.modules.recon.subdomains.socket.gethostbyname") as mock_gethost:

            mock_resolver = MagicMock()
            mock_cls.return_value = mock_resolver
            mock_resolver.resolve.side_effect = Exception("DNS failure")
            mock_gethost.return_value = "10.0.0.1"

            ip = _resolve_subdomain("www.example.com")
            assert ip == "10.0.0.1"

    def test_resolve_both_fail(self):
        """Both methods fail returns None."""
        with patch("src.modules.recon.subdomains.HAS_DNSPYTHON", True), \
             patch("src.modules.recon.subdomains.dns.resolver.Resolver") as mock_cls, \
             patch("src.modules.recon.subdomains.socket.gethostbyname") as mock_gethost:

            mock_resolver = MagicMock()
            mock_cls.return_value = mock_resolver
            mock_resolver.resolve.side_effect = Exception("DNS failure")
            mock_gethost.side_effect = socket.gaierror()

            ip = _resolve_subdomain("www.example.com")
            assert ip is None

    def test_resolve_socket_only_no_dnspython(self):
        """When dnspython is unavailable, use socket directly."""
        with patch("src.modules.recon.subdomains.HAS_DNSPYTHON", False), \
             patch("src.modules.recon.subdomains.socket.gethostbyname") as mock_gethost:

            mock_gethost.return_value = "10.0.0.1"
            ip = _resolve_subdomain("www.example.com")
            assert ip == "10.0.0.1"

    def test_resolve_socket_only_failure(self):
        """When dnspython is unavailable and socket fails, return None."""
        with patch("src.modules.recon.subdomains.HAS_DNSPYTHON", False), \
             patch("src.modules.recon.subdomains.socket.gethostbyname") as mock_gethost:

            mock_gethost.side_effect = socket.gaierror()
            ip = _resolve_subdomain("www.example.com")
            assert ip is None


class TestQueryCrtsh:
    """Tests for src.modules.recon.subdomains._query_crtsh."""

    def test_crtsh_success(self):
        """Successful crt.sh JSON response returns parsed subdomains."""
        with patch("src.modules.recon.subdomains.HAS_REQUESTS", True), \
             patch("src.modules.recon.subdomains.requests.get") as mock_get:

            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = [
                {"name_value": "www.example.com"},
                {"name_value": "mail.example.com\napi.example.com"},
                {"name_value": "*.example.com"},  # wildcard, should be excluded
            ]
            mock_get.return_value = mock_resp

            result = _query_crtsh("example.com")
            assert "www.example.com" in result
            assert "mail.example.com" in result
            assert "api.example.com" in result
            assert "*.example.com" not in result

    def test_crtsh_http_error(self):
        """Non-200 response returns empty set."""
        with patch("src.modules.recon.subdomains.HAS_REQUESTS", True), \
             patch("src.modules.recon.subdomains.requests.get") as mock_get:

            mock_resp = MagicMock()
            mock_resp.status_code = 429
            mock_get.return_value = mock_resp

            result = _query_crtsh("example.com")
            assert result == set()

    def test_crtsh_connection_error(self):
        """Connection error returns empty set."""
        with patch("src.modules.recon.subdomains.HAS_REQUESTS", True), \
             patch("src.modules.recon.subdomains.requests.get") as mock_get:

            from requests.exceptions import ConnectionError
            mock_get.side_effect = ConnectionError("Connection refused")

            result = _query_crtsh("example.com")
            assert result == set()

    def test_crtsh_invalid_json(self):
        """Invalid JSON response returns empty set."""
        with patch("src.modules.recon.subdomains.HAS_REQUESTS", True), \
             patch("src.modules.recon.subdomains.requests.get") as mock_get:

            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.side_effect = ValueError("Invalid JSON")
            mock_get.return_value = mock_resp

            result = _query_crtsh("example.com")
            assert result == set()

    def test_crtsh_no_requests(self):
        """When requests library is unavailable, return empty set."""
        with patch("src.modules.recon.subdomains.HAS_REQUESTS", False):
            result = _query_crtsh("example.com")
            assert result == set()

    def test_crtsh_filter_subdomain_match(self):
        """Only subdomains ending with .domain are included."""
        with patch("src.modules.recon.subdomains.HAS_REQUESTS", True), \
             patch("src.modules.recon.subdomains.requests.get") as mock_get:

            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = [
                {"name_value": "www.example.com"},
                {"name_value": "www.other.com"},  # different domain
                {"name_value": "test.example.org"},  # different TLD
            ]
            mock_get.return_value = mock_resp

            result = _query_crtsh("example.com")
            assert "www.example.com" in result
            assert "www.other.com" not in result
            assert "test.example.org" not in result

    def test_crtsh_user_agent_header(self):
        """Request includes the correct User-Agent header."""
        with patch("src.modules.recon.subdomains.HAS_REQUESTS", True), \
             patch("src.modules.recon.subdomains.requests.get") as mock_get:

            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = []
            mock_get.return_value = mock_resp

            _query_crtsh("example.com")

            # Verify the URL and headers
            call_kwargs = mock_get.call_args.kwargs
            assert "crt.sh" in mock_get.call_args.args[0]
            assert "User-Agent" in call_kwargs.get("headers", {})


# =============================================================================
# Portscan Tests
# =============================================================================

class TestPortscan:
    """Tests for src.modules.recon.portscan.scan_ports."""

    # -- Fixtures -----------------------------------------------------------

    @pytest.fixture
    def mock_resolve_host(self):
        """Patch _resolve_host to return a controlled IP."""
        with patch("src.modules.recon.portscan._resolve_host") as mock:
            mock.return_value = "93.184.216.34"
            yield mock

    @pytest.fixture
    def mock_scan_port(self):
        """Patch _scan_port to return controlled results."""
        with patch("src.modules.recon.portscan._scan_port") as mock:
            yield mock

    # -- Tests --------------------------------------------------------------

    def test_scan_ports_open_ports(self, mock_resolve_host, mock_scan_port):
        """Open ports are returned in sorted order (deduplicated by port)."""
        seen = set()

        def scan_side_effect(host, port, timeout):
            # TOP_PORTS has duplicates (443 appears 3×, etc.)
            # Only return result the first time a port is seen
            if port not in seen:
                seen.add(port)
                if port in (22, 80, 443):
                    return {"port": port, "state": "open", "service": "ssh", "banner": ""}
            return None

        mock_scan_port.side_effect = scan_side_effect

        results = scan_ports("example.com")

        assert len(results) == 3
        assert results[0]["port"] == 22
        assert results[1]["port"] == 80
        assert results[2]["port"] == 443

    def test_scan_ports_all_closed(self, mock_resolve_host, mock_scan_port):
        """All ports closed returns empty list."""
        mock_scan_port.return_value = None

        results = scan_ports("example.com")
        assert results == []

    def test_scan_ports_mixed(self, mock_resolve_host, mock_scan_port):
        """Mix of open/closed returns only open ports."""
        def scan_side_effect(host, port, timeout):
            if port == 22:
                return {"port": 22, "state": "open", "service": "ssh", "banner": "SSH-2.0"}
            return None

        mock_scan_port.side_effect = scan_side_effect

        results = scan_ports("example.com")
        assert len(results) == 1
        assert results[0]["port"] == 22

    def test_scan_ports_invalid_host_empty(self):
        """Empty host returns empty list."""
        results = scan_ports("")
        assert results == []

    def test_scan_ports_invalid_host_none(self):
        """None host returns empty list."""
        results = scan_ports(None)
        assert results == []

    def test_scan_ports_invalid_host_not_string(self):
        """Non-string host returns empty list."""
        results = scan_ports(123)
        assert results == []

    def test_scan_ports_host_resolution_failure(self):
        """Host resolution failure returns empty list."""
        with patch("src.modules.recon.portscan._resolve_host", return_value=None):
            results = scan_ports("nonexistent.example.com")
        assert results == []

    def test_scan_ports_result_format(self, mock_resolve_host, mock_scan_port):
        """Each result dict has the expected keys."""
        mock_scan_port.return_value = {"port": 80, "state": "open", "service": "http", "banner": "Apache"}

        results = scan_ports("example.com")

        assert len(results) > 0
        for r in results:
            assert set(r.keys()) == {"port", "state", "service", "banner"}
            assert isinstance(r["port"], int)
            assert isinstance(r["state"], str)
            assert isinstance(r["service"], str)
            assert isinstance(r["banner"], str)

    def test_scan_ports_timeout_passed(self, mock_resolve_host, mock_scan_port):
        """The timeout parameter is passed to _scan_port."""
        mock_scan_port.return_value = None

        scan_ports("example.com", timeout=2.5)

        for call_args in mock_scan_port.call_args_list:
            # Each call is (host, port, timeout)
            assert call_args[0][2] == 2.5

    def test_scan_ports_worker_count(self, mock_resolve_host, mock_scan_port):
        """max_workers controls concurrency (we just verify it doesn't crash)."""
        mock_scan_port.return_value = None

        # Should work with various worker counts
        results_1 = scan_ports("example.com", max_workers=1)
        results_50 = scan_ports("example.com", max_workers=50)

        assert results_1 == []
        assert results_50 == []

    def test_scan_ports_exception_in_scan(self, mock_resolve_host, mock_scan_port):
        """Exception in _scan_port is logged and skipped."""
        mock_scan_port.side_effect = RuntimeError("Port scan failed")

        results = scan_ports("example.com")
        assert results == []

    def test_scan_ports_sorted_by_port(self, mock_resolve_host, mock_scan_port):
        """Results are sorted by port number regardless of scan order."""
        seen = set()

        def scan_side_effect(host, port, timeout):
            if port not in seen:
                seen.add(port)
                if port in (8080, 22, 443):
                    return {"port": port, "state": "open", "service": "unknown", "banner": ""}
            return None

        mock_scan_port.side_effect = scan_side_effect

        results = scan_ports("example.com")

        assert len(results) == 3
        assert results[0]["port"] == 22
        assert results[1]["port"] == 443
        assert results[2]["port"] == 8080


class TestResolveHost:
    """Tests for src.modules.recon.portscan._resolve_host."""

    def test_resolve_host_ipv4(self):
        """An IPv4 address is returned as-is."""
        with patch("src.modules.recon.portscan.socket.inet_aton", return_value=b"\xc0\xa8\x00\x01"):
            ip = _resolve_host("192.168.0.1")
        assert ip == "192.168.0.1"

    def test_resolve_host_hostname(self):
        """A hostname is resolved to an IP."""
        with patch("src.modules.recon.portscan.socket.inet_aton", side_effect=OSError), \
             patch("src.modules.recon.portscan.socket.gethostbyname", return_value="93.184.216.34"):
            ip = _resolve_host("example.com")
        assert ip == "93.184.216.34"

    def test_resolve_host_failure(self):
        """Unresolvable hostname returns None."""
        with patch("src.modules.recon.portscan.socket.inet_aton", side_effect=OSError), \
             patch("src.modules.recon.portscan.socket.gethostbyname", side_effect=socket.gaierror()):
            ip = _resolve_host("nonexistent.example.com")
        assert ip is None


class TestScanPort:
    """Tests for src.modules.recon.portscan._scan_port."""

    def test_scan_port_open(self):
        """An open port returns a result dict with banner."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9\n"

        with patch("src.modules.recon.portscan.socket.socket", return_value=mock_sock):
            result = _scan_port("10.0.0.1", 22, 1.0)

        assert result is not None
        assert result["port"] == 22
        assert result["state"] == "open"
        assert result["service"] == "ssh"
        assert "SSH-2.0" in result["banner"]
        mock_sock.close.assert_called_once()

    def test_scan_port_closed(self):
        """A closed port returns None."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 1  # non-zero = connection refused

        with patch("src.modules.recon.portscan.socket.socket", return_value=mock_sock):
            result = _scan_port("10.0.0.1", 81, 1.0)

        assert result is None
        mock_sock.close.assert_called_once()

    def test_scan_port_unknown_service(self):
        """A port not in SERVICE_MAP gets service 'unknown'."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_sock.recv.return_value = b""

        with patch("src.modules.recon.portscan.socket.socket", return_value=mock_sock):
            result = _scan_port("10.0.0.1", 9999, 1.0)

        assert result is not None
        assert result["service"] == "unknown"
        assert result["banner"] == ""

    def test_scan_port_exception(self):
        """Exception during scan returns None."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = OSError("Connection refused")

        with patch("src.modules.recon.portscan.socket.socket", return_value=mock_sock):
            result = _scan_port("10.0.0.1", 22, 1.0)

        assert result is None
        mock_sock.close.assert_called_once()

    def test_scan_port_timeout(self):
        """Timeout during connect returns None."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_sock.recv.side_effect = socket.timeout

        with patch("src.modules.recon.portscan.socket.socket", return_value=mock_sock):
            result = _scan_port("10.0.0.1", 22, 1.0)

        # Port is open, banner empty due to timeout
        assert result is not None
        assert result["state"] == "open"
        assert result["banner"] == ""

    def test_scan_port_socket_cleanup_on_exception(self):
        """Socket is closed even when connect raises."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = Exception("Unexpected")

        with patch("src.modules.recon.portscan.socket.socket", return_value=mock_sock):
            result = _scan_port("10.0.0.1", 22, 1.0)

        assert result is None
        # close should have been called (in finally block)
        mock_sock.close.assert_called_once()

    def test_scan_port_timeout_set_on_socket(self):
        """Socket timeout is set from the parameter."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_sock.recv.return_value = b""

        with patch("src.modules.recon.portscan.socket.socket", return_value=mock_sock):
            _scan_port("10.0.0.1", 80, 3.0)

        assert mock_sock.settimeout.call_count >= 1


class TestGrabBanner:
    """Tests for src.modules.recon.portscan._grab_banner."""

    def test_grab_banner_http(self):
        """HTTP port sends HEAD request and reads response."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"HTTP/1.0 200 OK\r\nServer: Apache\r\n\r\n"

        banner = _grab_banner(mock_sock, 80, 1.0)
        assert "HTTP/1.0 200 OK" in banner
        # Verify HEAD request was sent
        mock_sock.sendall.assert_called_once_with(b"HEAD / HTTP/1.0\r\n\r\n")

    def test_grab_banner_https_alt(self):
        """8443 port sends HEAD request like HTTP."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"HTTP/1.0 200 OK\r\n\r\n"

        banner = _grab_banner(mock_sock, 8443, 1.0)
        assert banner == "HTTP/1.0 200 OK"
        mock_sock.sendall.assert_called_once()

    def test_grab_banner_non_banner_port(self):
        """Port not in banner_ports returns empty string."""
        mock_sock = MagicMock()

        banner = _grab_banner(mock_sock, 8081, 1.0)
        assert banner == ""
        mock_sock.recv.assert_not_called()

    def test_grab_banner_socket_timeout(self):
        """Socket timeout during read returns empty string."""
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = socket.timeout

        banner = _grab_banner(mock_sock, 22, 1.0)
        assert banner == ""

    def test_grab_banner_sanitized(self):
        """Non-printable characters in banner are replaced."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"SSH-2.0\x00OpenSSH\x7f\x01test\n"

        banner = _grab_banner(mock_sock, 22, 1.0)
        assert "\x00" not in banner
        assert "\x7f" not in banner
        assert "SSH-2.0" in banner

    def test_grab_banner_truncated(self):
        """Banners longer than 200 chars are truncated."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"X" * 1024

        banner = _grab_banner(mock_sock, 22, 1.0)
        assert len(banner) <= 200

    def test_grab_banner_empty_read(self):
        """Empty recv data returns empty string."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b""

        banner = _grab_banner(mock_sock, 22, 1.0)
        assert banner == ""

    def test_grab_banner_connection_reset(self):
        """Connection reset during read returns empty string."""
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = ConnectionResetError

        banner = _grab_banner(mock_sock, 22, 1.0)
        assert banner == ""

    def test_grab_banner_broken_pipe(self):
        """Broken pipe during send returns empty string."""
        mock_sock = MagicMock()
        mock_sock.sendall.side_effect = BrokenPipeError

        banner = _grab_banner(mock_sock, 80, 1.0)
        assert banner == ""

    def test_grab_banner_smtp_passive(self):
        """SMTP port (25) reads banner passively without sending a probe."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"220 smtp.example.com ESMTP Postfix\n"

        banner = _grab_banner(mock_sock, 25, 1.0)
        assert "220 smtp.example.com" in banner
        # No sendall for passive-read ports
        mock_sock.sendall.assert_not_called()

    def test_grab_banner_imap_passive(self):
        """IMAP port (143) reads banner passively without sending a probe."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"* OK IMAP server ready\n"

        banner = _grab_banner(mock_sock, 143, 1.0)
        assert "IMAP" in banner
        mock_sock.sendall.assert_not_called()

    def test_grab_banner_pop3_passive(self):
        """POP3 port (110) reads banner passively without sending a probe."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"+OK POP3 server ready\n"

        banner = _grab_banner(mock_sock, 110, 1.0)
        assert "POP3" in banner
        mock_sock.sendall.assert_not_called()


# =============================================================================
# Scanner Integration Tests
# =============================================================================

class TestScannerReconIntegration:
    """Tests for Scanner.run() with recon module integration.

    NOTE: The Scanner._run_recon() method imports functions directly
    (``from src.modules.recon.dns import resolve_dns``), so we must patch
    at the source module, NOT at ``src.core.scanner``.
    """

    @patch("src.modules.recon.dns.resolve_dns")
    @patch("src.modules.recon.whois.lookup_whois")
    @patch("src.modules.recon.subdomains.enumerate_subdomains")
    @patch("src.modules.recon.portscan.scan_ports")
    def test_scanner_run_recon_module(self, mock_scan, mock_sub, mock_whois, mock_dns,
                                       sample_target):
        """Scanner.run() with recon module calls all recon sub-modules."""
        # Configure mocks
        mock_dns.return_value = {"A": ["93.184.216.34"], "MX": [], "NS": [], "TXT": [], "CNAME": []}
        mock_whois.return_value = {"registrar": "Example Inc", "organization": None, "country": "US",
                                   "creation_date": None, "expiration_date": None, "updated_date": None,
                                   "name_servers": [], "raw": None}
        mock_sub.return_value = [{"subdomain": "www.example.com", "ip": "93.184.216.34", "source": "bruteforce"}]
        mock_scan.return_value = [{"port": 80, "state": "open", "service": "http", "banner": ""}]

        scanner = Scanner(sample_target, modules=["recon"])
        results = scanner.run()

        # Verify structure
        assert results["target"] == sample_target
        assert "recon" in results["modules"]
        assert "dns" in results["modules"]["recon"]
        assert "whois" in results["modules"]["recon"]
        assert "subdomains" in results["modules"]["recon"]
        assert "portscan" in results["modules"]["recon"]

        # Verify all mocks were called
        mock_dns.assert_called_once_with(sample_target)
        mock_whois.assert_called_once_with(sample_target)
        mock_sub.assert_called_once_with(sample_target)
        mock_scan.assert_called_once_with(sample_target)

    @patch("src.modules.recon.dns.resolve_dns")
    @patch("src.modules.recon.whois.lookup_whois")
    @patch("src.modules.recon.subdomains.enumerate_subdomains")
    @patch("src.modules.recon.portscan.scan_ports")
    def test_scanner_run_recon_module_all(self, mock_scan, mock_sub, mock_whois, mock_dns,
                                           sample_target):
        """Scanner.run() with modules=["all"] includes recon results."""
        mock_dns.return_value = {}
        mock_whois.return_value = {"registrar": None, "organization": None, "country": None,
                                   "creation_date": None, "expiration_date": None, "updated_date": None,
                                   "name_servers": [], "raw": None}
        mock_sub.return_value = []
        mock_scan.return_value = []

        scanner = Scanner(sample_target, modules=["all"])
        results = scanner.run()

        assert "recon" in results["modules"]
        assert "web" in results["modules"]
        assert "vuln" in results["modules"]

    @patch("src.modules.recon.dns.resolve_dns")
    @patch("src.modules.recon.whois.lookup_whois")
    @patch("src.modules.recon.subdomains.enumerate_subdomains")
    @patch("src.modules.recon.portscan.scan_ports")
    def test_scanner_recon_module_failure_graceful(self, mock_scan, mock_sub, mock_whois, mock_dns,
                                                     sample_target):
        """Exception in a recon sub-module does not crash the scanner."""
        mock_dns.side_effect = RuntimeError("DNS module crashed")
        mock_whois.return_value = {}
        mock_sub.return_value = []
        mock_scan.return_value = []

        scanner = Scanner(sample_target, modules=["recon"])
        results = scanner.run()

        # Should still have all keys, DNS should be {}
        assert results["modules"]["recon"]["dns"] == {}
        assert results["modules"]["recon"]["whois"] == {}
        assert results["modules"]["recon"]["subdomains"] == []
        assert results["modules"]["recon"]["portscan"] == []

    @patch("src.modules.recon.dns.resolve_dns")
    @patch("src.modules.recon.whois.lookup_whois")
    @patch("src.modules.recon.subdomains.enumerate_subdomains")
    @patch("src.modules.recon.portscan.scan_ports")
    def test_scanner_run_excludes_recon(self, mock_scan, mock_sub, mock_whois, mock_dns,
                                          sample_target):
        """Scanner with modules other than recon does not run recon."""
        scanner = Scanner(sample_target, modules=["web"])
        scanner.run()

        mock_dns.assert_not_called()
        mock_whois.assert_not_called()
        mock_sub.assert_not_called()
        mock_scan.assert_not_called()

    @patch("src.modules.recon.dns.resolve_dns")
    @patch("src.modules.recon.whois.lookup_whois")
    @patch("src.modules.recon.subdomains.enumerate_subdomains")
    @patch("src.modules.recon.portscan.scan_ports")
    def test_scanner_all_modules_fail_gracefully(self, mock_scan, mock_sub, mock_whois, mock_dns,
                                                   sample_target):
        """All recon sub-modules failing returns empty structures for each."""
        mock_dns.side_effect = RuntimeError("DNS crashed")
        mock_whois.side_effect = RuntimeError("WHOIS crashed")
        mock_sub.side_effect = RuntimeError("Subdomain crashed")
        mock_scan.side_effect = RuntimeError("Portscan crashed")

        scanner = Scanner(sample_target, modules=["recon"])
        results = scanner.run()

        assert results["modules"]["recon"]["dns"] == {}
        assert results["modules"]["recon"]["whois"] == {}
        assert results["modules"]["recon"]["subdomains"] == []
        assert results["modules"]["recon"]["portscan"] == []


# =============================================================================
# Helpers Tests
# =============================================================================

class TestHelpers:
    """Tests for tests/helpers.py utilities."""

    def test_make_mock_response_json(self):
        """Mock response with JSON data returns correct values."""
        from tests.helpers import make_mock_response

        resp = make_mock_response(
            status_code=200,
            json_data={"key": "value"},
            url="http://example.com/api"
        )

        assert resp.status_code == 200
        assert resp.ok is True
        assert resp.json() == {"key": "value"}
        assert resp.url == "http://example.com/api"

    def test_make_mock_response_text(self):
        """Mock response with text returns correct content."""
        from tests.helpers import make_mock_response

        resp = make_mock_response(
            status_code=404,
            text="Not Found"
        )

        assert resp.status_code == 404
        assert resp.ok is False
        assert resp.text == "Not Found"
        assert resp.content == b"Not Found"

    def test_make_mock_response_no_json(self):
        """Mock response without JSON raises ValueError on .json()."""
        from tests.helpers import make_mock_response

        resp = make_mock_response(status_code=200)

        import pytest
        with pytest.raises(ValueError, match="Not JSON"):
            resp.json()

    def test_make_mock_http_server_all_scenarios(self):
        """make_mock_http_server returns all expected scenarios."""
        from tests.helpers import make_mock_http_server

        server = make_mock_http_server()

        assert set(server.keys()) == {"ok", "redirect", "forbidden", "not_found", "server_error", "form"}
        assert server["ok"]().status_code == 200
        assert server["redirect"]().status_code == 301
        assert server["redirect"]().headers["Location"] == "http://example.com/redirected"
        assert server["forbidden"]().status_code == 403
        assert server["not_found"]().status_code == 404
        assert server["server_error"]().status_code == 500

    def test_make_mock_http_server_form(self):
        """Form scenario returns HTML with form elements."""
        from tests.helpers import make_mock_http_server

        resp = make_mock_http_server()["form"]()
        assert "form" in resp.text
        assert "username" in resp.text
        assert "password" in resp.text

    def test_patch_requests_get_context_manager(self):
        """patch_requests_get correctly patches requests.get."""
        from tests.helpers import patch_requests_get, make_mock_response
        import requests

        mock_resp = make_mock_response(status_code=200, text="mocked")

        with patch_requests_get(mock_resp):
            resp = requests.get("http://example.com")

        assert resp.status_code == 200
        assert resp.text == "mocked"

    def test_make_mock_response_security_headers(self):
        """OK scenario includes security headers."""
        from tests.helpers import make_mock_http_server

        resp = make_mock_http_server()["ok"]()
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("X-Frame-Options") == "DENY"
