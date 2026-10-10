"""Construction of the shared, connection-pooled requests session."""

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .._meta import __tool_name__, __version__


class _Session(requests.Session):
    """A session whose TLS-verification setting cannot be quietly overridden.

    ``requests`` consults ``REQUESTS_CA_BUNDLE`` and ``CURL_CA_BUNDLE`` whenever
    a request does not name ``verify`` itself, and the CA bundle it finds there
    wins over ``session.verify``. In an environment that sets either - a CI
    runner behind a TLS-inspecting proxy, a corporate image - that silently
    turns ``--insecure`` back off, and a scan of a host with a self-signed
    certificate fails every request while reporting the target as unreachable.

    Naming ``verify`` explicitly stops the environment being consulted at all.
    It is only forced when verification is off, so a target that legitimately
    needs a custom CA bundle from the environment still gets one.
    """

    def request(self, *args, **kwargs):
        if self.verify is False:
            kwargs.setdefault("verify", False)
        return super().request(*args, **kwargs)


def build_session(timeout, threads, insecure, proxy, extra_headers):
    """Create a connection-pooled, retry-aware requests session."""
    session = _Session()
    # Only a failed connection is retried. A retry driven by the response
    # *status* is issued inside urllib3, below both the rate limiter and the
    # request counter, so one logical request becomes up to three on the wire:
    # a scan would emit several times the rate the operator asked for, report a
    # fraction of the traffic it actually sent, and - because the retries and
    # their backoff fall inside the measured elapsed time - hand the
    # timing-based checks a delay the target never caused. Retrying 429 is the
    # worst of the set: it answers "slow down" by sending more.
    #
    # Every counter is named, ``other`` included. urllib3 leaves that one unset
    # by default, an unset counter is never decremented, and ``is_exhausted``
    # only looks for a counter that has gone negative - so an error it files as
    # neither connect nor read, a TLS error for instance, would still be
    # retried once however the others are set. Its own documentation warns that
    # those errors can happen after the request was sent, which is exactly the
    # duplicate this policy exists to prevent.
    retry = Retry(
        total=1,
        connect=1,
        read=0,
        status=0,
        other=0,
        backoff_factor=0.3,
        allowed_methods=None,  # applies to every method
        raise_on_status=False,
    )
    adapter = HTTPAdapter(
        pool_connections=max(threads, 10),
        pool_maxsize=max(threads * 2, 20),
        max_retries=retry,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({
        "User-Agent": f"Mozilla/5.0 (compatible; {__tool_name__}/{__version__})",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
    })
    if extra_headers:
        session.headers.update(extra_headers)
    if proxy:
        session.proxies.update({"http": proxy, "https": proxy})
    if insecure:
        session.verify = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    session.request_timeout = timeout
    return session
