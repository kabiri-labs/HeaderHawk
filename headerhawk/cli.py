"""Command-line entry point: argument parsing and scan orchestration."""

import argparse
import sys
from urllib.parse import urlparse

from colorama import Fore, Style, init

from ._meta import __github_url__, __tool_name__, __version__
from .checks.registry import CHECKS
from .core.auth import (FAILED, NOT_CONFIGURED, AuthConfig,
                        apply_credentials, is_configured, log_in, verify)
from .core.baseline import (collect_findings, compare, finding_identity,
                            load_baseline)
from .core.exitcodes import EXIT_ERROR, determine_exit_code
from .core.findings import DEFAULT_FAIL_ON, FAIL_ON_CLASSES, gated_finding_count
from .core.oob import OOBManager, confirm_oob_interactions
from .core.output import is_quiet, print_summary, resolve_quiet, set_quiet, status
from .core.ratelimit import RateLimiter
from .core.request_file import RequestFileError, load_request
from .core.session import build_session
from .core.scope import runs_on
from .core.stats import RequestStats
from .discovery import DEFAULT_LIMIT, discover
from .report.evidence import save_evidence
from .report.writer import save_results


def parse_headers(raw_headers):
    headers = {}
    for item in raw_headers or []:
        if ":" not in item:
            continue
        name, value = item.split(":", 1)
        headers[name.strip()] = value.strip()
    return headers


def parse_arguments():
    parser = argparse.ArgumentParser(
        prog="headerhawk",
        description="HeaderHawk - assess both sides of the HTTP exchange: the "
                    "request headers an attacker manipulates (Host, "
                    "X-Forwarded-*, routing and URL-override headers) and the "
                    "response headers a product is supposed to send (HSTS, "
                    "CSP, cookie attributes, framing). Findings are confirmed "
                    "before they are reported and mapped to the published "
                    "requirement they fail; --evidence writes the result as a "
                    "per-requirement compliance report.")
    parser.add_argument("url", nargs="?",
                        help="Target URL (omit when using --list or --request)")
    parser.add_argument("--list", "-l", dest="list",
                        help="File of target URLs to scan, one per line "
                             "(blank lines and '#' comments are ignored)")
    parser.add_argument("--request", "-r",
                        help="File holding a raw HTTP request, as saved from a "
                             "browser or an intercepting proxy. Its URL, "
                             "method, headers and body drive the scan; each "
                             "check still replaces the header it is testing and "
                             "adds it when the file does not carry it")
    parser.add_argument("--request-scheme", dest="request_scheme",
                        choices=["http", "https"],
                        help="Scheme for --request when the file has no "
                             "absolute URL (default: inferred from a port in "
                             "the Host header, otherwise https)")
    parser.add_argument("--oob", help="OOB/collaborator domain for SSRF correlation")
    parser.add_argument("--oob-poll-url", dest="oob_poll_url",
                        help="Listener export URL polled afterwards to confirm OOB hits")
    parser.add_argument("--wordlist", "-w",
                        help="File of virtual-host names for discovery (one per line)")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads (1-20)")
    parser.add_argument("--rate", type=float, default=0.0,
                        help="Max requests per second across all threads "
                             "(0 = unlimited; use a low value to avoid WAF/rate blocks)")
    parser.add_argument("--timeout", type=float, default=10, help="Per-request timeout in seconds")
    parser.add_argument("--methods", default=None,
                        help="Comma-separated HTTP methods (e.g. GET,POST). "
                             "Defaults to GET, or to the method in --request")
    parser.add_argument("--header", "-H", action="append", dest="headers",
                        help="Extra request header 'Name: Value' (repeatable)")
    parser.add_argument("--proxy", help="Proxy URL (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--insecure", "-k", action="store_true",
                        help="Disable TLS certificate verification")
    parser.add_argument("--verbose", type=int, choices=[1, 2], default=1,
                        help="Verbosity level")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Suppress progress bars and status output "
                             "(auto-enabled when stdout is not a TTY)")
    parser.add_argument("--enable-desync", dest="enable_desync",
                        action="store_true",
                        help="Confirm a suspected request-smuggling desync by "
                             "planting a smuggled prefix and checking whether a "
                             "following request is affected. INTRUSIVE: the "
                             "prefix can attach to another user's request and "
                             "corrupt or misroute live traffic. Without it, "
                             "smuggling is reported from timing alone")
    parser.add_argument("--discover", action="store_true",
                        help="Scan the endpoints the target publishes about "
                             "itself - OpenAPI, sitemap, robots.txt and its own "
                             "links - instead of only the URL given")
    parser.add_argument("--max-endpoints", dest="max_endpoints", type=int,
                        default=DEFAULT_LIMIT,
                        help=f"Most endpoints to scan when discovering "
                             f"(default {DEFAULT_LIMIT})")
    parser.add_argument("--openapi",
                        help="URL of an OpenAPI/Swagger description to take "
                             "endpoints from, when it is not at a standard path")
    parser.add_argument("--auth-cookie", dest="auth_cookie",
                        help="Cookies to scan with, as 'a=1; b=2'. Use "
                             "'env:NAME' to read them from an environment "
                             "variable instead of the command line")
    parser.add_argument("--auth-login-url", dest="auth_login_url",
                        help="Log in by submitting a form to this URL before "
                             "scanning; the resulting session is used for the "
                             "whole scan")
    parser.add_argument("--auth-login-data", dest="auth_login_data",
                        help="Form body for --auth-login-url, as "
                             "'user=a&pass=b'. Use 'env:NAME' to keep "
                             "credentials out of the command line")
    parser.add_argument("--auth-login-method", dest="auth_login_method",
                        default="POST",
                        help="HTTP method for the login request (default POST)")
    parser.add_argument("--auth-verify-text", dest="auth_verify_text",
                        help="Text that appears only when logged in. The scan "
                             "stops rather than report an unauthenticated run "
                             "as if it were authenticated")
    parser.add_argument("--auth-verify-absent", dest="auth_verify_absent",
                        help="Text that appears only when logged out, e.g. "
                             "'Sign in'. The inverse of --auth-verify-text")
    parser.add_argument("--baseline",
                        help="A previous scan's JSON output. Findings are "
                             "compared against it and reported as new, fixed or "
                             "unchanged")
    parser.add_argument("--fail-on-new", dest="fail_on_new", action="store_true",
                        help="Gate the exit code on findings that are not in "
                             "--baseline, so a pipeline fails on a regression "
                             "rather than on findings already accepted")
    parser.add_argument("--fail-on", dest="fail_on",
                        choices=sorted(FAIL_ON_CLASSES), default=DEFAULT_FAIL_ON,
                        help="Which findings make the process exit 1: "
                             "'vuln' (default) counts proven vulnerabilities, "
                             "'posture' counts missing response-header controls, "
                             "'any' counts both, 'none' never fails on findings")
    parser.add_argument("--output", "-o",
                        help="Output file (.json, .sarif or .md)")
    parser.add_argument("--evidence",
                        help="Write a per-control compliance evidence "
                             "report to this path (.md or .json). Every "
                             "catalogued requirement is reported as Pass, "
                             "Fail or Not assessed, with the reason")
    args = parser.parse_args()
    if not 1 <= args.threads <= 20:
        parser.error("The --threads argument must be between 1 and 20.")
    if args.rate < 0:
        parser.error("The --rate argument must be 0 (unlimited) or positive.")
    if not args.url and not args.list and not args.request:
        parser.error("Provide a target URL, --list <file> or --request <file>.")
    if args.request_scheme and not args.request:
        parser.error("--request-scheme only applies with --request.")
    if args.fail_on_new and not args.baseline:
        parser.error("--fail-on-new needs --baseline <file> to compare against.")
    if args.max_endpoints < 1:
        parser.error("The --max-endpoints argument must be 1 or more.")
    if args.openapi and not args.discover:
        parser.error("--openapi only applies with --discover.")
    return args


def load_wordlist(path):
    if not path:
        return None
    try:
        with open(path) as handle:
            return [line.strip() for line in handle
                    if line.strip() and not line.startswith("#")]
    except OSError as exc:
        print(Fore.YELLOW + f"Could not read wordlist '{path}': {exc}. "
              "Using built-in list.")
        return None


def resolve_request(args):
    """Load --request, if given, and let it fill in the URL and the method.

    A malformed file stops the scan rather than being skipped: continuing would
    silently test a bare URL, dropping the session cookie and the body that were
    the reason for supplying a request in the first place.
    """
    if not args.request:
        return None
    spec = load_request(args.request, scheme=args.request_scheme)
    if not args.url and not args.list:
        args.url = spec.url
    if not args.methods:
        # The file describes one exchange; testing it with a method it never
        # used would be asking the endpoint a different question.
        args.methods = spec.method
    return spec


def load_targets(args):
    """Resolve the target URLs from --list (a file) or the positional argument."""
    if args.list:
        targets = load_wordlist(args.list)
        if not targets:
            print(Fore.RED + f"No targets found in list file '{args.list}'.")
            sys.exit(EXIT_ERROR)
        return targets
    return [args.url]


def run_check(test):
    """Run one check, keeping an unexpected failure inside that check.

    Every check shares a process with the others and with the report writers,
    and a scan is a long sequence of them. A check that raises takes the whole
    run down with it: the findings every earlier check reported are lost, no
    report and no evidence file are written, and the traceback exits with the
    code that tells a pipeline findings *were* reported. None of that is honest
    about what happened, so an unexpected failure is contained here and recorded
    the way the evidence report already describes a check that could not finish.

    The reason stored on the check names the exception type and nothing more. It
    is published in the evidence report, and an exception message can carry a
    local path or a fragment of a response body; the operator gets the full
    message on the console, where it is theirs to read.
    """
    try:
        test.run()
    except Exception as exc:
        # Deliberately broad: anything a check can raise is either a defect in
        # the check or an unforeseen shape of response, and neither is a reason
        # to throw away the rest of the scan. KeyboardInterrupt is not an
        # ``Exception`` and still stops the run, as it should.
        test.skip(f"the check stopped on an unexpected {type(exc).__name__} "
                  f"before it could finish")
        print(Fore.RED + Style.BRIGHT +
              f"\n[!] {getattr(test, 'test_type', type(test).__name__)} stopped "
              f"on an unexpected error and was skipped: "
              f"{type(exc).__name__}: {exc}")


def scan_target(url, args, session, methods, wordlist, stats,
                rate_limiter=None, primary=True, request_spec=None):
    """Run every test against a single URL and return the test objects.

    Returns None for an invalid URL so a batch run can skip it and continue.
    """
    hostname = urlparse(url).hostname
    if not hostname:
        print(Fore.YELLOW + f"Skipping invalid URL: {url}")
        return None

    oob_manager = OOBManager(args.oob, args.oob_poll_url) if args.oob else None
    status(f"\nTarget URL: {url}")
    status(f"Original Host: {hostname}")
    if oob_manager:
        status(f"OOB domain: {args.oob} (scan id {oob_manager.scan_id}).")

    common = dict(session=session, oob_domain=args.oob, methods=methods,
                  threads=args.threads, verbose=args.verbose, timeout=args.timeout,
                  oob_manager=oob_manager, wordlist=wordlist, insecure=args.insecure,
                  stats=stats, quiet=is_quiet(), rate_limiter=rate_limiter,
                  enable_desync=args.enable_desync, request_spec=request_spec)
    # Host-level checks run against the requested target only; every other URL
    # in the scan is another route on the same host, and repeating them there
    # would issue identical requests and file identical findings.
    tests = [check(url, hostname, **common)
             for check in CHECKS if runs_on(check, primary)]
    for test in tests:
        run_check(test)
    if oob_manager and oob_manager.poll_url:
        status("\nPolling OOB listener for interactions...")
        confirm_oob_interactions(oob_manager, session, args.timeout, tests)
    return tests


def auth_config(args):
    """Collect the authentication options into one value, or None."""
    config = AuthConfig(cookie=args.auth_cookie,
                        login_url=args.auth_login_url,
                        login_data=args.auth_login_data,
                        login_method=args.auth_login_method,
                        verify_text=args.auth_verify_text,
                        verify_absent=args.auth_verify_absent)
    return config if is_configured(config) else None


def establish_session(args, session, config, session_factory):
    """Log in if asked, then report whether the scan is really authenticated.

    Returns the AuthResult. A configured login that demonstrably did not work is
    fatal: a scan that quietly assessed the login page would produce a report
    describing the wrong pages, which is worse than no report.
    """
    if config is None:
        return verify(session, args.url or "", None, args.timeout)
    apply_credentials(session, config)
    if config.login_url:
        outcome = log_in(session, config, args.timeout)
        status(Fore.CYAN + f"Login: {outcome.detail}")
        if outcome.state == FAILED:
            return outcome
    target = args.url or (load_targets(args) or [""])[0]
    return verify(session, target, config, args.timeout,
                  session_factory=session_factory)


def resolve_drift(args, all_tests):
    """Compare against the baseline, or return None when there is nothing to do.

    A baseline that cannot be read is reported rather than treated as empty: an
    empty baseline would make every current finding look new, which is exactly
    the wrong answer for a flag whose job is to spot regressions.
    """
    if not args.baseline:
        return None
    baseline = load_baseline(args.baseline)
    if baseline is None:
        print(Fore.YELLOW + f"Could not read baseline '{args.baseline}'; "
                            "skipping the comparison.")
        return None
    return compare(collect_findings(all_tests), baseline)


def run_scan():
    args = parse_arguments()

    # Resolve quiet mode before anything is printed so status output, colour
    # stripping and progress bars all honour it consistently. When stdout is
    # redirected (a CI log, a file), colours and progress bars are noise.
    set_quiet(resolve_quiet(args.quiet, sys.stdout.isatty()))
    init(autoreset=True, strip=is_quiet() or None)

    status(Fore.CYAN + Style.BRIGHT + f"{__tool_name__} {__version__}")
    status(Fore.CYAN + f"GitHub: {__github_url__}\n")

    try:
        request_spec = resolve_request(args)
    except RequestFileError as exc:
        print(Fore.RED + Style.BRIGHT + f"\n[!] --request could not be used: {exc}")
        return EXIT_ERROR

    targets = load_targets(args)
    methods = [m.strip().upper() for m in (args.methods or "GET").split(",")
               if m.strip()]
    # The file's headers ride on the session, so a check that sets a header of
    # the same name replaces it and one that sets a new name adds it - which is
    # exactly what per-request headers do to session headers in ``requests``.
    # An explicit -H still wins, being the more specific instruction.
    extra_headers = dict(request_spec.headers) if request_spec else {}
    extra_headers.update(parse_headers(args.headers))
    wordlist = load_wordlist(args.wordlist)

    rate_note = f"{args.rate:g} req/s" if args.rate > 0 else "unlimited"
    if request_spec:
        body_note = (f"{len(request_spec.body)}-byte body"
                     if request_spec.body else "no body")
        status(Fore.CYAN + f"Request file: {args.request} "
                           f"({request_spec.method} {request_spec.url}, "
                           f"{len(request_spec.headers)} header(s), {body_note})")
    status(f"Targets: {len(targets)}")
    status(f"Methods: {', '.join(methods)}")
    status(f"Using {args.threads} threads (timeout {args.timeout}s, rate {rate_note}).")
    status(f"Verbosity level set to {args.verbose}.\n")

    session = build_session(
        timeout=args.timeout,
        threads=args.threads,
        insecure=args.insecure,
        proxy=args.proxy,
        extra_headers=extra_headers,
    )

    config = auth_config(args)
    auth = establish_session(
        args, session, config,
        session_factory=lambda: build_session(
            timeout=args.timeout, threads=1, insecure=args.insecure,
            proxy=args.proxy, extra_headers=None))
    if auth.state != NOT_CONFIGURED:
        status(Fore.CYAN + f"Scan mode: {auth.state} - {auth.detail}")
    if auth.state == FAILED:
        print(Fore.RED + Style.BRIGHT +
              f"\n[!] Authentication did not take effect: {auth.detail}. "
              f"Scanning now would assess the logged-out pages and report them "
              f"as the product's, so the scan has been stopped.")
        return EXIT_ERROR

    # Discovery runs after authentication on purpose: an anonymous crawl of an
    # authenticated product discovers its login page and little else.
    if args.discover:
        found = discover(session, targets[0], args.timeout,
                         limit=args.max_endpoints, openapi_url=args.openapi)
        targets = found.urls
        origin = ", ".join(found.sources) or "the target URL alone"
        status(Fore.CYAN + f"Discovered {len(targets)} endpoint(s) from "
                           f"{origin}.")
        if found.considered > len(targets):
            print(Fore.YELLOW +
                  f"[!] {found.considered} distinct endpoints were found but "
                  f"only {len(targets)} are being scanned (--max-endpoints). "
                  f"The rest were not assessed.")

    stats = RequestStats()
    rate_limiter = RateLimiter(args.rate)
    all_tests = []
    try:
        for url in targets:
            if len(targets) > 1:
                status(Fore.CYAN + Style.BRIGHT + f"\n===== Scanning {url} =====")
            tests = scan_target(url, args, session, methods, wordlist, stats,
                                rate_limiter=rate_limiter,
                                primary=(url == targets[0]),
                                request_spec=request_spec)
            if tests:
                all_tests.extend(tests)
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Program interrupted by user.")
        save_results(args.output, all_tests, args.verbose)
        save_evidence(args.evidence, all_tests, targets, stats=stats,
                      version=__version__, tool_name=__tool_name__,
                      drift=resolve_drift(args, all_tests))
        sys.exit(EXIT_ERROR)

    if not all_tests:
        print(Fore.RED + "No valid targets were scanned.")
        return EXIT_ERROR

    if config is not None and auth.state != FAILED:
        recheck = verify(session, targets[0], config, args.timeout)
        if recheck.state == FAILED:
            print(Fore.RED + Style.BRIGHT +
                  f"\n[!] The session was valid at the start but not at the "
                  f"end ({recheck.detail}). Part of this scan ran logged out, "
                  f"so its results are inconclusive.")
            auth = recheck

    drift = resolve_drift(args, all_tests)
    save_results(args.output, all_tests, args.verbose)
    save_evidence(args.evidence, all_tests, targets, stats=stats,
                  version=__version__, tool_name=__tool_name__, drift=drift,
                  scan_mode=auth.state)
    print_summary(all_tests, targets, stats, drift=drift,
                  scan_mode=auth.state)
    # The exit code gates on the classes the caller asked for, so adding posture
    # checks does not turn an existing pipeline red on its own.
    gated = gated_finding_count(
        all_tests, args.fail_on,
        only_identities=(drift["new_identities"]
                         if drift is not None and args.fail_on_new else None),
        identity_of=finding_identity)
    return determine_exit_code(gated, stats)


def main():
    """Entry point: run a scan, and never exit with a lie about why.

    An unhandled exception would leave the process with status 1 - the code that
    means "the scan completed and reported findings" - and print a traceback
    carrying local paths. A crash is neither of those things, so it is reported
    in one line and gated as an error instead.
    """
    try:
        return run_scan()
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Program interrupted by user.")
        return EXIT_ERROR
    except Exception as exc:
        print(Fore.RED + Style.BRIGHT +
              f"\n[!] The scan stopped on an unexpected "
              f"{type(exc).__name__}: {exc}")
        print(Fore.YELLOW + "[!] No scan outcome can be reported from this run.")
        return EXIT_ERROR
