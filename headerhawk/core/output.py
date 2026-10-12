"""Console output: quiet-mode handling, status chatter and the run summary."""

from colorama import Fore, Style

from .baseline import describe_drift
from .findings import (CLASS_POSTURE, CLASS_VULNERABILITY, CONFIDENCE_ORDER,
                       DEFAULT_MIN_SEVERITY, confidence_of, count_by_class,
                       count_by_confidence, reportable, suppressed_count)

# Suppresses progress/status chatter (set from --quiet / non-TTY detection).
# Findings and the final summary are never suppressed - only the noise around
# them - so piping the tool into a log stays useful.
_QUIET = False


def status(*args, **kwargs):
    """Print progress/status output unless the scan is running in quiet mode."""
    if not _QUIET:
        print(*args, **kwargs)


def resolve_quiet(quiet_flag, stdout_isatty):
    """Quiet mode is on when explicitly requested or when stdout is not a TTY."""
    return bool(quiet_flag or not stdout_isatty)


def set_quiet(value):
    """Set the process-wide quiet mode.

    The flag lives here rather than in the CLI so that ``status`` reads the same
    object the CLI writes; callers in other modules must not rebind their own
    copy of it.
    """
    global _QUIET
    _QUIET = bool(value)


def is_quiet():
    """Return the current quiet-mode setting."""
    return _QUIET


def blind_spots(all_tests):
    """What each check said it could not judge, as ``(check, reason)`` pairs.

    A check reports this two ways: ``skip`` when the whole check could not run,
    and ``skip_type`` when it judged most of what it covers and had to leave one
    finding type alone. Both are a reason somebody recorded, and both have to
    reach the person reading the output - otherwise a scan that could not look
    and a scan that found nothing print the same thing.
    """
    blind = []
    for test in all_tests:
        name = getattr(test, "test_type", type(test).__name__)
        if not getattr(test, "assessed", True):
            reason = getattr(test, "skip_reason", None) or "the check did not run"
            blind.append((name, reason))
            # The whole check stood down; its per-type reasons say no more.
            continue
        for test_type, reason in sorted(
                (getattr(test, "unassessed", None) or {}).items()):
            label = name if test_type == name else f"{name} ({test_type})"
            blind.append((label, reason))
    return blind


def print_summary(all_tests, targets, stats, drift=None, scan_mode=None,
                  min_severity=DEFAULT_MIN_SEVERITY):
    """Print the aggregate summary and return the total finding count."""
    total_vulns = sum(len(test.vulnerabilities_found) for test in all_tests)
    quietened = suppressed_count(all_tests, min_severity)
    # Never suppressed by --quiet: a check that could not look is the one thing
    # an empty findings list cannot tell the reader by itself.
    blind = blind_spots(all_tests)
    scanned = len({test.target_url for test in all_tests})
    print(Fore.CYAN + Style.BRIGHT + "\n========== Test Summary ==========")
    print(Fore.CYAN + f"Targets scanned: {scanned}/{len(targets)}")
    if scan_mode:
        # Never suppressed: whether the scan saw the product or its login
        # page decides what every other line here means.
        print(Fore.CYAN + f"Scan mode: {scan_mode}")
    print(Fore.CYAN + f"Requests: {stats.succeeded}/{stats.total} succeeded "
          f"({stats.failed} failed).")
    counts = count_by_class(all_tests)
    print(Fore.CYAN + f"Total findings: {total_vulns} "
          f"({counts.get(CLASS_VULNERABILITY, 0)} vulnerability, "
          f"{counts.get(CLASS_POSTURE, 0)} posture)")
    if total_vulns:
        grades = count_by_confidence(all_tests)
        print(Fore.CYAN + "Evidence: " + ", ".join(
            f"{grades[name]} {name}" for name in CONFIDENCE_ORDER
            if grades.get(name)))
    if quietened:
        # Never silent about its own silence: a count, and where to read them.
        print(Fore.CYAN + f"Not shown: {quietened} posture finding(s) below "
                          f"--min-severity {min_severity} (the compliance "
                          f"evidence report lists every one)")
    if drift is not None:
        print(Fore.CYAN + f"Against baseline: {describe_drift(drift)}")

    by_type = {}
    for test in all_tests:
        for vuln in test.vulnerabilities_found:
            if not reportable(vuln, min_severity):
                continue
            by_type.setdefault(test.test_type, []).append(vuln)
    for test_type, vulns in by_type.items():
        print(Fore.MAGENTA + Style.BRIGHT + f"\n--- {test_type} ---")
        for vuln in vulns:
            print(Fore.RED + f"- [{vuln.get('severity', '')}, "
                  f"{confidence_of(vuln)}] "
                  f"{vuln['method']} {vuln['url']}")
            print(f"  Header/Parameter: {vuln.get('header_name') or vuln.get('param_name')}")
            print(f"  Payload: {vuln['payload']}")
            print(Fore.YELLOW + f"  Analysis: {vuln['analysis']}")
            print(Fore.RED + "-" * 80)

    if blind and not stats.all_failed:
        # When every request failed, every check is blind for the same reason
        # and the louder message below already says so; listing all of them
        # would bury it.
        print(Fore.YELLOW + Style.BRIGHT +
              f"\nCould not assess ({len(blind)}):")
        for name, reason in blind:
            print(Fore.YELLOW + f"- {name}: {reason}")
        print(Fore.YELLOW +
              "  The compliance evidence report names the requirements each "
              "of these leaves short of a pass.")

    # An unreachable target must not be reported as a clean result: every issued
    # request failing means the findings list is empty for the wrong reason.
    if stats.all_failed:
        print(Fore.RED + Style.BRIGHT +
              "\n[!] Every request failed - the target(s) appear unreachable. "
              "Results are inconclusive, not a clean bill of health.")
        if stats.all_tls_failures:
            print(Fore.YELLOW +
                  "    Every failure was a TLS certificate error. If this target "
                  "uses a self-signed or otherwise untrusted certificate - "
                  "normal in test environments - re-run with --insecure/-k.")
    elif total_vulns == 0:
        if blind and not stats.all_failed:
            # A clean result and a result nobody could obtain look identical
            # in a findings list, so the line that reports one says which.
            print(Fore.GREEN + "No vulnerabilities were found" +
                  Fore.YELLOW + " - but see what could not be assessed above; "
                                "this is not a clean bill of health for those "
                                "requirements.")
        else:
            print(Fore.GREEN + "No vulnerabilities were found.")
    print(Fore.CYAN + "=" * 35)
    return total_vulns
