#!/usr/bin/env python3
"""
METATRON - browser_probe.py
Origin-locked Playwright click probe. Opens a URL, clicks a capped set of
same-host links/buttons, and reports console errors, failed requests, and crashes.
Does not submit login/payment forms or inject payloads.
"""

from __future__ import annotations

import argparse
import sys
from urllib.parse import urljoin, urlparse


BLOCKED_SCHEMES = {"javascript", "data", "file", "blob", "about"}

CONSENT_LABELS = (
    "nécessaires",
    "necessaires",
    "necessary",
    "accept",
    "agree",
    "j'accepte",
    "jaccepte",
    "tout accepter",
    "only necessary",
    "reject",
    "refuser",
    "decline",
    "got it",
    "continue",
    "allow all",
)


def host_allowed(url: str, start_host: str, allowed_hosts: list, allow_subdomains: bool) -> bool:
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme in BLOCKED_SCHEMES:
        return False
    if scheme and scheme not in ("http", "https"):
        return False
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    start_host = (start_host or "").lower()
    extras = {h.lower() for h in allowed_hosts if h}
    if host == start_host or host in extras:
        return True
    if allow_subdomains:
        if start_host and host.endswith("." + start_host):
            return True
        for extra in extras:
            if extra and host.endswith("." + extra):
                return True
    return False


def _print(msg: str) -> None:
    print(msg, flush=True)


def _label_is_consent(label: str) -> bool:
    text = (label or "").strip().lower()
    if not text:
        return False
    return any(token in text for token in CONSENT_LABELS)


def dismiss_cookie_banner(page, timeout_ms: int) -> bool:
    """Click a consent/cookie dialog so later clicks are not intercepted."""
    try:
        page.wait_for_timeout(500)
    except Exception:
        pass

    selectors = (
        "[aria-modal='true']",
        "[role='dialog']",
        ".cookies-consent-overlay",
        "#cookies-consent",
        "[class*='cookie']",
        "[id*='cookie']",
        "[class*='consent']",
    )
    dialog = None
    for sel in selectors:
        try:
            dialog = page.query_selector(sel)
        except Exception:
            dialog = None
        if dialog:
            break

    candidates = []
    try:
        if dialog:
            candidates = dialog.query_selector_all("button, [role='button'], a")
        if not candidates:
            candidates = page.query_selector_all("button, [role='button']")
    except Exception:
        candidates = []

    for button in candidates:
        try:
            label = button.inner_text().strip()[:80]
        except Exception:
            continue
        if not _label_is_consent(label):
            continue
        try:
            _print(f"[*] dismiss consent: {label!r}")
            button.click(timeout=timeout_ms)
            page.wait_for_timeout(400)
            return True
        except Exception as exc:
            _print(f"  [!] consent click failed: {exc}")

    if dialog:
        try:
            first = dialog.query_selector("button, [role='button']")
            if first:
                label = (first.inner_text() or "dialog button").strip()[:80]
                _print(f"[*] dismiss consent (dialog first button): {label!r}")
                first.click(timeout=timeout_ms)
                page.wait_for_timeout(400)
                return True
        except Exception as exc:
            _print(f"  [!] consent dialog click failed: {exc}")
    return False


def run_probe(args: argparse.Namespace) -> int:
    try:
        from playwright.sync_api import sync_playwright
        import playwright as playwright_pkg
    except ImportError:
        _print("[!] Playwright is not installed. Install with:")
        _print("    pip install playwright && playwright install chromium")
        return 1

    start = urlparse(args.url)
    start_host = (start.hostname or "").lower()
    if not start_host:
        _print(f"[!] Could not parse hostname from URL: {args.url}")
        return 1

    allowed_hosts = [h.strip() for h in (args.allowed_hosts or "").split(",") if h.strip()]
    console_errors = []
    failed_requests = []
    skipped = []
    clicked = []
    page_errors = []

    _print(f"[*] playwright {getattr(playwright_pkg, '__version__', 'unknown')}")
    _print(f"[*] start URL: {args.url}")
    _print(f"[*] origin lock host: {start_host}")
    if allowed_hosts:
        _print(f"[*] extra allowed_hosts: {allowed_hosts}")
    _print(f"[*] allow_subdomains: {args.allow_subdomains}")
    _print(f"[*] max_clicks: {args.max_clicks}  headless: {args.headless}")

    def is_allowed(url: str) -> bool:
        return host_allowed(url, start_host, allowed_hosts, args.allow_subdomains)

    try:
        with sync_playwright() as p:
            try:
                browser = p.chromium.launch(headless=args.headless)
            except Exception as exc:
                _print(f"[!] Failed to launch Chromium: {exc}")
                _print("    Try: playwright install chromium")
                return 1

            _print(f"[*] Chromium: {browser.version}")
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()

            def on_console(msg):
                if msg.type in ("error", "warning"):
                    line = f"{msg.type}: {msg.text}"
                    console_errors.append(line)
                    _print(f"  [console] {line}")

            def on_page_error(exc):
                page_errors.append(str(exc))
                _print(f"  [pageerror] {exc}")

            def on_response(response):
                status = response.status
                if status >= 400:
                    entry = f"{status} {response.url}"
                    failed_requests.append(entry)
                    _print(f"  [http] {entry}")

            def handle_route(route):
                request = route.request
                if request.resource_type == "document" and not is_allowed(request.url):
                    skipped.append(request.url)
                    _print(f"  [skip] off-origin navigation: {request.url}")
                    try:
                        route.abort()
                    except Exception:
                        route.continue_()
                    return
                route.continue_()

            page.on("console", on_console)
            page.on("pageerror", on_page_error)
            page.on("response", on_response)
            page.route("**/*", handle_route)

            _print(f"[*] opening {args.url}")
            try:
                page.goto(args.url, wait_until="domcontentloaded", timeout=args.click_timeout_ms * 3)
            except Exception as exc:
                _print(f"[!] navigation failed: {exc}")

            title = ""
            final_url = page.url
            try:
                title = page.title()
            except Exception:
                pass
            _print(f"[*] title: {title}")
            _print(f"[*] final URL: {final_url}")
            if dismiss_cookie_banner(page, args.click_timeout_ms):
                try:
                    final_url = page.url
                except Exception:
                    pass
            if not is_allowed(final_url):
                _print(f"  [skip] landed off-origin after load: {final_url}")
                skipped.append(final_url)
                context.close()
                browser.close()
                _print_summary(title, final_url, clicked, skipped, console_errors, failed_requests, page_errors)
                return 0

            hrefs = []
            try:
                hrefs = page.eval_on_selector_all(
                    "a[href]",
                    "els => els.map(e => e.getAttribute('href') || '')",
                )
            except Exception as exc:
                _print(f"[!] could not collect links: {exc}")

            candidates = []
            seen = set()
            for href in hrefs:
                if not href:
                    continue
                absolute = urljoin(final_url, href)
                if absolute in seen:
                    continue
                seen.add(absolute)
                parsed = urlparse(absolute)
                if (parsed.scheme or "").lower() in BLOCKED_SCHEMES:
                    skipped.append(absolute)
                    _print(f"  [skip] blocked scheme: {absolute}")
                    continue
                if not is_allowed(absolute):
                    skipped.append(absolute)
                    _print(f"  [skip] off-origin href: {absolute}")
                    continue
                candidates.append(absolute)

            # Buttons that are not inside login/payment forms
            try:
                buttons = page.query_selector_all("button, [role='button']")
            except Exception:
                buttons = []

            clicks_left = args.max_clicks
            for url in candidates:
                if clicks_left <= 0:
                    break
                _print(f"[*] click link {url}")
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=args.click_timeout_ms)
                    landed = page.url
                    if not is_allowed(landed):
                        _print(f"  [skip] redirect off-origin: {landed}")
                        skipped.append(landed)
                        try:
                            page.go_back(timeout=args.click_timeout_ms)
                        except Exception:
                            page.goto(final_url, wait_until="domcontentloaded", timeout=args.click_timeout_ms)
                        continue
                    clicked.append(landed)
                    clicks_left -= 1
                except Exception as exc:
                    _print(f"  [!] click failed: {exc}")

            for button in buttons:
                if clicks_left <= 0:
                    break
                try:
                    form = button.evaluate(
                        """el => {
                            const form = el.closest('form');
                            if (!form) return null;
                            const hasPass = !!form.querySelector('input[type=password], input[type=email]');
                            const text = (form.innerText || '').toLowerCase();
                            const payment = /card|cvv|iban|paypal|billing/.test(text);
                            return { hasPass, payment };
                        }"""
                    )
                    if form and (form.get("hasPass") or form.get("payment")):
                        _print("  [skip] login/payment form button")
                        continue
                    label = button.inner_text().strip()[:80] or "(button)"
                    _print(f"[*] click button {label!r}")
                    button.click(timeout=args.click_timeout_ms)
                    page.wait_for_timeout(300)
                    landed = page.url
                    if not is_allowed(landed):
                        _print(f"  [skip] button navigated off-origin: {landed}")
                        skipped.append(landed)
                        try:
                            page.go_back(timeout=args.click_timeout_ms)
                        except Exception:
                            page.goto(final_url, wait_until="domcontentloaded", timeout=args.click_timeout_ms)
                        continue
                    clicked.append(f"button:{label} -> {landed}")
                    clicks_left -= 1
                except Exception as exc:
                    _print(f"  [!] button click failed: {exc}")

            context.close()
            browser.close()

    except Exception as exc:
        _print(f"[!] Unexpected Playwright error: {exc}")
        return 1

    _print_summary(title, final_url, clicked, skipped, console_errors, failed_requests, page_errors)
    return 0


def _print_summary(title, final_url, clicked, skipped, console_errors, failed_requests, page_errors):
    _print("")
    _print("=== playwright probe summary ===")
    _print(f"title: {title}")
    _print(f"final URL: {final_url}")
    _print(f"clicked ({len(clicked)}):")
    for item in clicked:
        _print(f"  - {item}")
    _print(f"skipped off-origin ({len(skipped)}):")
    for item in skipped:
        _print(f"  - {item}")
    _print(f"console issues ({len(console_errors)}):")
    for item in console_errors:
        _print(f"  - {item}")
    _print(f"HTTP 4xx/5xx ({len(failed_requests)}):")
    for item in failed_requests:
        _print(f"  - {item}")
    _print(f"page crashes ({len(page_errors)}):")
    for item in page_errors:
        _print(f"  - {item}")


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="METATRON origin-locked Playwright probe")
    parser.add_argument("--url", required=True)
    parser.add_argument("--max-clicks", type=int, default=15)
    parser.add_argument("--click-timeout-ms", type=int, default=5000)
    parser.add_argument("--headless", action="store_true", default=True)
    parser.add_argument("--headed", action="store_true")
    parser.add_argument("--allowed-hosts", default="")
    parser.add_argument("--allow-subdomains", action="store_true")
    args = parser.parse_args(argv)
    if args.headed:
        args.headless = False
    return args


if __name__ == "__main__":
    sys.exit(run_probe(parse_args()))
