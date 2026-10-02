"""Web UI smoke test in a real headless Chromium (Playwright).

Logs in, visits every page at desktop and phone width in light and dark
mode, opens the main dialogs, and fails on any JavaScript error or console
error. Screenshots go to $OUT (test/artifacts/ on the host).

  BASE_URL=https://webui-server:8443 PASSWORD=... OUT=/out python3 smoke.py
"""
import os
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ["BASE_URL"].rstrip("/")
USER = os.environ.get("USERNAME", "admin")
PASSWORD = os.environ["PASSWORD"]
OUT = os.environ.get("OUT", "/out")

PAGES = [
    ("dashboard", "Dashboard"),
    ("clients", "Clients"),
    ("users", "Password users"),
    ("config/settings", "Configuration"),
    ("config/raw", "Configuration"),
    ("logs", "Logs"),
]
VIEWS = [("desktop", {"width": 1440, "height": 900}), ("phone", {"width": 390, "height": 844})]
SCHEMES = ["light", "dark"]

problems = []
shots = []


def shot(page, name):
    path = os.path.join(OUT, name + ".png")
    # Whole pages, but dialogs as the screen shows them (after their animation).
    if name.startswith("dialog-"):
        page.wait_for_timeout(400)
    page.screenshot(path=path, full_page=not name.startswith("dialog-"))
    shots.append(path)


def run(pw):
    browser = pw.chromium.launch()
    for view, size in VIEWS:
        for scheme in SCHEMES:
            tag = f"{view}-{scheme}"
            ctx = browser.new_context(viewport=size, color_scheme=scheme, ignore_https_errors=True,
                                      device_scale_factor=2 if view == "phone" else 1,
                                      is_mobile=view == "phone", has_touch=view == "phone")
            page = ctx.new_page()
            page.set_default_timeout(15000)
            page.on("console", lambda m, tag=tag: m.type == "error" and problems.append(f"{tag}: console error: {m.text}"))
            page.on("pageerror", lambda e, tag=tag: problems.append(f"{tag}: page error: {e}"))
            page.on("response", lambda r, tag=tag: r.status >= 400 and problems.append(f"{tag}: HTTP {r.status} {r.url}"))

            page.goto(BASE + "/")
            page.wait_for_selector("input[name=password]")
            shot(page, f"login-{tag}")
            page.fill("input[name=username]", USER)
            page.fill("input[name=password]", PASSWORD)
            page.press("input[name=password]", "Enter")
            page.wait_for_selector(".shell")

            for route, title in PAGES:
                page.goto(f"{BASE}/#/{route}")
                page.wait_for_selector(f"main h1:text-is('{title}')")
                page.wait_for_timeout(900)  # live data and the first validation
                if page.locator(".loading").count():
                    page.wait_for_selector(".loading", state="detached", timeout=10000)
                shot(page, f"{route.replace('/', '-')}-{tag}")
                if page.evaluate("document.documentElement.scrollWidth > window.innerWidth + 1"):
                    problems.append(f"{tag}: #/{route} scrolls sideways (wider than the screen)")

            # Dialogs: new client, a profile download, a destructive confirmation.
            page.goto(f"{BASE}/#/clients")
            page.wait_for_selector("main h1:text-is('Clients')")
            page.wait_for_timeout(500)
            new = page.locator("button:has-text('New client')").first
            if new.is_enabled():
                new.click()
                page.wait_for_selector("dialog[open]")
                page.fill("dialog[open] input[type=text]", "ui-smoke-" + tag)
                shot(page, f"dialog-new-client-{tag}")
                page.keyboard.press("Escape")
                page.wait_for_selector("dialog[open]", state="detached")
            if page.locator("button:has-text('Revoke')").count():
                page.locator("button:has-text('Revoke')").first.click()
                page.wait_for_selector("dialog[open]")
                shot(page, f"dialog-revoke-{tag}")
                page.locator("dialog[open] button:has-text('Cancel')").click()
            if page.locator("button:has-text('Profile')").count():
                page.locator("button:has-text('Profile')").first.click()
                page.wait_for_selector("dialog[open]")
                shot(page, f"dialog-profile-{tag}")
                page.locator("dialog[open] button:has-text('Close')").click()

            # The review dialog for a settings change (cancelled: nothing is applied).
            page.goto(f"{BASE}/#/config/settings")
            page.wait_for_selector("main h1:text-is('Configuration')")
            page.wait_for_timeout(500)
            mtu = page.locator("#sec-advanced input[inputmode=numeric]").last
            if mtu.is_enabled():
                mtu.fill("1400")
                page.locator("button:has-text('Review and apply')").click()
                page.wait_for_selector("dialog[open] .diff")
                shot(page, f"dialog-review-{tag}")
                page.locator("dialog[open] button:has-text('Cancel')").click()
                page.locator("button:has-text('Discard')").click()
                page.wait_for_selector("dialog[open]")
                page.locator("dialog[open] button:has-text('Discard')").click()
                page.wait_for_timeout(300)

            # Keyboard: the first Tab stop is reachable and visible.
            page.goto(f"{BASE}/#/dashboard")
            page.wait_for_selector("main h1:text-is('Dashboard')")
            page.keyboard.press("Tab")
            if not page.evaluate("document.activeElement && document.activeElement !== document.body"):
                problems.append(f"{tag}: nothing focusable with Tab")
            ctx.close()
    browser.close()


with sync_playwright() as pw:
    run(pw)

for s in shots:
    print("screenshot", s)
if problems:
    for p in problems:
        print("PROBLEM", p)
    sys.exit(1)
print(f"ok: {len(shots)} screenshots, no JavaScript or console errors")
