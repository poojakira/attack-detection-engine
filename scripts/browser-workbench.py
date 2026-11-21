"""Synthetic browser acceptance against an already-running loopback workbench.

Run with the verification venv's Playwright and Chromium installed. Never logs
credentials, cookies or local/session storage. Artifacts stay out of source.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

from playwright.async_api import async_playwright, expect


async def verify(base_url: str, evidence: Path):
    if urlsplit(base_url).hostname not in ("127.0.0.1", "localhost"):
        raise ValueError("browser verification requires a controlled loopback target")
    evidence.mkdir(parents=True, exist_ok=True)
    results = []
    errors = []
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            executable_path=os.environ.get("CHROMIUM_EXECUTABLE", "/usr/bin/chromium")
            or None,
            headless=True,
            args=["--no-sandbox"],
        )
        page = await browser.new_page(viewport={"width": 1440, "height": 1050})
        page.on("pageerror", lambda error: errors.append(str(error)))
        # AEGIS-QA-01: retain the actual initial list response while a later
        # import and authoritative refresh complete. No detector/API mock.
        initial_list_fetched = asyncio.Event()
        release_initial_list = asyncio.Event()
        first_list = True

        async def delay_initial_list(route):
            nonlocal first_list
            if not first_list:
                await route.continue_()
                return
            first_list = False
            actual_response = await route.fetch()
            initial_list_fetched.set()
            await release_initial_list.wait()
            await route.fulfill(response=actual_response)

        list_url = base_url + "/api/v1/workbench/cases"
        await page.route(list_url, delay_initial_list)
        await page.goto(base_url)
        await page.get_by_label("Username", exact=True).fill("synthetic-analyst")
        await page.get_by_label("Password", exact=True).fill(
            "SyntheticLocalEvaluation-42"
        )
        await page.get_by_role("button", name="Sign in", exact=True).click()
        await page.get_by_role(
            "heading", name="Security Investigation Workbench"
        ).wait_for()
        await asyncio.wait_for(initial_list_fetched.wait(), timeout=10)
        # Editing before the first list arrives must not invalidate the list's
        # independent request sequence.
        await page.get_by_label("Investigation title").fill(
            "Synthetic delayed-list regression"
        )
        await page.get_by_role("button", name="Load synthetic sample").click()
        await expect(page.get_by_label("FHIR JSON", exact=True)).to_have_value(
            re.compile("synthetic-access-29", re.S)
        )
        async with page.expect_response(
            lambda response: response.url == list_url
            and response.request.method == "POST"
        ) as imported_info:
            await page.get_by_role("button", name="Import and investigate").click()
        imported_report = await (await imported_info.value).json()
        new_case_id = imported_report["case_id"]
        await page.get_by_test_id("finding-count").filter(has_text="1").wait_for()
        # The fresh list contains a newly generated case id, not an older case
        # sharing its title. Read the real report's id from the import response.
        await expect(
            page.get_by_label("Saved investigation").locator(
                f'option[value="{new_case_id}"]'
            )
        ).to_have_count(1)
        async with page.expect_response(
            lambda response: response.url == list_url
            and response.request.method == "GET"
        ) as old_response_info:
            release_initial_list.set()
        await (await old_response_info.value).finished()
        await page.evaluate(
            "() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))"
        )
        await expect(
            page.get_by_label("Saved investigation").locator(
                f'option[value="{new_case_id}"]'
            )
        ).to_have_count(1)
        await page.unroute(list_url, delay_initial_list)
        results.append(
            "AEGIS-QA-01: delayed initial real case list cannot hide a freshly imported persisted case"
        )
        await page.get_by_text("HC-ACCESS-BULK", exact=True).click()
        assert await page.get_by_text(
            "Related persisted events: 30", exact=True
        ).is_visible()
        await page.locator("ol.timeline summary").first.click()
        assert await page.get_by_role(
            "heading", name="Source event", exact=True
        ).is_visible()
        await page.locator(
            'section[aria-label="Run evidence"]'
        ).scroll_into_view_if_needed()
        await page.screenshot(path=str(evidence / "desktop.png"), full_page=False)
        results.append(
            "Actual synthetic import: 30 persisted events, canonical HC-ACCESS-BULK finding, source/normalized evidence"
        )
        await page.get_by_label("Distinct patient read threshold").fill("40")
        assert await page.get_by_role(
            "button", name="Export reproducible report"
        ).is_disabled()
        await page.get_by_role("button", name="Rerun same dataset").click()
        await expect(page.get_by_test_id("finding-count")).to_have_text("0")
        assert "−1" in await page.get_by_test_id("finding-delta").inner_text()
        async with page.expect_download() as info:
            await page.get_by_role("button", name="Export reproducible report").click()
        download = await info.value
        await download.save_as(str(evidence / "report.json"))
        report = json.loads((evidence / "report.json").read_text())
        assert (
            report["config"]["bulk_access_threshold"] == 40
            and len(report["findings"]) == 0
        )
        assert report["delta"]["removed"] == 1 and report["data_origin"] == "synthetic"
        assert len(report["events"]) == 30
        assert report["input_sha256"] and report["config_sha256"]
        results.append(
            "Same exact dataset rerun: threshold 40, removed 1 finding, checksum-verified JSON export"
        )
        await page.reload()
        await page.get_by_label("Saved investigation").select_option(report["case_id"])
        await page.get_by_test_id("finding-count").wait_for()
        assert await page.get_by_test_id("finding-count").inner_text() == "0"
        assert await page.get_by_label("Run history").locator("option").count() == 2
        results.append(
            "Page reload: saved case and both immutable run reports restored from PostgreSQL"
        )
        # Hold digest completion, change input, release: obsolete exports must not download.
        await page.evaluate("""() => {
          const original = crypto.subtle.digest.bind(crypto.subtle);
          crypto.subtle.digest = async (...args) => { const result = await original(...args); return new Promise(resolve => {window.releaseDigest = () => resolve(result);}); };
        }""")
        downloads = []
        page.on(
            "download", lambda download: downloads.append(download.suggested_filename)
        )
        await page.get_by_role("button", name="Export reproducible report").click()
        for _ in range(100):
            if await page.evaluate('() => typeof window.releaseDigest === "function"'):
                break
            await page.wait_for_timeout(50)
        assert await page.evaluate('() => typeof window.releaseDigest === "function"')
        await page.get_by_label("FHIR JSON", exact=True).fill('{"new":"input"}')
        await page.evaluate("window.releaseDigest()")
        await page.wait_for_timeout(150)
        assert downloads == []
        results.append(
            "Obsolete checksum completion cannot download a report after new input"
        )
        # Delay File.text itself, then manually edit; later file completion loses.
        await page.evaluate(
            """() => { File.prototype.text = function() { return new Promise(resolve => {window.releaseFile = () => resolve('{"obsolete":true}');}); }; }"""
        )
        await page.get_by_label("FHIR JSON file", exact=True).set_input_files(
            {"name": "synthetic.json", "mimeType": "application/json", "buffer": b"{}"}
        )
        assert await page.evaluate('() => typeof window.releaseFile === "function"')
        await page.get_by_label("FHIR JSON", exact=True).fill('{"manual":"wins"}')
        await page.evaluate("window.releaseFile()")
        assert (
            await page.get_by_label("FHIR JSON", exact=True).input_value()
            == '{"manual":"wins"}'
        )
        results.append("Delayed File.text cannot overwrite a later manual edit")
        # Restore fresh page, upload XSS-shaped metadata as inert JSON text.
        await page.reload()
        await page.get_by_role("button", name="Load synthetic sample").click()
        await expect(page.get_by_label("FHIR JSON", exact=True)).to_have_value(
            re.compile("synthetic-access-29", re.S)
        )
        payload = json.loads(
            await page.get_by_label("FHIR JSON", exact=True).input_value()
        )
        payload["entry"][0]["resource"]["agent"][0]["who"]["reference"] = (
            "Practitioner/<img src=x onerror=window.xss=true>"
        )
        payload["entry"].append({"resource": {"resourceType": "Patient"}})
        await page.get_by_label("FHIR JSON", exact=True).fill(json.dumps(payload))
        await page.get_by_label("Investigation title").fill(
            "<img src=x onerror=window.xss=true>"
        )
        await page.get_by_role("button", name="Import and investigate").click()
        await page.get_by_test_id("finding-count").wait_for()
        assert await page.get_by_text("unspecified", exact=True).is_visible()
        assert await page.locator("img").count() == 0
        assert await page.evaluate("window.xss !== true")
        await page.get_by_text("Rejected / unsupported entries", exact=True).click()
        assert (
            "resource is not an AuditEvent"
            in await page.locator('section[aria-label="Run evidence"]').inner_text()
        )
        results.append(
            "XSS-shaped title/reference render as text; mixed unsupported Bundle resource counted, origin unspecified"
        )
        await page.get_by_label("FHIR JSON", exact=True).fill("{malformed")
        await page.get_by_role("button", name="Import and investigate").click()
        await page.get_by_role("alert").wait_for()
        assert await page.get_by_test_id("finding-count").count() == 0
        results.append("Malformed JSON displays an error and clears obsolete results")
        await page.set_viewport_size({"width": 390, "height": 844})
        await page.screenshot(path=str(evidence / "mobile.png"), full_page=True)
        assert await page.evaluate(
            "document.documentElement.scrollWidth <= window.innerWidth"
        )
        results.append("390px mobile layout has no horizontal overflow")
        assert not errors, errors
        await browser.close()
    output = {
        "base_url": base_url,
        "checks": results,
        "page_errors": errors,
        "case_list_race": {
            "new_case_id": new_case_id,
            "new_case_visible_after_old_list": True,
            "held_actual_initial_api_response": True,
        },
        "report_sha256": hashlib.sha256(
            (evidence / "report.json").read_bytes()
        ).hexdigest(),
    }
    (evidence / "browser.json").write_text(json.dumps(output, indent=2) + "\n")
    print(json.dumps({"checks_passed": len(results), "page_errors": len(errors)}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    asyncio.run(verify(args.url, args.evidence))
