"""
Smishing Detection Pipeline — Automated Test Runner
====================================================
Run with:
    python test_runner.py                  # default http://localhost:8000
    python test_runner.py --url http://192.168.1.x:8000
    python test_runner.py --report html    # also saves report.html
    python test_runner.py --stage cnn      # run only one stage
    python test_runner.py --fail-only      # print only failures
"""

import argparse
import json
import time
import sys
import os
from datetime import datetime
from typing import Optional

try:
    import requests
except ImportError:
    print("[ERROR] requests not installed. Run: pip install requests")
    sys.exit(1)

# ──────────────────────────────────────────────────────────────────────────────
# Test Suite Definition
# ──────────────────────────────────────────────────────────────────────────────
# Each test:
#   id          : unique number
#   stage       : which pipeline layer this primarily exercises
#   label       : short description
#   msg         : the SMS text sent to /predict
#   expect      : "Smishing Detected" | "Safe" | "Edge"
#   expect_exact: if True, status must match exactly; if False, treat as informational
#   triggers    : which components should fire (informational, used in report)
#   lime        : whether LIME output is expected
#   note        : extra context

TESTS = [
    # ── Stage 1: Domain Checker ──────────────────────────────────────────────
    {"id":1, "stage":"domain", "label":"Malicious .tk TLD",
     "msg":"Your account is at risk! Verify now: http://secure-bank-login.tk/verify",
     "expect":"Smishing Detected", "expect_exact":True,
     "triggers":["domain_checker"], "lime":True,
     "note":"domain_checker catches .tk TLD"},

    {"id":2, "stage":"domain", "label":"Shortened URL — bit.ly",
     "msg":"Urgent claim your prize! bit.ly/123",
     "expect":"Smishing Detected", "expect_exact":True,
     "triggers":["domain_checker"], "lime":True,
     "note":"bit.ly in malicious/shortened domain list"},

    {"id":3, "stage":"domain", "label":"Shortened URL — tinyurl",
     "msg":"Get your free gift: tinyurl.com/win2026",
     "expect":"Smishing Detected", "expect_exact":True,
     "triggers":["domain_checker"], "lime":True,
     "note":"tinyurl.com in shortened list"},

    {"id":4, "stage":"domain", "label":"Shortened URL — goo.gl",
     "msg":"Check this out: goo.gl/abcd",
     "expect":"Smishing Detected", "expect_exact":True,
     "triggers":["domain_checker"], "lime":False,
     "note":"goo.gl in shortened list — minimal content so LIME may be empty"},

    {"id":5, "stage":"domain", "label":"Subdomain spoofing",
     "msg":"Your package is held. Track: delivery.fedex.com.parcel-track.xyz",
     "expect":"Smishing Detected", "expect_exact":True,
     "triggers":["domain_checker"], "lime":True,
     "note":"Legit brand as subdomain of bad domain"},

    {"id":6, "stage":"domain", "label":"Homograph attack — digit substitution",
     "msg":"Log in to paypa1.com to confirm your identity.",
     "expect":"Smishing Detected", "expect_exact":True,
     "triggers":["domain_checker"], "lime":True,
     "note":"Digit-substitution in domain name"},

    {"id":7, "stage":"domain", "label":"Legitimate HTTPS URL — must be safe",
     "msg":"Your Amazon order has shipped. Track it at https://www.amazon.com/orders",
     "expect":"Safe", "expect_exact":True,
     "triggers":[], "lime":False,
     "note":"Legit domain — all stages should pass"},

    # ── Stage 2: Heuristic Rule Engine ───────────────────────────────────────
    {"id":8, "stage":"heuristic", "label":"Urgency keyword — 'urgent'",
     "msg":"URGENT: Your bank account will be suspended in 24 hours. Call 1-800-555-0100 immediately.",
     "expect":"Smishing Detected", "expect_exact":True,
     "triggers":["rule_engine"], "lime":True,
     "note":"Urgency keyword hit"},

    {"id":9, "stage":"heuristic", "label":"Urgency keyword — 'winner'",
     "msg":"Congratulations! You are today's lucky winner. Claim your $1000 prize before midnight.",
     "expect":"Smishing Detected", "expect_exact":True,
     "triggers":["rule_engine"], "lime":True,
     "note":"'winner' keyword"},

    {"id":10, "stage":"heuristic", "label":"Urgency keyword — 'account suspended'",
     "msg":"Your PayPal account has been suspended. Click here to restore access.",
     "expect":"Smishing Detected", "expect_exact":True,
     "triggers":["rule_engine"], "lime":True,
     "note":"'account suspended' keyword"},

    {"id":11, "stage":"heuristic", "label":"Urgency keyword — 'verify'",
     "msg":"Please verify your identity immediately to avoid service interruption.",
     "expect":"Smishing Detected", "expect_exact":True,
     "triggers":["rule_engine"], "lime":True,
     "note":"'verify' keyword"},

    {"id":12, "stage":"heuristic", "label":"Urgency keyword — 'password reset'",
     "msg":"Password reset required. If this wasn't you, call us now at 555-0199.",
     "expect":"Smishing Detected", "expect_exact":True,
     "triggers":["rule_engine"], "lime":True,
     "note":"'password reset' keyword"},

    {"id":13, "stage":"heuristic", "label":"Multiple suspicious phone numbers",
     "msg":"Call our team at (800) 555-0101 or (888) 555-0202 for your exclusive offer.",
     "expect":"Smishing Detected", "expect_exact":True,
     "triggers":["rule_engine"], "lime":True,
     "note":"2+ suspicious numbers pattern"},

    {"id":14, "stage":"heuristic", "label":"Domain + urgency word combo",
     "msg":"Security alert: Unusual login detected. Tap to review: ow.ly/abc",
     "expect":"Smishing Detected", "expect_exact":True,
     "triggers":["domain_checker", "rule_engine"], "lime":True,
     "note":"Both domain_checker and rule_engine should fire"},

    # ── Stage 3: CNN Model ────────────────────────────────────────────────────
    {"id":15, "stage":"cnn", "label":"Spam language — no URL, no keyword",
     "msg":"You have been selected for a free iPhone 15! Reply YES to confirm your delivery address.",
     "expect":"Smishing Detected", "expect_exact":True,
     "triggers":["cnn"], "lime":True,
     "note":"No heuristic triggers — relies entirely on CNN"},

    {"id":16, "stage":"cnn", "label":"Credential harvesting — no URL",
     "msg":"Dear customer, please send us your full name, date of birth, and last 4 digits of your card.",
     "expect":"Smishing Detected", "expect_exact":True,
     "triggers":["cnn"], "lime":True,
     "note":"Phishing body without URL or urgency word"},

    {"id":17, "stage":"cnn", "label":"Lottery scam phrasing",
     "msg":"UK National Lottery: ref EN45. You have won 850000 GBP. Contact claim agent on WhatsApp.",
     "expect":"Smishing Detected", "expect_exact":True,
     "triggers":["cnn"], "lime":True,
     "note":"Classic lottery scam, no domain trigger"},

    {"id":18, "stage":"cnn", "label":"Bank impersonation — no URL",
     "msg":"HSBC Bank: We detected a new payee added to your account. If this wasn't you, call 0300 555 0199.",
     "expect":"Smishing Detected", "expect_exact":True,
     "triggers":["cnn"], "lime":True,
     "note":"No URL, mild urgency — CNN differentiates"},

    {"id":19, "stage":"cnn", "label":"Package delivery fraud",
     "msg":"Your parcel could not be delivered. A fee of 1.99 GBP is required to rearrange. Reply PARCEL.",
     "expect":"Smishing Detected", "expect_exact":True,
     "triggers":["cnn"], "lime":True,
     "note":"Classic smishing without explicit keywords"},

    {"id":20, "stage":"cnn", "label":"Borderline CNN confidence",
     "msg":"Exclusive deal just for you. Limited time only. Respond now.",
     "expect":"Smishing Detected", "expect_exact":False,  # CNN may vary
     "triggers":["cnn"], "lime":True,
     "note":"Borderline — tests CNN confidence threshold (>0.5). Result may vary."},

    # ── Stage 4: LIME / XAI ───────────────────────────────────────────────────
    {"id":21, "stage":"lime", "label":"Rich vocabulary — LIME multi-word",
     "msg":"URGENT: You have won a FREE iPhone. Claim your prize immediately at bit.ly/win2026 before it expires!",
     "expect":"Smishing Detected", "expect_exact":True,
     "triggers":["domain_checker", "rule_engine", "lime"], "lime":True,
     "note":"LIME should surface multiple high-weight words"},

    {"id":22, "stage":"lime", "label":"Low-confidence CNN — LIME critical",
     "msg":"Final notice: your subscription renewal failed. Update billing to keep service.",
     "expect":"Smishing Detected", "expect_exact":False,
     "triggers":["cnn", "lime"], "lime":True,
     "note":"Low confidence — LIME is the only meaningful explanation"},

    {"id":23, "stage":"lime", "label":"LIME single-word impact",
     "msg":"Verify your account now to avoid being locked out permanently.",
     "expect":"Smishing Detected", "expect_exact":True,
     "triggers":["rule_engine", "lime"], "lime":True,
     "note":"LIME should weight 'verify' and 'locked' heavily"},

    {"id":24, "stage":"lime", "label":"LIME — mixed safe and spam words",
     "msg":"Hi, your interview is confirmed for Monday. Please verify your email to get the Zoom link.",
     "expect":"Edge", "expect_exact":False,
     "triggers":["rule_engine", "lime"], "lime":True,
     "note":"'verify' triggers heuristic but context is legit — mixed LIME weights expected"},

    # ── Stage 5: Safe / Ham ───────────────────────────────────────────────────
    {"id":25, "stage":"safe", "label":"OTP message",
     "msg":"Your OTP is 847291. It expires in 10 minutes. Do not share this with anyone.",
     "expect":"Safe", "expect_exact":True,
     "triggers":[], "lime":False,
     "note":"Standard OTP — all stages should pass cleanly"},

    {"id":26, "stage":"safe", "label":"Appointment reminder",
     "msg":"Reminder: Your dentist appointment is on Thursday 10 April at 3:00 PM. Reply CONFIRM or CANCEL.",
     "expect":"Safe", "expect_exact":True,
     "triggers":[], "lime":False,
     "note":"Legitimate scheduling SMS"},

    {"id":27, "stage":"safe", "label":"Bank debit alert",
     "msg":"HDFC Bank: INR 2500 debited from A/c XX1234 on 07-Apr-26. Avl Bal: INR 14820.",
     "expect":"Safe", "expect_exact":True,
     "triggers":[], "lime":False,
     "note":"Standard bank debit notification"},

    {"id":28, "stage":"safe", "label":"Casual friend message",
     "msg":"Hey! Are we still on for dinner tonight? Let me know.",
     "expect":"Safe", "expect_exact":True,
     "triggers":[], "lime":False,
     "note":"Casual message — nothing should trigger"},

    {"id":29, "stage":"safe", "label":"Amazon delivery notification",
     "msg":"Your Amazon order #408-1234567 has been delivered. If you have issues, visit amazon.com/help.",
     "expect":"Safe", "expect_exact":True,
     "triggers":[], "lime":False,
     "note":"Legit brand and domain"},

    {"id":30, "stage":"safe", "label":"Work Slack notification",
     "msg":"You have 3 unread messages in #engineering. Open Slack to reply.",
     "expect":"Safe", "expect_exact":True,
     "triggers":[], "lime":False,
     "note":"Corporate notification format"},

    # ── Stage 6: Edge Cases ───────────────────────────────────────────────────
    {"id":31, "stage":"edge", "label":"Legitimate urgency in medical context",
     "msg":"URGENT: Your medication prescription is ready for pickup. Call 555-0100 to confirm.",
     "expect":"Edge", "expect_exact":False,
     "triggers":["rule_engine"], "lime":True,
     "note":"Heuristic false positive — 'urgent' fires but context is benign"},

    {"id":32, "stage":"edge", "label":"Legitimate bit.ly link",
     "msg":"Here is the meeting agenda: bit.ly/team-agenda-apr7",
     "expect":"Edge", "expect_exact":False,
     "triggers":["domain_checker"], "lime":True,
     "note":"bit.ly used legitimately — expected false positive"},

    {"id":33, "stage":"edge", "label":"Real password reset from Netflix",
     "msg":"Netflix: Someone requested a password reset. If this was you, click: netflix.com/reset/abc123",
     "expect":"Edge", "expect_exact":False,
     "triggers":["rule_engine"], "lime":True,
     "note":"'password reset' triggers but domain is legit"},

    {"id":34, "stage":"edge", "label":"Foreign language smishing — Spanish",
     "msg":"Urgente: Su cuenta bancaria ha sido bloqueada. Llame al 900-555-0123 ahora mismo.",
     "expect":"Smishing Detected", "expect_exact":False,
     "triggers":["rule_engine", "cnn"], "lime":True,
     "note":"Non-English spam — tests multilingual robustness"},

    {"id":35, "stage":"edge", "label":"Emoji-heavy obfuscation",
     "msg":"YOU WON Claim here http://prize-claim.ml to collect your $500 reward NOW!",
     "expect":"Smishing Detected", "expect_exact":True,
     "triggers":["domain_checker", "rule_engine"], "lime":True,
     "note":"Emoji obfuscation — tests URL extraction through noise"},

    {"id":36, "stage":"edge", "label":"Zero-width character injection",
     "msg":"Verify\u200b your acc\u200bount at secure\u200b-bank.com/log\u200bin",
     "expect":"Smishing Detected", "expect_exact":False,
     "triggers":["domain_checker", "cnn"], "lime":True,
     "note":"Zero-width spaces to evade regex — tests text_processor robustness"},

    {"id":37, "stage":"edge", "label":"Very short message",
     "msg":"Click here: goo.gl/abc",
     "expect":"Smishing Detected", "expect_exact":True,
     "triggers":["domain_checker"], "lime":False,
     "note":"Minimal content — LIME may not have enough tokens"},

    {"id":38, "stage":"edge", "label":"Empty string — crash safety",
     "msg":"",
     "expect":"Edge", "expect_exact":False,
     "triggers":[], "lime":False,
     "note":"Empty string — pipeline must not crash; any non-500 response passes"},

    {"id":39, "stage":"edge", "label":"Whitespace only — crash safety",
     "msg":"     ",
     "expect":"Edge", "expect_exact":False,
     "triggers":[], "lime":False,
     "note":"Whitespace-only — LIME guard must not crash"},

    {"id":40, "stage":"edge", "label":"Extremely long spam message",
     "msg":("CONGRATULATIONS! You have been selected as the lucky winner of our annual sweepstakes! "
            "You have won a cash prize of $50,000 USD. To claim your winnings you must verify your "
            "identity immediately. Please provide your full name, date of birth, home address, bank "
            "account number, and social security number. Reply or call 1-800-555-0199 before midnight "
            "tonight or your prize will be forfeited. This is your final notice. Act now!"),
     "expect":"Smishing Detected", "expect_exact":True,
     "triggers":["rule_engine", "cnn", "lime"], "lime":True,
     "note":"Max-length message — tests tokenizer truncation at maxlen=100"},
]

# ──────────────────────────────────────────────────────────────────────────────
# ANSI colours for terminal output
# ──────────────────────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

def col(text, *codes):
    return "".join(codes) + str(text) + RESET

# ──────────────────────────────────────────────────────────────────────────────
# Core runner
# ──────────────────────────────────────────────────────────────────────────────

def run_test(test: dict, base_url: str, timeout: int = 15) -> dict:
    """POST one test case to /predict and return a result dict."""
    url = base_url.rstrip("/") + "/predict"
    start = time.perf_counter()

    result = {
        "id":           test["id"],
        "stage":        test["stage"],
        "label":        test["label"],
        "msg":          test["msg"],
        "expect":       test["expect"],
        "expect_exact": test["expect_exact"],
        "lime_expected":test["lime"],
        "note":         test["note"],
        "triggers":     test["triggers"],
        # filled in below
        "status":       None,
        "risk_score":   None,
        "reason":       None,
        "important_words": [],
        "latency_ms":   None,
        "http_code":    None,
        "passed":       None,
        "lime_ok":      None,
        "error":        None,
    }

    try:
        resp = requests.post(
            url,
            json={"message": test["msg"]},
            timeout=timeout,
            headers={"Content-Type": "application/json"},
        )
        result["http_code"]  = resp.status_code
        result["latency_ms"] = round((time.perf_counter() - start) * 1000, 1)

        if resp.status_code != 200:
            result["error"]  = f"HTTP {resp.status_code}: {resp.text[:200]}"
            result["passed"] = False
            return result

        body = resp.json()
        result["status"]          = body.get("status")
        result["risk_score"]      = body.get("risk_score")
        result["reason"]          = body.get("reason")
        result["important_words"] = body.get("important_words", [])

        # ── Pass / Fail logic ──────────────────────────────────────────────
        if test["expect"] == "Edge":
            # Edge cases: pass if server didn't crash (any 2xx response)
            result["passed"] = True
        elif test["expect_exact"]:
            result["passed"] = result["status"] == test["expect"]
        else:
            # Informational — log but don't count as failure
            result["passed"] = True

        # ── LIME check ────────────────────────────────────────────────────
        if test["lime"]:
            result["lime_ok"] = len(result["important_words"]) > 0
        else:
            result["lime_ok"] = True  # not required, so trivially ok

    except requests.exceptions.ConnectionError:
        result["error"]      = "Connection refused — is the FastAPI server running?"
        result["passed"]     = False
        result["latency_ms"] = round((time.perf_counter() - start) * 1000, 1)
    except requests.exceptions.Timeout:
        result["error"]      = f"Request timed out after {timeout}s"
        result["passed"]     = False
        result["latency_ms"] = round((time.perf_counter() - start) * 1000, 1)
    except Exception as e:
        result["error"]      = str(e)
        result["passed"]     = False
        result["latency_ms"] = round((time.perf_counter() - start) * 1000, 1)

    return result


def print_result(r: dict, fail_only: bool, verbose: bool):
    if fail_only and r["passed"] and r["lime_ok"]:
        return

    icon   = col("PASS", GREEN, BOLD) if r["passed"] else col("FAIL", RED, BOLD)
    lime_i = col("LIME OK", GREEN) if r["lime_ok"] else (
             col("LIME --", YELLOW) if not r["lime_expected"] else col("LIME MISSING", RED))
    lat    = col(f"{r['latency_ms']}ms", DIM) if r["latency_ms"] else ""

    print(f"\n  [{icon}] #{r['id']:02d} {col(r['label'], BOLD)}  {lat}")
    print(f"         Stage   : {r['stage'].upper()}   {lime_i}")
    if r["error"]:
        print(f"         Error   : {col(r['error'], RED)}")
    else:
        print(f"         Got     : {r['status']}  (risk={r['risk_score']:.3f})")
        print(f"         Reason  : {r['reason']}")
        if verbose and r["important_words"]:
            words = ", ".join(f"{w['word']}(+{w['score']:.2f})" for w in r["important_words"])
            print(f"         LIME    : {words}")
    if not r["passed"]:
        print(f"         Expected: {col(r['expect'], YELLOW)}")
    if not r["lime_ok"] and r["lime_expected"]:
        print(f"         {col('LIME output expected but important_words was empty', YELLOW)}")


def print_summary(results: list, elapsed: float):
    total  = len(results)
    passed = sum(1 for r in results if r["passed"])
    failed = total - passed
    lime_f = sum(1 for r in results if r["lime_expected"] and not r["lime_ok"])
    avg_ms = sum(r["latency_ms"] or 0 for r in results) / total

    by_stage = {}
    for r in results:
        by_stage.setdefault(r["stage"], {"pass":0,"fail":0})
        if r["passed"]: by_stage[r["stage"]]["pass"] += 1
        else:           by_stage[r["stage"]]["fail"] += 1

    print("\n" + "═"*60)
    print(col("  PIPELINE TEST SUMMARY", BOLD))
    print("═"*60)
    print(f"  Total   : {total} cases    Time: {elapsed:.1f}s    Avg: {avg_ms:.0f}ms/req")
    print(f"  Passed  : {col(passed, GREEN, BOLD)}    Failed: {col(failed, RED, BOLD) if failed else col(0, DIM)}    LIME gaps: {col(lime_f, YELLOW) if lime_f else col(0, DIM)}")
    print()
    print(f"  {'Stage':<12} {'Pass':>5} {'Fail':>5}")
    print(f"  {'─'*24}")
    for stage in ["domain","heuristic","cnn","lime","safe","edge"]:
        if stage in by_stage:
            d = by_stage[stage]
            fc = RED if d["fail"] else DIM
            print(f"  {stage:<12} {col(d['pass'], GREEN):>14} {col(d['fail'], fc):>14}")
    print("═"*60)
    return failed == 0 and lime_f == 0


# ──────────────────────────────────────────────────────────────────────────────
# HTML report generator
# ──────────────────────────────────────────────────────────────────────────────

def generate_html_report(results: list, base_url: str) -> str:
    now    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total  = len(results)
    passed = sum(1 for r in results if r["passed"])
    failed = total - passed
    lime_f = sum(1 for r in results if r["lime_expected"] and not r["lime_ok"])

    stage_colors = {
        "domain":"#185FA5","heuristic":"#854F0B","cnn":"#534AB7",
        "lime":"#0F6E56","safe":"#3B6D11","edge":"#A32D2D"
    }
    stage_bg = {
        "domain":"#E6F1FB","heuristic":"#FAEEDA","cnn":"#EEEDFE",
        "lime":"#E1F5EE","safe":"#EAF3DE","edge":"#FCEBEB"
    }

    rows = ""
    for r in results:
        pass_cell = ('<td style="color:#3B6D11;font-weight:500">PASS</td>'
                     if r["passed"] else
                     '<td style="color:#A32D2D;font-weight:500">FAIL</td>')
        lime_cell = ('<td style="color:#3B6D11">OK</td>'
                     if r["lime_ok"] else
                    ('<td style="color:#888">—</td>'
                     if not r["lime_expected"] else
                     '<td style="color:#854F0B">MISSING</td>'))
        status_cell = r["status"] or (f'<span style="color:red">{r["error"][:60]}</span>')
        words = ", ".join(f'{w["word"]}(+{w["score"]:.2f})' for w in r["important_words"]) or "—"
        sc = stage_colors.get(r["stage"],"#555")
        sb = stage_bg.get(r["stage"],"#eee")
        stage_pill = (f'<span style="background:{sb};color:{sc};font-size:11px;'
                      f'padding:2px 7px;border-radius:20px">{r["stage"]}</span>')
        rows += f"""<tr>
          <td style="color:#888;font-size:12px">{r['id']}</td>
          <td>{stage_pill}</td>
          <td style="font-size:12px;font-weight:500">{r['label']}</td>
          <td style="font-size:11px;color:#555;max-width:300px;word-break:break-word">{r['msg'][:120] + ('…' if len(r['msg'])>120 else '')}</td>
          <td style="font-size:12px">{status_cell}</td>
          <td style="font-size:12px">{r['risk_score']:.3f if r['risk_score'] is not None else '—'}</td>
          <td style="font-size:11px;color:#555;max-width:200px">{r['reason'] or '—'}</td>
          <td style="font-size:11px;color:#555;max-width:200px">{words}</td>
          <td style="font-size:11px">{r['latency_ms']}ms</td>
          {pass_cell}
          {lime_cell}
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Smishing Test Report — {now}</title>
<style>
  body{{font-family:system-ui,sans-serif;margin:0;padding:24px;background:#f9f9f7;color:#1a1a1a}}
  h1{{font-size:22px;font-weight:500;margin-bottom:4px}}
  .meta{{font-size:13px;color:#666;margin-bottom:24px}}
  .stats{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:24px}}
  .stat{{background:#fff;border:0.5px solid #e0e0d8;border-radius:10px;padding:12px 16px}}
  .stat-label{{font-size:11px;color:#888;margin-bottom:4px;text-transform:uppercase;letter-spacing:.04em}}
  .stat-val{{font-size:22px;font-weight:500}}
  table{{width:100%;border-collapse:collapse;background:#fff;border:0.5px solid #e0e0d8;border-radius:10px;overflow:hidden;font-size:13px}}
  th{{font-size:11px;font-weight:500;color:#888;text-align:left;padding:8px 10px;border-bottom:0.5px solid #e8e8e0;background:#fafaf8}}
  td{{padding:7px 10px;border-bottom:0.5px solid #f0f0e8;vertical-align:top}}
  tr:last-child td{{border-bottom:none}}
  tr:hover td{{background:#fafaf8}}
</style>
</head>
<body>
<h1>Smishing detection — pipeline test report</h1>
<p class="meta">Server: {base_url} &nbsp;|&nbsp; Run at: {now}</p>
<div class="stats">
  <div class="stat"><div class="stat-label">Total</div><div class="stat-val">{total}</div></div>
  <div class="stat"><div class="stat-label">Passed</div><div class="stat-val" style="color:#3B6D11">{passed}</div></div>
  <div class="stat"><div class="stat-label">Failed</div><div class="stat-val" style="color:#A32D2D">{failed}</div></div>
  <div class="stat"><div class="stat-label">LIME gaps</div><div class="stat-val" style="color:#854F0B">{lime_f}</div></div>
  <div class="stat"><div class="stat-label">Pass rate</div><div class="stat-val">{passed/total*100:.0f}%</div></div>
</div>
<table>
<thead><tr>
  <th>#</th><th>Stage</th><th>Label</th><th>Message</th>
  <th>Status</th><th>Risk</th><th>Reason</th><th>LIME words</th>
  <th>Latency</th><th>Result</th><th>LIME</th>
</tr></thead>
<tbody>{rows}</tbody>
</table>
</body>
</html>"""


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Smishing pipeline automated test runner")
    parser.add_argument("--url",       default="http://localhost:8000",
                        help="Base URL of the FastAPI backend (default: http://localhost:8000)")
    parser.add_argument("--stage",     default=None,
                        choices=["domain","heuristic","cnn","lime","safe","edge"],
                        help="Run only tests for a specific pipeline stage")
    parser.add_argument("--report",    default=None,
                        choices=["html","json","both"],
                        help="Also save a report file (html / json / both)")
    parser.add_argument("--fail-only", action="store_true",
                        help="Only print failing test cases to terminal")
    parser.add_argument("--verbose",   action="store_true",
                        help="Print LIME word breakdown for every test")
    parser.add_argument("--timeout",   type=int, default=15,
                        help="Per-request timeout in seconds (default: 15)")
    parser.add_argument("--delay",     type=float, default=0.0,
                        help="Delay between requests in seconds (default: 0)")
    args = parser.parse_args()

    tests = TESTS if not args.stage else [t for t in TESTS if t["stage"] == args.stage]

    print(col(f"\n  Smishing Pipeline — Automated Test Runner", BOLD, CYAN))
    print(f"  Server : {args.url}")
    print(f"  Cases  : {len(tests)}  (stage filter: {args.stage or 'all'})")
    print(f"  Timeout: {args.timeout}s per request\n")

    # Health-check
    try:
        r = requests.get(args.url.rstrip("/") + "/docs", timeout=5)
        print(col(f"  Server reachable (HTTP {r.status_code})\n", GREEN))
    except Exception:
        print(col("  WARNING: Could not reach server — tests will likely fail\n", YELLOW))

    results   = []
    start_all = time.perf_counter()

    for i, test in enumerate(tests, 1):
        print(f"  Running {i}/{len(tests)}: #{test['id']} {test['label'][:50]}…", end="\r")
        r = run_test(test, args.url, timeout=args.timeout)
        results.append(r)
        print_result(r, args.fail_only, args.verbose)
        if args.delay:
            time.sleep(args.delay)

    elapsed = time.perf_counter() - start_all
    all_ok  = print_summary(results, elapsed)

    # Save reports
    if args.report in ("html", "both"):
        html = generate_html_report(results, args.url)
        fname = f"smishing_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(fname, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"\n  HTML report saved: {col(fname, CYAN)}")

    if args.report in ("json", "both"):
        fname = f"smishing_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(fname, "w", encoding="utf-8") as f:
            json.dump({"run_at": datetime.now().isoformat(),
                       "server": args.url, "results": results}, f, indent=2)
        print(f"  JSON report saved: {col(fname, CYAN)}")

    print()
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
