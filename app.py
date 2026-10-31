#!/usr/bin/env python3
"""PasteGuard — scrub private info out of text before it goes into an AI chat.

Standard library only. Run:  python3 app.py [port]
Then open:  http://127.0.0.1:8000

Privacy: pasted text is processed in memory and never saved, logged, or
written to disk. The server does not even echo the original text back —
only the redacted version is returned. No external calls of any kind.
"""

import html
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import config
from scrub import scrub_text

CSS = """
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
  max-width:760px;margin:0 auto;padding:24px 16px;color:#1e1f24;line-height:1.5}
h1{font-size:1.7em;margin-bottom:0}
.tagline{color:#555;margin-top:4px}
.privacy{background:#eef7ee;border:1px solid #b7ddb7;border-radius:8px;
  padding:12px 16px;margin:16px 0}
textarea{width:100%;min-height:150px;font:14px/1.5 ui-monospace,Menlo,monospace;
  padding:10px;box-sizing:border-box;border:1px solid #bbb;border-radius:6px}
textarea.rules{min-height:64px}
label{font-weight:600;display:block;margin:14px 0 4px}
.hint{color:#666;font-size:.9em;font-weight:400}
button{background:#1f6feb;color:#fff;border:0;border-radius:6px;padding:10px 18px;
  font-size:1em;cursor:pointer;margin-top:12px}
button.secondary{background:#555}
button:hover{opacity:.9}
pre.output{background:#111;color:#e8e8e8;padding:14px;border-radius:6px;
  white-space:pre-wrap;word-break:break-word;font-size:14px}
table{border-collapse:collapse;width:100%;margin:12px 0}
th,td{border:1px solid #ccc;padding:6px 10px;text-align:left}
th{background:#f0f0f0}
.warn{background:#fdf0ec;border:1px solid #e0a898;border-radius:8px;
  padding:12px 16px;margin:16px 0}
.error{background:#fdf0ec;border:1px solid #e0a898;border-radius:8px;
  padding:10px 14px;margin:12px 0}
.ad-slot{border:1px dashed #aaa;border-radius:6px;text-align:center;
  padding:18px;margin:24px 0;color:#888}
.ad-label{font-size:.8em;text-transform:uppercase;letter-spacing:1px}
.pro{border:1px solid #d9c27a;background:#fffbe6;border-radius:8px;
  padding:16px 20px;margin:24px 0}
.pro a.btn{display:inline-block;background:#b58900;color:#fff;text-decoration:none;
  border-radius:6px;padding:10px 18px;margin-top:8px}
footer{color:#777;font-size:.9em;margin-top:32px;border-top:1px solid #ddd;
  padding-top:12px}
code{background:#f0f0f0;padding:1px 5px;border-radius:4px}
details{margin:10px 0}
"""

JS = """
function copyRedacted(){
  var el = document.getElementById('redacted-output');
  var btn = document.getElementById('copy-btn');
  var done = function(){ btn.textContent = 'Copied \\u2713';
    setTimeout(function(){ btn.textContent = 'Copy redacted text'; }, 2000); };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(el.innerText).then(done);
  } else {
    var r = document.createRange(); r.selectNodeContents(el);
    var s = window.getSelection(); s.removeAllRanges(); s.addRange(r);
    try { document.execCommand('copy'); done(); } catch(e) {}
    s.removeAllRanges();
  }
}
function countChars(){
  var t = document.getElementById('input-text');
  document.getElementById('char-count').textContent = t.value.length + ' characters';
}
"""

PAGE_HEAD = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PasteGuard — scrub private info before it goes into an AI chat</title>
<style>{css}</style></head><body>
<h1>PasteGuard</h1>
<p class="tagline">Scrub private info out of your text <em>before</em> you paste it
into an AI chatbot.</p>
<div class="privacy"><strong>Privacy promise:</strong> Your text is processed
on this server and never saved. It is never written to disk, never logged,
and never sent anywhere else. The original text is not even sent back to
your browser — only the redacted version comes back.</div>
"""

PAGE_FORM = """
<form method="post" action="/scrub">
<label for="input-text">Paste your text here
<span class="hint" id="char-count"></span></label>
<textarea id="input-text" name="text" oninput="countChars()" required
placeholder="Paste the message you were about to send to an AI..."></textarea>
<details><summary><strong>Custom redaction rules</strong>
<span class="hint">(optional — one per line)</span></summary>
<p class="hint">Format: <code>LABEL: regex</code> or <code>LABEL=regex</code>,
or just a regex on its own. Matched text is replaced with
<code>[LABEL_1]</code>, <code>[LABEL_2]</code>, and so on. Your rules run
before the built-in ones.</p>
<textarea class="rules" name="custom_rules"
placeholder="EMPLOYEE_ID: EMP-\\d{6}&#10;INTERNAL: Project Falcon"></textarea>
</details>
<button type="submit">Scrub it</button>
</form>
"""

PAGE_PRO = """
<div class="pro"><h2>PasteGuard Pro — $5 one-time</h2>
<p>Batch scanning of multiple texts at once, plus custom redaction rules you
define and save, so your whole team scrubs the same way every time.</p>
<a class="btn" href="{pro_link}">Get PasteGuard Pro — $5 one-time</a></div>
"""

PAGE_FOOT = """
<footer>PasteGuard detects emails, US phone numbers, Social Security numbers,
credit-card-shaped numbers (Luhn-checked), AWS keys, GitHub and Slack tokens,
Stripe live keys, password/secret assignments, and other high-entropy tokens.
No detector is perfect — always glance at the redacted text before pasting it
anywhere. Built with Python's standard library only; no data ever leaves
this server.</footer>
<script>{js}</script></body></html>
"""


def render_page(results=None, errors=None):
    parts = [PAGE_HEAD.format(css=CSS), config.AD_SLOT_HTML, PAGE_FORM]
    if errors:
        parts.append('<div class="error"><strong>Custom rule problems:</strong>'
                     '<ul>%s</ul></div>'
                     % "".join("<li>%s</li>" % html.escape(e) for e in errors))
    if results is not None:
        redacted, rows, ssn_found = results
        if ssn_found:
            parts.append(
                '<div class="warn"><strong>Warning: a Social Security number '
                'was found and redacted.</strong> SSNs should never be pasted '
                'into AI chats or anywhere else online. If this text was ever '
                'sent anywhere before scrubbing, treat that SSN as exposed.'
                '</div>')
        parts.append('<h2>Redacted text</h2>')
        parts.append('<pre class="output" id="redacted-output">%s</pre>'
                     % html.escape(redacted))
        parts.append('<button type="button" class="secondary" id="copy-btn" '
                     'onclick="copyRedacted()">Copy redacted text</button>')
        if rows:
            parts.append('<h2>What was found</h2>'
                         '<table><tr><th>Type</th><th>Count</th>'
                         '<th>Placeholders used</th></tr>')
            for row in rows:
                parts.append('<tr><td>%s</td><td>%d</td><td>%s</td></tr>'
                             % (html.escape(row["type"]), row["count"],
                                ", ".join(html.escape(p)
                                          for p in row["placeholders"])))
            parts.append('</table>')
        else:
            parts.append('<p>No sensitive patterns were found — but give the '
                         'text one more look before pasting it anywhere.</p>')
    parts.append(PAGE_PRO.format(pro_link=html.escape(config.STRIPE_PRO_LINK,
                                                      quote=True)))
    parts.append(PAGE_FOOT.format(js=JS))
    return "".join(parts).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    # Silence all request logging: pasted text must never appear in logs.
    def log_message(self, *args):
        pass

    def _send(self, body, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(render_page())
        else:
            self._send(b"Not found.", status=404)

    def do_POST(self):
        if self.path != "/scrub":
            self._send(b"Not found.", status=404)
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        try:
            fields = parse_qs(raw.decode("utf-8", "replace"))
        except Exception:
            self._send(render_page(errors=["Could not read the form."]))
            return
        text = fields.get("text", [""])[0]
        custom_rules = fields.get("custom_rules", [""])[0]
        if len(text) > config.MAX_INPUT_CHARS:
            self._send(render_page(
                errors=["Text too long (max %d characters)."
                        % config.MAX_INPUT_CHARS]))
            return
        redacted, rows, ssn_found, rule_errors = scrub_text(text, custom_rules)
        self._send(render_page(results=(redacted, rows, ssn_found),
                               errors=rule_errors or None))


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else int(
        os.environ.get("PORT", config.PORT))
    server = ThreadingHTTPServer((config.HOST, port), Handler)
    print("PasteGuard running at http://%s:%d  (text is never saved)"
          % (config.HOST, port), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
