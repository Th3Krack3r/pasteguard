# PasteGuard

A free privacy tool that scrubs private information out of text **before**
you paste it into an AI chatbot. People paste passwords, API keys, emails,
phone numbers, and company data into AI chats, where it gets stored on
someone else's servers. PasteGuard catches that first.

## Run it

No dependencies. Python 3 standard library only.

```bash
python3 app.py
```

Then open http://127.0.0.1:8000 in your browser.

Use a different port with `python3 app.py 9000` or the `PORT` environment
variable. The server binds to localhost only.

## How it works

1. Paste text into the box and click **Scrub it**.
2. The page returns the redacted text, with placeholders like `[EMAIL_1]`,
   `[PHONE_1]`, `[API_KEY_1]`. The same value always gets the same
   placeholder within one paste.
3. A mapping table shows what was found and how many of each type — never
   the original values.
4. Click **Copy redacted text** and paste the safe version into the AI chat.

### What it detects

- Email addresses
- US phone numbers (all common formats, with or without country code)
- Social Security numbers — with an on-page warning that SSNs should never
  be pasted anywhere
- Credit-card-shaped digit sequences (Luhn-checked, so random long numbers
  are left alone)
- AWS access keys (`AKIA...`)
- GitHub tokens (`ghp_...`, `github_pat_...`)
- Slack tokens (`xoxb-...`, etc.)
- Stripe live keys (`sk_live_...`)
- Password/secret assignments (`password=`, `api_key=`, `token=`,
  `secret=`, and variants) — the key name stays, the value is redacted
- Generic high-entropy tokens (long mixed-case/digit strings, long hex)

### Custom redaction rules

Open **Custom redaction rules** on the page and add one rule per line:

```
EMPLOYEE_ID: EMP-\d{6}
INTERNAL=Project Falcon
\d{3}-\d{2}-\d{4}     (a bare regex gets an auto-generated label)
```

Matched text is replaced with `[LABEL_1]`, `[LABEL_2]`, and so on. Your
rules run before the built-in ones, so they win on overlaps. Bad regexes
are reported on the results page instead of crashing the tool.

## Privacy guarantees

- Pasted text is processed **in memory only**. It is never written to disk,
  never logged (request logging is disabled in the server), and never sent
  anywhere — the app makes **zero external calls**.
- The server does not even echo your original text back to the browser.
  Only the redacted version is returned, so the original never appears in
  a response, a log, or a file.
- The mapping table lists types, counts, and placeholders — never values.

## Monetization

### Ads

`config.py` defines `AD_SLOT_HTML`, which is rendered in the page layout.
To monetize, paste your ad network's code inside the ad-slot div in
`config.py`, replacing the `<!-- PASTE AD NETWORK CODE HERE -->` comment.
Keep the outer `<div class="ad-slot">` wrapper so the layout stays intact.

### PasteGuard Pro ($5 one-time)

The page includes a Pro upsell section: batch scanning of multiple texts
plus custom redaction rules you define and save. The checkout button
points at `STRIPE_PRO_LINK` in `config.py`, which is currently the
placeholder `https://example.com/replace-with-stripe-link` — replace it
with the real Stripe payment link before advertising Pro.

Status note: in this MVP the custom-rules box on the page is already
fully working for everyone (a real feature, not a mock), and batch
scanning is the Pro-only feature still to be gated once the Stripe link
is wired up. The checkout button itself is a placeholder link by design
until then.

## Files

- `app.py` — the web server and page (inline HTML/CSS/JS, no build step)
- `scrub.py` — the regex redaction engine
- `config.py` — ad slot HTML, Stripe Pro link, host/port, input cap

## Honest limits

No detector is perfect. New secret formats appear constantly, and a
determined secret can look like ordinary text. PasteGuard leans toward
over-redacting, and the page tells users to glance at the redacted text
before pasting it anywhere.
