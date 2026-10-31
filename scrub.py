"""PasteGuard redaction engine — regex only, standard library only.

Design rules:
- Nothing is ever written to disk. This module holds no state between calls
  except the per-call placeholder map, which is discarded when the call ends.
- Each unique value maps to the same placeholder for the whole paste
  (e.g. the same email always becomes [EMAIL_1]).
- Placeholders are short, bracketed, uppercase tokens, so later detection
  passes cannot match inside them.
- The mapping table returned to the page lists TYPES, COUNTS and the
  placeholders used — never the original values.
"""

import re

# ---------------------------------------------------------------- patterns

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

PHONE_RE = re.compile(
    r"(?<![A-Za-z0-9])"          # not glued to other letters/digits
    r"(?:\+?1[-.\s]?)?"         # optional US country code
    r"(?:\(\d{3}\)|\d{3})"      # area code, with or without parens
    r"[-.\s]?\d{3}[-.\s]?\d{4}"  # exchange + subscriber
    r"(?![A-Za-z0-9])"
)

SSN_RE = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")

# Credit-card-shaped digit runs; Luhn-checked before redaction so that
# random long numbers (order IDs, dates) are left alone.
CC_RE = re.compile(r"(?<![\d])\d(?:[ -]?\d){12,18}(?![\d])")

AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
GITHUB_TOKEN_RE = re.compile(r"\bghp_[A-Za-z0-9]{36,}\b")
GITHUB_PAT_RE = re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")
SLACK_TOKEN_RE = re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")
STRIPE_LIVE_RE = re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b")

# Generic high-entropy token: 20+ chars mixing upper, lower and digit
# (covers base64-ish API keys with no known prefix), or 32+ hex chars.
HIGH_ENTROPY_RE = re.compile(
    r"\b(?=[A-Za-z0-9+/=_-]*[a-z])(?=[A-Za-z0-9+/=_-]*[A-Z])"
    r"(?=[A-Za-z0-9+/=_-]*\d)[A-Za-z0-9+/=_-]{20,}\b"
)
HEX_TOKEN_RE = re.compile(r"\b[0-9a-fA-F]{32,64}\b")

# password= / api_key: / token= / secret: style assignments. Group 1 is the
# key name, group 2 the separator, group 3 an optional quote, group 4 the
# value, group 5 the matching optional closing quote.
ASSIGNMENT_RE = re.compile(
    r"(?i)\b([A-Za-z0-9_]*(?:password|passwd|pwd|api[_-]?key|secret|token)"
    r"[A-Za-z0-9_]*)\s*([:=])\s*([\"']?)([^\s\"',;\}\]]+)([\"']?)"
)


def _luhn_ok(digits):
    """True if the digit string passes the Luhn checksum."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _assignment_type(key_name):
    key = key_name.lower()
    if "password" in key or "passwd" in key or key.endswith("pwd"):
        return "PASSWORD"
    if "api" in key:
        return "API_KEY"
    if "secret" in key:
        return "SECRET"
    return "TOKEN"


class Redactor:
    """One redaction run. Holds the value -> placeholder map for one paste."""

    def __init__(self):
        self.counters = {}   # type -> next number
        self.mapping = {}    # (type, value) -> placeholder
        self.ssn_found = False

    def placeholder_for(self, type_name, value):
        key = (type_name, value)
        if key not in self.mapping:
            self.counters[type_name] = self.counters.get(type_name, 0) + 1
            self.mapping[key] = "[%s_%d]" % (type_name, self.counters[type_name])
        return self.mapping[key]

    def _sub(self, text, pattern, type_name, skip_bracketed=True):
        def repl(match):
            value = match.group(0)
            if skip_bracketed and value.startswith("["):
                return value
            return self.placeholder_for(type_name, value)
        return pattern.sub(repl, text)

    def _sub_credit_cards(self, text):
        def repl(match):
            candidate = match.group(0)
            digits = re.sub(r"[ -]", "", candidate)
            if 13 <= len(digits) <= 19 and _luhn_ok(digits):
                return self.placeholder_for("CREDIT_CARD", candidate)
            return candidate
        return CC_RE.sub(repl, text)

    def _sub_assignments(self, text):
        # Rebuild with a single space around the separator for a clean,
        # readable result; quotes around the value are preserved.
        def repl(match):
            key, sep, open_q, value, close_q = match.groups()
            if value.startswith("["):
                return match.group(0)  # already redacted by an earlier pass
            ph = self.placeholder_for(_assignment_type(key), value)
            return "%s %s %s%s%s" % (key, sep, open_q, ph, close_q)
        return ASSIGNMENT_RE.sub(repl, text)

    def _sub_custom(self, text, custom_rules):
        """custom_rules: list of (label, compiled_pattern). Applied first so
        the user's own rules win over the built-ins."""
        for label, pattern in custom_rules:
            text = self._sub(text, pattern, label)
        return text

    def findings(self):
        """Mapping table rows: type, count, placeholders used. No values."""
        rows = []
        by_type = {}
        for (type_name, _value), ph in self.mapping.items():
            by_type.setdefault(type_name, []).append(ph)
        for type_name in sorted(by_type):
            placeholders = sorted(
                by_type[type_name],
                key=lambda p: int(p.rsplit("_", 1)[1].rstrip("]")),
            )
            rows.append({
                "type": type_name,
                "count": len(placeholders),
                "placeholders": placeholders,
            })
        return rows


def parse_custom_rules(rules_text):
    """Parse the custom-rules box. One rule per line, in any of these forms:

        LABEL: <regex>
        LABEL= <regex>
        <regex>            (label auto-generated as CUSTOM)

    Returns (rules, errors): rules is a list of (LABEL, compiled pattern);
    errors is a list of human-readable problem lines (bad regex, empty label).
    """
    rules = []
    errors = []
    auto_n = 0
    for lineno, raw in enumerate(rules_text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        label, pattern = None, line
        for sep in (":", "="):
            if sep in line:
                maybe_label, maybe_pattern = line.split(sep, 1)
                maybe_label = maybe_label.strip()
                if maybe_label and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*",
                                                maybe_label):
                    label, pattern = maybe_label.upper(), maybe_pattern.strip()
                    break
        if not pattern:
            errors.append("Line %d: no pattern after the label." % lineno)
            continue
        if label is None:
            auto_n += 1
            label = "CUSTOM%d" % auto_n if auto_n > 1 else "CUSTOM"
        try:
            rules.append((label, re.compile(pattern)))
        except re.error as exc:
            errors.append("Line %d: bad regex (%s)." % (lineno, exc))
    return rules, errors


def scrub_text(text, custom_rules_text=""):
    """Redact one paste. Returns (redacted_text, findings_rows, ssn_found,
    rule_errors). Never stores anything."""
    redactor = Redactor()
    rules, errors = parse_custom_rules(custom_rules_text or "")
    out = redactor._sub_custom(text, rules)
    out = redactor._sub_assignments(out)
    # SSN pass (also sets the warning flag).
    def ssn_repl(match):
        redactor.ssn_found = True
        return redactor.placeholder_for("SSN", match.group(0))
    out = SSN_RE.sub(ssn_repl, out)
    out = redactor._sub_credit_cards(out)
    out = redactor._sub(out, AWS_KEY_RE, "AWS_KEY")
    out = redactor._sub(out, GITHUB_TOKEN_RE, "GITHUB_TOKEN")
    out = redactor._sub(out, GITHUB_PAT_RE, "GITHUB_TOKEN")
    out = redactor._sub(out, SLACK_TOKEN_RE, "SLACK_TOKEN")
    out = redactor._sub(out, STRIPE_LIVE_RE, "STRIPE_KEY")
    out = redactor._sub(out, EMAIL_RE, "EMAIL")
    out = redactor._sub(out, PHONE_RE, "PHONE")
    out = redactor._sub(out, HEX_TOKEN_RE, "TOKEN")
    out = redactor._sub(out, HIGH_ENTROPY_RE, "TOKEN")
    return out, redactor.findings(), redactor.ssn_found, errors
