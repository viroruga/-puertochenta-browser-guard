# Security Policy

BrowserGuard is a security library, so we take vulnerabilities in it seriously.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅        |

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report it privately through GitHub's **"Report a vulnerability"** button in this repository's
**Security** tab (private vulnerability reporting). Include:

- the affected version;
- a description of the issue and its impact;
- steps or a minimal page that reproduces it.

We aim to acknowledge reports within 3 business days and to share a remediation plan within
10 business days.

## Scope

In scope:

- ways in which BrowserGuard **leaks sensitive data** (tokens, cookies, form contents, full URLs)
  through findings, console output or remote reporting;
- ways in which BrowserGuard **breaks or alters the host application** (lost arguments, changed
  return values, unhandled exceptions, functions not restored after `Stop()`);
- vulnerabilities in the example collector that would also affect production deployments copied
  from it.

Out of scope (documented limitations, see the README):

- evasion by an attacker who already runs code in the page before or after BrowserGuard starts;
- scrapers that do not execute JavaScript, or that forge the verdict header;
- false positives or negatives of the heuristics, unless they cause one of the in-scope issues.
