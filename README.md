# Invisible Character Detector

A high-performance Rust CLI tool and GitHub Action designed to detect **Glassworm**, **Trojan Source**, and **ASCII Smuggling** attacks. It identifies hidden Unicode characters that are invisible to the human eye but interpreted by compilers and interpreters.

[![GitHub Action](https://img.shields.io/badge/GitHub-Action-blue)](https://github.com/marketplace/actions/invisible-char-detector)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## The Threat
Modern supply-chain attacks exploit the discrepancy between what a human sees in a code editor and what a machine executes. 

* **Logic Hiding:** Using Zero-Width characters to create "invisible" variables or logic.
* **Trojan Source:** Using BiDi (Bidirectional) overrides to flip code logic visually (e.g., making a malicious `return` appear inside a comment).
* **Glassworm/Smuggling:** Encoding malicious payloads inside Variation Selectors or Private Use Areas.

---

## Detection Capabilities
This tool flags high-risk Unicode categories while maintaining a low false-positive rate by ignoring standard whitespace (Tabs/LF/CR).

* **Zero-Width & Joiners:** `U+200B` (ZWSP), `U+200C` (ZWNJ), `U+200D` (ZWJ), `U+2060` (Word Joiner).
* **Bidi Controls:** Full suite of directional overrides (`U+202A`–`U+202E`) and isolates (`U+2066`–`U+2069`).
* **Variation Selectors:** `U+FE00`–`U+FE0F` (The smuggling layer).
* **Private Use Areas (PUA):** Any character in the ranges `U+E000`–`U+F8FF`, `U+F0000`–`U+FFFFD`, and `U+100000`–`U+10FFFD`.
* **Suspicious Controls:** Non-standard C0/C1 control characters.
* **Confusable Whitespace:** Non-ASCII spaces like `U+00A0` (NBSP) and `U+2007` (Figure Space).

---

## GitHub Action Integration
Add this to your `.github/workflows/security.yml` to automatically block malicious Pull Requests.

```yaml
name: Security Scan
on: [pull_request, push]

jobs:
  unicode-hygiene:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Scan for Hidden Characters
        uses: nealhar/invisible-char-detector@v1
        with:
          pattern: "src/**/*.{rs,js,py,ts,json}"
          scan_bundles: "false" # Set to true to scan dist/build folders
          fail_on_skip: "true"  # Exit with error if a file is unreadable
```

## Manual Usage (CLI)
If you prefer to run it locally or as a pre-commit hook:
```bash
# Compile
cargo build -- release
```
# Examples
```bash
# Basic scan of all Rust files
invisible-char-detector "**/*.rs"

# Verbose scan including build artifacts
invisible-char-detector "**/*.js" --verbose --scan-bundles

# CI/Tooling integration with JSON output
invisible-char-detector "src/" --json > security-report.json
```

## Exit Codes

The tool is designed for automation and CI integration.

| Code | Meaning |
| :--- | :--- |
| 0 | Clean — no suspicious characters found |
| 1 | **Threat detected** — suspicious characters found (build fails) |
| 2 | Operational error (invalid glob pattern or file permissions) |

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.