# Changelog

## 0.1.0 (unreleased)

- Dart OpenGrep/Semgrep rules become native SonarQube rules in the `opengrep-dart` repository, typed as
  Vulnerability / Security Hotspot / Bug / Code Smell from rule metadata, with CWE and OWASP Top 10 (2017, 2021)
  security standards and OWASP Mobile / MASVS tags. Requires sonar-flutter for the `dart` language.
- Importer for `opengrep --json` / Semgrep JSON and SDT `findings.json`. Unknown or inactive rules fall back to
  external issues, and the scanner log accounts for every result.
- Built-in "OpenGrep Security" Dart profile; `scripts/setup-quality-profile.sh` creates a profile that inherits
  sonar-flutter's rules.
- `sonar.opengrep.languages` (server): publish rules for more languages than Dart (`*` for all installed).
- SDT reports: gitleaks secrets and Trivy dependency vulnerabilities become native `sdt` rules. Secrets found only in
  git history are raised on the project, and dependencies no source imports become Security Hotspots.
- Bundled Dart/Flutter rule pack (18 rules, each with fixtures) and `examples/flutter-vulnerable`.
