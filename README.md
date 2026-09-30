# OpenGrep for Dart (SonarQube)

**Dart and Flutter security rules for SonarQube.** [OpenGrep](https://github.com/opengrep/opengrep) (or Semgrep)
findings on Dart code become **native SonarQube rules**. They show up as real **Vulnerabilities** and
**Security Hotspots**, are mapped to **CWE** and **OWASP Top 10**, and appear in SonarQube's security reports,
not as anonymous "external issues".

It ships with a Dart/Flutter security rule pack and can also load your own Dart rule directories.

| | External issues (generic import, SARIF) | This plugin |
|---|---|---|
| Security Hotspots with review workflow | ✗ | ✓ |
| CWE / OWASP Top 10 security reports | ✗ | ✓ |
| Rules visible and configurable in quality profiles | ✗ | ✓ |
| Rule descriptions, remediation, references | ✗ | ✓ |

## Requirements

- SonarQube with [sonar-flutter](https://github.com/insideapp-oss/sonar-flutter), which provides the `dart`
  language. Without it the plugin publishes no rules (and logs why).
- OpenGrep in your CI. The plugin does not run it; it imports its JSON report.

## How it works

```
 rule YAML (Dart) ──► SonarQube server: rule repository "opengrep-dart"
                      (type, severity, CWE/OWASP from rule metadata)
 opengrep scan --json ──► sonar-scanner + sonar.opengrep.reportPaths
                          └─► each result lands on its rule: Vulnerability or Security Hotspot
```

## Install

1. Download the jar from the releases page (or build it with `mvn package`) and copy it to `extensions/plugins/`.
2. Restart SonarQube.
3. Create a quality profile that keeps sonar-flutter's Dart rules and adds the OpenGrep ones. A project uses one
   profile per language, and a plugin cannot add rules to another plugin's built-in profile:

   ```bash
   export SONAR_HOST_URL=https://sonar.example.com SONAR_TOKEN=...   # needs Administer Quality Profiles
   scripts/setup-quality-profile.sh dart dartanalyzer "Dart + OpenGrep" --default
   ```

   The plugin also registers a built-in **OpenGrep Security** Dart profile (OpenGrep rules only).

## Analyze

```bash
opengrep scan --json --config path/to/rules -o opengrep.json .
dart analyze --format=machine > dart-analyze.txt || true
sonar-scanner \
  -Dsonar.opengrep.reportPaths=opengrep.json \
  -Dsonar.dart.analyzer.mode=MANUAL -Dsonar.dart.analyzer.report.mode=MACHINE \
  -Dsonar.dart.analyzer.report.path=dart-analyze.txt -Dsonar.dart.analyzer.options.override=false
```

The `sonar.dart.analyzer.*` settings are for sonar-flutter. By default it runs `flutter analyze` itself, and the
whole analysis fails when `flutter`/`dart` is not on the scanner's `PATH`. `report.mode=MACHINE` matters too:
without it the plugin runs `dart` just to detect the report format.

| Property | Where | Default | Meaning |
|---|---|---|---|
| `sonar.opengrep.reportPaths` | scanner | — | Comma-separated OpenGrep/Semgrep JSON reports (or SDT canonical `findings.json`) |
| `sonar.opengrep.externalIssuesFallback` | scanner | `true` | A result with no active rule becomes an external issue instead of being dropped |
| `sonar.opengrep.rules.directories` | server (`sonar.properties`) | — | Extra rule directories loaded at startup (comma-separated) |
| `sonar.opengrep.rules.bundled` | server (`sonar.properties`) | `true` | `false` publishes only your own directories |

The scanner log accounts for every result, for example
`OpenGrep: 11 imported on OpenGrep rules, 0 as external issues, 0 skipped`, with a reason for each skip
(file not indexed, duplicate, no active rule).

## Rule metadata

The plugin reads standard OpenGrep/Semgrep rule YAML. A rule is published when it targets Dart
(`languages: [dart]`, a `paths.include` glob ending in `.dart`, or `metadata.sonar.language: dart`); rules for
other languages are skipped. These `metadata` keys shape the Sonar rule:

| Key | Effect |
|---|---|
| `category: security` (or any `cwe`) | Security rule: a Vulnerability or a Security Hotspot (see below) |
| `confidence: HIGH` | Security rule becomes a **Vulnerability** |
| `mode: taint` (top level) | Data-flow rule: a **Vulnerability** whatever its confidence |
| otherwise | Security rule becomes a **Security Hotspot**: a human must judge the context |
| `sonar: {type: vulnerability \| hotspot \| bug \| code_smell}` | Explicit type; always wins (flat `sonar-type:` works too) |
| `sonar: {severity: BLOCKER…INFO}` | Explicit severity; otherwise `CRITICAL`→Blocker, `ERROR`/`HIGH`→Critical, `WARNING`/`MEDIUM`→Major, `INFO`/`LOW`→Minor |
| `cwe: ["CWE-295"]` | CWE security standard |
| `owasp: ["A02:2021 - …"]` | OWASP Top 10 (2021 or 2017) security standard |
| `owasp-mobile: ["M5: …"]`, `masvs: ["MASVS-NETWORK-1"]` | Tags `owasp-mobile-m5`, `masvs-network-1` (Sonar has no built-in mobile standard) |
| `name`, `description`, `remediation`, `references` | Rule title, description, "How to fix it", links |
| `category: correctness` | Non-security: Bug (other categories: Code Smell) |

Rule keys are the OpenGrep rule ids. OpenGrep prefixes ids with the config path in its output
(`rules.dart.my-rule`); the importer handles that.

## Bundled rule pack

`rules/` holds 18 Dart rules, each with vulnerable and safe fixtures (`opengrep scan --test`):

| File | Rules |
|---|---|
| `rules/dart/security.yaml` | TLS certificate validation disabled, weak MD5 / SHA-1, AES-ECB, zero key, insecure random, shell command, SQL injection (taint), WebView untrusted script (taint), WebView unrestricted JavaScript |
| `rules/flutter/mobile.yaml` | cleartext `http://` URLs, secrets in SharedPreferences, hardcoded API keys / auth headers, secrets in logs, WebView JavaScript channels, static IV, `biometricOnly: false`, unvalidated deep-link handlers |

## Try it

`examples/flutter-vulnerable/` is an intentionally vulnerable Dart file set. `scripts/integration-test.sh` scans it
against a running SonarQube (with sonar-flutter and this plugin installed) and checks that every Dart result
became a native issue or hotspot.

## Compatibility

Built against the plugin API of SonarQube 9.9 LTA (`pluginApiMinVersion` 9.14).

| SonarQube | Status |
|---|---|
| 10.7 Community + sonar-flutter 0.5.2 | tested (unit + integration) |
| 9.9 LTA, latest | built for; exercised by the CI matrix |

## Limitations

- A finding in a file SonarQube does not index (deleted files, git history) cannot be shown; the log says so.
- Hotspot review status in SonarQube is not synchronised back to OpenGrep or any other triage system.
- Rules are loaded at server start: restart after changing `sonar.opengrep.rules.directories`.
- The sample secrets in `examples/` and the rule fixtures are fake, and exist so the rules have something to find.

## Build

```bash
mvn verify                                                              # unit tests + jar in target/
opengrep scan --test --config rules/dart/security.yaml rules/dart/security.test.dart
opengrep scan --test --config rules/flutter/mobile.yaml rules/flutter/mobile.test.dart
```

## License

[LGPL-3.0](LICENSE)
