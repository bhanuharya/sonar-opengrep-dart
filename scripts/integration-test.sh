#!/usr/bin/env bash
# End-to-end check against a running SonarQube that has the plugin installed:
# scan examples/flutter-vulnerable with OpenGrep, import it with sonar-scanner, and
# verify every Dart result became a native issue or hotspot. Needs sonar-flutter.
#
#   SONAR_HOST_URL=http://localhost:9000 SONAR_TOKEN=... [SONAR_SCANNER=sonar-scanner] \
#     scripts/integration-test.sh
#
# Needs: opengrep, sonar-scanner, python3. The token needs Execute Analysis and
# Administer Quality Profiles (the script sets up the combined profiles first).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOST="${SONAR_HOST_URL:-http://localhost:9000}"
SCANNER="${SONAR_SCANNER:-sonar-scanner}"
PROJECT="${PROJECT_KEY:-opengrep-it-flutter}"
: "${SONAR_TOKEN:?set SONAR_TOKEN}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

api() { printf 'user = "%s:"\n' "$SONAR_TOKEN" | curl -sS --fail-with-body -K - "$HOST$1"; }
installed() { api /api/languages/list | python3 -c 'import json,sys; print(" ".join(l["key"] for l in json.load(sys.stdin)["languages"]))'; }

LANGS="$(installed)"
case " $LANGS " in *" dart "*) ;; *) echo "no dart language: install sonar-flutter first" >&2; exit 1 ;; esac
"$ROOT/scripts/setup-quality-profile.sh" dart dartanalyzer "Dart + OpenGrep" --default

cd "$ROOT/examples/flutter-vulnerable"
opengrep scan --quiet --json --config "$ROOT/rules" --exclude '*.test.dart' . > "$WORK/opengrep.json"
: > "$WORK/empty-dart.txt"
SONAR_TOKEN="$SONAR_TOKEN" "$SCANNER" -Dsonar.host.url="$HOST" -Dsonar.projectKey="$PROJECT" \
  -Dsonar.sources=. -Dsonar.opengrep.reportPaths="$WORK/opengrep.json" \
  -Dsonar.qualitygate.wait=false \
  -Dsonar.dart.analyzer.mode=MANUAL -Dsonar.dart.analyzer.report.mode=MACHINE \
  -Dsonar.dart.analyzer.report.path="$WORK/empty-dart.txt" \
  -Dsonar.working.directory="$WORK/scannerwork" > "$WORK/scan.log" 2>&1 || { tail -40 "$WORK/scan.log"; exit 1; }
grep "OpenGrep:" "$WORK/scan.log"

TASK="$(grep -oE 'api/ce/task[?]id=[A-Za-z0-9_-]+' "$WORK/scan.log" | head -1 | cut -d= -f2)"
for _ in $(seq 1 60); do
  STATUS="$(api "/api/ce/task?id=$TASK" | python3 -c 'import json,sys; print(json.load(sys.stdin)["task"]["status"])')"
  [ "$STATUS" = SUCCESS ] && break
  [ "$STATUS" = FAILED ] && { echo "compute engine task failed"; exit 1; }
  sleep 3
done

api "/api/issues/search?componentKeys=$PROJECT&ps=500" > "$WORK/issues.json"
api "/api/hotspots/search?projectKey=$PROJECT&ps=500" > "$WORK/hotspots.json"
python3 - "$WORK" <<'PY'
import json, sys
work = sys.argv[1]
results = json.load(open(f"{work}/opengrep.json"))["results"]
expected = sorted((r["check_id"].split(".rules.", 1)[-1].split(".", 1)[-1], r["path"], r["start"]["line"])
                  for r in results if r["path"].endswith(".dart"))
issues = json.load(open(f"{work}/issues.json"))["issues"]
hotspots = json.load(open(f"{work}/hotspots.json"))["hotspots"]
got = sorted([(i["rule"].split(":", 1)[1], i["component"].split(":", 1)[1], i.get("line")) for i in issues
              if i["rule"].startswith("opengrep-")] +
             [(h["ruleKey"].split(":", 1)[1], h["component"].split(":", 1)[1], h.get("line")) for h in hotspots
              if h["ruleKey"].startswith("opengrep-")])
vulns = sum(1 for i in issues if i["rule"].startswith("opengrep-") and i["type"] == "VULNERABILITY")
spots = sum(1 for h in hotspots if h["ruleKey"].startswith("opengrep-"))
print(f"expected {len(expected)} OpenGrep results; Sonar has {vulns} vulnerabilities + {spots} hotspots")
missing = [e for e in expected if e not in got]
extra = [g for g in got if g not in expected]
for item in missing:
    print("MISSING", item)
for item in extra:
    print("UNEXPECTED", item)
sys.exit(1 if missing or extra or not expected else 0)
PY
echo "integration test passed"
