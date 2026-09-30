#!/usr/bin/env bash
# Create (or update) a quality profile that keeps a language plugin's own rules and
# adds every OpenGrep rule for that language.
#
# A SonarQube project uses exactly one profile per language, and built-in profiles
# cannot be extended by another plugin. So this script creates a normal profile that
# inherits from the language's existing profile (e.g. "Sonar way", or "dartanalyzer"
# for sonar-flutter) and activates the opengrep-<language> repository in it.
#
# Usage:
#   SONAR_HOST_URL=http://localhost:9000 SONAR_TOKEN=... \
#     scripts/setup-quality-profile.sh <language> <parent profile> [profile name] [--default]
#
# Examples:
#   scripts/setup-quality-profile.sh dart dartanalyzer "Dart + OpenGrep" --default
#   scripts/setup-quality-profile.sh xml "Sonar way" "XML + OpenGrep" --default
#
# The token needs the "Administer Quality Profiles" permission. It is passed to curl
# on stdin, never on the command line.
set -euo pipefail

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
[ $# -ge 2 ] || usage
LANGUAGE="$1"; PARENT="$2"; NAME="${3:-${1^} + OpenGrep}"; MAKE_DEFAULT="${4:-}"
[ "$NAME" = "--default" ] && { NAME="${1^} + OpenGrep"; MAKE_DEFAULT="--default"; }
HOST="${SONAR_HOST_URL:-http://localhost:9000}"
: "${SONAR_TOKEN:?set SONAR_TOKEN to a token with Administer Quality Profiles}"

api() { # api METHOD PATH [curl --data-urlencode args...]
  local method="$1" path="$2"; shift 2
  printf 'user = "%s:"\n' "$SONAR_TOKEN" | curl -sS --fail-with-body -K - -X "$method" "$HOST$path" "$@"
}

profile_key() { # the key of the profile named $1 for $LANGUAGE, or empty
  api GET /api/qualityprofiles/search --get --data-urlencode "language=$LANGUAGE" \
    | python3 -c 'import json,sys
name = sys.argv[1]
print(next((p["key"] for p in json.load(sys.stdin)["profiles"] if p["name"] == name), ""))' "$1"
}

[ -n "$(profile_key "$PARENT")" ] || { echo "no '$PARENT' profile for language '$LANGUAGE'" >&2; exit 1; }

if [ -z "$(profile_key "$NAME")" ]; then
  api POST /api/qualityprofiles/create --data-urlencode "language=$LANGUAGE" --data-urlencode "name=$NAME" > /dev/null
  echo "created profile '$NAME' ($LANGUAGE)"
fi
KEY="$(profile_key "$NAME")"

api POST /api/qualityprofiles/change_parent --data-urlencode "language=$LANGUAGE" \
  --data-urlencode "qualityProfile=$NAME" --data-urlencode "parentQualityProfile=$PARENT" > /dev/null
echo "'$NAME' inherits from '$PARENT'"

api POST /api/qualityprofiles/activate_rules --data-urlencode "targetKey=$KEY" \
  --data-urlencode "repositories=opengrep-$LANGUAGE" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print("activated %s OpenGrep rules (%s failed)" % (d.get("succeeded", 0), d.get("failed", 0)))'

if [ "$MAKE_DEFAULT" = "--default" ]; then
  api POST /api/qualityprofiles/set_default --data-urlencode "language=$LANGUAGE" \
    --data-urlencode "qualityProfile=$NAME" > /dev/null
  echo "'$NAME' is now the default $LANGUAGE profile"
fi
