#!/usr/bin/env bash
# Configures npm trusted publishing (OIDC) for the seven @paratix/ssh-native
# packages that join the release in #255 B3: the six platform packages and
# @paratix/ssh-native itself. paratix and create-paratix already have their
# trusted publisher.
#
# Run it locally as the npm owner of the @paratix scope, after `npm login`,
# right before merging the first release-please PR that contains
# @paratix/ssh-native. Afterwards set "Require two-factor authentication and
# disallow tokens" for each of the seven packages on npmjs.com. npm gives a
# freshly configured trusted publisher two days for its first publish; an OIDC
# token exchange without a publish does not extend that window.
#
# Every package gets exactly one GitHub Actions trusted publisher:
# repository sebastian-software/paratix, workflow publish.yml, environment npm.
# The script is idempotent: a package that already has exactly this publisher
# is skipped, and a package with any other trust configuration aborts the run,
# because npm keeps one trusted publisher per package and a foreign one must
# be reviewed and revoked by hand (`npm trust revoke <package> --id=<id>`).
#
# Usage: scripts/configure-trust.sh [--dry-run]
#   --dry-run  only list the current configuration and print what would be
#              created; changes nothing on the registry.
#
# Needs npm 11.10 or newer (`npm trust`). npm asks for a one-time password per
# change because trust changes require two-factor authentication.
set -euo pipefail

REPOSITORY="sebastian-software/paratix"
WORKFLOW_FILE="publish.yml"
ENVIRONMENT="npm"
PACKAGES=(
  "@paratix/ssh-native-linux-x64-gnu"
  "@paratix/ssh-native-linux-arm64-gnu"
  "@paratix/ssh-native-linux-x64-musl"
  "@paratix/ssh-native-linux-arm64-musl"
  "@paratix/ssh-native-darwin-x64"
  "@paratix/ssh-native-darwin-arm64"
  "@paratix/ssh-native"
)

dry_run=false
case "${1:-}" in
  "") ;;
  --dry-run) dry_run=true ;;
  *)
    echo "usage: $0 [--dry-run]" >&2
    exit 2
    ;;
esac

if ! npm trust --help > /dev/null 2>&1; then
  echo "npm $(npm --version) has no 'npm trust' command; install npm 11.10 or newer." >&2
  exit 1
fi

npm_user="$(npm whoami)"
echo "npm user: $npm_user, npm $(npm --version)"
echo "Trusted publisher: GitHub Actions ${REPOSITORY}, workflow ${WORKFLOW_FILE}, environment ${ENVIRONMENT}"

# `npm trust` reads package.json in the working directory; run it from an
# empty directory so no repository manifest is picked up.
work_directory="$(mktemp -d)"
trap 'rm -rf "$work_directory"' EXIT
cd "$work_directory"

# Classifies `npm trust list --json` output (one JSON object per
# configuration, separated by blank lines; nothing when there is none):
# prints "none", "match" or "foreign: <details>".
classify() {
  node -e '
    const [repository, file, environment] = process.argv.slice(1)
    const text = require("node:fs").readFileSync(0, "utf8").trim()
    if (text === "") {
      console.log("none")
      process.exit(0)
    }
    const configs = JSON.parse(`[${text.replace(/\}\s*\{/g, "},{")}]`)
    const matches = (config) =>
      config.type === "github" &&
      config.repository === repository &&
      config.file === file &&
      config.environment === environment
    if (configs.length === 1 && matches(configs[0])) {
      console.log("match")
    } else {
      console.log(`foreign: ${JSON.stringify(configs)}`)
    }
  ' "$REPOSITORY" "$WORKFLOW_FILE" "$ENVIRONMENT"
}

failed=0
for package in "${PACKAGES[@]}"; do
  echo
  echo "== $package"
  if ! npm view "$package" name > /dev/null 2>&1; then
    echo "error: $package does not exist on the registry (the 0.0.0 placeholder is missing)." >&2
    failed=1
    continue
  fi
  state="$(npm trust list "$package" --json | classify)"
  case "$state" in
    match)
      echo "already configured; skipping"
      ;;
    none)
      if [ "$dry_run" = true ]; then
        npm trust github "$package" --repository "$REPOSITORY" --file "$WORKFLOW_FILE" \
          --environment "$ENVIRONMENT" --allow-publish --dry-run
      else
        npm trust github "$package" --repository "$REPOSITORY" --file "$WORKFLOW_FILE" \
          --environment "$ENVIRONMENT" --allow-publish --yes
      fi
      ;;
    *)
      echo "error: $package has a different trust configuration: ${state#foreign: }" >&2
      echo "Review it, revoke it with 'npm trust revoke $package --id=<id>' and run this script again." >&2
      failed=1
      ;;
  esac
done

if [ "$failed" -ne 0 ]; then
  exit 1
fi

echo
if [ "$dry_run" = true ]; then
  echo "Dry run finished; nothing was changed."
else
  echo "Done. Now enable \"Require two-factor authentication and disallow tokens\" for all seven"
  echo "packages (npmjs.com > package > Settings > Publishing access) and merge the release PR"
  echo "within two days."
fi
