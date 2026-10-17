#!/bin/sh
# Builds the deploy bundle of a release, as .github/workflows/release.yml did for GitHub releases.
# Usage: .onedev/bundle.sh <image> <version> <where the bundle is downloaded from> [output directory, default dist]
# Writes <output>/current-<version>-deploy.tar.gz, SHA256SUMS and notes.md (the release description). Needs yq.
set -eu
APP=current; IMAGE=$1; VERSION=$2; URL=$3; OUT=${4:-dist}; TAG=v$VERSION
DIR="$OUT/$APP-$VERSION"
rm -rf "$OUT"; mkdir -p "$DIR"
cp -r deploy/current/. "$DIR/"
[ -e LICENSE ] && cp LICENSE "$DIR/"
# The application runs from the published image of this version: no build section.
yq -i '(.services[] | select(has("build"))) |= (del(.build) | .pull_policy = "missing")' "$DIR/docker-compose.yml"
sed -i -e "s#^FLOW_IMAGE=.*#FLOW_IMAGE=$IMAGE:$VERSION#" -e "s#^FLOW_VERSION=.*#FLOW_VERSION=$VERSION#" "$DIR/.env.example"
tar -C "$OUT" -czf "$OUT/$APP-$VERSION-deploy.tar.gz" "$APP-$VERSION"
rm -rf "$DIR"
( cd "$OUT" && sha256sum "$APP-$VERSION-deploy.tar.gz" > SHA256SUMS )
NOTES=".github/release-notes/$TAG.md"
# shellcheck disable=SC2016 # the backticks are Markdown, not an expansion
{ [ -f "$NOTES" ] && cat "$NOTES" && echo; \
  printf '## Install\n\n```bash\ncurl -L %s | tar xz\ncd %s-%s && cp .env.example .env && docker compose pull && docker compose up -d\n```\n\nImage: `%s:%s`. See README.md in the bundle.\n' \
    "$URL" "$APP" "$VERSION" "$IMAGE" "$VERSION"; } > "$OUT/notes.md"
