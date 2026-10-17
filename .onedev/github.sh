#!/bin/sh
# Publishes to the GitHub mirror of the project what OneDev keeps besides the code: the wiki and the releases.
#   .onedev/github.sh wiki <owner/repo>
#       wiki/ to the GitHub wiki of the repository (links between pages lose .md, as GitHub wiki links)
#   .onedev/github.sh release <owner/repo> <tag> <title> <dir>
#       creates or updates the GitHub release of the tag: <dir>/notes.md is the description, the other files of <dir>
#       are attached (an attachment of the same name is replaced)
# Env: GITHUB_TOKEN (contents and packages write), COMMIT (commit of the release, the tag is created on it if missing).
# Needs git, curl and perl.
set -eu
CMD=${1:?wiki or release}
REPO=${2:?owner/repo}
: "${GITHUB_TOKEN:?}"
API=https://api.github.com

# api METHOD PATH [curl options...]: prints the response body, fails on an HTTP error.
api() {
  m=$1; p=$2; shift 2
  out=$(mktemp)
  code=$(curl -sS -o "$out" -w '%{http_code}' -X "$m" -H "Authorization: Bearer $GITHUB_TOKEN" \
    -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28" "$@" "$p")
  cat "$out"; rm -f "$out"
  case $code in 2??) return 0 ;; *) echo "$m $p: HTTP $code" >&2; return 1 ;; esac
}

# json FIELD: prints FIELD of the JSON object on stdin; for an array, prints "id name" of every element.
json() {
  perl -MJSON::PP -e '
    local $/; my $d = decode_json(<STDIN>);
    if (ref $d eq "ARRAY") { for (@$d) { print "$_->{id} $_->{name}\n" } } else { print $d->{$ARGV[0]} // "" }
  ' "$1"
}

case $CMD in
wiki)
  tmp=$(mktemp -d)
  if ! git clone -q "https://x-access-token:$GITHUB_TOKEN@github.com/$REPO.wiki.git" "$tmp" 2>/dev/null; then
    echo "The wiki of $REPO does not exist on GitHub yet: open the Wiki tab of the repository, create the first page once."
    exit 0
  fi
  find "$tmp" -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
  cp -r wiki/. "$tmp/"
  PAGES=$(ls wiki | sed -n 's/\.md$//p' | tr '\n' '|') perl -i -pe '
    BEGIN { %page = map { $_ => 1 } grep { length } split /\|/, $ENV{PAGES} }
    s{\]\(([^)#\s/]+)\.md(#[^)]*)?\)}{ $page{$1} ? "]($1" . ($2 // "") . ")" : $& }ge;
  ' "$tmp"/*.md
  cd "$tmp"
  git add -A
  if git diff --cached --quiet; then
    echo "The GitHub wiki is up to date."
    exit 0
  fi
  git -c user.name="OneDev" -c user.email="onedev@evcsbrw.ru" commit -q -m "Wiki from ${COMMIT:-OneDev}"
  git push -q origin HEAD
  ;;
release)
  TAG=${3:?tag}; TITLE=${4:?title}; DIR=${5:?directory}
  body=$(TAG=$TAG TITLE=$TITLE NOTES="$DIR/notes.md" COMMIT=${COMMIT:-} perl -MJSON::PP -e '
    open my $f, "<:raw", $ENV{NOTES} or die "$ENV{NOTES}: $!"; local $/; my $notes = <$f>;
    my %r = (tag_name => $ENV{TAG}, name => $ENV{TITLE}, body => $notes, make_latest => "true");
    $r{target_commitish} = $ENV{COMMIT} if $ENV{COMMIT};
    print JSON::PP->new->canonical->encode(\%r);
  ')
  if id=$(api GET "$API/repos/$REPO/releases/tags/$TAG" 2>/dev/null | json id) && [ -n "$id" ]; then
    api PATCH "$API/repos/$REPO/releases/$id" -d "$body" >/dev/null
    echo "Updated the GitHub release $TAG"
  else
    body=$(printf '%s' "$body" | perl -MJSON::PP -e 'local $/; my $r = decode_json(<STDIN>); $r->{generate_release_notes} = JSON::PP::true; print encode_json($r)')
    id=$(api POST "$API/repos/$REPO/releases" -d "$body" | json id)
    echo "Created the GitHub release $TAG"
  fi
  assets=$(api GET "$API/repos/$REPO/releases/$id/assets?per_page=100" | json name)
  for f in "$DIR"/*; do
    n=$(basename "$f")
    [ "$n" = notes.md ] && continue
    old=$(printf '%s\n' "$assets" | awk -v n="$n" '$2 == n { print $1 }')
    [ -n "$old" ] && api DELETE "$API/repos/$REPO/releases/assets/$old" >/dev/null
    api POST "https://uploads.github.com/repos/$REPO/releases/$id/assets?name=$n" \
      -H "Content-Type: application/octet-stream" --data-binary "@$f" >/dev/null
    echo "Attached $n"
  done
  ;;
*)
  echo "unknown command: $CMD" >&2
  exit 2
  ;;
esac
