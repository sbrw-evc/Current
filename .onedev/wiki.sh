#!/bin/sh
# Rebuilds wiki/ — the pages of the OneDev wiki of the project — from the documentation.
# DOCS/wiki/ is taken as it is when it exists (GitHub wiki links [[Text|Page]] become links to Page.md); otherwise the
# wiki is made from README.md (the home page), README.ru.md and the documents of DOCS (one page each, links between them
# turned into wiki links, everything else linked to the file in the repository).
# Usage: .onedev/wiki.sh <project URL, e.g. https://onedev.example.com/Group/Project> [branch]
# Env: DOCS (default docs).
set -eu
BASE=${1:?project URL}
REV=${2:-main}
DOCS=${DOCS:-docs}
OUT=wiki
export DOCS BASE REV

rm -rf "$OUT"
mkdir "$OUT"

# Rewrites the relative links of a page read from $FROM; wiki links of the GitHub wiki are kept as wiki links.
fix() {
  PAGES=$(ls "$OUT" 2>/dev/null | sed -n 's/\.md$//p' | tr '\n' '|') perl -CSD -MFile::Spec -pe '
    BEGIN { %page = map { $_ => 1 } grep { length } split /\|/, $ENV{PAGES} }
    sub fix {
      my ($t) = @_;
      return $t if $t =~ m{^(?:[a-z][a-z0-9+.-]*:|#|/)}i;
      my ($p, $frag) = $t =~ m{^([^#]*)(#.*)?$}; $frag //= "";
      return $t if $p eq "";
      return "$p.md$frag" if $page{$p};
      my @parts;
      for (split m{/}, File::Spec::Unix->canonpath("$ENV{FROM}/$p")) {
        if ($_ eq "..") { pop @parts } elsif ($_ ne "." && $_ ne "") { push @parts, $_ }
      }
      my $r = join "/", @parts;
      return "Home.md$frag" if $r eq "README.md";
      return "Home-ru.md$frag" if $r eq "README.ru.md";
      return "$1.md$frag" if $r =~ m{^\Q$ENV{DOCS}\E/(?:wiki/)?([^/]+)\.md$};
      return "$1$frag" if $ENV{WIKI} && $r =~ m{^\Q$ENV{DOCS}\E/wiki/(.+)$};
      return "$ENV{BASE}/~raw?revision=$ENV{REV}&file=$r" if $r =~ m{\.(?:png|jpe?g|gif|svg|webp)$}i;
      return "$ENV{BASE}/~files/$ENV{REV}/$r$frag";
    }
    s{\[\[([^\]|]+)\|([^\]]+)\]\]}{"[$1](" . fix($2) . ")"}ge;
    s{\[\[([^\]|]+)\]\]}{"[$1](" . fix($1) . ")"}ge;
    s{\]\(([^)\s]+)\)}{"](" . fix($1) . ")"}ge;
    s{(src|href)="([^"]+)"}{"$1=\"" . fix($2) . "\""}ge;
  '
}

if [ -d "$DOCS/wiki" ]; then
  cp -r "$DOCS/wiki/." "$OUT/"
  for f in "$OUT"/*.md; do
    FROM="$DOCS/wiki" WIKI=1 fix < "$f" > "$f.tmp" && mv "$f.tmp" "$f"
  done
else
  cp README.md "$OUT/Home.md"
  [ -f README.ru.md ] && cp README.ru.md "$OUT/Home-ru.md"
  for f in "$DOCS"/*.md; do
    [ -e "$f" ] && cp "$f" "$OUT/$(basename "$f")"
  done
  for f in "$OUT"/*.md; do
    case "$(basename "$f")" in Home.md|Home-ru.md) from=. ;; *) from="$DOCS" ;; esac
    FROM="$from" fix < "$f" > "$f.tmp" && mv "$f.tmp" "$f"
  done
  {
    if [ -f "$OUT/Home-ru.md" ]; then echo "**[Home](Home.md)** · [Русский](Home-ru.md)"; else echo "**[Home](Home.md)**"; fi
    echo
    for f in "$OUT"/*.md; do
      n=$(basename "$f" .md)
      case "$n" in Home|Home-ru|_Sidebar|_Footer) continue ;; esac
      echo "- [$n]($n.md)"
    done
  } > "$OUT/_Sidebar.md"
fi
