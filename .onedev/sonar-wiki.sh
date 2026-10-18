#!/bin/sh
# Writes the result of the SonarQube analysis of a release to the wiki: the page SonarQube-<tag> and a row in the page
# SonarQube (all releases, newest first), and pushes them to main.
# Usage: .onedev/sonar-wiki.sh <tag> <commit> [branch, default main]
# Runs after sonar-scanner in the same working directory (reads .scannerwork/report-task.txt).
# Env: SONAR_TOKEN. Needs git, curl and perl.
set -eu
TAG=${1:?tag}; COMMIT=${2:?commit}; BRANCH=${3:-main}
: "${SONAR_TOKEN:?}"
REPORT=.scannerwork/report-task.txt
[ -f "$REPORT" ] || { echo "$REPORT not found: run sonar-scanner first" >&2; exit 1; }
prop() { sed -n "s/^$1=//p" "$REPORT"; }
SERVER=$(prop serverUrl); KEY=$(prop projectKey); TASK=$(prop ceTaskId); DASHBOARD=$(prop dashboardUrl)

api() { curl -fsS -u "$SONAR_TOKEN:" "$SERVER/api/$1"; }

# The analysis is processed by the server after the upload; wait for it.
i=0
while :; do
  task=$(api "ce/task?id=$TASK")
  status=$(printf '%s' "$task" | perl -MJSON::PP -e 'local $/; print decode_json(<STDIN>)->{task}{status}')
  case $status in SUCCESS) break ;; FAILED|CANCELED) echo "SonarQube task $TASK: $status" >&2; exit 1 ;; esac
  i=$((i + 1)); [ $i -lt 120 ] || { echo "SonarQube task $TASK is not done after 10 minutes" >&2; exit 1; }
  sleep 5
done
ANALYSIS=$(printf '%s' "$task" | perl -MJSON::PP -e 'local $/; print decode_json(<STDIN>)->{task}{analysisId}')
GATE=$(api "qualitygates/project_status?analysisId=$ANALYSIS")
METRICS=bugs,vulnerabilities,security_hotspots,code_smells,coverage,duplicated_lines_density,ncloc,reliability_rating,security_rating,sqale_rating
MEASURES=$(api "measures/component?component=$KEY&metricKeys=$METRICS")

tmp=$(mktemp -d)
git fetch -q origin "$BRANCH"
git worktree add -q --detach "$tmp" FETCH_HEAD
mkdir -p "$tmp/wiki"

GATE=$GATE MEASURES=$MEASURES TAG=$TAG COMMIT=$COMMIT DASHBOARD=$DASHBOARD KEY=$KEY OUT="$tmp/wiki" perl -CSD -Mutf8 -MJSON::PP -e '
  my $gate = decode_json($ENV{GATE})->{projectStatus};
  my %m = map { $_->{metric} => $_->{value} } @{ decode_json($ENV{MEASURES})->{component}{measures} };
  my %rating = (1 => "A", 2 => "B", 3 => "C", 4 => "D", 5 => "E");
  my $r = sub { my $v = $m{$_[0]}; defined $v ? ($rating{int $v} // $v) : "—" };
  my $v = sub { my ($k, $suffix) = @_; defined $m{$k} ? "$m{$k}$suffix" : "—" };
  my %gname = (OK => "Passed", ERROR => "Failed", WARN => "Warning", NONE => "None");
  my $status = $gname{$gate->{status}} // $gate->{status};
  my ($tag, $commit) = ($ENV{TAG}, substr($ENV{COMMIT}, 0, 7));
  my @t = gmtime; my $date = sprintf "%04d-%02d-%02d", $t[5] + 1900, $t[4] + 1, $t[3];

  my %label = (
    new_reliability_rating => "Reliability rating on new code", new_security_rating => "Security rating on new code",
    new_maintainability_rating => "Maintainability rating on new code", new_coverage => "Coverage on new code",
    new_duplicated_lines_density => "Duplicated lines on new code", new_security_hotspots_reviewed => "Security hotspots reviewed on new code",
    new_violations => "New issues", new_software_quality_reliability_rating => "Reliability rating on new code",
    new_software_quality_security_rating => "Security rating on new code",
    new_software_quality_maintainability_rating => "Maintainability rating on new code",
  );
  my %op = (GT => ">", LT => "<");

  open my $p, ">", "$ENV{OUT}/SonarQube-$tag.md" or die $!;
  print $p "# SonarQube: $tag\n\n";
  print $p "Quality gate: **$status** · analysed $date · commit `$commit` · [dashboard]($ENV{DASHBOARD})\n\n";
  print $p "| Metric | Value |\n|---|---|\n";
  print $p "| Bugs | ", $v->("bugs", ""), " |\n";
  print $p "| Vulnerabilities | ", $v->("vulnerabilities", ""), " |\n";
  print $p "| Security hotspots | ", $v->("security_hotspots", ""), " |\n";
  print $p "| Code smells | ", $v->("code_smells", ""), " |\n";
  print $p "| Coverage | ", $v->("coverage", "%"), " |\n";
  print $p "| Duplicated lines | ", $v->("duplicated_lines_density", "%"), " |\n";
  print $p "| Lines of code | ", $v->("ncloc", ""), " |\n";
  print $p "| Reliability rating | ", $r->("reliability_rating"), " |\n";
  print $p "| Security rating | ", $r->("security_rating"), " |\n";
  print $p "| Maintainability rating | ", $r->("sqale_rating"), " |\n";
  if (my @c = @{ $gate->{conditions} // [] }) {
    print $p "\n## Quality gate conditions\n\n| Condition | Threshold | Actual | Result |\n|---|---|---|---|\n";
    for (@c) {
      my $name = $label{$_->{metricKey}} // $_->{metricKey};
      my $res = $_->{status} eq "OK" ? "passed" : lc($gname{$_->{status}} // $_->{status});
      printf $p "| %s | %s %s | %s | %s |\n", $name, $op{$_->{comparator}} // $_->{comparator},
        $_->{errorThreshold} // "", $_->{actualValue} // "—", $res;
    }
  }
  print $p "\n[All releases](SonarQube.md)\n";
  close $p;

  # The index: a table of releases, newest first; the row of this release replaces an older one.
  my $index = "$ENV{OUT}/SonarQube.md";
  my @rows;
  if (open my $i, "<", $index) {
    while (<$i>) { push @rows, $_ if /^\| \[v/ && !/^\| \[\Q$tag\E\]/ }
  }
  unshift @rows, sprintf "| [%s](SonarQube-%s.md) | %s | %s | %s | %s | %s | %s | %s | %s |\n", $tag, $tag, $date, $status,
    $v->("bugs", ""), $v->("vulnerabilities", ""), $v->("code_smells", ""), $v->("coverage", "%"),
    $v->("duplicated_lines_density", "%"), "[`$commit`]($ENV{DASHBOARD})";
  open my $o, ">", $index or die $!;
  print $o "# SonarQube\n\nEvery release is analysed by [SonarQube]($ENV{DASHBOARD}) (project `$ENV{KEY}`) before its images are built; ",
    "a release whose quality gate fails is not published.\n\n",
    "| Release | Date | Quality gate | Bugs | Vulnerabilities | Code smells | Coverage | Duplications | Commit |\n",
    "|---|---|---|---|---|---|---|---|---|\n", @rows;
  close $o;
'

cd "$tmp"
git add wiki/SonarQube.md "wiki/SonarQube-$TAG.md"
if git diff --cached --quiet; then
  echo "The wiki already has the results of $TAG."
  exit 0
fi
git -c user.name="OneDev" -c user.email="onedev@evcsbrw.ru" commit -q -m "Wiki: SonarQube results of $TAG"
# main may move meanwhile: rebase and retry.
for i in 1 2 3; do
  if git push -q origin "HEAD:$BRANCH"; then echo "Published wiki/SonarQube-$TAG.md"; exit 0; fi
  git fetch -q origin "$BRANCH" && git rebase -q FETCH_HEAD
done
echo "Could not push the wiki pages to $BRANCH" >&2
exit 1
