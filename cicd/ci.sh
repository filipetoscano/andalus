#!/bin/bash
# ------------------------------------------------------------------------
set -eux

yell() { echo "$0: $*" >&2; }
die() { yell "$*"; exit 111; }
try() { "$@" || die "cannot $*"; }


#
# Run all commands from the repository root!
# (That's the directory above the current one :)
# ------------------------------------------------------------------------
#
SCRIPT_PATH="${BASH_SOURCE[0]}"
if ([ -h "${SCRIPT_PATH}" ]); then
  while([ -h "${SCRIPT_PATH}" ]); do cd "$(dirname "$SCRIPT_PATH")";
  SCRIPT_PATH=$(readlink "${SCRIPT_PATH}"); done
fi
cd "$(dirname ${SCRIPT_PATH})" > /dev/null
cd ..


#
# Build
# ------------------------------------------------------------------------
dotnet clean   -c Release
dotnet restore --packages .nuget
dotnet build   -c Release --no-restore

[ -d ./TestResults ] && rm -rf ./TestResults

for proj in $(find . -name "*.Tests.csproj"); do
  name=$(basename "$proj" .csproj)

  dotnet test --project "$proj" \
    --results-directory "TestResults/$name" \
    --coverage \
    --coverage-output-format cobertura \
    --coverage-output coverage.cobertura.xml \
    --report-junit \
    --report-junit-filename test-results.junit.xml
done

# eof