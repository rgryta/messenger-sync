#!/bin/sh
# Regenerates crates/client/tests/fixtures/securehistory_archive.json from mautrix-meta's
# securehistory package: zz_fixture_test.go runs as a test inside a throwaway copy of it.
#
#   scripts/securehistory-archive-fixture/run.sh <mautrix-meta checkout>
#
# Needs docker and the golang:1.27-alpine image; GOMODCACHE, when set, is mounted as the
# container's module cache. The output differs on every run (fresh random keys and nonces);
# the Rust tests read whatever it holds.
set -eu
meta=$(cd "$1" && pwd)
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp -r "$meta/." "$work/"
cp "$here/zz_fixture_test.go" "$work/pkg/messagix/securehistory/"
docker run --rm ${GOMODCACHE:+-v "$GOMODCACHE:/go/pkg/mod"} -v "$work:/meta" -v "$repo/crates/client/tests/fixtures:/out" -w /meta \
  -e FIXTURE_OUT=/out/securehistory_archive.json golang:1.27-alpine \
  go test -count=1 -run TestWriteFixture ./pkg/messagix/securehistory/
