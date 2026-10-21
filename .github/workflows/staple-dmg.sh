#!/bin/bash
# Submit a signed disk image to Apple and staple the ticket onto it.
#
# Gatekeeper checks the image a browser saved. A notarized app inside an
# image that has no ticket of its own is rejected, and the app never opens.
# Tauri notarizes the .app, then wraps it in a Developer ID signed DMG.
# This does the image.
#
#   staple-dmg.sh --built '*.dmg' v0.1.0   # image this job just built; replace that release asset
#   staple-dmg.sh --built '*.dmg'          # staple in place, do not upload
#   staple-dmg.sh --tag v0.1.0             # images already on that release
#
# Uses bash 3.2, which is /bin/bash on the macOS runner.

set -euo pipefail

if [ -z "${APPLE_ID:-}" ] || [ -z "${APPLE_PASSWORD:-}" ] || [ -z "${APPLE_TEAM_ID:-}" ]; then
  echo "APPLE_ID, APPLE_PASSWORD and APPLE_TEAM_ID are required. An unstapled image would be published and then refused by Gatekeeper." >&2
  exit 1
fi

# The wallet is not a workspace member, so bundles land here rather than
# in a repo-root target/.
BUNDLE_ROOT="${BUNDLE_ROOT:-wallet/src-tauri/target}"

staple_one() {
  src="$1"
  echo "submitting ${src}"
  xcrun notarytool submit "$src" \
    --apple-id "$APPLE_ID" \
    --team-id "$APPLE_TEAM_ID" \
    --password "$APPLE_PASSWORD" \
    --wait

  # The status flips to Accepted a few seconds before the ticket can be fetched.
  n=0
  while [ "$n" -lt 8 ]; do
    n=$((n + 1))
    if xcrun stapler staple "$src"; then
      break
    fi
    if [ "$n" -eq 8 ]; then
      echo "no ticket could be stapled to ${src}" >&2
      exit 1
    fi
    sleep 15
  done

  out=$(xcrun stapler validate "$src" 2>&1) || true
  echo "$out"
  echo "$out" | grep -q "The validate action worked"
}

upload_one() {
  src="$1"
  tag="$2"
  gh release upload "$tag" "$src" --clobber
  echo "uploaded $(basename "$src") to ${tag}"
}

# Stapling changes the bytes. The release notes tell people to check
# SHA256SUMS, so a repaired image has to update the DMG lines there.
note_checksum() {
  tag="$1"
  src="$2"
  sums_dir=$(mktemp -d)
  err=$(mktemp)
  if ! gh release download "$tag" --pattern SHA256SUMS --dir "$sums_dir" --clobber 2>"$err"; then
    if grep -q 'no assets match' "$err"; then
      echo "no SHA256SUMS on ${tag}; left the checksum file unchanged"
      return 0
    fi
    cat "$err" >&2
    exit 1
  fi
  digest=$(shasum -a 256 "$src" | awk 'NR==1 {print $1}')
  name=$(basename "$src")
  python3 - "$sums_dir/SHA256SUMS" "$name" "$digest" <<'PY'
import pathlib
import sys

path, name, digest = sys.argv[1:]
if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
    sys.exit("bad digest for %s" % name)
file = pathlib.Path(path)
out = []
found = False
for line in file.read_text().splitlines():
    if not line.strip():
        continue
    if "  " not in line:
        sys.exit("bad checksum line: %s" % line)
    _old, old_name = line.split("  ", 1)
    if old_name == name:
        out.append("%s  %s" % (digest, name))
        found = True
    else:
        out.append(line)
if not found:
    sys.exit("SHA256SUMS has no line for %s" % name)
file.write_text("".join("%s\n" % line for line in out))
PY
  gh release upload "$tag" "$sums_dir/SHA256SUMS" --clobber
  echo "updated SHA256SUMS for ${name}"
}

require_tag() {
  tag="$1"
  if ! printf '%s' "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'; then
    echo "need a tag vX.Y.Z or vX.Y.Z-prerelease (got '${tag:-<empty>}')" >&2
    exit 1
  fi
}

case "${1:-}" in
  --built)
    glob="${2:-*.dmg}"
    tag="${3:-}"
    case "$glob" in
      v[0-9]*)
        echo "--built takes a find glob, then the tag. Example: --built '*.dmg' v0.1.0" >&2
        exit 2
        ;;
    esac
    if [ -n "$tag" ]; then
      require_tag "$tag"
    fi
    files=$(find "$BUNDLE_ROOT" -type f -path '*/bundle/dmg/*' -name "$glob")
    if [ -z "$files" ]; then
      echo "no disk image matching ${glob} under ${BUNDLE_ROOT}" >&2
      find "$BUNDLE_ROOT" -type d -name bundle >&2 || true
      exit 1
    fi
    # A pipe would run the loop in a subshell, and a failed notarization
    # would not fail the job. Split on newlines; these names have none.
    IFS='
'
    for src in $files; do
      [ -n "$src" ] || continue
      staple_one "$src"
      if [ -n "$tag" ]; then
        # tauri-action already published this filename, unstapled. Replace it.
        upload_one "$src" "$tag"
      fi
    done
    ;;
  --tag)
    tag="${2:-}"
    require_tag "$tag"
    dir=$(mktemp -d)
    gh release download "$tag" --pattern "*.dmg" --dir "$dir" --clobber
    files=$(find "$dir" -type f -name "*.dmg")
    if [ -z "$files" ]; then
      echo "no disk image on ${tag}" >&2
      exit 1
    fi
    IFS='
'
    for src in $files; do
      [ -n "$src" ] || continue
      staple_one "$src"
      upload_one "$src" "$tag"
      note_checksum "$tag" "$src"
    done
    ;;
  *)
    echo "usage: staple-dmg.sh --built <glob> [tag] | --tag <tag>" >&2
    exit 2
    ;;
esac
