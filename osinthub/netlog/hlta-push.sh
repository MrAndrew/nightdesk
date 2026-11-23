#!/bin/sh
# hlta-push.sh: send Zeek / Suricata JSON logs from this device to HLTA (Night Desk).
#
# The device pushes; HLTA never logs in to it. Run from cron every few minutes:
#   */5 * * * * /usr/local/bin/hlta-push.sh
#
# Two ways to pick up logs (use one per log, not both):
#   HLTA_FILES  folders holding finished (rotated) logs, e.g. Zeek's dated archive folders.
#               Each finished file is sent once.
#   HLTA_TAIL   live files that keep growing, e.g. Suricata's eve.json or Zeek's current/conn.log.
#               Only the new complete lines since the last run are sent.
#
# Settings come from /usr/local/etc/hlta-push.conf (or the file named by HLTA_CONF, or the first
# argument). Example:
#   HLTA_URL=https://192.0.2.10:8788
#   HLTA_TOKEN_FILE=/usr/local/etc/hlta-push.token       # the token, readable by root only
#   HLTA_PIN='sha256//...'                               # the public-key pin shown in HLTA
#   HLTA_FILES="/opt/zeek/logs"                          # finished logs
#   HLTA_MATCH='*.log.gz'
#   HLTA_TAIL="/var/log/suricata/eve.json"               # growing logs
#
# Every run also checks in (a heartbeat), so HLTA can alert when the device goes quiet.
# Flags: --check (test the address, pin and token, send nothing), --dry-run (list what would be
# sent), --help. Needs: sh, curl (7.55+), gzip, find, tail, head, wc. Exit code 1 if anything failed.
# Reference: okf/data/netlog.md#push-uploads
set -u

CONF=${HLTA_CONF:-/usr/local/etc/hlta-push.conf}
MODE=run
for a in "$@"; do
  case $a in
    --check) MODE=check ;;
    --dry-run) MODE=dry ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    -*) echo "unknown flag: $a" >&2; exit 2 ;;
    *) CONF=$a ;;
  esac
done
if [ -f "$CONF" ]; then . "$CONF"; elif [ -n "${HLTA_CONF:-}" ] || [ "$CONF" != /usr/local/etc/hlta-push.conf ]; then
  echo "settings file not found: $CONF" >&2; exit 2
fi

HLTA_URL=${HLTA_URL:?set HLTA_URL in $CONF}
HLTA_URL=${HLTA_URL%/}
HLTA_TOKEN_FILE=${HLTA_TOKEN_FILE:-/usr/local/etc/hlta-push.token}
HLTA_PIN=${HLTA_PIN:-}
HLTA_CACERT=${HLTA_CACERT:-}
HLTA_FILES=${HLTA_FILES:-}
HLTA_MATCH=${HLTA_MATCH:-*.log.gz}
HLTA_DEPTH=${HLTA_DEPTH:-2}
HLTA_MIN_AGE_MIN=${HLTA_MIN_AGE_MIN:-2}
HLTA_TAIL=${HLTA_TAIL:-}
HLTA_MAX_MB=${HLTA_MAX_MB:-200}
HLTA_STATE=${HLTA_STATE:-/var/db/hlta-push}
HLTA_NAME=${HLTA_NAME:-$(hostname 2>/dev/null | cut -d. -f1)}

say() { echo "$(date '+%Y-%m-%d %H:%M:%S') hlta-push: $*" >&2; }
die() { say "$*"; exit 1; }

[ -r "$HLTA_TOKEN_FILE" ] || die "cannot read the token file $HLTA_TOKEN_FILE"
umask 077
mkdir -p "$HLTA_STATE" || die "cannot create $HLTA_STATE"

# One run at a time (cron may start the next run while a big upload is still going).
LOCK="$HLTA_STATE/lock"
if ! mkdir "$LOCK" 2>/dev/null; then
  if [ -n "$(find "$LOCK" -maxdepth 0 -mmin +60 2>/dev/null)" ]; then
    say "removing a stale lock"; rmdir "$LOCK" 2>/dev/null; mkdir "$LOCK" 2>/dev/null || exit 0
  else
    exit 0
  fi
fi
TMP="$HLTA_STATE/tmp.$$"
trap 'rm -f "$TMP" "$TMP.gz" "$HLTA_STATE/auth.hdr"; rmdir "$LOCK" 2>/dev/null' EXIT INT TERM

# The token goes to curl through a header file, so it never shows up in `ps`.
printf 'Authorization: Bearer %s\n' "$(tr -d ' \r\n' < "$HLTA_TOKEN_FILE")" > "$HLTA_STATE/auth.hdr"

# TLS: with a pin, curl checks the server's public key and refuses anything else, so the
# certificate does not need to name this address. -k only skips the CA check, never the pin.
set -- -sS --fail --max-time 900 --connect-timeout 10 -H "@$HLTA_STATE/auth.hdr"
case $HLTA_URL in
  https:*)
    if [ -n "$HLTA_PIN" ]; then set -- "$@" -k --pinnedpubkey "$HLTA_PIN"
    elif [ -n "$HLTA_CACERT" ]; then set -- "$@" --cacert "$HLTA_CACERT"
    else die "set HLTA_PIN (shown in HLTA) or HLTA_CACERT; refusing to send without checking the server"
    fi ;;
  http:*) say "warning: plain http; the token and logs cross the network unencrypted" ;;
esac

if [ "$MODE" = check ]; then
  out=$(curl "$@" "$HLTA_URL/ingest/check") || die "check failed (address, pin or token is wrong, or HLTA's upload port is off)"
  say "ok: $out"
  exit 0
fi

FAILED=0
# send FILE NAME CURL-OPTIONS...: upload one file (gzipped or plain) as NAME.
send() {
  src=$1; name=$2; shift 2
  if [ "$MODE" = dry ]; then say "would send $name ($(wc -c < "$src" | tr -d ' ') bytes)"; return 0; fi
  if out=$(curl "$@" -H "X-HLTA-Name: $name" -H "Content-Type: application/octet-stream" \
             --data-binary "@$src" "$HLTA_URL/ingest" 2>&1); then
    return 0
  fi
  say "upload of $name failed: $out"
  FAILED=1; echo fail > "$HLTA_STATE/failed"   # also seen from subshells
  return 1
}

# --------------------------------------------------------------- finished files (sent once)
SENT="$HLTA_STATE/sent"
touch "$SENT"
if [ -n "$HLTA_FILES" ]; then
  for root in $HLTA_FILES; do
    [ -d "$root" ] || { say "not a folder: $root"; continue; }
    find "$root" -maxdepth "$HLTA_DEPTH" -type f -name "$HLTA_MATCH" -mmin +"$HLTA_MIN_AGE_MIN" 2>/dev/null
  done | sort | while IFS= read -r f; do
    size=$(wc -c < "$f" | tr -d ' ')
    key=$(printf '%s\t%s' "$f" "$size")
    grep -Fqx "$key" "$SENT" && continue
    base=${f##*/}
    case $f in
      *.gz|*.zip|*.tar) src=$f ;;
      *.bz2) bzip2 -dc "$f" | gzip -c > "$TMP.gz" || { say "cannot read $f"; continue; }; src=$TMP.gz; base=${base%.bz2}.gz ;;
      *.xz) xz -dc "$f" | gzip -c > "$TMP.gz" || { say "cannot read $f"; continue; }; src=$TMP.gz; base=${base%.xz}.gz ;;
      *.zst) zstd -dc "$f" | gzip -c > "$TMP.gz" || { say "cannot read $f"; continue; }; src=$TMP.gz; base=${base%.zst}.gz ;;
      *) gzip -c "$f" > "$TMP.gz" || { say "cannot read $f"; continue; }; src=$TMP.gz; base=$base.gz ;;
    esac
    dir=${f%/*}; dir=${dir##*/}
    if send "$src" "$HLTA_NAME-$dir-$base" "$@"; then
      [ "$MODE" = dry ] || printf '%s\n' "$key" >> "$SENT"
    else
      echo fail > "$HLTA_STATE/failed"
    fi
    rm -f "$TMP.gz"
  done
  # keep the list of sent files from growing forever (HLTA ignores a file it already has)
  if [ "$(wc -l < "$SENT")" -gt 50000 ]; then tail -n 20000 "$SENT" > "$TMP" && mv "$TMP" "$SENT"; fi
fi

# --------------------------------------------------------------- growing files (new lines only)
inode() { ls -i "$1" | awk '{print $1}'; }
# send_new FILE OFFSET LABEL CURL-OPTIONS...: send whole lines after OFFSET; prints the new offset.
send_new() {
  sf=$1; soff=$2; label=$3; shift 3
  ssize=$(wc -c < "$sf" | tr -d ' ')
  [ "$ssize" -gt "$soff" ] || { echo "$soff"; return 0; }
  n=$((ssize - soff)); max=$((HLTA_MAX_MB * 1048576)); [ "$n" -gt "$max" ] && n=$max
  tail -c +"$((soff + 1))" "$sf" | head -c "$n" > "$TMP"
  # only whole lines: hold back a partial last line until the next run
  if [ "$(tail -c 1 "$TMP" | od -An -c | tr -d ' ')" != '\n' ]; then
    part=$(tail -n 1 "$TMP" | wc -c | tr -d ' ')
    keep=$(( $(wc -c < "$TMP" | tr -d ' ') - part ))
    [ "$keep" -gt 0 ] || { echo "$soff"; return 0; }
    head -c "$keep" "$TMP" > "$TMP.cut" && mv "$TMP.cut" "$TMP"
  fi
  sent=$(wc -c < "$TMP" | tr -d ' ')
  gzip -c "$TMP" > "$TMP.gz"
  if send "$TMP.gz" "$label" "$@" >&2; then
    [ "$MODE" = dry ] && echo "$soff" || echo "$((soff + sent))"
  else
    echo "$soff"
  fi
  rm -f "$TMP" "$TMP.gz"
}

for f in $HLTA_TAIL; do
  [ -f "$f" ] || { say "no such file: $f"; continue; }
  pos="$HLTA_STATE/pos.$(printf '%s' "$f" | cksum | cut -d' ' -f1)"
  ino=$(inode "$f")
  size=$(wc -c < "$f" | tr -d ' ')
  last_ino=; off=0
  [ -f "$pos" ] && read -r last_ino off < "$pos"
  base=${f##*/}; stamp=$(date -u +%Y%m%dT%H%M%S)
  if [ -n "$last_ino" ] && { [ "$ino" != "$last_ino" ] || [ "$size" -lt "$off" ]; }; then
    # rotated since the last run: finish the old file first if it is still next to this one
    if [ "$ino" != "$last_ino" ]; then
      for old in "$f".* "${f%.*}"-*; do
        [ -f "$old" ] && [ "$(inode "$old")" = "$last_ino" ] || continue
        send_new "$old" "$off" "$HLTA_NAME-${base%.*}-$stamp-rotated.${base##*.}.gz" "$@" > /dev/null
        break
      done
    fi
    off=0
  fi
  newoff=$(send_new "$f" "$off" "$HLTA_NAME-${base%.*}-$stamp.${base##*.}.gz" "$@")
  [ "$MODE" = dry ] || printf '%s %s\n' "$ino" "$newoff" > "$pos"
done

# Heartbeat: check in every run, even with nothing new to send, so HLTA can tell a quiet device
# from one that stopped (it alerts when a device misses its usual cadence).
if [ "$MODE" = run ] && ! out=$(curl "$@" "$HLTA_URL/ingest/check" 2>&1); then
  say "check-in failed: $out"; FAILED=1
fi

[ -f "$HLTA_STATE/failed" ] && { rm -f "$HLTA_STATE/failed"; FAILED=1; }
exit $FAILED
