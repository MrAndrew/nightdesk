#!/bin/sh
# Night Desk installer: runs Night Desk in Docker with HTTPS (Caddy, with its own local certificate authority).
#
#   curl -fsSL <release>/install.sh | sh                  install, or update an existing install
#   curl -fsSL <release>/install.sh | sh -s -- --yes      take every default without asking
#   curl -fsSL <release>/install.sh | sh -s -- --uninstall
#
# Options: --yes, --data DIR, --lan, --port N, --no-trust, --no-open, --no-mdns, --reconfigure (keeps the keys you
# added to .env; --reset-keys removes them), --source DIR|URL, --move-data DIR (move the data folder of an existing
# install; Settings › Data shows this command), --uninstall, --help. It needs Docker with Compose (Docker Desktop, OrbStack, colima, or Docker Engine on Linux),
# asks a few questions (each has a default), builds the image on this computer, starts it, trusts the certificate
# on this computer if you agree (one admin password prompt), and opens the browser. macOS first; Linux works too.
# Settings live in the install folder's .env (NIGHTDESK_HOME, default ~/.nightdesk); your data folder is separate.
# Details: okf/architecture/deployment.md#one-line-install-docker
set -eu

VERSION="v0.1.0-prealpha"
REPO="https://github.com/MrAndrew/nightdesk"      # the public repo
HOME_DIR="${NIGHTDESK_HOME:-$HOME/.nightdesk}"
APP="$HOME_DIR/app"
ENVF="$HOME_DIR/.env"
# A line of .env as Compose reads it: optional leading spaces and `export `, NAME=value, the value bare or in quotes.
ENV_LINE='^[[:space:]]*(export[[:space:]]+)?'
# The installer reads its own settings only in the form it writes them, NAME='value': no guessing at other forms.
getenv() { [ -f "$ENVF" ] || return 0; tr -d '\r' <"$ENVF" | sed -n "s/^$1='\([^']*\)'\$/\1/p" | tail -1; }
# the Compose project name (kept from before the rename); an install remembers its own in .env
PROJECT="${ND_PROJECT:-$(getenv ND_PROJECT)}"; PROJECT="${PROJECT:-nightdesk}"

YES=0 LAN="" PORT="" DATA="" TRUST=1 OPEN=1 MDNS=1 RECONF=0 RESET_KEYS=0 SOURCE="" UNINSTALL=0 MOVE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --yes|-y) YES=1 ;;
    --lan) LAN=1 ;;
    --port) PORT="$2"; shift ;;
    --data) DATA="$2"; shift ;;
    --no-trust) TRUST=0 ;;
    --no-open) OPEN=0 ;;
    --no-mdns) MDNS=0 ;;
    --reconfigure) RECONF=1 ;;
    --reset-keys) RECONF=1 RESET_KEYS=1 ;;
    --source) SOURCE="$2"; shift ;;
    --uninstall) UNINSTALL=1 ;;
    --move-data) MOVE="$2"; shift ;;
    --help|-h)  # run from a file: its header; piped into sh ($0 is the shell): the options in short
      if [ -f "$0" ] && grep -q '^# Night Desk installer' "$0" 2>/dev/null; then sed -n '2,/^# Details/p' "$0"
      else printf '%s\n' "Night Desk installer. Options: --yes, --data DIR, --lan, --port N, --no-trust, --no-open," \
        "--no-mdns, --reconfigure (keeps the keys you added to .env), --reset-keys (--reconfigure that removes them)," \
        "--source DIR|URL, --move-data DIR, --uninstall. Details: $REPO/blob/main/okf/architecture/deployment.md"; fi
      exit 0 ;;
    *) echo "Unknown option: $1 (try --help)" >&2; exit 2 ;;
  esac
  shift
done

say() { printf '%s\n' "$*"; }
step() { printf '\n\033[1m%s\033[0m\n' "$*"; }
die() { printf '\nNight Desk: %s\n' "$*" >&2; exit 1; }

# Questions come from the terminal (stdin is this script when piped into sh). No terminal or --yes: the default.
TTY=""
if [ "$YES" = 0 ] && [ -r /dev/tty ] && (exec </dev/tty) 2>/dev/null; then TTY=/dev/tty; fi
ask() {  # ask "Question" "default" -> echoes the answer
  if [ -z "$TTY" ]; then printf '%s\n' "$2"; return; fi
  printf '%s [%s]: ' "$1" "$2" >/dev/tty
  read -r a </dev/tty || a=""
  printf '%s\n' "${a:-$2}"
}
yes_no() {  # yes_no "Question" y|n -> exit 0 for yes
  a=$(ask "$1 (y/n)" "$2")
  case "$a" in [Yy]*) return 0 ;; *) return 1 ;; esac
}

OS=$(uname -s)
case "$OS" in
  Darwin|Linux) ;;
  *) die "this installer runs on macOS and Linux. On Windows, run it inside WSL for now." ;;
esac

default_data() {  # the same app-data folder a native run uses (osinthub/config.py default_lake)
  if [ "$OS" = Darwin ]; then printf '%s\n' "$HOME/Library/Application Support/Night Desk"
  else printf '%s\n' "${XDG_DATA_HOME:-$HOME/.local/share}/nightdesk"; fi
}

compose() { docker compose -p "$PROJECT" --project-directory "$APP" -f "$APP/docker-compose.yml" --env-file "$ENVF" "$@"; }
setenv() {  # setenv NAME value: replace (or add) one line of .env
  t="$ENVF.tmp"; grep -v "^$1=" "$ENVF" >"$t" || true; printf "%s='%s'\n" "$1" "$2" >>"$t"; mv "$t" "$ENVF"; chmod 600 "$ENVF"
}

# The settings the installer writes itself. Every other line of .env (the keys and settings a user added, and their
# comments) is the user's own: --reconfigure carries it over unless they ask to reset it.
MANAGED="ND_BIND|HTTPS_PORT|HLTA_HOSTS|LAKE_DIR|ND_UID|ND_GID|NIGHTDESK_HOME|ND_PROJECT|HLTA_AUTH_USER|HLTA_AUTH_HASH"
own_lines() {  # the user's own lines of .env, as written (values are never printed)
  [ -f "$ENVF" ] || return 0
  tr -d '\r' <"$ENVF" | grep -Ev "${ENV_LINE}($MANAGED)[[:space:]]*=|^# (Written by the Night Desk installer|\(it keeps this file\)|Every setting is explained|Your own settings)" |
    sed '/./,$!d' || true
}
odd_settings() {  # the installer's own settings that a hand edit wrote in another form (named, never read or shown)
  [ -f "$ENVF" ] || return 0
  tr -d '\r' <"$ENVF" | grep -Ev "^($MANAGED)='[^']*'\$" | sed -En "s/${ENV_LINE}($MANAGED)[[:space:]]*=.*/\\2/p" |
    awk '!seen[$0]++' | paste -sd ',' - | sed 's/,/, /g'
}
own_settings() {  # the user's own lines to keep in a rewritten .env: kept unless --reset-keys or the user says no
  keep=$(own_lines)
  [ -n "$keep" ] || return 0
  names=$(printf '%s\n' "$keep" | sed -En "s/${ENV_LINE}([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=.*/\\2/p" |
    awk '!seen[$0]++' | paste -sd ',' - | sed 's/,/, /g')
  if [ "$RESET_KEYS" = 1 ]; then
    say "Removing the keys and settings you added yourself${names:+: $names} (--reset-keys)." >&2; return 0
  fi
  if [ -n "$names" ] && ! yes_no "Keep the keys and settings you added yourself ($names)?" y; then
    say "Removed: $names." >&2; return 0
  fi
  [ -z "$names" ] || say "Keeping your own settings: $names." >&2
  printf '%s\n' "$keep"
}

port_free() {
  if command -v lsof >/dev/null 2>&1; then ! lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
  elif command -v ss >/dev/null 2>&1; then ! ss -ltnH "sport = :$1" 2>/dev/null | grep -q .
  else ! (command -v nc >/dev/null 2>&1 && nc -z 127.0.0.1 "$1" 2>/dev/null); fi
}

MDNS_LABEL="local.nightdesk.mdns"
MDNS_PLIST="$HOME/Library/LaunchAgents/$MDNS_LABEL.plist"
mdns_stop() {
  [ "$OS" = Darwin ] || return 0
  launchctl bootout "gui/$(id -u)/$MDNS_LABEL" 2>/dev/null || true
  rm -f "$MDNS_PLIST"
}

# ------------------------------------------------------------------ uninstall
if [ "$UNINSTALL" = 1 ]; then
  [ -f "$ENVF" ] || die "no install found in $HOME_DIR."
  data=$(getenv LAKE_DIR)
  step "Stopping and removing Night Desk"
  compose down --rmi local || true
  docker volume rm "${PROJECT}_caddy_data" "${PROJECT}_caddy_config" >/dev/null 2>&1 || true
  mdns_stop
  if [ -f "$HOME_DIR/nightdesk-root.crt" ] && [ "$OS" = Darwin ]; then
    sha=$(openssl x509 -noout -fingerprint -sha1 -in "$HOME_DIR/nightdesk-root.crt" 2>/dev/null | sed 's/.*=//; s/://g')
    if [ -n "$sha" ] && security find-certificate -a -Z /Library/Keychains/System.keychain 2>/dev/null | grep -q "$sha"; then
      say "Removing the trusted certificate (asks for your admin password):"
      sudo security delete-certificate -Z "$sha" /Library/Keychains/System.keychain || true
    fi
  fi
  if [ -n "$data" ] && [ -d "$data" ] && yes_no "Also delete your data folder $data?" n; then rm -rf "$data"; say "Deleted $data."
  elif [ -n "$data" ]; then say "Your data stays in $data."; fi
  rm -rf "$HOME_DIR"
  say "Night Desk is uninstalled."
  exit 0
fi

# ------------------------------------------------------------------ move the data folder
if [ -n "$MOVE" ]; then
  [ -f "$ENVF" ] || die "no install found in $HOME_DIR."
  old=$(getenv LAKE_DIR)
  [ -n "$old" ] || die "this install keeps its data in a Docker volume, not a folder; it cannot be moved this way."
  case "$MOVE" in "~"*) MOVE="$HOME${MOVE#\~}" ;; esac
  case "$MOVE" in /*) ;; *) die "give the full path of the new folder (starting with / or ~)." ;; esac
  MOVE=${MOVE%/}
  [ "$MOVE" != "$old" ] || die "that is the folder Night Desk already uses."
  case "$MOVE/" in "$old"/*) die "the new folder cannot be inside the current one." ;; esac
  case "$old/" in "$MOVE"/*) die "the new folder cannot contain the current one." ;; esac
  if [ -e "$MOVE" ] && [ -n "$(ls -A "$MOVE" 2>/dev/null | grep -v '^.DS_Store$')" ]; then
    die "$MOVE is not empty. Choose a new or empty folder."
  fi
  mkdir -p "$MOVE" || die "cannot create $MOVE."
  step "Moving your data to $MOVE"
  say "Stopping Night Desk while the data is copied..."
  compose stop app
  if ! cp -Rp "$old"/. "$MOVE"/; then compose start app; die "the copy failed; Night Desk is back on $old."; fi
  a=$(cd "$old" && find . -type f | wc -l | tr -d ' '); b=$(cd "$MOVE" && find . -type f | wc -l | tr -d ' ')
  if [ "$a" != "$b" ]; then compose start app; die "the copy is incomplete ($b of $a files); Night Desk is back on $old."; fi
  setenv LAKE_DIR "$MOVE"
  compose up -d app
  say "Done: Night Desk now keeps its data in $MOVE ($a files)."
  say "The old folder $old is unchanged; delete it when you no longer need it."
  exit 0
fi

# ------------------------------------------------------------------ 1. Docker
step "Night Desk $VERSION"
command -v docker >/dev/null 2>&1 || die "Docker is not installed. Install Docker Desktop (https://www.docker.com/products/docker-desktop/), OrbStack or colima, start it, and run this again."
docker info >/dev/null 2>&1 || die "Docker is installed but not running. Start it (Docker Desktop, OrbStack or colima) and run this again."
docker compose version >/dev/null 2>&1 || die "Docker Compose is missing (the 'docker compose' command). Update Docker and run this again."
command -v curl >/dev/null 2>&1 || die "curl is needed."

# ------------------------------------------------------------------ 2. the code (the release, or --source for testing)
step "Getting Night Desk"
mkdir -p "$HOME_DIR"
NEW="$HOME_DIR/app.new"
rm -rf "$NEW"; mkdir -p "$NEW"
if [ -n "$SOURCE" ] && [ -d "$SOURCE" ]; then
  if [ -e "$SOURCE/.git" ]; then git -C "$SOURCE" archive --format=tar HEAD | tar -xf - -C "$NEW"
  else cp -R "$SOURCE"/. "$NEW"/; fi
  say "From $SOURCE"
else
  url="${SOURCE:-$REPO/archive/refs/tags/$VERSION.tar.gz}"
  curl -fsSL "$url" | tar -xzf - -C "$NEW" --strip-components=1 || die "could not download $url"
  say "From $url"
fi
[ -f "$NEW/docker-compose.yml" ] || die "the download does not look like Night Desk (no docker-compose.yml)."
rm -rf "$APP"; mv "$NEW" "$APP"

# ------------------------------------------------------------------ 3. settings (asked once; kept on updates)
if [ ! -f "$ENVF" ] || [ "$RECONF" = 1 ]; then
  step "A few questions (press Enter for the default)"
  # --reconfigure starts from the current answers
  odd=$(odd_settings)
  [ -z "$odd" ] || say "$odd in .env isn't written the installer's way (NAME='value'), so the new answer replaces it." >&2
  old_data=$(getenv LAKE_DIR); old_bind=$(getenv ND_BIND); old_port=$(getenv HTTPS_PORT); old_hash=$(getenv HLTA_AUTH_HASH)
  old_user=$(getenv HLTA_AUTH_USER)
  [ -n "$DATA" ] || DATA=$(ask "Where should Night Desk keep its data?" "${old_data:-$(default_data)}")
  case "$DATA" in "~"*) DATA="$HOME${DATA#\~}" ;; esac
  if [ -z "$LAN" ]; then
    say "Who should be able to open it?"
    say "  1  only this computer"
    say "  2  this computer and other devices on your network (with a password)"
    case $(ask "Choose 1 or 2" "$( [ "$old_bind" = 0.0.0.0 ] && echo 2 || echo 1 )") in 2) LAN=1 ;; *) LAN=0 ;; esac
  fi
  [ -n "$PORT" ] || PORT="$old_port"    # its own running stack holds that port, so keep it rather than probing
  if [ -z "$PORT" ]; then
    for p in 443 8443 8444 8445 8446 8447 8448 8449; do if port_free "$p"; then PORT=$p; break; fi; done
    [ -n "$PORT" ] || die "no free port among 443 and 8443-8449; pass one with --port N."
  fi
  HASH="" PASSWORD="" AUTH_USER=""
  if [ "$LAN" = 1 ]; then
    BIND=0.0.0.0
    # the sign-in name for other devices: asked, or nightdeskuser with --yes (a re-run keeps the current one)
    while :; do
      AUTH_USER=$(ask "User name for signing in from other devices" "${old_user:-nightdeskuser}")
      case "$AUTH_USER" in
        import) [ -n "$TTY" ] || die "the sign-in user name can't be 'import', a word Caddy reserves."
          say "'import' is a word Caddy reserves; choose another name." ;;
        "" | *[!A-Za-z0-9._-]*) [ -n "$TTY" ] || die "the sign-in user name in $ENVF can use only letters, digits, '.', '_' and '-'."
          say "Use only letters, digits, '.', '_' and '-'." ;;
        *) [ "${#AUTH_USER}" -le 64 ] && break; [ -n "$TTY" ] || die "the sign-in user name is longer than 64 characters."
          say "Use at most 64 characters." ;;
      esac
    done
    if [ "$OS" = Darwin ]; then HOSTS="nightdesk.local, $(scutil --get LocalHostName 2>/dev/null || hostname -s).local, localhost"
    else HOSTS="$(hostname -s 2>/dev/null || hostname).local, localhost"; fi
    if [ -n "$old_hash" ] && ! yes_no "Make a new password for other devices? (No keeps the current one)" n; then
      HASH="$old_hash"
    else
      PASSWORD=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20)
      HASH=$(docker run --rm caddy:2.8.4-alpine caddy hash-password --plaintext "$PASSWORD") || die "could not make the password hash."
    fi
  else
    BIND=127.0.0.1
    HOSTS="nightdesk.localhost, localhost"
  fi
  mkdir -p "$DATA" || die "cannot create the data folder $DATA."
  KEEP=$(own_settings)    # read before the file is rewritten
  umask 077
  {
    say "# Written by the Night Desk installer on $(date '+%Y-%m-%d'). Change a value and run the install line again"
    say "# (it keeps this file), or apply it with: docker compose -p $PROJECT --project-directory '$APP' --env-file '$ENVF' up -d"
    say "# Every setting is explained in app/.env.example."
    say "ND_BIND='$BIND'"
    say "HTTPS_PORT='$PORT'"
    say "HLTA_HOSTS='$HOSTS'"
    say "LAKE_DIR='$DATA'"
    say "ND_UID='$(id -u)'"
    say "ND_GID='$(id -g)'"
    say "NIGHTDESK_HOME='$HOME_DIR'"
    say "ND_PROJECT='$PROJECT'"
    [ -z "$AUTH_USER" ] || say "HLTA_AUTH_USER='$AUTH_USER'"
    [ -z "$HASH" ] || say "HLTA_AUTH_HASH='$HASH'"
    if [ -n "$KEEP" ]; then
      say ""
      say "# Your own settings: --reconfigure keeps them, --reset-keys removes them."
      printf '%s\n' "$KEEP"
    fi
  } >"$ENVF"
  chmod 600 "$ENVF"       # it holds keys: owner only, also when an older file had looser permissions
  umask 022
else
  say "Keeping your settings in $ENVF (run with --reconfigure to answer the questions again)."
  odd=$(odd_settings)
  [ -z "$odd" ] || say "$odd in .env isn't written the installer's way (NAME='value'); run with --reconfigure to set it again." >&2
  PASSWORD=""
fi
BIND=$(getenv ND_BIND); PORT=$(getenv HTTPS_PORT); DATA=$(getenv LAKE_DIR); HOSTS=$(getenv HLTA_HOSTS)
AUTH_USER=$(getenv HLTA_AUTH_USER); AUTH_USER=${AUTH_USER:-nightdeskuser}   # Compose's default when .env has none
NAME=${HOSTS%%,*}
URL="https://$NAME$( [ "$PORT" = 443 ] || printf ':%s' "$PORT" )/"

# ------------------------------------------------------------------ 4. build and start
step "Building and starting (the first build takes a few minutes)"
compose up -d --build

step "Waiting for Night Desk to answer"
say "The first start downloads about 140 MB of reference data (maps, IP locations), usually a minute or two."
i=0
while :; do
  cid=$(compose ps -q app 2>/dev/null || true)
  st=$( [ -n "$cid" ] && docker inspect -f '{{.State.Health.Status}}' "$cid" 2>/dev/null || echo starting)
  [ "$st" = healthy ] && break
  i=$((i + 1)); [ "$i" -le 120 ] || die "it did not come up within 10 minutes. See what it is doing: docker compose -p $PROJECT logs app"
  printf '.'; sleep 5
done
code=$(curl -sk -o /dev/null -w '%{http_code}' --resolve "$NAME:$PORT:127.0.0.1" "${URL}api/health" || true)
case "$code" in 200|401) printf ' up.\n' ;; *) die "the app is up but the HTTPS front (Caddy) answered $code. See: docker compose -p $PROJECT logs caddy" ;; esac

# ------------------------------------------------------------------ 5. trust the certificate on this computer
CRT="$HOME_DIR/nightdesk-root.crt"
n=0; until compose cp caddy:/data/caddy/pki/authorities/local/root.crt "$CRT" >/dev/null 2>&1; do
  n=$((n + 1)); [ "$n" -le 10 ] || break; sleep 1; done
trusted=0
if [ -f "$CRT" ] && [ "$TRUST" = 1 ]; then
  if [ "$OS" = Darwin ]; then
    if security verify-cert -c "$CRT" >/dev/null 2>&1; then trusted=1
    elif yes_no "Trust Night Desk's certificate on this Mac, so the browser shows no warning? (asks for your admin password)" y; then
      sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$CRT" && trusted=1
    fi
  elif yes_no "Trust Night Desk's certificate on this computer? (asks for your admin password)" y; then
    if [ -d /usr/local/share/ca-certificates ]; then
      sudo cp "$CRT" /usr/local/share/ca-certificates/nightdesk-root.crt && sudo update-ca-certificates >/dev/null && trusted=1
    elif [ -d /etc/pki/ca-trust/source/anchors ]; then
      sudo cp "$CRT" /etc/pki/ca-trust/source/anchors/nightdesk-root.crt && sudo update-ca-trust && trusted=1
    else say "Could not find the system certificate store; import $CRT in your browser."; fi
  fi
fi

# ------------------------------------------------------------------ 6. the network name (LAN only, macOS)
mdns_stop
if [ "$BIND" = 0.0.0.0 ] && [ "$OS" = Darwin ] && [ "$MDNS" = 1 ]; then
  ip=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || true)
  if [ -n "$ip" ]; then
    mkdir -p "$HOME/Library/LaunchAgents"
    cat >"$MDNS_PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$MDNS_LABEL</string>
  <key>ProgramArguments</key><array>
    <string>/usr/bin/dns-sd</string><string>-P</string><string>Night Desk</string><string>_https._tcp</string>
    <string>local</string><string>$PORT</string><string>nightdesk.local</string><string>$ip</string>
  </array>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
</dict></plist>
PLIST
    launchctl bootstrap "gui/$(id -u)" "$MDNS_PLIST" 2>/dev/null || true
    say "Announcing nightdesk.local on your network ($ip). If this Mac's address changes, run the install line again."
  else
    say "No network address found for nightdesk.local; other devices can use $(scutil --get LocalHostName 2>/dev/null).local."
  fi
fi

# ------------------------------------------------------------------ 7. done
[ "$OPEN" = 1 ] && { if [ "$OS" = Darwin ]; then open "$URL"; elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$URL" >/dev/null 2>&1 || true; fi; }
step "Night Desk is running"
say "  Open:         $URL"
if [ -n "$PASSWORD" ]; then say "  Sign-in:      user $AUTH_USER, password $PASSWORD   (shown once; keep it somewhere safe)"
elif [ "$BIND" = 0.0.0.0 ]; then say "  Sign-in:      user $AUTH_USER, with your current password"; fi
[ "$BIND" = 0.0.0.0 ] && say "  Other devices: trust the certificate once from ${URL}ca/root.crt"
[ "$trusted" = 1 ] || say "  Certificate:  not trusted on this computer yet, so the browser warns once; run the install line again to trust it."
say "  Your data:    $DATA"
say "  Settings:     $ENVF"
say "  Stop / start: docker compose -p $PROJECT stop    |    docker compose -p $PROJECT start"
say "  Update:       run the install line again    Uninstall: add  -s -- --uninstall  after sh"
