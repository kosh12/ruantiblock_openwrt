#!/bin/sh
#
# autoinstall.sh — installer for ruantiblock packages
#
# Downloads the latest GitHub release from the ruantiblock_openwrt fork
# and installs every .apk it contains.
#
# Requirements:
#   - OpenWrt >= 25.12.6   (APK-based; older opkg/ipk releases are rejected)
#   - root
#   - internet access (the device's own repos are used to pull dependencies)
#
# Usage on the router:
#     sh autoinstall.sh
# or, as a one-liner from the repo:
#     wget -qO- https://raw.githubusercontent.com/kosh12/ruantiblock_openwrt/master/autoinstall.sh | sh
#

set -eu

REPO="kosh12/ruantiblock_openwrt"
MIN_VERSION="25.12.6"
UA="ruantiblock-autoinstall/1.0"

log() { printf '[*] %s\n' "$*"; }
die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

TMPDIR=""
cleanup() { [ -n "$TMPDIR" ] && rm -rf "$TMPDIR"; }
trap cleanup EXIT INT TERM

# ---- version comparison: exit 0 if $1 >= $2 ----
version_ge() {
    awk -v a="$1" -v b="$2" 'BEGIN{
        na = split(a, va, "."); nb = split(b, vb, ".");
        n  = (na > nb) ? na : nb;
        for (i = 1; i <= n; i++) {
            xa = (i <= na) ? va[i]+0 : 0;
            xb = (i <= nb) ? vb[i]+0 : 0;
            if (xa > xb) exit 0;
            if (xa < xb) exit 1;
        }
        exit 0;
    }'
}

# ---- download helper: fetch_url URL OUTPUT_FILE ----
# Tries curl, then wget, then uclient-fetch; falls back to no-cert-check.
fetch_url() {
    _url="$1"; _out="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -A "$UA" -o "$_out" "$_url" 2>/dev/null || \
        curl -fsSL -A "$UA" -k  -o "$_out" "$_url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -U "$UA" -O "$_out" "$_url" 2>/dev/null || \
        wget -q -U "$UA" --no-check-certificate -O "$_out" "$_url"
    elif command -v uclient-fetch >/dev/null 2>&1; then
        uclient-fetch -q -O "$_out" "$_url" 2>/dev/null || \
        uclient-fetch -q --no-check-certificate -O "$_out" "$_url"
    else
        die "No download tool found (need curl, wget or uclient-fetch)."
    fi
}

# ---- must be root ----
[ "$(id -u)" -eq 0 ] || die "Run this script as root."

# ---- must be OpenWrt ----
[ -f /etc/openwrt_release ] || die "/etc/openwrt_release not found — not an OpenWrt system."
. /etc/openwrt_release
CUR="${DISTRIB_RELEASE:-unknown}"
log "OpenWrt version: ${CUR}"

version_ge "$CUR" "$MIN_VERSION" || \
    die "OpenWrt ${CUR} is too old; this installer requires >= ${MIN_VERSION}."
log "Version OK (>= ${MIN_VERSION})."

# ---- must have apk (OpenWrt 25.x) ----
command -v apk >/dev/null 2>&1 || \
    die "apk not found. OpenWrt below 25.x uses opkg/.ipk and is not supported."

# ---- fetch latest release info from GitHub ----
log "Fetching latest release info from ${REPO}..."
TMPDIR=$(mktemp -d /tmp/ruantiblock.XXXXXX)
fetch_url "https://api.github.com/repos/${REPO}/releases/latest" "${TMPDIR}/rel.json" \
    || die "Failed to reach GitHub API. Check internet/CA bundle (opkg install ca-bundle)."

# ---- extract .apk asset URLs ----
URLS=$(grep -o '"browser_download_url": *"[^"]*\.apk"' "${TMPDIR}/rel.json" \
       | sed 's/.*": *"//; s/"$//')
[ -n "$URLS" ] || die "No .apk assets found in the latest release of ${REPO}."

n=$(printf '%s\n' "$URLS" | wc -w | tr -d ' ')
log "Found ${n} package(s):"
for u in $URLS; do printf '  - %s\n' "$(basename "$u")"; done

# ---- download every .apk ----
log "Downloading packages..."
for u in $URLS; do
    fn=$(basename "$u")
    fetch_url "$u" "${TMPDIR}/${fn}" || die "Failed to download ${fn}."
done
log "Download complete."

# ---- install ----
# CI-built apks are unsigned, so --allow-untrusted is required.
# apk resolves runtime deps (dnsmasq-full, kmod-nft-tproxy, luci-base, ...)
# from the device's configured repositories automatically.
log "Installing (using --allow-untrusted for unsigned CI builds)..."
apk add --allow-untrusted "${TMPDIR}"/*.apk || die "apk add failed."

log "Done."
log "Configure via LuCI (Services -> ruantiblock) or /etc/config/ruantiblock."
log "Enable the service:  /etc/init.d/ruantiblock enable && /etc/init.d/ruantiblock start"
