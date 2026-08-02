#!/bin/bash

set -euo pipefail

if [[ -f setup.sh ]]; then
	bash setup.sh
fi

sed \
	-e 's,https://git.openwrt.org/feed/,https://github.com/openwrt/,' \
	-e 's,https://git.openwrt.org/openwrt/,https://github.com/openwrt/,' \
	-e 's,https://git.openwrt.org/project/,https://github.com/openwrt/,' \
	feeds.conf.default > feeds.conf
echo 'src-link action /feed' >> feeds.conf

./scripts/feeds update base packages luci action
./scripts/feeds install -p action -f luci-app-zarap
printf '%s\n' \
	'CONFIG_PACKAGE_sing-box=m' \
	'CONFIG_PACKAGE_luci-app-zarap=m' >> .config
make defconfig

# Use OpenWrt's public package target: raw APK file targets are internal to
# recursive make and are not exported at the SDK top level. Clearing IDEPEND
# prevents runtime dependencies (notably sing-box and its Go toolchain) from
# being compiled while retaining them in the generated APK metadata.
make -j"$(nproc)" IDEPEND= package/luci-app-zarap/compile V=s

mapfile -t apks < <(find bin/packages -type f -name 'luci-app-zarap-*.apk' -print)
if [[ "${#apks[@]}" -ne 1 ]]; then
	printf 'Expected exactly one Zarap APK, found %d\n' "${#apks[@]}" >&2
	exit 1
fi

cp -v "${apks[0]}" /artifacts/
