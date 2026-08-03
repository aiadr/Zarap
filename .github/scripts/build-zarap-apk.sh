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
make defconfig

# Use OpenWrt's public package target: raw APK file targets are internal to
# recursive make and are not exported at the SDK top level. DEVELOPER makes
# the APK target available without selecting Zarap or sing-box in .config;
# clearing IDEPEND prevents runtime dependencies from being compiled. Their
# constraints are still taken from the package-specific metadata.
make -j"$(nproc)" DEVELOPER=1 IDEPEND= package/luci-app-zarap/compile V=s

mapfile -t apks < <(find bin/packages -type f -name 'luci-app-zarap-*.apk' -print)
if [[ "${#apks[@]}" -ne 1 ]]; then
	printf 'Expected exactly one Zarap APK, found %d\n' "${#apks[@]}" >&2
	exit 1
fi

cp -v "${apks[0]}" /artifacts/
