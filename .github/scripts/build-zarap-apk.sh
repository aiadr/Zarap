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

pkg_version="$(sed -n 's/^PKG_VERSION:=//p' /feed/luci-app-zarap/Makefile)"
pkg_release="$(sed -n 's/^PKG_RELEASE:=//p' /feed/luci-app-zarap/Makefile)"
package_arch="$(sed -n 's/^CONFIG_TARGET_ARCH_PACKAGES="\([^"]*\)"/\1/p' .config)"
apk_target="${PWD}/bin/packages/${package_arch}/action/luci-app-zarap-${pkg_version}-r${pkg_release}.apk"

# The top-level package target adds runtime packages to the build graph. Call
# the package sub-make's APK target instead: it builds and packages Zarap while
# preserving its dependency metadata, without compiling sing-box or a kernel.
make -r -C package/feeds/action/luci-app-zarap \
	TOPDIR="${PWD}" DEVELOPER=1 "${apk_target}" V=s

mapfile -t apks < <(find bin/packages -type f -name 'luci-app-zarap-*.apk' -print)
if [[ "${#apks[@]}" -ne 1 ]]; then
	printf 'Expected exactly one Zarap APK, found %d\n' "${#apks[@]}" >&2
	exit 1
fi

cp -v "${apks[0]}" /artifacts/
