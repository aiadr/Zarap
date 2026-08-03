#!/bin/bash

set -euo pipefail

sdk_name='openwrt-sdk-25.12.4-x86-64_gcc-14.3.0_musl.Linux-x86_64.tar.zst'
sdk_url="https://downloads.openwrt.org/releases/25.12.4/targets/x86/64/${sdk_name}"
sdk_sha='28e004c1be4d215d19c1f12a6aa4c8d8f80689549eb707d0ff5a71f16fa8d05f'
sdk_archive="/sdk-cache/${sdk_name}"

if ! printf '%s  %s\n' "${sdk_sha}" "${sdk_archive}" | sha256sum -c -; then
	rm -f "${sdk_archive}"
	wget -nv -O "${sdk_archive}" "${sdk_url}"
	printf '%s  %s\n' "${sdk_sha}" "${sdk_archive}" | sha256sum -c -
fi
tar -xf "${sdk_archive}" --strip-components=1 --no-same-owner

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
