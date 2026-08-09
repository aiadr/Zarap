include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI support for Zarap transparent proxy
LUCI_DEPENDS:=+luci-base +rpcd-mod-ucode sing-box +firewall4 +kmod-nft-tproxy +kmod-nft-socket +ip-full +ss
LUCI_PKGARCH:=all

PKG_NAME:=luci-app-zarap
# Development placeholder. Release builds stamp the published version here:
# PKG_VERSION becomes the build date (YYYY.MM.DD) and PKG_RELEASE counts the
# releases made on that date. See .github/workflows/release.yml.
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_LICENSE:=GPL-3.0-or-later

define Package/luci-app-zarap/conffiles
/etc/config/zarap
/etc/zarap/
/etc/nftables.d/90-zarap.nft
endef

# Applying a configuration turns off router advertisement and DHCPv6 on the LAN,
# because the capture is IPv4 only and an advertised IPv6 would be a path around
# sing-box. Those are somebody else's settings, so removing the package has to
# hand them back — from the values recorded on the first apply, not from a guess
# at the default.
define Package/luci-app-zarap/prerm
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] && exit 0
for key in ra dhcpv6 ndp; do
	saved="$$(uci -q get "zarap.main.saved_$$key")"
	if [ -z "$$saved" ]; then
		uci -q delete "dhcp.lan.$$key"
	else
		uci -q set "dhcp.lan.$$key=$$saved"
	fi
done
uci -q commit dhcp
/etc/init.d/dnsmasq reload 2>/dev/null
/etc/init.d/odhcpd reload 2>/dev/null
exit 0
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
