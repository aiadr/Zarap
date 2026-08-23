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
section="$$(uci -q show dhcp | sed -n 's/^dhcp\.\([^.=]*\)=dnsmasq$$/\1/p' | head -n 1)"
if [ -n "$$section" ]; then
	# Режим «резолвить имена через подключение» забирал у dnsmasq server,
	# noresolv и cachesize целиком. Прежние значения лежат в zarap.main и
	# возвращаются как есть; пустое означает, что ключа не было вовсе.
	for key in server noresolv cachesize; do
		if saved="$$(uci -q get "zarap.main.saved_dns_$$key")"; then
			uci -q delete "dhcp.$$section.$$key"
			# server — список, и `uci set` со пробелами схлопнул бы его в одну
			# строку; поэтому запись по одной. Пустое сохранённое значение
			# означает, что ключа не было вовсе, и удаления достаточно.
			for value in $$saved; do
				uci -q add_list "dhcp.$$section.$$key=$$value"
			done
		fi
	done
	# Пересылка названных доменов на наш DNS-слушатель: своими считаются строки,
	# указывающие на него, чужие остаются нетронутыми.
	uci -q get "dhcp.$$section.server" | tr ' ' '\n' | grep -F '127.0.0.1#5353' |
	while read -r entry; do
		[ -n "$$entry" ] && uci -q del_list "dhcp.$$section.server=$$entry"
	done
fi
uci -q commit dhcp
/etc/init.d/dnsmasq reload 2>/dev/null
/etc/init.d/odhcpd reload 2>/dev/null
exit 0
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
