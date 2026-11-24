include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI support for Zarap transparent proxy
LUCI_DEPENDS:=+luci-base +rpcd-mod-ucode xray-core +curl +firewall4 +kmod-nft-tproxy +kmod-nft-socket +ip-full +ss
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
# xray-core. Those are somebody else's settings, so removing the package has to
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
	# Удаляем только точные строки пересылки, добавленные самим Zarap:
	# если managed_dns_servers уже записан — он считается полным списком;
	# иначе при отсутствии managed_dns_tracked=1 восстанавливаем строки
	# из сохранённых правил zarap с учётом rule_set.
	if managed="$$(uci -q get zarap.main.managed_dns_servers)"; then
		for entry in $$managed; do
			[ -n "$$entry" ] && uci -q del_list "dhcp.$$section.server=$$entry"
		done
	elif [ "$$(uci -q get zarap.main.managed_dns_tracked)" != "1" ]; then
		idx=0
		order=""
		has_domain=""
		while target="$$(uci -q get "zarap.@rule[$$idx].target")"; do
			domains="$$(uci -q get "zarap.@rule[$$idx].domain")"
			rsets="$$(uci -q get "zarap.@rule[$$idx].rule_set")"
			if [ "$$target" != "direct" ] && [ "$$target" != "block" ]; then
				if [ -n "$$domains" ] || [ -n "$$rsets" ]; then
					case " $$order " in
						*" $$target "*) ;;
						*) order="$$order $$target" ;;
					esac
				fi
				if [ -n "$$domains" ]; then
					case " $$has_domain " in
						*" $$target "*) ;;
						*) has_domain="$$has_domain $$target" ;;
					esac
				fi
			fi
			idx=$$((idx + 1))
		done
		domain_tags=""
		for t in $$order; do
			case " $$has_domain " in
				*" $$t "*) domain_tags="$$domain_tags $$t" ;;
			esac
		done
		idx=0
		while target="$$(uci -q get "zarap.@rule[$$idx].target")"; do
			domains="$$(uci -q get "zarap.@rule[$$idx].domain")"
			if [ -n "$$domains" ] && [ "$$target" != "direct" ] && [ "$$target" != "block" ]; then
				pos=0
				port=5353
				for t in $$domain_tags; do
					if [ "$$t" = "$$target" ]; then
						port=$$((5353 + pos))
						break
					fi
					pos=$$((pos + 1))
				done
				for d in $$domains; do
					d="$${d#.}"
					uci -q del_list "dhcp.$$section.server=/$$d/127.0.0.1#5353"
					[ "$$port" -ne 5353 ] && uci -q del_list "dhcp.$$section.server=/$$d/127.0.0.1#$$port"
				done
			fi
			idx=$$((idx + 1))
		done
	fi
fi
uci -q commit dhcp
/etc/init.d/dnsmasq reload 2>/dev/null
/etc/init.d/odhcpd reload 2>/dev/null
exit 0
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
