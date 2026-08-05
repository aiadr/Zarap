include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI support for Zarap transparent proxy
LUCI_DEPENDS:=+luci-base +rpcd-mod-ucode sing-box +firewall4 +kmod-nft-tproxy +kmod-nft-socket +ip-full
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

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
