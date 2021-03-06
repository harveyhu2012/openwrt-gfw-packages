#
# Copyright (C) 2013-2014 hackgfw
#
# This is free software, licensed under the GNU General Public License v3.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=gfw-vpn
PKG_VERSION:=0.2
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/gfw-vpn
  SECTION:=net
  CATEGORY:=Network
  DEPENDS += +ip +ipset +iptables-mod-ipopt
  PKGARCH:=all
  TITLE:=VPN script to tear down gfw
  URL:=https://github.com/hackgfw/openwrt-gfw/
  MAINTAINER:=hackgfw <hackgfw@aim.com>
endef

define Package/gfw-vpn/description
  VPN script to tear down gfw
  For more information, please refer to https://github.com/hackgfw/openwrt-gfw
endef

define Package/gfw-vpn/conffiles
/etc/config/gfw-vpn
endef

define Build/Compile
endef

define Package/gfw-vpn/install
	$(INSTALL_DIR) $(1)/etc/ppp
	$(INSTALL_DIR) $(1)/etc/ppp/ip-up.d
	$(INSTALL_DIR) $(1)/etc/ppp/ip-down.d
	$(INSTALL_BIN) ./files/ip-up-wall $(1)/etc/ppp/ip-up.d/ip-up-wall
	$(INSTALL_BIN) ./files/ip-down-wall $(1)/etc/ppp/ip-down.d/ip-down-wall
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/$(PKG_NAME).config $(1)/etc/config/$(PKG_NAME)
	$(INSTALL_CONF) ./files/$(PKG_NAME).whiteip $(1)/etc/config/$(PKG_NAME).whiteip
	$(INSTALL_CONF) ./files/$(PKG_NAME).whitezone $(1)/etc/config/$(PKG_NAME).whitezone
endef

define Package/gfw-vpn/postinst
#!/bin/sh
chkfirewall=$$(grep ". /var/gfw-vpn.user" $${IPKG_INSTROOT}/etc/firewall.user 2>/dev/null)
if [ -z "$$chkfirewall" ]; then
	echo "[[ -s /var/gfw-vpn.user ]] && . /var/gfw-vpn.user" >> $${IPKG_INSTROOT}/etc/firewall.user
fi
exit 0
endef

define Package/gfw-vpn/postrm
#!/bin/sh
sed -i '/gfw-vpn.user/d' $${IPKG_INSTROOT}/etc/firewall.user 2>/dev/null
exit 0
endef

$(eval $(call BuildPackage,gfw-vpn))
