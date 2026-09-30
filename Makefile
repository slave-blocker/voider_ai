# voider build: every binary is part of the appliance.
CXX ?= g++
CC  ?= cc
CXXFLAGS ?= -Os -std=c++17 -Wall -Wextra -Iinclude
CFLAGS   ?= -Os -Wall -Wextra
B := build

BINS := $(shell cat config/release-binaries)

all: $(addprefix $(B)/,$(BINS))

$(B):
	mkdir -p $@

$(B)/voider-nfqd: src/voider_nfqd.cpp include/voider_config.hpp | $(B)
	$(CXX) $(CXXFLAGS) $< -o $@ -lnetfilter_queue

$(B)/voiderctl: src/voiderctl.cpp include/voider_config.hpp include/voider_util.hpp | $(B)
	$(CXX) $(CXXFLAGS) $< -o $@

$(B)/voider-superd: src/voider_superd.cpp include/voider_config.hpp | $(B)
	$(CXX) $(CXXFLAGS) $< -o $@

$(B)/voider-peerd: src/voider_peerd.cpp include/voider_config.hpp include/voider_wan_ipv6.hpp include/voider_transport_protocol.hpp include/voider_transport_allowlist.hpp include/voider_util.hpp | $(B)
	$(CXX) $(CXXFLAGS) $< -o $@ -lcrypto

$(B)/voider-netns: src/voider_netns.cpp include/voider_config.hpp include/voider_util.hpp | $(B)
	$(CXX) $(CXXFLAGS) $< -o $@

$(B)/voider-holepunch: src/voider_holepunch.cpp include/voider_config.hpp include/voider_wan_ipv6.hpp include/voider_util.hpp | $(B)
	$(CXX) $(CXXFLAGS) $< -o $@

$(B)/voider-sync: src/voider_sync.cpp include/voider_config.hpp include/voider_mailbox.hpp include/voider_transport_protocol.hpp include/voider_util.hpp | $(B)
	$(CXX) $(CXXFLAGS) $< -o $@

$(B)/voider-cap2: src/voider_cap2.cpp include/voider_config.hpp include/voider_wan_ipv6.hpp include/voider_mailbox.hpp include/voider_transport_protocol.hpp include/voider_transport_allowlist.hpp include/voider_util.hpp | $(B)
	$(CXX) $(CXXFLAGS) $< -o $@ -lcrypto

$(B)/voider-usb: src/voider_usb.cpp include/voider_config.hpp include/voider_contacts.hpp include/voider_mailbox.hpp include/voider_util.hpp | $(B)
	$(CXX) $(CXXFLAGS) $< -o $@

$(B)/voider-peerctl: src/voider_peerctl.cpp include/voider_config.hpp include/voider_util.hpp | $(B)
	$(CXX) $(CXXFLAGS) $< -o $@

$(B)/voider-publicip: src/voider_publicip.cpp include/voider_config.hpp include/voider_util.hpp | $(B)
	$(CXX) $(CXXFLAGS) $< -o $@

$(B)/voider-ipv6-ready: src/voider_ipv6_ready.cpp include/voider_config.hpp include/voider_wan_ipv6.hpp include/voider_util.hpp | $(B)
	$(CXX) $(CXXFLAGS) $< -o $@

$(B)/voider-sftp-setup: src/voider_sftp_setup.cpp include/voider_config.hpp include/voider_mailbox.hpp include/voider_util.hpp | $(B)
	$(CXX) $(CXXFLAGS) $< -o $@

$(B)/voider-integrity: src/voider_integrity.cpp include/voider_config.hpp include/voider_util.hpp | $(B)
	$(CXX) $(CXXFLAGS) $< -o $@ -lcrypto

$(B)/voider-ui: src/voider_ui.cpp include/voider_ui_font.hpp include/voider_ui_strings.hpp include/voider_config.hpp include/voider_contacts.hpp include/voider_transport_allowlist.hpp include/voider_util.hpp | $(B)
	$(CXX) $(CXXFLAGS) $< -o $@

$(B)/voider-appliance-boot: src/voider_appliance_boot.cpp include/voider_config.hpp include/voider_util.hpp | $(B)
	$(CXX) $(CXXFLAGS) $< -o $@

$(B)/voider-main: src/voider_main.cpp include/voider_config.hpp include/voider_contacts.hpp include/voider_mailbox.hpp include/voider_transport_allowlist.hpp include/voider_util.hpp | $(B)
	$(CXX) $(CXXFLAGS) $< -o $@

$(B)/voider-dhcp: src/voider_dhcp.cpp include/voider_config.hpp include/voider_util.hpp | $(B)
	$(CXX) $(CXXFLAGS) $< -o $@

$(B)/voider-wan: src/voider_wan.cpp include/voider_config.hpp include/voider_util.hpp | $(B)
	$(CXX) $(CXXFLAGS) $< -o $@

$(B)/voider-phone: src/voider_phone.cpp include/voider_config.hpp include/voider_util.hpp | $(B)
	$(CXX) $(CXXFLAGS) $< -o $@

$(B)/voider-selftest: src/voider_selftest.cpp include/voider_config.hpp include/voider_transport_allowlist.hpp include/voider_util.hpp | $(B)
	$(CXX) $(CXXFLAGS) $< -o $@


$(B)/voider-install: src/voider_install.cpp include/voider_config.hpp include/voider_util.hpp | $(B)
	$(CXX) $(CXXFLAGS) $< -o $@

# Wire v8: mutual pair authentication and fixed two-stream Tor duplication.
$(B)/tundup-v7-secure: src/tundup_v7_secure.c | $(B)
	$(CC) $(CFLAGS) $< -o $@ -lcrypto

$(B)/voider-tor-netns-socks: src/voider_tor_netns_socks.cpp include/voider_config.hpp include/voider_util.hpp $(B)
	$(CXX) $(CXXFLAGS) $< -o $@

install: all
	./build/voider-install

selftest: all
	./build/voider-selftest all

render-ui: $(B)/voider-ui
	python3 scripts/render-ui-gallery.py

clean:
	rm -rf $(B)
