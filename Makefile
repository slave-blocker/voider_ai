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

$(B)/voider-peerd: src/voider_peerd.cpp include/voider_mailbox.hpp include/voider_config.hpp include/voider_wan_ipv6.hpp include/voider_transport_protocol.hpp include/voider_transport_allowlist.hpp include/voider_util.hpp | $(B)
	$(CXX) $(CXXFLAGS) $< -o $@ -lcrypto -pthread

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

$(B)/util-semantics-test: tests/util-semantics.cpp include/voider_util.hpp include/voider_config.hpp | $(B)
	$(CXX) $(CXXFLAGS) $< -o $@

$(B)/hp6-readiness-test: tests/hp6-readiness.cpp include/voider_config.hpp include/voider_wan_ipv6.hpp | $(B)
	$(CXX) $(CXXFLAGS) $< -o $@

$(B)/peerd-health-test: tests/service-lifecycle.cpp src/voider_peerd.cpp $(wildcard include/*.hpp) | $(B)
	$(CXX) $(CXXFLAGS) $< -o $@ -lcrypto -pthread -Wl,--wrap=system,--wrap=popen,--wrap=pclose,--wrap=posix_spawnp

$(B)/runtime-lifecycle-test: tests/runtime-lifecycle.cpp include/voider_runtime.hpp | $(B)
	$(CXX) $(CXXFLAGS) $< -o $@ -pthread

$(addprefix $(B)/,voider-nfqd voider-peerd voider-ui voider-main voider-sync voider-cap2 voider-wan voider-phone voider-holepunch): include/voider_runtime.hpp

$(B)/wan-address-test: tests/wan-address.cpp src/voider_wan.cpp include/voider_config.hpp include/voider_util.hpp | $(B)
	$(CXX) $(CXXFLAGS) $< -o $@ -Wl,--wrap=system

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

$(B)/factory-layout-test: tests/factory-layout.cpp src/voider_install.cpp include/voider_config.hpp include/voider_util.hpp | $(B)
	$(CXX) $(CXXFLAGS) $< -o $@

# Wire v8: mutual pair authentication and fixed two-stream Tor duplication.
$(B)/tundup-v7-secure: src/tundup_v7_secure.c | $(B)
	$(CC) $(CFLAGS) $< -o $@ -lcrypto

$(B)/tundup-security-test: tests/tundup-security.c src/tundup_v7_secure.c | $(B)
	$(CC) $(CFLAGS) $< -o $@ -lcrypto

$(B)/tundup-test-driver: tests/tundup-driver.c src/tundup_v7_secure.c | $(B)
	$(CC) $(CFLAGS) $< -o $@ -lcrypto

tundup-test: $(B)/tundup-security-test $(B)/tundup-test-driver
	./build/tundup-security-test
	python3 tests/tundup-streams.py

$(B)/voider-tor-netns-socks: src/voider_tor_netns_socks.cpp include/voider_config.hpp include/voider_util.hpp $(B)
	$(CXX) $(CXXFLAGS) $< -o $@

install: all
	./build/voider-install

selftest: all
	./build/voider-selftest all

ui-test: $(B)/voider-ui
	./build/voider-ui --selftest

integrity-test: $(B)/voider-integrity
	./tests/integrity-model.sh

factory-test: $(B)/voider-ui $(B)/voider-install
	./tests/factory-install-model.sh

release-test:
	./tests/run-release-tests.sh

transport-test: $(B)/voider-cap2 $(B)/voider-peerd $(B)/voider-sync
	./build/voider-cap2 selftest
	./build/voider-peerd --selftest
	./build/voider-sync selftest
	./tests/transport-mailbox-model.sh

render-ui: $(B)/voider-ui
	python3 scripts/render-ui-gallery.py

usb-loop-test: $(B)/voider-usb
	./tests/usb-loop-safety.sh

usb-lifecycle-test: $(B)/voider-usb
	./tests/usb-lifecycle.sh

usb-test: $(B)/voider-usb
	./build/voider-usb selftest

button-hardware-test:
	./tests/pitft-bridge-lifecycle.sh

clean:
	rm -rf $(B)
