// voider_config.hpp: compact configuration model.
//
// Most settings can come from /etc/voider/voider.conf. A few appliance
// invariants are fixed defaults: the phone-side address is always
// 172.16.19.85/30 behind voider gateway 172.16.19.86.

#pragma once
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstdint>
#include <ctime>
#include <cstdio>
#include <filesystem>
#include <set>
#include <system_error>
#include "voider_transport_allowlist.hpp"
struct Cfg {
    std::string
    phone_ip="172.16.19.85",
    phone_gw="172.16.19.86",
    phone_if="eth1",
    wan_if="eth0",
    client_ifs="wg+,tcs+",
    server_br_prefix="br",
    pc="/etc/voider/peers/clients.d",
    ps="/etc/voider/peers/servers.d",
    pstate="/run/voider/peers",
    status="/run/voider/status",
    sync="/etc/voider/sync",
    cert="/etc/voider/certs",
    mat="/etc/voider/peers/material",
    node_dir="/etc/voider/node",
    pubip_file="/run/voider/public_ip",
    pubip_runtime="/run/voider/public_ip",
    pubip_services="https://api.ipify.org,"
    "https://ifconfig.me/ip,"
    "https://icanhazip.com,"
    "https://checkip.amazonaws.com",
    sftp_base="/var/sftp",
    mailbox_group="voider-mailbox",
    mailbox_key_dir="/etc/voider/certs/mailboxes",
    admin_auth_keys="/etc/voider/certs/admin_authorized_keys",
    sftp_host_pub="/etc/voider/node/host.pub",
    sftp_limits="/etc/security/limits.d/voider-mailboxes.conf",
    sftp_sshd_snippet="/etc/ssh/sshd_config.d/00-voider-mailboxes.conf",
    tor_hs_dir="/var/lib/tor/voider",
    tor_dot_dir="/var/lib/tor/.tor",
    tor_dot_tmpfs_size="256M",
    torrc="/etc/tor/torrc",
    node_onion="/etc/voider/private/node_onion",
    sync_onion="/etc/voider/private/node_onion",
    socks_host="127.0.0.1",
    tor_netns_socks_if="voider-socks0",
    tor_netns_socks_ip="172.30.255.1",
    transports_available="lan4,lan6,direct4,direct6,hp4,hp6,tor",
    usb_label="VOIDER",
    usb_mount="/run/voider/usb-mount",
    usb_bundle="voider-bundle.tar",
    usb_fs="vfat",
    usb_fp_dir="/etc/voider/certs/fingerprints",
    usb_import_dir="/etc/voider/imports",
    usb_reject_dir="/etc/voider/certs/rejected",
    boot_dev="AUTO",
    system_dev="AUTO",
    state_dev="AUTO",
    state_mount="/mnt/voider-state",
    state_dir="/mnt/voider-state/voider",
    state_tar="/mnt/voider-state/voider/state.tar.gz",
    integrity_manifest="/mnt/voider-state/voider/integrity.manifest",
    integrity_freeze_meta="/mnt/voider-state/voider/integrity.freeze.meta",
    ram_state_root="/run/voider/state-root",
    ram_overlay_root="/run/voider/overlay-root",
    state_allowlist="/etc/voider/voider.conf,/etc/voider/peers,"
    "/etc/voider/private,/etc/voider/certs,/etc/voider/imports,/etc/voider/dhcp,/etc/voider/node,"
    "/var/lib/tor/voider,"
    "/etc/ssh/ssh_host_ed25519_key,"
    "/etc/ssh/ssh_host_ed25519_key.pub,"
    "/etc/ssh/ssh_host_rsa_key,"
    "/etc/ssh/ssh_host_rsa_key.pub,"
    "/etc/ssh/sshd_config.d/00-voider-mailboxes.conf,"
    "/etc/network/interfaces,/etc/hostname,/etc/machine-id",
    runtime_allowlist="/etc/voider/sync,/var/sftp",
    fake_seed="/run/voider/fakeip.seed",
    ui_page_file="/run/voider/ui.page",
    ui_event_log="/run/voider/ui.events",
    ui_paths_stage="/run/voider/ui.paths.stage",
    ui_paths_cursor="/run/voider/ui.paths.cursor",
    ui_fb="/dev/fb0",
    ui_tty="/dev/tty2",
    dhcp_conf="/etc/voider/dhcp/udhcpd.conf",
    dhcp_leases="/run/voider/udhcpd.leases",
    dhcp_pid="/run/voider/udhcpd-phone.pid",
    dhcp_start="172.16.19.85",
    dhcp_end="172.16.19.85",
    dhcp_netmask="255.255.255.252",
    dhcp_router="172.16.19.86",
    dhcp_dns="172.16.19.86",
    wan_dhcp_pid="/run/voider/udhcpc-wan.pid",
    wan_status="/run/voider/wan.status",
    wan_check_host="1.1.1.1",
    phone_status="/run/voider/phone.status";
    int
    dhcp_enabled=1,
    dhcp_lease_sec=86400,
    dhcp_cidr=30,
    wan_dhcp_enabled=1,
    admin_ssh_lan=0,
    wan_monitor_sec=5,
    phone_probe_sec=3,
    ui_refresh=1,
    ui_buttons=4,
    fake_client_base3=40,
    fake_server_base3=10,
    fake_width=10,
    fake_host_base=10,
    socks_port=9050,
    tor_netns_socks_port=19050,
    pubip_timeout=4,
    hp_punch_delay=6,
    hp_burst_count=5,
    hp_burst_packets=24,
    hp_burst_interval_ms=60,
    hp_retries=3,
    hp_port_max=60999,
    mailbox_record_bytes=4096,
    mailbox_max_pending=8,
    mailbox_ttl_sec=600,
    tundup_torport_base=7000,
    sip=5060,
    qc=10,
    qp=12,
    bypass=0,
    maxc=253,
    maxs=253,
    maxp=506;
    bool config_valid=true;
    std::string config_error;
}
;
static inline std::string trim(std::string s){
    auto f=[](int c){
        return !std::isspace(c);
    }
    ;
    s.erase(s.begin(),std::find_if(s.begin(),s.end(),f));
    s.erase(std::find_if(s.rbegin(),s.rend(),f).base(),s.end());
    return s;
}
static inline int toi(const std::string&v,int d){
    try{
        return std::stoi(v);
    }
    catch(...){
        return d;
    }
}
static inline void setkv(Cfg&c,const std::string&k,const std::string&v){
    // The phone link is fixed; accept old values without making them settings.
    if(k=="PHONE_IP"||k=="PHONE_GW"||k=="DHCP_START"||k=="DHCP_END"||
       k=="DHCP_NETMASK"||k=="DHCP_ROUTER"||k=="DHCP_DNS"||k=="DHCP_CIDR")return;
    if(k=="PHONE_IF")c.phone_if=v;
    else if(k=="WAN_IF")c.wan_if=v;
    else if(k=="SIP_PORT")c.sip=toi(v,c.sip);
    else if(k=="CLIENT_TUN_IFS")c.client_ifs=v;
    else if(k=="SERVER_BR_PREFIX")c.server_br_prefix=v;
    else if(k=="QUEUE_CLIENT_IN")c.qc=toi(v,c.qc);
    else if(k=="QUEUE_SERVER_IN")return; // Legacy queue has no rule producer.
    else if(k=="QUEUE_PHONE_OUT")c.qp=toi(v,c.qp);
    else if(k=="QUEUE_BYPASS")c.bypass=toi(v,c.bypass);
    else if(k=="PEER_CLIENT_DIR")c.pc=v;
    else if(k=="PEER_SERVER_DIR")c.ps=v;
    else if(k=="PEER_STATE_DIR")c.pstate=v;
    else if(k=="STATUS_FILE")c.status=v;
    else if(k=="SYNC_DIR")c.sync=v;
    else if(k=="CERT_DIR")c.cert=v;
    else if(k=="PEER_MATERIAL_DIR")c.mat=v;
    else if(k=="NODE_DIR")c.node_dir=v;
    else if(k=="PUBLIC_IP_FILE")c.pubip_file=v;
    else if(k=="PUBLIC_IP_RUNTIME")c.pubip_runtime=v;
    else if(k=="PUBLIC_IP_SERVICES")c.pubip_services=v;
    else if(k=="PUBLIC_IP_TIMEOUT_SEC")c.pubip_timeout=toi(v,c.pubip_timeout);
    else if(k=="HP_PUNCH_DELAY_SEC")c.hp_punch_delay=toi(v,c.hp_punch_delay);
    else if(k=="HP_BURST_COUNT")c.hp_burst_count=toi(v,c.hp_burst_count);
    else if(k=="HP_BURST_PACKETS")c.hp_burst_packets=toi(v,c.hp_burst_packets);
    else if(k=="HP_BURST_INTERVAL_MS")c.hp_burst_interval_ms=toi(v,c.hp_burst_interval_ms);
    else if(k=="HP_RETRIES")c.hp_retries=toi(v,c.hp_retries);
    else if(k=="HP_PORT_MAX")c.hp_port_max=toi(v,c.hp_port_max);
    else if(k=="SFTP_BASE")c.sftp_base=v;
    else if(k=="MAILBOX_GROUP")c.mailbox_group=v;
    else if(k=="MAILBOX_KEY_DIR")c.mailbox_key_dir=v;
    else if(k=="ADMIN_AUTH_KEYS")c.admin_auth_keys=v;
    else if(k=="SFTP_HOST_PUB")c.sftp_host_pub=v;
    else if(k=="SFTP_LIMITS")c.sftp_limits=v;
    else if(k=="SFTP_SSHD_SNIPPET")c.sftp_sshd_snippet=v;
    else if(k=="TOR_HS_DIR")c.tor_hs_dir=v;
    else if(k=="TOR_DOT_DIR")c.tor_dot_dir=v;
    else if(k=="TOR_DOT_TMPFS_SIZE")c.tor_dot_tmpfs_size=v;
    else if(k=="TORRC")c.torrc=v;
    else if(k=="NODE_ONION")c.node_onion=v;
    else if(k=="SYNC_ONION")c.sync_onion=v;
    else if(k=="TOR_SOCKS_HOST")c.socks_host=v;
    else if(k=="TOR_SOCKS_PORT")c.socks_port=toi(v,c.socks_port);
    else if(k=="TOR_NETNS_SOCKS_IF")c.tor_netns_socks_if=v;
    else if(k=="TOR_NETNS_SOCKS_IP")c.tor_netns_socks_ip=v;
    else if(k=="TOR_NETNS_SOCKS_PORT")c.tor_netns_socks_port=toi(v,c.tor_netns_socks_port);
    // Legacy settings remain readable in curated STATE, but select no behavior.
    // Tundup always authenticates plaintext and duplicates on two Tor streams.
    else if(k=="TUNDUP_CIRCUITS"||k=="TUNDUP_STREAMS"||k=="TUNDUP_SCHED"||
            k=="TUNDUP_MODE"||k=="TUNDUP_AEAD"){}
    else if(k=="TRANSPORTS_AVAILABLE")c.transports_available=v;
    else if(k=="USB_REJECT_DIR")c.usb_reject_dir=v;
    else if(k=="BOOT_DEVICE")c.boot_dev=v;
    else if(k=="SYSTEM_DEVICE")c.system_dev=v;
    else if(k=="STATE_DEVICE")c.state_dev=v;
    else if(k=="STATE_MOUNT")c.state_mount=v;
    else if(k=="STATE_DIR")c.state_dir=v;
    else if(k=="STATE_TAR")c.state_tar=v;
    else if(k=="INTEGRITY_MANIFEST")c.integrity_manifest=v;
    else if(k=="INTEGRITY_FREEZE_META")c.integrity_freeze_meta=v;
    else if(k=="RAM_STATE_ROOT")c.ram_state_root=v;
    else if(k=="RAM_OVERLAY_ROOT")c.ram_overlay_root=v;
    else if(k=="STATE_ALLOWLIST")c.state_allowlist=v;
    else if(k=="RUNTIME_ALLOWLIST")c.runtime_allowlist=v;
    else if(k=="UI_REFRESH_SEC")c.ui_refresh=toi(v,c.ui_refresh);
    else if(k=="UI_PAGE_FILE")c.ui_page_file=v;
    else if(k=="UI_EVENT_LOG")c.ui_event_log=v;
    else if(k=="UI_PATHS_STAGE")c.ui_paths_stage=v;
    else if(k=="UI_PATHS_CURSOR")c.ui_paths_cursor=v;
    else if(k=="UI_BUTTONS")c.ui_buttons=toi(v,c.ui_buttons);
    else if(k=="UI_ADAFRUIT_FB")c.ui_fb=v;
    else if(k=="UI_ADAFRUIT_TTY")c.ui_tty=v;
    else if(k=="DHCP_ENABLED")c.dhcp_enabled=toi(v,c.dhcp_enabled);
    else if(k=="DHCP_CONF")c.dhcp_conf=v;
    else if(k=="DHCP_LEASES")c.dhcp_leases=v;
    else if(k=="DHCP_PID")c.dhcp_pid=v;
    else if(k=="DHCP_LEASE_SEC")c.dhcp_lease_sec=toi(v,c.dhcp_lease_sec);
    else if(k=="WAN_DHCP_ENABLED")c.wan_dhcp_enabled=toi(v,c.wan_dhcp_enabled);
    else if(k=="ADMIN_SSH_LAN"||k=="DEBUG_SSH_LAN")c.admin_ssh_lan=toi(v,c.admin_ssh_lan);
    else if(k=="WAN_DHCP_PID")c.wan_dhcp_pid=v;
    else if(k=="WAN_STATUS")c.wan_status=v;
    else if(k=="WAN_CHECK_HOST")c.wan_check_host=v;
    else if(k=="WAN_MONITOR_SEC")c.wan_monitor_sec=toi(v,c.wan_monitor_sec);
    else if(k=="PHONE_STATUS")c.phone_status=v;
    else if(k=="PHONE_PROBE_SEC")c.phone_probe_sec=toi(v,c.phone_probe_sec);
    else if(k=="FAKEIP_SEED")c.fake_seed=v;
    else if(k=="FAKEIP_CLIENT_BASE3")c.fake_client_base3=toi(v,c.fake_client_base3);
    else if(k=="FAKEIP_SERVER_BASE3")c.fake_server_base3=toi(v,c.fake_server_base3);
    else if(k=="FAKEIP_WIDTH")c.fake_width=toi(v,c.fake_width);
    else if(k=="FAKEIP_HOST_BASE")c.fake_host_base=toi(v,c.fake_host_base);
    else if(k=="USB_LABEL")c.usb_label=v;
    else if(k=="USB_MOUNT")c.usb_mount=v;
    else if(k=="USB_BUNDLE")c.usb_bundle=v;
    else if(k=="USB_FS")c.usb_fs=v;
    else if(k=="USB_FINGERPRINT_DIR")c.usb_fp_dir=v;
    else if(k=="USB_IMPORT_DIR")c.usb_import_dir=v;
    else if(k=="MAILBOX_RECORD_BYTES")c.mailbox_record_bytes=toi(v,c.mailbox_record_bytes);
    else if(k=="MAILBOX_MAX_PENDING")c.mailbox_max_pending=toi(v,c.mailbox_max_pending);
    else if(k=="MAILBOX_TTL_SEC")c.mailbox_ttl_sec=toi(v,c.mailbox_ttl_sec);
    else if(k=="TUNDUP_TORPORT_BASE")c.tundup_torport_base=toi(v,c.tundup_torport_base);
    else if(k=="MAX_CLIENTS")c.maxc=toi(v,c.maxc);
    else if(k=="MAX_SERVERS")c.maxs=toi(v,c.maxs);
    else if(k=="MAX_PEERS")c.maxp=toi(v,c.maxp);
    else {c.config_valid=false;if(c.config_error.empty())c.config_error="unknown setting "+k;}
}
static inline Cfg cfg(const char*p=getenv("VOIDER_CONFIG")?getenv("VOIDER_CONFIG"):"/etc/voider/voider.conf"){
    Cfg c;
    std::ifstream f(p);
    std::string l;
    std::set<std::string> seen;
    while(std::getline(f,l)){
        l=trim(l);
        if(l.empty()||l[0]=='#')continue;
        auto q=l.find('=');
        if(q==std::string::npos){c.config_valid=false;if(c.config_error.empty())c.config_error="invalid setting line";continue;}
        std::string key=trim(l.substr(0,q));
        if(key.empty()||!seen.insert(key).second){c.config_valid=false;if(c.config_error.empty())c.config_error="duplicate or empty setting "+key;continue;}
        setkv(c,key,trim(l.substr(q+1)));
    }
    if(!vta::valid(c.transports_available)){c.config_valid=false;c.config_error="invalid TRANSPORTS_AVAILABLE";c.transports_available.clear();}
    return c;
}
static inline std::vector<std::string> csv(std::string s){
    std::vector<std::string>v;
    std::stringstream ss(s);
    std::string x;
    while(std::getline(ss,x,',')){
        x=trim(x);
        if(!x.empty())v.push_back(x);
    }
    return v;
}
// First matching key wins. Preserve this for configuration and USB metadata;
// runtime status readers have different formats and duplicate-key semantics.
static inline std::string key_value(std::istream& input,const std::string& key){
    std::string line;
    while(std::getline(input,line)){
        auto at=line.find('=');
        if(at!=std::string::npos&&trim(line.substr(0,at))==key)return trim(line.substr(at+1));
    }
    return "";
}
static inline std::string val(const std::string& path,const std::string& key){
    std::ifstream input(path);
    return key_value(input,key);
}
static inline uint32_t fake_seed_value(const Cfg&c){
    std::ifstream f(c.fake_seed);
    uint32_t v=0;
    if(f>>v && v) return v;
    std::ifstream u("/dev/urandom", std::ios::binary);
    if(u.read((char*)&v,sizeof(v)) && v){
    }
    else v=(uint32_t)time(nullptr)^0xA5A55A5Au;
    std::error_code mkdir_error;
    std::filesystem::create_directories(
        std::filesystem::path(c.fake_seed).parent_path(),mkdir_error);
    std::ofstream o(c.fake_seed);
    o<<v<<"\n";
    return v;
}
static inline int fake_a(uint32_t seed) {
    static const int A[] = {
        2, 3, 5, 6, 7, 10, 12, 14, 15, 17, 19, 20, 21, 22, 24, 26,
        27, 28, 29, 30, 31, 33, 34, 35, 37, 38, 40, 41, 42, 43, 45, 46,
        47, 48, 50, 51, 52, 54, 55, 56, 57, 59, 60, 61, 62, 63, 65, 66,
        68, 69, 70, 71, 73, 74, 75, 76, 77, 78, 80, 82, 83, 84, 85, 87,
        88, 89, 90, 92, 94, 95, 96, 97, 98, 99, 101, 102, 103, 104, 105, 106,
        108, 109, 110, 111, 112, 113, 115, 116, 118, 119, 120, 121, 122, 123, 124, 125,
        127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 140, 141, 142, 143,
        144, 145, 146, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 160, 161,
        162, 163, 164, 165, 166, 167, 168, 169, 171, 172, 173, 174, 175, 176, 177, 178,
        179, 180, 181, 183, 184, 185, 186, 187, 188, 190, 191, 192, 193, 194, 195, 196,
        197, 199, 200, 201, 202, 203, 204, 205, 207, 208, 209, 210, 211, 213, 214, 215,
        216, 217, 218, 219, 220, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232,
        234, 235, 236, 237, 239, 240, 241, 242, 243, 244, 246, 247, 248, 249, 251, 252
    }
    ;
    return A[seed % (sizeof(A) / sizeof(A[0]))];
}
static inline int fake_perm_idx(const Cfg&c,int slot,const std::string&role){
    uint32_t s=fake_seed_value(c) ^ (role=="server"?0x9e3779b9u:0x51f15eedu);
    int a=fake_a(s);
    int b=(s/253u)%253;
    int n=slot-2;
    if(n<0)n=0;
    if(n>252)n=252;
    return (a*n+b)%253;
}
static inline int fake_inv_idx(const Cfg&c,int idx,const std::string&role){
    uint32_t s=fake_seed_value(c) ^ (role=="server"?0x9e3779b9u:0x51f15eedu);
    int a=fake_a(s),b=(s/253u)%253;
    int inv=1;
    for(int i=1;i<253;i++)if((a*i)%253==1){
        inv=i;
        break;
    }
    int n=(inv*((idx-b+253)%253))%253;
    return n+2;
}
static inline std::string fake_ip(const Cfg&c,const std::string&role,int slot){
    int idx=fake_perm_idx(c,slot,role);
    int base3=(role=="server")?c.fake_server_base3:c.fake_client_base3;
    int third=base3+(idx/c.fake_width);
    int fourth=c.fake_host_base+(idx%c.fake_width);
    return "172.16."+std::to_string(third)+"."+std::to_string(fourth);
}
static inline int slot_from_fake_ip(const Cfg&c,const std::string&role,const std::string&ip){
    unsigned a,b,d,e;
    if(sscanf(ip.c_str(),"%u.%u.%u.%u",&a,&b,&d,&e)!=4)return 0;
    if(a!=172||b!=16)return 0;
    int base3=(role=="server")?c.fake_server_base3:c.fake_client_base3;
    int idx=((int)d-base3)*c.fake_width+((int)e-c.fake_host_base);
    if(idx<0||idx>252)return 0;
    return fake_inv_idx(c,idx,role);
}
