// voider-selftest: non-destructive health checks.
//
// Hard invariants fail: fixed phone /30, four UI buttons, and BOOT/SYSTEM/STATE paths.
// Runtime dependencies and current state are warnings where the check may be
// run on a development machine instead of the final Alpine appliance.

#include <filesystem>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>
#include "voider_transport_allowlist.hpp"
#include "voider_util.hpp"

using vu::read_file;

namespace fs=std::filesystem;
static Cfg C;
static int fails=0,warns=0;
static void ok(const std::string& s){
    std::cout<<"OK   "<<s<<"\n";
}
static void warn(const std::string& s){
    warns++;
    std::cout<<"WARN "<<s<<"\n";
}
static void fail(const std::string& s){
    fails++;
    std::cout<<"FAIL "<<s<<"\n";
}
static void want(bool b,const std::string& s){
    b?ok(s):fail(s);
}
static void soft(bool b,const std::string& s){
    b?ok(s):warn(s);
}
static bool cmd(const std::string& c){
    return std::system(("command -v "+c+" >/dev/null 2>&1").c_str())==0;
}
static int config(){
    want(C.config_valid,"configuration contains only known, valid settings");
    want(C.phone_ip=="172.16.19.85","fixed phone IP 172.16.19.85");
    want(C.phone_gw=="172.16.19.86","fixed voider phone gateway 172.16.19.86");
    want(C.dhcp_start==C.phone_ip&&C.dhcp_end==C.phone_ip,"DHCP is one fixed lease");
    want(C.dhcp_enabled==1,"factory-reset phone receives the fixed lease automatically");
    want(C.dhcp_cidr==30&&C.dhcp_netmask=="255.255.255.252","phone side is /30");
    want(C.ui_buttons==4,"UI uses 4 physical buttons");
    want(C.boot_dev.size()&&C.system_dev.size()&&C.state_dev.size(),"BOOT/SYSTEM/STATE devices configured or AUTO");
    want(C.integrity_manifest.size(),"canonical integrity manifest path configured");
    want((C.admin_ssh_lan==0||C.admin_ssh_lan==1)&&C.admin_auth_keys.rfind(C.cert+"/",0)==0,
         "management SSH has a fail-closed boolean switch and curated public key");
    want(!C.tor_dot_dir.empty()&&!C.tor_dot_tmpfs_size.empty(),"Tor writable dot-state tmpfs path/size configured");
    want(C.state_allowlist.find(C.tor_hs_dir)!=std::string::npos&&C.state_allowlist.find(C.tor_dot_dir)==std::string::npos&&C.state_allowlist.find(C.sftp_base)==std::string::npos&&C.runtime_allowlist.find(C.sftp_base)!=std::string::npos,
         "STATE includes Tor identity while volatile Tor/SFTP runtime data stays in RAM");
    want(C.transports_available==vta::all()&&vta::valid(C.transports_available),
         "fresh configuration makes all seven transports available in fixed priority order");
    want(C.mailbox_record_bytes==4096&&C.mailbox_max_pending==8&&C.mailbox_ttl_sec==600,
         "CAP2 mailbox record count, size, and lifetime are bounded");
    return fails;
}
static int build(){
    for(auto f:{
        "Makefile","include/voider_config.hpp","include/voider_util.hpp","config/voider.conf"
    }
    )want(fs::exists(f),std::string("source file present: ")+f);
    for(auto f:{
        "src/voider_nfqd.cpp","src/voider_ui.cpp","src/voider_wan.cpp","src/voider_phone.cpp","src/voider_selftest.cpp","src/voider_ipv6_ready.cpp"
    }
    )want(fs::exists(f),std::string("source file present: ")+f);
    return fails;
}
static int deps(){
    for(auto c:{
        "ip","udhcpc","udhcpd","wg","tor","ssh-keygen","openssl","iptables","ip6tables","conntrack","nc"
    }
    )soft(cmd(c),std::string("runtime command visible: ")+c);
    soft(fs::exists("/sbin/openrc")||fs::exists("/sbin/rc-service"),"OpenRC visible");
    return fails;
}

static int appliance_model(){
    auto boot=read_file("src/voider_appliance_boot.cpp");
    auto install=read_file("src/voider_install.cpp");
    auto svc=read_file("openrc/voider-appliance");
    auto ui=read_file("src/voider_ui.cpp");
    auto wan=read_file("src/voider_wan.cpp");
    auto wan_svc=read_file("openrc/voider-wan");
    auto display_svc=read_file("openrc/voider-display");
    auto integrity=read_file("src/voider_integrity.cpp");
    auto usb=read_file("src/voider_usb.cpp");
    auto contacts=read_file("include/voider_contacts.hpp");
    auto mainctl=read_file("src/voider_main.cpp");
    auto buttons=read_file("scripts/pitft-bridge");
    auto sftp=read_file("src/voider_sftp_setup.cpp");
    auto ctl=read_file("src/voiderctl.cpp");
    want(install.find("rc-update add voider-appliance boot")!=std::string::npos&&
         install.find("rc-update del voider-appliance boot")==std::string::npos,
         "installer enables voider-appliance in OpenRC boot runlevel");
    want(svc.find("start()")!=std::string::npos&&svc.find("status()")!=std::string::npos&&
         svc.find("mkdir -p /run/voider")!=std::string::npos,
         "voider-appliance is an explicit OpenRC one-shot with a truthful status check");
    auto ready=boot.find("{\"appliance-ready\",\"READY");
    auto proof=boot.find("/usr/local/sbin/voider-integrity verify");
    want(ready!=std::string::npos&&proof!=std::string::npos&&proof<ready,
         "complete BOOT and SYSTEM verification blocks appliance-ready");
    want(boot.find("blockdev --setro")!=std::string::npos&&boot.find("Only safe power-off is permitted")!=std::string::npos&&
         boot.find("STATE=failure\\n")!=std::string::npos&&boot.find("FAILURE=")!=std::string::npos,
         "BOOT and SYSTEM become read-only early and every failure closes the appliance with UI status");
    want(integrity.find("VOIDER_INTEGRITY_1")!=std::string::npos&&integrity.find("BOOT_SHA256")!=std::string::npos&&
         integrity.find("SYSTEM_SHA256")!=std::string::npos&&integrity.find("COMBINED_SHA256")!=std::string::npos&&
         integrity.find("VOIDER-EXTERNAL-STATE-FINGERPRINT-V1")!=std::string::npos,
         "versioned manifest and external STATE fingerprint cover BOOT then SYSTEM");
    want(ui.find("FBIOGET_FSCREENINFO")!=std::string::npos&&
         ui.find("--display-probe")!=std::string::npos&&ui.find("static constexpr int W=320,H=240")!=std::string::npos&&
         ui.find("/proc/device-tree/hat/product")!=std::string::npos,
         "UI renders natively only when a physical panel HAT is present");
    want(display_svc.find("--display-probe")!=std::string::npos&&
         display_svc.find("/dev/tty")==std::string::npos,
         "display service refuses hardware without the supported panel and does not squeeze terminal output");
    want(wan.find("accept_ra\",\"2")!=std::string::npos&&wan_svc.find("need voider-appliance voider-firewall networking")!=std::string::npos,
         "WAN starts networking only after the integrity gate, then applies router-mode IPv6 RA handling");
    want(integrity.find("ensure_tor_runtime")!=std::string::npos && boot.find("normalize_live_tor")!=std::string::npos && svc.find("before tor")!=std::string::npos,
         "appliance boot puts volatile Tor runtime state in RAM before tor");
    want(integrity.find("INTEGRITY_SEAL_ERROR BOOT or SYSTEM not read-only")!=std::string::npos&&
         integrity.find("bo.find(\",ro,\")")!=std::string::npos&&
         install.find("rc-service chronyd stop")!=std::string::npos&&
         install.find("rc-service syslog stop")!=std::string::npos,
         "installer quiesces writers and refuses to hash a writable OS filesystem");
    want(integrity.find("normalize_identity_state")!=std::string::npos&&
         integrity.find("-exec chown ")!=std::string::npos&&
         integrity.find("-exec chmod 600")!=std::string::npos&&
         integrity.find("C.admin_auth_keys")!=std::string::npos,
         "STATE restore normalizes SFTP mailboxes and the root-owned admin public key");
    want(ui.find("enum class Action")!=std::string::npos&&ui.find("struct PageSpec")!=std::string::npos&&
         ui.find("--selftest")!=std::string::npos&&ui.find("--render-dir")!=std::string::npos&&
         ui.find("hold(\"ERASE\",Action::PairRun")!=std::string::npos,
         "UI labels and handlers share one page/action table with exhaustive and render test modes");
    want(ui.find("KDSETMODE")!=std::string::npos&&ui.find("KD_GRAPHICS")!=std::string::npos,
         "display owns the framebuffer console without a blinking text cursor");
    want(ui.find("--console-probe")!=std::string::npos&&ui.find("KDGETMODE")!=std::string::npos,
         "display console graphics mode has a hardware verification path");
    want(buttons.find("mkfifo -m 600")!=std::string::npos&&buttons.find("wait \"$gpiomon_pid\"")!=std::string::npos&&
         buttons.find("trap cleanup EXIT")!=std::string::npos,
         "button service retains a supervised parent and cleans up GPIO children");
    if(fs::exists("build/voider-ui"))
        want(std::system("./build/voider-ui --selftest >/tmp/voider-ui-selftest.log 2>&1")==0,
             "every UI page/button/short/long combination passes the pure state-machine test");
    if(fs::exists("build/voider-usb"))
        want(std::system("./build/voider-usb selftest >/tmp/voider-usb-selftest.log 2>&1")==0,
             "USB bundle, restore archive, and fingerprint replacement tests pass");
    want(usb.find("USB_AMBIGUOUS")!=std::string::npos&&usb.find("SYSTEM DISK")!=std::string::npos&&
         usb.find("confirmed_selection")!=std::string::npos&&usb.find("validate_bundle")!=std::string::npos&&
         usb.find("UsbMount mount(media,true)")!=std::string::npos&&usb.find("valid_state_archive")!=std::string::npos&&
         usb.find("set_conf_value(pconf(role,id),\"USB_FP\",bundle.fp)")!=std::string::npos&&
         mainctl.find("auto_usb")==std::string::npos,
         "USB erase requires unique safe media plus a bound confirmation; import is read-only and validated");
    want(contacts.find("return \"10.1.\"+std::to_string(slot)+\".1\"")!=std::string::npos&&
         contacts.find("return \"10.\"+std::to_string(slot)+\".1.1\"")!=std::string::npos&&
         contacts.find("x.name=connection_name(role,slot)")!=std::string::npos&&
         contacts.find("x.dial_ip=dial_ip(role,slot)")!=std::string::npos&&
         contacts.find("human_name")==std::string::npos&&usb.find("CONTACT_NAME")==std::string::npos,
         "display keeps neutral link labels and master 10/8 dial targets separate from inbound fake identities");
    want(install.find("if(!display)return install_fail(4,\"DISPLAY NOT DETECTED\")")!=std::string::npos&&
         install.find("rc-update add voider-display boot")!=std::string::npos&&
         read_file("Makefile").find("voider-paird")==std::string::npos&&
         read_file("scripts/stage-release-payload.sh").find("voider-paird")==std::string::npos,
         "installation requires the physical display and excludes the obsolete no-display service");
    want(install.find("valid_admin_public_key")!=std::string::npos&&
         install.find("/etc/voider/certs/admin_authorized_keys")!=std::string::npos&&
         install.find("configure_admin_switch(admin_enabled)")!=std::string::npos&&
         install.find("set_root_unknown_password")!=std::string::npos&&
         sftp.find("AuthenticationMethods publickey")!=std::string::npos&&
         sftp.find("AllowUsers root@10.0.0.0/8")!=std::string::npos&&
         sftp.find("AllowTcpForwarding no")!=std::string::npos&&
         ctl.find("is_regular_file(C.admin_auth_keys)")!=std::string::npos,
         "factory key becomes persistent private-LAN admin access with passwords and forwarding closed");
    want(mainctl.find("admin-key-new")!=std::string::npos&&mainctl.find("admin-key-revoke")!=std::string::npos&&
         mainctl.find("admin-ssh-enable")!=std::string::npos&&mainctl.find("admin-ssh-disable")!=std::string::npos&&
         mainctl.find("C.admin_ssh_lan=0")!=std::string::npos&&
         usb.find("/run/voider/admin-key-new")!=std::string::npos&&usb.find("/voider-admin")!=std::string::npos&&
         ui.find("DISABLE SSH?")!=std::string::npos&&ui.find("ENABLE SSH?")!=std::string::npos&&
         ui.find("Action::AdminRevokeRun")!=std::string::npos&&ui.find("Action::AdminNewRun")!=std::string::npos,
         "UI separately toggles management access, creates a USB login key, permanently revokes a key, and reset leaves SSH off");
    want(read_file("config/voider.conf").find("/etc/machine-id")!=std::string::npos&&
         read_file("include/voider_config.hpp").find("/etc/machine-id")!=std::string::npos,
         "factory-reset machine identity remains inside curated STATE");
    return fails;
}

static int tundup_model(){
    auto secure=read_file("src/tundup_v7_secure.c");
    auto sftp=read_file("src/voider_sftp_setup.cpp");
    auto usb=read_file("src/voider_usb.cpp");
    auto sync=read_file("src/voider_sync.cpp");
    auto install=read_file("src/voider_install.cpp");
    auto openrc_voider=read_file("openrc/voider");
    auto doc=read_file("README.md");
    want(secure.find("[TUN_NAME]")!=std::string::npos&&secure.find("tun_open(tun_name)")!=std::string::npos,
         "tundup-v7-secure supports explicit TUN_NAME");
    if(fs::exists("build/voider-cap2"))
        want(std::system("./build/voider-cap2 selftest >/tmp/voider-cap2-selftest.log 2>&1")==0,
             "CAP2 parser rejects malformed/stale records and correlates one offer with one answer");
    if(fs::exists("build/voider-sync"))
        want(std::system("./build/voider-sync selftest >/tmp/voider-sync-selftest.log 2>&1")==0,
             "CAP2 keeps a complete downloaded record when only late SFTP shutdown fails");
    if(fs::exists("build/voider-peerd"))
        want(std::system("./build/voider-peerd --selftest >/tmp/voider-lan-selftest.log 2>&1")==0,
             "LAN discovery authenticates challenges and CAP2 waits for independent local NTP readiness");
    if(fs::exists("build/tundup-security-test"))
        want(std::system("./build/tundup-security-test")==0,
             "tundup v8 authenticates plaintext frames before replay admission");
    want(sftp.find("Match Group \" + C.mailbox_group")!=std::string::npos&&
         sftp.find("ChrootDirectory %h")!=std::string::npos&&
         sftp.find("ForceCommand internal-sftp -d / -u 477 -p")!=std::string::npos&&
         sftp.find("AuthorizedKeysFile \" + C.mailbox_key_dir")!=std::string::npos&&
         sftp.find("chmod 711 \"+C.mailbox_key_dir")!=std::string::npos&&
         sftp.find("chmod 644 {}")!=std::string::npos&&
         sftp.find("MaxSessions 1")!=std::string::npos&&
         sftp.find("MaxStartups 8:30:16")!=std::string::npos&&
         sftp.find("PerSourceMaxStartups 8")!=std::string::npos,
         "SFTP uses one restricted internal-SFTP account, key file, and chroot per pairing");
    want(sftp.find("10-voider-security.conf")!=std::string::npos&&
         sftp.find("PasswordAuthentication no")!=std::string::npos&&
         sftp.find("KbdInteractiveAuthentication no")!=std::string::npos&&
         sftp.find("sshd -T | grep -qx 'passwordauthentication no'")!=std::string::npos&&
         sftp.find("Match all")!=std::string::npos,
         "installer enforces and validates global key-only SSH policy");
    want(sync.find("slot-put")==std::string::npos&&sync.find("slot-get")==std::string::npos&&
         sync.find("slot-read")==std::string::npos&&sync.find("/in/")!=std::string::npos&&
         sync.find("/out/")!=std::string::npos&&sync.find("rename ")!=std::string::npos,
         "CAP2 uses XID-scoped direction-separated atomic mailboxes with no legacy slot API");
    want(sync.find("ProxyCommand=")!=std::string::npos&&sync.find("nc -x ")!=std::string::npos&&
         sync.find("torsocks")==std::string::npos,
         "voider-sync uses the required OpenSSH/netcat SOCKS path without optional torsocks");
    want(sync.find("validated record survived late SFTP failure")!=std::string::npos&&
         read_file("src/voider_cap2.cpp").find("deferring confirmation to transport proof")!=std::string::npos,
         "CAP2 tolerates late SFTP exit only behind authenticated records and real transport proof");
    want(install.find("RESOLV_CONF=/run/resolv.conf")!=std::string::npos&&
         install.find("create_symlink(\"/run/resolv.conf\",\"/etc/resolv.conf\"")!=std::string::npos,
         "DHCP resolver state is RAM-backed under sealed SYSTEM");
    want(install.find("makestep 10 5")!=std::string::npos,
         "Chrony can correct an RTC-less boot after delayed DHCP/DNS, then returns to slew-only operation");
    want(read_file("openrc/chronyd").find("chown chrony:chrony /run/chrony")!=std::string::npos&&
         read_file("openrc/chronyd").find("chmod 0750 /run/chrony")!=std::string::npos,
         "Chrony receives its writable command-socket directory on every RAM-backed boot");
    auto chrony_service=read_file("openrc/chronyd");
    want(chrony_service.find("command=\"/usr/sbin/chronyd\"")!=std::string::npos&&
         chrony_service.find("supervise-daemon")==std::string::npos&&
         read_file("scripts/voider-tor").find("while ! timeout -k 2 5 chronyc -n waitsync 1 1 0 1")!=std::string::npos&&
         read_file("openrc/tor").find("voider-tor-netns-socks chronyd")!=std::string::npos,
         "Tor requires native Chrony startup and keeps retrying bounded clock-readiness checks");
    want(sftp.find("DataDirectory \"+C.tor_dot_dir")!=std::string::npos,
         "Tor uses its prepared writable data directory instead of the service user's inherited home");
    want(read_file("src/voider_peerd.cpp").find("waiting for local NTP synchronization")!=std::string::npos&&
         read_file("src/voider_peerd.cpp").find("Reference ID")!=std::string::npos&&
         read_file("src/voider_peerd.cpp").find("inspect NTP packet delay")!=std::string::npos,
         "Remote CAP2 waits only for this appliance's own selected, synchronized NTP source");
    want(usb.find("vmb::keys(C,\"client\",slot)")!=std::string::npos&&usb.find("restrict,no-port-forwarding")!=std::string::npos&&
         usb.find("bundle.fp.substr(0,12)+\"\\n\",0644)")!=std::string::npos,
         "USB export atomically binds exactly one peer key to its slot account");
    want(openrc_voider.find("need voider-appliance voider-firewall voider-wan voider-phone voider-nfqd")!=std::string::npos&&
         read_file("openrc/chronyd").find("need voider-appliance voider-firewall voider-wan")!=std::string::npos&&
         read_file("openrc/tor").find("need voider-appliance voider-firewall voider-wan")!=std::string::npos&&
         read_file("openrc/sshd").find("need voider-appliance voider-firewall")!=std::string::npos,
         "OpenRC owns providers behind the integrity gate and persistent firewall");
    want(usb.find("meta/server_wg0.pub")!=std::string::npos&&usb.find("WG_PEER_PUBLIC_KEY")!=std::string::npos,
         "USB imported-server config carries authoritative remote server wg0 public key");
    want(read_file("src/voider_ipv6_ready.cpp").find("while(std::getline(addresses,ip))")!=std::string::npos&&
         read_file("src/voider_ipv6_ready.cpp").find("LAN6=")!=std::string::npos,
         "IPv6 readiness scans past ULA addresses and reports a separate LAN6 endpoint");

    want(sftp.find("for(int p=7002;p<=7254;p++)")!=std::string::npos,
         "Tor hidden service exposes 253 inbound tundup ports, not 506");
    want(doc.find("Never derive s from X")!=std::string::npos,
         "X and the imported remote certificate slot remain separate documented identities");
    auto nfqd=read_file("src/voider_nfqd.cpp");
    auto netns=read_file("src/voider_netns.cpp");
    auto sipdoc=read_file("docs/NETNS_SIP_STATELESS_REWRITE.md");
    want(netns.find("server_wg_port")!=std::string::npos,
         "imported WireGuard listeners use and restore their advertised fixed port");
    want(nfqd.find("--netns-server")!=std::string::npos&&
         nfqd.find("netns_server_rewrite")!=std::string::npos,
         "netns imported-server SIP rewrite is implemented in NFQUEUE");
    want(nfqd.find("out = repl(out, natid, C.phone_ip);")==std::string::npos&&
         nfqd.find("SIP called identity must remain the logical")!=std::string::npos,
         "netns inbound preserves logical called identity in SIP payload while IP dst goes to phone");
 want(nfqd.find("ip->check = htons(csum(ip, ihl));")!=std::string::npos&&
 nfqd.find("udp->check = htons(udp4_checksum(ip, udp, pay, new_payload.size()));")!=std::string::npos,
 "NFQUEUE rebuilt IPv4/UDP SIP checksums are stored in network byte order");
    want(nfqd.find("out = repl(out, src, fake)")!=std::string::npos&&
         nfqd.find("server-side incoming SIP from 172.29.X.1")!=std::string::npos,
         "normalize_in rewrites real incoming SIP source occurrences to fake IP in payload");
    auto ctl=read_file("src/voiderctl.cpp");
    want(ctl.find("172.29.1.1 -p udp --sport")!=std::string::npos&&
         ctl.find("PHONE_IF must be off")!=std::string::npos,
         "phone_out rewritten SIP has FORWARD allow and PHONE_IF rp_filter disabled");
    want(ctl.find("--dport 10000:20000")!=std::string::npos&&
         ctl.find("-p udp ! --dport \"+sip+\" -j ACCEPT")==std::string::npos,
         "phone INPUT keeps a bounded media range instead of accepting every non-SIP UDP port");
    want(ctl.find("! --dport \"+sip+\" ! --sport \"+sip+\" -j ACCEPT")!=std::string::npos,
         "forwarded RTP follows SDP-selected UDP ports only across phone and call interfaces");
    want(netns.find("add_netns_sip_nfq")!=std::string::npos&&
         netns.find("! --dport")!=std::string::npos&&netns.find("! --sport")!=std::string::npos,
         "netns SIP is excluded from NAT and sent to raw NOTRACK NFQUEUE");
    want(netns.find("bridge_ip=\"172.30.\"+xS+\".1\"")!=std::string::npos&&
         netns.find("DNAT --to-destination \"+bridge_ip")!=std::string::npos&&
         netns.find("A direct-IP phone is allowed to wait for inbound RTP")!=std::string::npos&&
         netns.find("netnsX returns inbound media as handoff -> bridge")!=std::string::npos&&
         netns.find("PREROUTING -i br\"+xS")!=std::string::npos,
         "RTP/SRTP can seed phone translation from either direction without callee-first conntrack");
    want(sipdoc.find("not conntrack NAT")!=std::string::npos,
         "docs state imported-server SIP is stateless, not conntrack NAT");
    want(secure.find("sequence exhaustion")!=std::string::npos,
         "tundup fails closed on cryptographic failure and sequence exhaustion");
    return fails;
}

static int runtime(){
    soft(fs::exists("/run/voider"),"/run/voider exists");
    soft(fs::exists(C.wan_status),"WAN status file exists");
    soft(fs::exists(C.phone_status),"phone status file exists");
    soft(fs::exists(C.integrity_manifest),"STATE integrity manifest exists now");
    soft(fs::exists(C.state_tar),"deterministic STATE archive exists now");
    soft(fs::exists("/run/voider/integrity.status"),"integrity status file exists");
    if(fs::exists("/run/voider/integrity.status")){
        auto s=read_file("/run/voider/integrity.status");
        soft(s.find("STATE=calculating")!=std::string::npos||s.find("STATE=match")!=std::string::npos||s.find("STATE=failure")!=std::string::npos,
             "integrity status file has a supported state");
    }
    if(fs::exists("/proc/sys/net/ipv6/conf/"+C.wan_if+"/accept_ra"))
        soft(vu::read1("/proc/sys/net/ipv6/conf/"+C.wan_if+"/accept_ra")=="2",
             "WAN accepts IPv6 Router Advertisements while forwarding");
    if(fs::exists("/sys/class/graphics/fb0/name")){
        auto display=vu::cap("/usr/local/sbin/voider-ui --display-probe 2>/dev/null");
        auto name=vu::read1("/sys/class/graphics/fb0/name");
        bool physical=name.find("ili9340")!=std::string::npos||name.find("PITFT")!=std::string::npos;
        soft(physical?display.find("DISPLAY_FOUND")==0:display=="DISPLAY_NONE",
             "display service probe matches attached physical panel");
    }
    return fails;
}
int main(int ac,char**av){
    C=cfg();
    std::string mode=ac>1?av[1]:"all";
    bool source_tree=fs::exists("Makefile")&&fs::exists("src/voider_selftest.cpp")&&
                     fs::exists("docs/NETNS_SIP_STATELESS_REWRITE.md");
    if(mode=="all"){
        config();
        deps();
        runtime();
        if(source_tree){
            build();
            appliance_model();
            tundup_model();
        }else ok("source-model checks skipped on installed appliance");
    }else if(mode=="config")config();
    else if(mode=="build")build();
    else if(mode=="deps")deps();
    else if(mode=="runtime")runtime();
    else if(mode=="appliance")appliance_model();
    else if(mode=="tundup")tundup_model();
    else{
        std::cerr<<"usage: voider-selftest all|config|build|deps|runtime|appliance|tundup\n";
        return 2;
    }
    std::cout<<"SUMMARY fails="<<fails<<" warnings="<<warns<<"\n";
    return fails?1:0;
}
