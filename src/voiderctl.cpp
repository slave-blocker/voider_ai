#include <cstdlib>
#include <iostream>
#include "voider_config.hpp"
#include "voider_util.hpp"

using vu::run;

static Cfg C;

static bool close_policies(){
    int in4=run("iptables -w -P INPUT DROP");
    int fwd4=run("iptables -w -P FORWARD DROP");
    int in6=run("ip6tables -w -P INPUT DROP");
    int fwd6=run("ip6tables -w -P FORWARD DROP");
    return in4==0&&fwd4==0&&in6==0&&fwd6==0;
}

// ── Rule helpers ────────────────────────────────────────────────
// add()     = append (-A). Rules end up in code order (top→bottom).
// add_top() = insert (-I). Only for anti-lockout rules.
// add_raw() = insert (-I) into raw table. Needed for NOTRACK/NFQUEUE
//             ordering where last-inserted must be on top.

static void add(const std::string&t,const std::string&rule){
    run("iptables -w -t "+t+" -C "+rule+" 2>/dev/null || iptables -w -t "+t+" -A "+rule);
}

static void add_top(const std::string&t,const std::string&rule){
    run("iptables -w -t "+t+" -C "+rule+" 2>/dev/null || iptables -w -t "+t+" -I "+rule);
}

static bool add_raw(const std::string&rule){
    return run("iptables -w -t raw -C "+rule+" 2>/dev/null || iptables -w -t raw -I "+rule)==0;
}

static void del(const std::string&t,const std::string&rule){
    run("while iptables -w -t "+t+" -C "+rule+" 2>/dev/null; do iptables -w -t "+t+" -D "+rule+"; done");
}

static std::string phone_source_guard(){
    return "PREROUTING -i "+C.phone_if+" ! -s "+C.phone_ip+" -j DROP";
}
static std::string phone_dhcp_exception(){
    return "PREROUTING -i "+C.phone_if+
        " -s 0.0.0.0/32 -p udp --sport 68 --dport 67 -j ACCEPT";
}

static void allow_call_forward(const std::string& match){
    const std::string udp=match+" -p udp ";
    const std::string sip=std::to_string(C.sip);
    add("filter",udp+"--dport "+sip+" -j ACCEPT");
    add("filter",udp+"--sport "+sip+" -j ACCEPT");
    // RTP ports are selected by the two supported phones and advertised in
    // SDP; they are not confined to 10000:20000 (the GXP family commonly
    // uses 5004). Keep the OPSEC boundary narrow by allowing only non-SIP UDP
    // between the exact phone identity and Voider-owned call interfaces.
    add("filter",udp+"! --dport "+sip+" ! --sport "+sip+" -j ACCEPT");
}

// ── NOTRACK helpers (CT --notrack with legacy NOTRACK fallback) ──

static void add_notrack(const std::string&match){
 std::string ct=match+" -j CT --notrack";
 std::string old=match+" -j NOTRACK";
 // Install both rules independently. The previous OR-chain stopped after
 // the CT rule succeeded, so the legacy NOTRACK fallback was not actually
 // present on normal kernels. Ordering stays: CT/NOTRACK above NFQUEUE.
 run("iptables -w -t raw -C "+ct+" 2>/dev/null || "
 "iptables -w -t raw -I "+ct+" 2>/dev/null || true");
 run("iptables -w -t raw -C "+old+" 2>/dev/null || "
 "iptables -w -t raw -I "+old+" 2>/dev/null || true");
}

static void del_notrack(const std::string&match){
    del("raw",match+" -j CT --notrack");
    del("raw",match+" -j NOTRACK");
}

// ── SIP NFQUEUE helpers (raw PREROUTING, NOTRACK + NFQUEUE) ──

static bool add_sip_nfq(const std::string&match,int queue){
    std::string nfq=match+" -j NFQUEUE --queue-num "+std::to_string(queue);
    del_notrack(match);
    del("raw",nfq+" --queue-bypass");
    del("raw",nfq);
    if(!add_raw(nfq))return false;
    add_notrack(match);
    return true;
}

static void del_sip_nfq(const std::string&match,int queue){
    del("raw",match+" -j NFQUEUE --queue-num "+std::to_string(queue)+" --queue-bypass");
    del("raw",match+" -j NFQUEUE --queue-num "+std::to_string(queue));
    del_notrack(match);
}

// ── IPv6 firewall (ip6tables) ───────────────────────────────────

static void apply_ip6(){
    // The phone is an IPv4-only product link. Link-local IPv6 must not expose
    // transport listeners or become a route into a peer tunnel.
    run("ip6tables -w -P INPUT DROP");
    run("ip6tables -w -C INPUT -i lo -j ACCEPT 2>/dev/null || ip6tables -w -I INPUT -i lo -j ACCEPT");
    run("ip6tables -w -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || "
      "ip6tables -w -I INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT");
    run("ip6tables -w -C INPUT -i "+C.phone_if+" -j DROP 2>/dev/null || "
      "ip6tables -w -I INPUT 1 -i "+C.phone_if+" -j DROP");
    run("ip6tables -w -C INPUT -i "+C.wan_if+" -p udp --dport 51820:52074 -j ACCEPT 2>/dev/null || "
      "ip6tables -w -A INPUT -i "+C.wan_if+" -p udp --dport 51820:52074 -j ACCEPT");
    run("ip6tables -w -C INPUT -i "+C.wan_if+" -p udp --dport 45820 "
      "-m limit --limit 20/second --limit-burst 40 -j ACCEPT 2>/dev/null || "
      "ip6tables -w -A INPUT -i "+C.wan_if+" -p udp --dport 45820 "
      "-m limit --limit 20/second --limit-burst 40 -j ACCEPT");
    // Exclude discovery from the broad hole-punch range so its rate limit
    // cannot be bypassed by the following ACCEPT rules.
    for(const auto& range:{"20000:45819","45821:60999"})
        run("ip6tables -w -C INPUT -i "+C.wan_if+" -p udp --dport "+range+
          " -j ACCEPT 2>/dev/null || ip6tables -w -A INPUT -i "+C.wan_if+
          " -p udp --dport "+range+" -j ACCEPT");
    run("ip6tables -w -C INPUT -p icmpv6 -j ACCEPT 2>/dev/null || "
      "ip6tables -w -A INPUT -p icmpv6 -j ACCEPT");

    // FORWARD: no IPv6 phone path; the inner call plane is IPv4.
    run("ip6tables -w -P FORWARD DROP");
    run("ip6tables -w -C FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || "
      "ip6tables -w -I FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT");
    run("ip6tables -w -C FORWARD -i "+C.phone_if+" -j DROP 2>/dev/null || "
      "ip6tables -w -I FORWARD 1 -i "+C.phone_if+" -j DROP");
    run("ip6tables -w -C FORWARD -o "+C.phone_if+" -j DROP 2>/dev/null || "
      "ip6tables -w -I FORWARD 1 -o "+C.phone_if+" -j DROP");
    run("ip6tables -w -C FORWARD -i wg+ -j ACCEPT 2>/dev/null || "
      "ip6tables -w -A FORWARD -i wg+ -j ACCEPT");
    run("ip6tables -w -C FORWARD -o wg+ -j ACCEPT 2>/dev/null || "
      "ip6tables -w -A FORWARD -o wg+ -j ACCEPT");

    // OUTPUT: keep ACCEPT
    run("ip6tables -w -P OUTPUT ACCEPT");
}

static void clear_ip6(){
    run("ip6tables -w -P OUTPUT ACCEPT");
    run("ip6tables -w -F INPUT");
    run("ip6tables -w -F FORWARD");
    run("ip6tables -w -F OUTPUT");
    run("ip6tables -w -A INPUT -i lo -j ACCEPT");
    run("ip6tables -w -A INPUT -i "+C.wan_if+
      " -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT");
}

// ── Filter table hardening (IPv4) ───────────────────────────────

static void apply_filter(){
    std::string sip=std::to_string(C.sip);
    std::string pip=C.phone_ip;
    std::string pif=C.phone_if;
    std::string wif=C.wan_if;
    std::string brp=C.server_br_prefix;

    // ── Anti-lockout: -I (insert at top) BEFORE setting policy DROP ──
    // These two rules are always at the very top of INPUT.
    // If apply crashes later, existing sessions survive.
    add_top("filter","INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT");
    add_top("filter","INPUT -i lo -j ACCEPT");

    // ── INPUT chain: default DROP ──
    run("iptables -w -P INPUT DROP");

    // All rules below use -A (append) so chain order matches code order.

    // Installed administration is key-only and private-LAN-only. Both the
    // retained public key and the display-controlled switch must be present;
    // disabled and revoked appliances do not open port 22 on the WAN interface.
    if(C.admin_ssh_lan&&std::filesystem::is_regular_file(C.admin_auth_keys)){
        add("filter","INPUT -i "+wif+" -s 10.0.0.0/8 -p tcp --dport 22 -j ACCEPT");
        add("filter","INPUT -i "+wif+" -s 172.16.0.0/12 -p tcp --dport 22 -j ACCEPT");
        add("filter","INPUT -i "+wif+" -s 192.168.0.0/16 -p tcp --dport 22 -j ACCEPT");
    }
    // SSH: block public WAN and the dedicated phone link.
    add("filter","INPUT -i "+wif+" -p tcp --dport 22 -j DROP");
    add("filter","INPUT -i "+pif+" -p tcp --dport 22 -j DROP");

    // phone side: SIP, RTP range, DHCP, ICMP from known phone IP
    add("filter","INPUT -i "+pif+" -s "+pip+" -p udp --dport "+sip+" -j ACCEPT");
    add("filter","INPUT -i "+pif+" -s "+pip+" -p udp --dport 10000:20000 -j ACCEPT");
    add("filter","INPUT -i "+pif+" -p udp --sport 68 --dport 67 -j ACCEPT");
    add("filter","INPUT -i "+pif+" -s "+pip+" -d "+C.phone_gw+
        " -p icmp -j ACCEPT");

    // WAN side: DHCP client reply
    add("filter","INPUT -i "+wif+" -p udp --sport 67 --dport 68 -j ACCEPT");

    // Authenticated, offline LAN discovery. Invalid datagrams receive no reply.
    add("filter","INPUT -i "+wif+" -p udp --dport 45820 "
        "-m limit --limit 20/second --limit-burst 40 -j ACCEPT");

    // WAN side: WireGuard listen ports for initial handshake (254 slots)
    add("filter","INPUT -i "+wif+" -p udp --dport 51820:52074 -j ACCEPT");

    // WAN side: holepunch UDP, excluding rate-limited discovery port 45820.
    add("filter","INPUT -i "+wif+" -p udp --dport 20000:45819 -j ACCEPT");
    add("filter","INPUT -i "+wif+" -p udp --dport 45821:60999 -j ACCEPT");

    // tunnel/bridge interfaces: allow SIP
    for(auto&i:csv(C.client_ifs)){
        add("filter","INPUT -i "+i+" -p udp --dport "+sip+" -j ACCEPT");
        add("filter","INPUT -i "+i+" -p udp --sport "+sip+" -j ACCEPT");
    }
    // wg+ wildcard: all per-slot wgN interfaces (wg2..wg254)
    add("filter","INPUT -i wg+ -p udp --dport "+sip+" -j ACCEPT");
    add("filter","INPUT -i wg+ -p udp --sport "+sip+" -j ACCEPT");
    add("filter","INPUT -i wg0 -s 172.31.0.0/24 -d 172.31.0.1/32 -p icmp -j ACCEPT");
    // fix40: Tor/tundup fallback proof is ICMP over tcsX/tdsX.  The server-side
    // clients-of-us endpoint is tcsX in the default namespace, so allow proof
    // echo request/reply locally instead of relying on broad OUTPUT/INPUT policy.
    add("filter","INPUT -i tcs+ -p icmp -j ACCEPT");
    add("filter","OUTPUT -o tcs+ -p icmp -j ACCEPT");
    add("filter","INPUT -i "+brp+"+ -p udp --dport "+sip+" -j ACCEPT");
    add("filter","INPUT -i "+brp+"+ -p udp --sport "+sip+" -j ACCEPT");
    // Imported-server fallback: netnsX tundup reaches default Tor SOCKS via brX -> 172.30.X.1:19050.
    add("filter","INPUT -i "+brp+"+ -s 172.30.0.0/16 -d "+C.tor_netns_socks_ip+
        "/32 -p tcp --dport "+std::to_string(C.tor_netns_socks_port)+" -j ACCEPT");

    // log anything that reaches here (about to be policy-DROPped)
    add("filter","INPUT -m limit --limit 5/min -j LOG --log-prefix \"VOIDER-INPUT-DROP \"");

    // ── FORWARD chain: default DROP ──
    run("iptables -w -P FORWARD DROP");

    // established/related forwarded traffic (append, but should be first real rule)
    add("filter","FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT");

    // Phone-originated traffic is limited to SIP and media UDP. The raw
    // PREROUTING source guard runs before SIP can be rewritten to 172.29.1.1.
    for(auto&i:csv(C.client_ifs)){
        allow_call_forward("FORWARD -i "+pif+" -o "+i+" -s "+pip);
    }
    allow_call_forward("FORWARD -i "+pif+" -o wg+ -s "+pip);
    allow_call_forward("FORWARD -i "+pif+" -o "+brp+"+ -s "+pip);

    // phone_out SIP is rewritten by raw PREROUTING before FORWARD. After
    // queue 12, server-side clients-of-us packets no longer have source
    // PHONE_IP; they are 172.29.1.1 -> 172.29.X.1. Allow both request and
    // response shapes on tunnel interfaces so ACK/200/BYE survive default DROP.
    for(auto&i:csv(C.client_ifs)){
        add("filter","FORWARD -i "+pif+" -o "+i+" -s 172.29.1.1 -p udp --dport "+sip+" -j ACCEPT");
        add("filter","FORWARD -i "+pif+" -o "+i+" -s 172.29.1.1 -p udp --sport "+sip+" -j ACCEPT");
    }
    add("filter","FORWARD -i "+pif+" -o wg+ -s 172.29.1.1 -p udp --dport "+sip+" -j ACCEPT");
    add("filter","FORWARD -i "+pif+" -o wg+ -s 172.29.1.1 -p udp --sport "+sip+" -j ACCEPT");

    // tunnel/bridge -> phone (inbound media/SIP to phone)
    for(auto&i:csv(C.client_ifs)){
        allow_call_forward("FORWARD -i "+i+" -o "+pif+" -d "+pip);
    }
    allow_call_forward("FORWARD -i wg+ -o "+pif+" -d "+pip);
    allow_call_forward("FORWARD -i "+brp+"+ -o "+pif+" -d "+pip);

    // bridge <-> tunnel internal forwarding
    for(auto&i:csv(C.client_ifs)){
        add("filter","FORWARD -i "+brp+"+ -o "+i+" -j ACCEPT");
        add("filter","FORWARD -i "+i+" -o "+brp+"+ -j ACCEPT");
    }
    add("filter","FORWARD -i "+brp+"+ -o wg+ -j ACCEPT");
    add("filter","FORWARD -i wg+ -o "+brp+"+ -j ACCEPT");

    // log anything about to be policy-DROPped in FORWARD
    add("filter","FORWARD -m limit --limit 5/min -j LOG --log-prefix \"VOIDER-FWD-DROP \"");

    // ── OUTPUT chain: keep ACCEPT, log unexpected WAN egress ──
    run("iptables -w -P OUTPUT ACCEPT");
    add("filter","OUTPUT -o "+wif+" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT");
    add("filter","OUTPUT -o "+wif+" -p udp --dport 67 -j ACCEPT");
    add("filter","OUTPUT -o "+wif+" -p udp --dport 53 -j ACCEPT");
    add("filter","OUTPUT -o "+wif+" -p tcp --dport 443 -j ACCEPT");
    add("filter","OUTPUT -o "+wif+" -p tcp --dport 80 -j ACCEPT");
    add("filter","OUTPUT -o "+wif+" -p udp -j ACCEPT");
    add("filter","OUTPUT -o "+wif+" -m limit --limit 5/min -j LOG --log-prefix \"VOIDER-WAN-OUT \"");

    // ── IPv6 firewall ──
    apply_ip6();
}

static bool clear_filter(){
    // Keep new ingress and forwarding closed even while Voider is stopped or
    // rules are being rebuilt. Existing uplink management sessions may finish.
    if(!close_policies())return false;
    run("iptables -w -P OUTPUT ACCEPT");
    run("iptables -w -F INPUT");
    run("iptables -w -F FORWARD");
    run("iptables -w -F OUTPUT");
    run("iptables -w -A INPUT -i lo -j ACCEPT");
    run("iptables -w -A INPUT -i "+C.wan_if+
      " -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT");
    clear_ip6();
    return true;
}

// ── SIP NFQUEUE rules (raw PREROUTING, unchanged logic) ─────────
// Phone-out queues both request-shaped packets (dport 5060) and
// response-shaped packets (sport 5060). Real SIP phones send 100/180/200/BYE
// from source port 5060 back to the caller's ephemeral port.

static bool apply(){
    if(!close_policies())return false;
    if(!add_raw(phone_source_guard()))return false;
    if(!add_raw(phone_dhcp_exception()))return false;
    if(!add_sip_nfq("PREROUTING -i "+C.phone_if+" -s "+C.phone_ip+" -p udp --dport "+std::to_string(C.sip),C.qp))return false;
    if(!add_sip_nfq("PREROUTING -i "+C.phone_if+" -s "+C.phone_ip+" -p udp --sport "+std::to_string(C.sip),C.qp))return false;
    for(auto&i:csv(C.client_ifs)){
        if(!add_sip_nfq("PREROUTING -i "+i+" -p udp --dport "+std::to_string(C.sip),C.qc))return false;
        if(!add_sip_nfq("PREROUTING -i "+i+" -p udp --sport "+std::to_string(C.sip),C.qc))return false;
    }
    apply_filter();
 // No raw NFQUEUE on br+: imported-server SIP is already rewritten inside netnsX.
 // Keep br+ only in filter/FORWARD allow rules for routing between netnsX and phone.
    return true;
}

static bool clear(){
    if(!clear_filter())return false;
    del_sip_nfq("PREROUTING -i "+C.phone_if+" -s "+C.phone_ip+" -p udp --dport "+std::to_string(C.sip),C.qp);
    del_sip_nfq("PREROUTING -i "+C.phone_if+" -s "+C.phone_ip+" -p udp --sport "+std::to_string(C.sip),C.qp);
    for(auto&i:csv(C.client_ifs)){
        del_sip_nfq("PREROUTING -i "+i+" -p udp --dport "+std::to_string(C.sip),C.qc);
        del_sip_nfq("PREROUTING -i "+i+" -p udp --sport "+std::to_string(C.sip),C.qc);
    }
 // br+ raw NFQUEUE is intentionally not installed, so there is nothing to delete.
    del("raw",phone_dhcp_exception());
    del("raw",phone_source_guard());
    return true;
}

// Update management admission only. No call-plane rules, queues, routes, or
// transport listeners are flushed when the display toggles SSH.
static bool admin_rules(){
    std::string blocked="INPUT -i "+C.wan_if+" -p tcp --dport 22 -m conntrack --ctstate NEW -j DROP";
    if(run("iptables -w -t filter -C "+blocked+" 2>/dev/null || iptables -w -t filter -I "+blocked))return false;
    for(const auto* subnet:{"10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"})
        del("filter","INPUT -i "+C.wan_if+" -s "+subnet+" -p tcp --dport 22 -j ACCEPT");
    if(C.admin_ssh_lan&&std::filesystem::is_regular_file(C.admin_auth_keys))
        for(const auto* subnet:{"10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"}){
            std::string rule="INPUT -i "+C.wan_if+" -s "+subnet+" -p tcp --dport 22 -j ACCEPT";
            if(run("iptables -w -t filter -I "+rule))return false;
        }
    return true;
}

int main(int ac,char**av){
    C=cfg();
    if(ac<2)return 2;
    std::string a=av[1];
    if(a=="rules"){
        std::string b=ac>2?av[2]:"apply";
        if(b=="admin")return admin_rules()?0:1;
        if(b=="clear")return clear()?0:1;
        else if(b=="reload"){
            if(!clear())return 1;
            return apply()?0:1;
        }
        return apply()?0:1;
    }
    if(a=="sysctl"){
        // ── IPv4 forwarding ──
        run("echo 1 >/proc/sys/net/ipv4/ip_forward");

        // ── IPv6 forwarding (needed for IPv6 holepunch/direct) ──
        run("echo 1 >/proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || true");

        // ── rp_filter: WAN may stay strict, but PHONE_IF must be off. ──
        // queue 12 rewrites phone-originated SIP in raw PREROUTING, e.g.
        // eth1 packet source 172.16.19.85 becomes 172.29.1.1 before routing
        // to wg0/tcsX. Strict rp_filter on eth1 can drop this rewritten source
        // before FORWARD. Keep reverse-path filtering disabled on local/tunnel
        // call-plane interfaces.
        run("echo 0 >/proc/sys/net/ipv4/conf/"+C.phone_if+"/rp_filter");
        run("echo 1 >/proc/sys/net/ipv4/conf/"+C.wan_if+"/rp_filter");
        run("echo 0 >/proc/sys/net/ipv4/conf/default/rp_filter");
        run("echo 0 >/proc/sys/net/ipv4/conf/all/rp_filter");
        run("for f in /proc/sys/net/ipv4/conf/wg*/rp_filter /proc/sys/net/ipv4/conf/tcs*/rp_filter /proc/sys/net/ipv4/conf/"+C.server_br_prefix+"*/rp_filter; do [ -e \"$f\" ] && echo 0 >\"$f\"; done");

        // ── accept_local: only where voider fake-IP trick needs it ──
        run("echo 0 >/proc/sys/net/ipv4/conf/"+C.wan_if+"/accept_local");
        run("echo 1 >/proc/sys/net/ipv4/conf/"+C.phone_if+"/accept_local");
        run("echo 1 >/proc/sys/net/ipv4/conf/default/accept_local");
        run("for f in /proc/sys/net/ipv4/conf/"+C.server_br_prefix+"*/accept_local; do echo 1 >\"$f\"; done");
        // fix40: server-side Tor/tundup proof uses tcsX as a local TUN endpoint.
        // Keep accept_local enabled on tcs*/wg* so the fallback proof reply path
        // survives hardened default-namespace sysctl state after reboot/rules reload.
        run("for f in /proc/sys/net/ipv4/conf/tcs*/accept_local /proc/sys/net/ipv4/conf/wg*/accept_local; do [ -e \"$f\" ] && echo 1 >\"$f\"; done");

        // ── Disable conntrack SIP helper (conflicts with voider SIP rewrite) ──
        run("echo 0 >/proc/sys/net/netfilter/nf_conntrack_helper 2>/dev/null || true");
        run("modprobe -r nf_conntrack_sip 2>/dev/null || true");

        // ── Blacklist SIP helper so it never loads again ──
        run("echo 'blacklist nf_conntrack_sip' > /etc/modprobe.d/voider-no-sip-helper.conf 2>/dev/null || true");

        return 0;
    }
    return 2;
}
