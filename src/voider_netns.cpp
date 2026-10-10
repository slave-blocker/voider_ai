#include <iostream>
#include <cstdlib>
#include "voider_config.hpp"
#include "voider_util.hpp"

using vu::run;

static Cfg C;
static bool ok(int x){
    return x>=2&&x<=254;
}
static std::string X(int x){
    return std::to_string(x);
}
static std::string fc(int x){
    return fake_ip(C,"client",x);
}
static std::string fsrv(int x){
    return fake_ip(C,"server",x);
}
static std::string pconf(const std::string&role,int id){
    return (role=="client"?C.pc:C.ps)+"/"+std::to_string(id)+".conf";
}
static std::string ip_without_cidr(std::string s){
    auto p=s.find('/');
    if(p!=std::string::npos)s=s.substr(0,p);
    return trim(s);
}
static int ip4_last_octet(const std::string&ip,int fallback){
    unsigned a,b,c,d;
    if(sscanf(ip.c_str(),"%u.%u.%u.%u",&a,&b,&c,&d)==4&&d>=1&&d<=254)return (int)d;
    return fallback;
}
static std::string server_wg_ip(int x){
    // Imported-server slots keep the master addressing split:
    //   X selects the local namespace/dial slot.
    //   s comes from the imported WireGuard cert address 172.31.0.s.
    // The NAT/call-plane identity derived from s is 172.29.s.1, but that is
    // NOT the WireGuard interface address.
    std::string a=ip_without_cidr(val(pconf("server",x),"LOCAL_ADDR"));
    if(a.rfind("172.31.0.",0)==0)return a;
    a=ip_without_cidr(val(pconf("server",x),"ADDRESS"));
    if(a.rfind("172.31.0.",0)==0)return a;
    return "172.31.0."+std::to_string(x);
}
static std::string server_nat_identity(int x){
    int s=ip4_last_octet(server_wg_ip(x),x);
    return "172.29."+std::to_string(s)+".1";
}
static int server_wg_port(int x){
    int fallback=51820+x;
    int port=atoi(val(pconf("server",x),"PORT").c_str());
    return port>=1024&&port<=65535?port:fallback;
}
static void addnat(const std::string&r){
    run("iptables -w -t nat -C "+r+" 2>/dev/null || iptables -w -t nat -A "+r);
}
static void delnat(const std::string&r){
    run("while iptables -w -t nat -C "+r+" 2>/dev/null; do iptables -w -t nat -D "+r+"; done");
}
static void addrawns(const std::string&ns,const std::string&r){
    run("ip netns exec "+ns+" iptables -w -t raw -C "+r+" 2>/dev/null || "
        "ip netns exec "+ns+" iptables -w -t raw -I "+r);
}
static void delrawns(const std::string&ns,const std::string&r){
    run("while ip netns exec "+ns+" iptables -w -t raw -C "+r+" 2>/dev/null; do "
        "ip netns exec "+ns+" iptables -w -t raw -D "+r+"; done");
}
static void add_netns_sip_nfq(const std::string&ns,const std::string&match,int queue){
    std::string nfq=match+" -j NFQUEUE --queue-num "+std::to_string(queue);
    std::string ct=match+" -j CT --notrack";
    std::string old=match+" -j NOTRACK";
    delrawns(ns,nfq+" --queue-bypass");
    delrawns(ns,nfq);
    delrawns(ns,ct);
    delrawns(ns,old);
    addrawns(ns,nfq);
    addrawns(ns,old);
    addrawns(ns,ct);
}
static void add_netns_nat(const std::string&ns,const std::string&r){
    run("ip netns exec "+ns+" iptables -w -t nat -C "+r+" 2>/dev/null || "
        "ip netns exec "+ns+" iptables -w -t nat -A "+r);
}
static void del_netns_nat(const std::string&ns,const std::string&r){
    run("while ip netns exec "+ns+" iptables -w -t nat -C "+r+" 2>/dev/null; do "
        "ip netns exec "+ns+" iptables -w -t nat -D "+r+"; done");
}
static void ensure_server_wg0(){
    // Master-faithful server role: there is exactly one server WireGuard
    // interface in the default namespace. Client slots are peers behind wg0,
    // not per-slot server interfaces. Imported remote servers still use wgX
    // inside netnsX; this helper is only for clients-of-us/server mode.
    run("ip link add wg0 type wireguard 2>/dev/null || true");
    run("ip addr replace 172.31.0.1/24 dev wg0");
    run("ip link set wg0 up");
    // Remove legacy catch-all rules if this helper is re-run on an upgraded
    // appliance. The global firewall owns narrow call and ICMP proof rules.
    for(const auto& rule:{
        "INPUT -i wg0 -s 172.31.0.0/24 -j ACCEPT",
        "INPUT -i wg0 -s 172.29.0.0/16 -j ACCEPT",
        "FORWARD -i wg0 -j ACCEPT",
        "FORWARD -o wg0 -j ACCEPT"})
        run("while iptables -w -C "+std::string(rule)+
            " 2>/dev/null; do iptables -w -D "+rule+"; done");
}
static void client_nat(int x){
    std::string xS=X(x),fake=fc(x),real="172.29."+xS+".1",peer="172.31.0."+xS;
    if(fake.empty())return;
    // Server mode, master-faithful:
    //   one default-namespace wg0 = 172.31.0.1/24
    //   each client is a peer 172.31.0.X behind that same wg0
    //   phone-visible fake client IP maps to 172.29.X.1
    //   this server's call-plane identity is 172.29.1.1
    addnat("PREROUTING -i "+C.phone_if+" -s "+C.phone_ip+" -d "+fake+" -p udp ! --dport "+std::to_string(C.sip)+
    " -j DNAT --to-destination "+real);
    addnat("POSTROUTING -d "+real+" -p udp -j SNAT --to-source 172.29.1.1");
    // A direct-IP phone is allowed to wait for inbound RTP before it emits its
    // first media packet.  Do not depend on phone-originated conntrack state to
    // make that first packet deliverable: seed the same mapping from either
    // direction for WireGuard and Tor client paths.
    addnat("PREROUTING -i wg0 -s "+real+" -d 172.29.1.1 -p udp ! --sport "+std::to_string(C.sip)+
    " -j DNAT --to-destination "+C.phone_ip);
    addnat("PREROUTING -i tcs+ -s "+real+" -d 172.29.1.1 -p udp ! --sport "+std::to_string(C.sip)+
    " -j DNAT --to-destination "+C.phone_ip);
    addnat("POSTROUTING -o "+C.phone_if+" -s "+real+" -d "+C.phone_ip+" -p udp ! --sport "+
    std::to_string(C.sip)+" -j SNAT --to-source "+fake);
    run("ip route replace "+real+"/32 via "+peer+" dev wg0");
}
static void server_nat(int x){
    std::string xS=X(x),fake=fsrv(x),real="10."+xS+".1.1",bridge="172.30."+xS+".1";
    if(fake.empty())return;
    addnat("PREROUTING -i "+C.phone_if+" -s "+C.phone_ip+" -d "+fake+" -p udp ! --dport "+std::to_string(C.sip)+
    " -j DNAT --to-destination "+real);
    addnat("POSTROUTING -d "+real+" -p udp -j SNAT --to-source "+bridge);
    // netnsX returns inbound media as handoff -> bridge.  Translate it to the
    // phone explicitly so an answering phone that waits for inbound RTP does
    // not deadlock before the reverse conntrack entry exists.
    addnat("PREROUTING -i br"+xS+" -s "+real+" -d "+bridge+" -p udp ! --sport "+
    std::to_string(C.sip)+" -j DNAT --to-destination "+C.phone_ip);
    addnat("POSTROUTING -o "+C.phone_if+" -s "+real+" -d "+C.phone_ip+" -p udp ! --sport "+
    std::to_string(C.sip)+" -j SNAT --to-source "+fake);
    run("ip route replace "+real+"/32 via 172.30."+xS+".2");
}
static void client_up(int x){
    ensure_server_wg0();
    client_nat(x);
}
static void server_up(int x){
    std::string xS=X(x),ns="netns"+xS,br="br"+xS,va="veth"+xS+"a",vb="veth"+xS+"b",wg="wg"+xS;
    run("ip netns add "+ns+" 2>/dev/null || true");
    run("ip link add "+br+" type bridge 2>/dev/null || true");
    run("ip addr replace 172.30."+xS+".1/30 dev "+br);
    run("ip link set "+br+" up");
    run("ip link add "+va+" type veth peer name "+vb+" 2>/dev/null || true");
    run("ip link set "+va+" master "+br+" 2>/dev/null || true");
    run("ip link set "+va+" up");
    run("ip link set "+vb+" netns "+ns+" 2>/dev/null || true");
    run("ip -n "+ns+" addr replace 172.30."+xS+".2/30 dev "+vb);
    run("ip -n "+ns+" link set "+vb+" up");
    run("ip -n "+ns+" link set lo up");
    // CRITICAL: wgX is born in default namespace, then moved. WG UDP socket stays in default namespace.
    run("ip link add "+wg+" type wireguard 2>/dev/null || true");
    run("ip link set "+wg+" netns "+ns+" 2>/dev/null || true");
    std::string wgip=server_wg_ip(x);
    std::string natid=server_nat_identity(x);
    std::string wg_gateway="172.31.0.1";
    std::string remote="172.29.1.1";
    std::string handoff="10."+xS+".1.1";
    std::string bridge_ip="172.30."+xS+".1";
    run("ip -n "+ns+" addr replace "+wgip+"/24 dev "+wg);
    // An unconfigured WireGuard interface chooses an ephemeral UDP port. CAP2
    // advertises the slot's fixed PORT, so install it before either peer dials.
    run("ip netns exec "+ns+" wg set "+wg+" listen-port "+std::to_string(server_wg_port(x)));
    run("ip -n "+ns+" link set "+wg+" up");
    // Keep the master server-import addressing model:
    //   handoff 10.X.1.1 selects local netnsX from the phone side.
    //   wgX inside netnsX uses the imported cert address 172.31.0.s.
    //   NAT/call-plane identity is 172.29.s.1.
    //   remote server WireGuard gateway is 172.31.0.1.
    //   remote call target remains 172.29.1.1 via 172.31.0.1.
    // NFQUEUE replaces the old replay namespace for SIP. SIP is translated by
    // the per-netns voider-nfqd worker without conntrack. These NAT rules now
    // intentionally cover only non-SIP UDP/RTP/SRTP.
    run("ip netns exec "+ns+" sysctl -w net.ipv4.ip_forward=1 >/dev/null");
    run("ip -n "+ns+" route add default via 172.30."+xS+".1 2>/dev/null || true");
    run("ip -n "+ns+" route replace "+C.tor_netns_socks_ip+"/32 via 172.30."+xS+".1 dev "+vb+" 2>/dev/null || true");
    run("ip -n "+ns+" route replace "+remote+"/32 via "+wg_gateway+" dev "+wg);
    // SIP is deliberately not handled by conntrack NAT in netnsX. The raw
    // NOTRACK+NFQUEUE rules below rewrite SIP statelessly before routing.
    // Keep NAT only for non-SIP UDP/RTP/SRTP. Return media is sent back to
    // bridge_ip so default namespace conntrack can reverse fake-IP NAT.
    del_netns_nat(ns,"PREROUTING -i "+vb+" -d "+handoff+
        " -j DNAT --to-destination "+remote);
    del_netns_nat(ns,"POSTROUTING -o "+wg+" -d "+remote+
        " -j SNAT --to-source "+natid);
    del_netns_nat(ns,"PREROUTING -i "+wg+" -d "+natid+
        " -p udp -j DNAT --to-destination "+C.phone_ip);
    del_netns_nat(ns,"PREROUTING -i "+wg+" -d "+natid+
        " -p udp ! --sport "+std::to_string(C.sip)+" -j DNAT --to-destination "+C.phone_ip);
    del_netns_nat(ns,"PREROUTING -i tds+ -d "+natid+
        " -p udp ! --sport "+std::to_string(C.sip)+" -j DNAT --to-destination "+C.phone_ip);
    del_netns_nat(ns,"POSTROUTING -o "+vb+" -s "+remote+
        " -d "+C.phone_ip+" -p udp -j SNAT --to-source "+handoff);
    del_netns_nat(ns,"POSTROUTING -o "+vb+" -s "+remote+
        " -d "+C.phone_ip+" -p udp ! --sport "+std::to_string(C.sip)+
        " -j SNAT --to-source "+handoff);

    add_netns_nat(ns,"PREROUTING -i "+vb+" -d "+handoff+
        " -p udp ! --dport "+std::to_string(C.sip)+" -j DNAT --to-destination "+remote);
    add_netns_nat(ns,"POSTROUTING -o "+wg+" -d "+remote+
        " -p udp ! --dport "+std::to_string(C.sip)+" -j SNAT --to-source "+natid);
    add_netns_nat(ns,"PREROUTING -i "+wg+" -d "+natid+
        " -p udp ! --sport "+std::to_string(C.sip)+" -j DNAT --to-destination "+bridge_ip);
    add_netns_nat(ns,"POSTROUTING -o tds+ -d "+remote+
        " -p udp ! --dport "+std::to_string(C.sip)+" -j SNAT --to-source "+natid);
    add_netns_nat(ns,"PREROUTING -i tds+ -d "+natid+
        " -p udp ! --sport "+std::to_string(C.sip)+" -j DNAT --to-destination "+bridge_ip);
    add_netns_nat(ns,"POSTROUTING -o "+vb+" -s "+remote+
        " -d "+bridge_ip+" -p udp ! --sport "+std::to_string(C.sip)+
        " -j SNAT --to-source "+handoff);

    int q=1000+x;
    add_netns_sip_nfq(ns,"PREROUTING -i "+vb+" -s "+C.phone_ip+" -d "+handoff+
        " -p udp --dport "+std::to_string(C.sip),q);
    add_netns_sip_nfq(ns,"PREROUTING -i "+wg+" -s "+remote+" -d "+natid+
        " -p udp --sport "+std::to_string(C.sip),q);
    add_netns_sip_nfq(ns,"PREROUTING -i tds+ -s "+remote+" -d "+natid+
        " -p udp --sport "+std::to_string(C.sip),q);
    // peerd owns the translator process; this helper only prepares networking.
    run("ip netns exec "+ns+" sh -c 'for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > \"$f\"; done' 2>/dev/null || true");
    run("ip netns exec "+ns+" sh -c 'for f in /proc/sys/net/ipv4/conf/*/accept_local; do echo 1 > \"$f\"; done' 2>/dev/null || true");
    server_nat(x);
}
static void down(int x,const std::string&role=""){
    std::string xS=X(x);
    std::string c=fc(x),s=fsrv(x);
    if(role!="server"&&!c.empty()){
        delnat("PREROUTING -i "+C.phone_if+" -s "+C.phone_ip+" -d "+c+" -p udp ! --dport "+
        std::to_string(C.sip)+" -j DNAT --to-destination 172.29."+xS+".1");
        delnat("POSTROUTING -d 172.29."+xS+".1 -p udp -j SNAT --to-source 172.29.1.1");
        delnat("PREROUTING -i wg0 -s 172.29."+xS+".1 -d 172.29.1.1 -p udp ! --sport "+
        std::to_string(C.sip)+" -j DNAT --to-destination "+C.phone_ip);
        delnat("PREROUTING -i tcs+ -s 172.29."+xS+".1 -d 172.29.1.1 -p udp ! --sport "+
        std::to_string(C.sip)+" -j DNAT --to-destination "+C.phone_ip);
        delnat("POSTROUTING -o "+C.phone_if+" -s 172.29."+xS+".1 -d "+C.phone_ip+
        " -p udp ! --sport "+std::to_string(C.sip)+" -j SNAT --to-source "+c);
        run("ip route del 172.29."+xS+".1/32 via 172.31.0."+xS+" dev wg0 2>/dev/null || true");
    }
    if(role!="client"&&!s.empty()){
        delnat("PREROUTING -i "+C.phone_if+" -s "+C.phone_ip+" -d "+s+" -p udp ! --dport "+
        std::to_string(C.sip)+" -j DNAT --to-destination 10."+xS+".1.1");
        delnat("POSTROUTING -d 10."+xS+".1.1 -p udp -j SNAT --to-source 172.30."+xS+".1");
        delnat("PREROUTING -i br"+xS+" -s 10."+xS+".1.1 -d 172.30."+xS+
        ".1 -p udp ! --sport "+std::to_string(C.sip)+" -j DNAT --to-destination "+C.phone_ip);
        delnat("POSTROUTING -o "+C.phone_if+" -s 10."+xS+".1.1 -d "+C.phone_ip+
        " -p udp ! --sport "+std::to_string(C.sip)+" -j SNAT --to-source "+s);
        run("ip route del 10."+xS+".1.1/32 via 172.30."+xS+".2 2>/dev/null || true");
    }
    if(role=="client")return;
    run("ip link del wg"+xS+" 2>/dev/null || true");
    run("ip netns exec netns"+xS+" ip link del wg"+xS+" 2>/dev/null || true");
    run("ip netns del netns"+xS+" 2>/dev/null || true");
    run("ip link del br"+xS+" 2>/dev/null || true");
    run("ip link del veth"+xS+"a 2>/dev/null || true");
}
int main(int ac,char**av){
    C=cfg();
    if(ac<3)return 2;
    int x=atoi(av[2]);
    if(!ok(x))return 3;
    std::string c=av[1];
    if(c=="client-up")client_up(x);
    else if(c=="server-up")server_up(x);
    else if(c=="dialable"){
        if(ac>3&&std::string(av[3])=="client")client_up(x);
        else server_up(x);
    }
    else if(c=="client-down")down(x,"client");
    else if(c=="server-down")down(x,"server");
    else if(c=="down"||c=="undialable")down(x);
    else return 2;
    return 0;
}
