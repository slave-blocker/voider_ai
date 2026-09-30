// voider-ipv6-ready: conservative IPv6 underlay gate for CAP2.
//
// This helper does not make phone/SIP/RTP IPv6. voider keeps the inside of
// WireGuard IPv4. IPv6 here means only: the WAN underlay can carry the outer
// encrypted WireGuard UDP packet.

#include <array>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include "voider_config.hpp"
#include "voider_util.hpp"

#include "voider_wan_ipv6.hpp"

using vu::cap;

static Cfg C;

static bool okcmd(const std::string&cmd){
    return std::system((cmd+" >/dev/null 2>&1").c_str())==0;
}
static void wan_addresses(std::string&global,std::string&lan){
    std::string cmd="ip -6 -o addr show dev "+C.wan_if+
        " scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1";
    std::istringstream addresses(cap(cmd));
    std::string ip;
    while(std::getline(addresses,ip)){
        ip=trim(ip);
        if(global.empty()&&vwan6::global(ip))global=ip;
        if(lan.empty()&&!ip.empty()&&ip.find(':')!=std::string::npos&&
           ip.rfind("fe80",0)!=0&&ip.rfind("FE80",0)!=0)lan=ip;
    }
}
static bool route6(){
    return okcmd("ip -6 route show default dev "+C.wan_if+" | grep -q '^default '");
}
static bool ping6(){
    return okcmd("ping -6 -I "+C.wan_if+" -c1 -W2 2606:4700:4700::1111");
}
static bool ip6_nat(){
    return okcmd("ip6tables -w -t nat -L PREROUTING");
}
static bool redirect6_test(){
    // Shared wg0 HP6 needs IPv6 NAT REDIRECT from the negotiated public HP
    // port to fixed wg0:51820. Test add/delete with a high unused-looking port
    // and a comment so cleanup is exact and repeatable.
    int port=C.hp_port_max>1024?C.hp_port_max+1:61000;
    if(port>65534)port=61000;
    std::string p=std::to_string(port);
    std::string rule="PREROUTING -i "+C.wan_if+
        " -p udp --dport "+p+
        " -m comment --comment VOIDER-IPV6-READY-TEST -j REDIRECT --to-ports 51820";
    okcmd("while ip6tables -w -t nat -C "+rule+
        " 2>/dev/null; do ip6tables -w -t nat -D "+rule+"; done");
    bool added=okcmd("ip6tables -w -t nat -A "+rule);
    okcmd("while ip6tables -w -t nat -C "+rule+
        " 2>/dev/null; do ip6tables -w -t nat -D "+rule+"; done");
    return added;
}

int main(int ac,char**av){
    C=cfg();
    std::string role=ac>1?av[1]:"client";
    std::string addr,lan_addr;
    wan_addresses(addr,lan_addr);
    bool have_addr=!addr.empty();
    bool have_route=route6();
    bool have_ping=ping6();
    // For IPv6 the actual reachable endpoint should be the current global
    // address on WAN_IF. The public service is only an extra sanity signal;
    // never advertise a stale cached service result after prefix changes.
    std::string pub=addr;
    bool nat=ip6_nat();
    bool need_redirect=(role=="client"||role=="wg0"||role=="shared-wg0");
    bool redir=need_redirect?redirect6_test():true;

    bool base=have_addr&&have_route&&have_ping&&nat;
    bool direct6=base;
    bool hp6=base&&redir;

    std::cout<<"READY="<<(base?1:0)<<"\n";
    std::cout<<"DIRECT6="<<(direct6?1:0)<<"\n";
    std::cout<<"HP6="<<(hp6?1:0)<<"\n";
    std::cout<<"PUB6="<<(base?pub:"")<<"\n";
    std::cout<<"WAN6="<<addr<<"\n";
    std::cout<<"LAN6="<<lan_addr<<"\n";
    std::cout<<"ADDR6="<<(have_addr?"ok":"missing")<<"\n";
    std::cout<<"ROUTE6="<<(have_route?"ok":"missing")<<"\n";
    std::cout<<"PING6="<<(have_ping?"ok":"bad")<<"\n";
    std::cout<<"IP6TABLES_NAT="<<(nat?"ok":"bad")<<"\n";
    std::cout<<"REDIRECT6="<<(need_redirect?(redir?"ok":"bad"):"skip")<<"\n";
    std::cout<<"MODE=outer-ipv6-inner-ipv4\n";
    return base?0:1;
}
