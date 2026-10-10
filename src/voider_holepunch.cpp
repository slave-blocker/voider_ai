#include <unistd.h>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iostream>
#include <thread>
#include <chrono>
#include <cstring>
#include <cerrno>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "voider_config.hpp"
#include "voider_runtime.hpp"
#include "voider_util.hpp"

#include "voider_wan_ipv6.hpp"

using vu::cap;
using vu::read1;
using vu::run;
static Cfg C;
static bool is6(const std::string&fam){
    return fam=="6"||fam=="ipv6";
}
static bool port_free(int p){
    return system(("ss -H -lun sport = :"+std::to_string(p)+" 2>/dev/null | grep -q .").c_str())!=0;
}
static std::string local_public(const std::string&fam){
    // The WAN monitor owns public-address refresh. Rendezvous must not block
    // its critical path on an external address-discovery service.
    return is6(fam)?vwan6::current(C,true):read1(C.pubip_file);
}
static std::string pconf(const std::string&role,const std::string&id){
    return (role=="client"?C.pc:C.ps)+"/"+id+".conf";
}
static int stable_hp_port(const std::string&role,const std::string&id){
    int slot=atoi(id.c_str());
    if(role=="client")return 20000+slot;
    std::string p=val(pconf(role,id),"PORT");
    if(!p.empty())return atoi(p.c_str());
    return 51820+slot;
}

static int fixed_wg0_port(){
    // Master-faithful server mode: wg0 is the one shared server listener.
    // It must not be moved per-client during holepunch. The exported-client
    // per-slot PORT field used to drift; force the real shared listener here.
    return 51820;
}
static std::string local_route_source(const std::string&peer_ip){
    // The public IP is advertised to the peer through SFTP rendezvous.
    // Local Linux conntrack normally sees the source address selected by the
    // route to the peer. On IPv4 behind a retail router this is usually the
    // eth0 LAN address, not the router's public address.
    std::string tool=peer_ip.find(':')==std::string::npos?"ip route get":"ip -6 route get";
    std::string cmd=tool+" "+peer_ip+
        " 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i==\"src\") {print $(i+1); exit}}'";
    return cap(cmd);
}
static void conntrack_del(const std::string&lip,const std::string&pip,int lp,const std::string&pp){
    if(lip.empty()||pip.empty()||pp.empty())return;
    std::string l=std::to_string(lp);
    run("conntrack -D -p udp --orig-src "+lip+" --orig-dst "+pip+" --orig-port-src "+l+" --orig-port-dst "+pp+
    " 2>/dev/null || true");
    run("conntrack -D -p udp --reply-src "+pip+" --reply-dst "+lip+" --reply-port-src "+pp+" --reply-port-dst "+
    l+" 2>/dev/null || true");
}

static bool is_imported_server_wgx(const std::string&role){ return role=="server"; }
static const char* fam_name(const std::string&fam){ return is6(fam)?"hp6":"hp4"; }

static void wg_endpoint(const std::string&role,const std::string&id,const std::string&peer,
    const std::string&fam,const std::string&ip,const std::string&port);
static void send_udp_probe_burst(const std::string&fam,int local_port,const std::string&peer_ip,const std::string&peer_port){
    if(local_port<=0||peer_ip.empty()||peer_port.empty())return;
    int af=is6(fam)?AF_INET6:AF_INET;
    int fd=socket(af,SOCK_DGRAM,0);
    if(fd<0){ std::cerr<<fam_name(fam)<<" probe socket failed: "<<strerror(errno)<<"\n"; return; }
    int one=1;
    setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
#ifdef SO_REUSEPORT
    setsockopt(fd,SOL_SOCKET,SO_REUSEPORT,&one,sizeof(one));
#endif
    if(af==AF_INET6){
        sockaddr_in6 a{}; a.sin6_family=AF_INET6; a.sin6_port=htons((uint16_t)local_port); a.sin6_addr=in6addr_any;
        if(bind(fd,(sockaddr*)&a,sizeof(a))<0){ std::cerr<<"hp6 probe bind :"<<local_port<<" failed: "<<strerror(errno)<<"\n"; close(fd); return; }
    }else{
        sockaddr_in a{}; a.sin_family=AF_INET; a.sin_port=htons((uint16_t)local_port); a.sin_addr.s_addr=htonl(INADDR_ANY);
        if(bind(fd,(sockaddr*)&a,sizeof(a))<0){ std::cerr<<"hp4 probe bind :"<<local_port<<" failed: "<<strerror(errno)<<"\n"; close(fd); return; }
    }
    addrinfo hints{}; hints.ai_family=af; hints.ai_socktype=SOCK_DGRAM; hints.ai_flags=AI_NUMERICHOST|AI_NUMERICSERV;
    addrinfo*res=nullptr; int gai=getaddrinfo(peer_ip.c_str(),peer_port.c_str(),&hints,&res);
    if(gai||!res){ std::cerr<<fam_name(fam)<<" probe bad peer "<<peer_ip<<":"<<peer_port<<" "<<gai_strerror(gai)<<"\n"; close(fd); return; }
    int packets=C.hp_burst_packets>0?C.hp_burst_packets:3;
    int interval=C.hp_burst_interval_ms>0?C.hp_burst_interval_ms:60;
    const char msg[]="Monero";
    for(int i=0;i<packets;i++){
        ssize_t n=sendto(fd,msg,sizeof(msg)-1,0,res->ai_addr,res->ai_addrlen);
        if(n<0)std::cerr<<fam_name(fam)<<" probe send failed: "<<strerror(errno)<<"\n";
        std::this_thread::sleep_for(std::chrono::milliseconds(interval));
    }
    freeaddrinfo(res); close(fd);
}
static void punch_round_imported_server_wgx(const std::string&role,const std::string&id,const std::string&fam,const std::string&peerkey,const std::string&peer_ip,const std::string&peer_port,int wg_port,const std::string&ct_src){
    conntrack_del(ct_src,peer_ip,wg_port,peer_port);
    wg_endpoint(role,id,peerkey,fam,peer_ip,peer_port);
    conntrack_del(ct_src,peer_ip,wg_port,peer_port);
}
static void punch_round_shared_server_wg0(const std::string&role,const std::string&id,const std::string&fam,const std::string&peerkey,const std::string&peer_ip,const std::string&peer_port,int hp_port,int wg_port,const std::string&ct_src){
    conntrack_del(ct_src,peer_ip,wg_port,peer_port);
    conntrack_del(ct_src,peer_ip,hp_port,peer_port);
    wg_endpoint(role,id,peerkey,fam,peer_ip,peer_port);
    send_udp_probe_burst(fam,hp_port,peer_ip,peer_port);
    conntrack_del(ct_src,peer_ip,hp_port,peer_port);
}

static std::string redirect_state_file(const std::string&role,const std::string&id){
 return C.pstate+"/"+role+"-"+id+".wg0_redirect";
}
static void del_wg0_redirect(const std::string&fam,int hp_port,int wg_port){
 // Delete every matching copy, not just one. This mirrors the idempotent
 // cleanup style used by voider-netns for NAT rules.
 std::string hp=std::to_string(hp_port),wg=std::to_string(wg_port);
 std::string tool=is6(fam)?"ip6tables":"iptables";
 run("while "+tool+" -w -t nat -C PREROUTING -i "+C.wan_if+
 " -p udp --dport "+hp+" -j REDIRECT --to-ports "+wg+
 " 2>/dev/null; do "+tool+" -w -t nat -D PREROUTING -i "+C.wan_if+
 " -p udp --dport "+hp+" -j REDIRECT --to-ports "+wg+"; done");
}
static void cleanup_wg0_redirect(const std::string&role,const std::string&id){
 // Only clients-of-us use shared wg0 REDIRECT. Imported-server wgX HP owns the
 // random listen port directly and has no REDIRECT to clean.
 if(role=="server")return;
 std::ifstream f(redirect_state_file(role,id));
 std::string fam;
 int hp_port=0,wg_port=0;
 if(f>>fam>>hp_port>>wg_port){
 del_wg0_redirect(fam,hp_port,wg_port);
 }
 run("rm -f "+redirect_state_file(role,id)+" 2>/dev/null || true");
}
static void add_wg0_redirect(const std::string&role,const std::string&id,const std::string&fam,int hp_port,int wg_port){
 // Shared wg0 server mode only: keep wg0 fixed and redirect the temporary
 // public holepunch port to the fixed local wg0 listener. Keep the rule for
 // the lifetime of the selected HP connection so REDIRECT conntrack can
 // reverse-translate wg0 replies back to the public HP port.
 cleanup_wg0_redirect(role,id);
 std::string hp=std::to_string(hp_port),wg=std::to_string(wg_port);
 std::string tool=is6(fam)?"ip6tables":"iptables";
 run(tool+" -w -t nat -C PREROUTING -i "+C.wan_if+
 " -p udp --dport "+hp+" -j REDIRECT --to-ports "+wg+
 " 2>/dev/null || "+tool+" -w -t nat -A PREROUTING -i "+C.wan_if+
 " -p udp --dport "+hp+" -j REDIRECT --to-ports "+wg+" 2>/dev/null || true");
 run("mkdir -p "+C.pstate);
 std::ofstream(redirect_state_file(role,id))<<fam<<" "<<hp_port<<" "<<wg_port<<"\n";
}
static void wg_listen(const std::string&role,const std::string&id,int p){
    std::string wg="wg"+id,ns="netns"+id;
    if(role=="server"){
        // Imported-server slot: wgX is per-slot, so the WG socket may own the
        // negotiated random punch port directly. No redirect is needed.
        run("ip netns exec "+ns+" wg set "+wg+" listen-port "+std::to_string(p)+" 2>/dev/null || true");
        return;
    }
    // Clients-of-us/server mode: wg0 is shared by all clients and must stay on
    // the fixed listener. Random HP ports are redirected to this fixed port.
    run("wg set wg0 listen-port "+std::to_string(fixed_wg0_port())+" 2>/dev/null || true");
}
static void wg_endpoint(const std::string&role,const std::string&id,const std::string&peer,
const std::string&fam,const std::string&ip,const std::string&port){
    std::string ep=is6(fam)?"["+ip+"]:"+port:ip+":"+port;
    std::string wg="wg"+id,ns="netns"+id;
    if(role=="server")run("ip netns exec "+ns+" wg set "+wg+" peer "+peer+" endpoint "+ep+
    " persistent-keepalive 5 2>/dev/null || true");
    else{
        // Shared server wg0 HP is inbound: random public HP port is redirected
        // to fixed wg0:51820. Do not rewrite wg0 to the peer endpoint here;
        // WireGuard learns the endpoint from the authenticated incoming packet.
        (void)ep;
        run("true # shared wg0 HP waits for incoming redirected authenticated packet");
    }
}
static long now(){
    return time(nullptr);
}
static void sleep_until(long t){
    while(now()<t)std::this_thread::sleep_for(std::chrono::milliseconds(100));
}
static int do_hp(const std::string&role,const std::string&id,const std::string&fam,std::string peer_ip,
std::string peer_port,const std::string&peerkey,long requested_ptime=0){
    // HP is only part of the authenticated CAP2 offer/answer flow. There is no
    // second shared slot rendezvous namespace.
    if(peer_ip.empty()||peer_port.empty()){
        std::cerr<<"CAP2 peer endpoint required\n";
        return 5;
    }
    int lp=stable_hp_port(role,id);
    if(lp<=1024||(role!="server"&&!port_free(lp))){
        std::cerr<<"advertised hole-punch port unavailable: "<<lp<<"\n";
        return 3;
    }
    std::string pub_ip=local_public(fam);
    if(pub_ip.empty()){
        std::cerr<<"no public ip for family "<<fam<<"\n";
        return 4;
    }
    wg_listen(role,id,lp);
    int wg_port=(role=="server")?lp:fixed_wg0_port();
    if(role!="server")add_wg0_redirect(role,id,fam,lp,wg_port);
    long ptime=requested_ptime>now()?requested_ptime:now()+C.hp_punch_delay;
    std::string route_src=local_route_source(peer_ip);
    std::string ct_src=route_src.empty()?pub_ip:route_src;
    for(int a=0;a<C.hp_retries;a++){
        long at=ptime+(a*(C.hp_burst_count+1));
        sleep_until(at);
        if(is_imported_server_wgx(role)){
            punch_round_imported_server_wgx(role,id,fam,peerkey,peer_ip,peer_port,wg_port,ct_src);
        }else{
            punch_round_shared_server_wg0(role,id,fam,peerkey,peer_ip,peer_port,lp,wg_port,ct_src);
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    run("mkdir -p "+C.pstate+"; echo holepunch-"+fam+"-wg0-redirect-or-wgx-socket >"+C.pstate+"/"+role+"-"+id+".state");
    return 0;
}
int main(int ac,char**av){
    if(!vr::guard_parent())return 1;
    C=cfg();
    if(ac<2){
        std::cerr<<"usage: voider-holepunch run ROLE ID 4|6 PEER_IP PEER_PORT WGPEER [PUNCH_AT] | cleanup ROLE ID\n";
        return 2;
    }
    std::string cmd=av[1];
    if(cmd=="cleanup"&&ac>=4){
        cleanup_wg0_redirect(av[2],av[3]);
        return 0;
    }
    if(cmd=="run"&&ac>=8){ long at=ac>8?std::atol(av[8]):0; return do_hp(av[2],av[3],av[4],av[5],av[6],av[7],at); }
    if(ac>=7){ long at=ac>7?std::atol(av[7]):0; return do_hp(av[1],av[2],av[3],av[4],av[5],av[6],at); }
    return 2;
}
