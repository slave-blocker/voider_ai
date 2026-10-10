// voider-wan: router-side DHCP and recovery monitor.
//
// Alpine can handle DHCP, but the appliance should recover by itself after a
// long cable unplug. This helper owns WAN_IF readiness for voider: carrier,
// udhcpc PID, IPv4 lease, default route, basic reachability, and public-IP
// refresh after recovery.

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <sstream>
#include <thread>
#include <unistd.h>
#include "voider_util.hpp"
#include "voider_runtime.hpp"

using vu::read_file;

static Cfg C;
static const std::string ipv6_cache="/run/voider/ipv6.status";
static const std::string public_refresh="/run/voider/public-ip.refresh";

static bool stale(const std::string& path,int seconds){
    std::error_code error;
    auto changed=std::filesystem::last_write_time(path,error);
    return error||std::filesystem::file_time_type::clock::now()-changed>std::chrono::seconds(seconds);
}

static void ensure_ipv6_router_ra(){
    // Linux ignores Router Advertisements when forwarding is enabled unless
    // the receiving router-facing interface uses accept_ra=2.  IPv6 is only
    // an outer WireGuard underlay; the phone and call plane remain IPv4.
    vu::write1("/proc/sys/net/ipv6/conf/all/forwarding","1");
    vu::write1("/proc/sys/net/ipv6/conf/"+C.wan_if+"/accept_ra","2");
}

static bool carrier(){
    return vu::read1("/sys/class/net/"+C.wan_if+"/carrier")=="1";
}
static bool defroute(){
    return std::system(("ip route show default dev "+C.wan_if+" 2>/dev/null | grep -q '^default '").c_str())==0;
}
static std::string route_gateway(const std::string& route){
    auto via=route.find(" via ");
    if(via==std::string::npos)return "";
    via+=5;
    auto end=route.find_first_of(" \t\r\n",via);
    return route.substr(via,end-via);
}
static std::string gateway(){
    return route_gateway(vu::cap("ip route show default dev "+C.wan_if+" 2>/dev/null | head -n1"));
}
static bool gateway_reachable(){
    auto gw=gateway();
    if(gw.empty())return defroute();
    vu::run("ping -I "+C.wan_if+" -c1 -W1 "+vu::shq(gw)+" >/dev/null 2>&1 || true");
    return std::system(("ip neigh show to "+vu::shq(gw)+" dev "+C.wan_if+
        " | grep -Eq 'lladdr .*(REACHABLE|STALE|DELAY|PROBE|PERMANENT)'").c_str())==0;
}
static std::string ip4(){
    return vu::cap("ip -4 -o addr show dev "+C.wan_if+
        " scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1");
}
static std::string v6field(const std::string&blob,const std::string&key){
    std::string needle=key+"=";
    std::stringstream ss(blob);
    std::string line;
    while(std::getline(ss,line)){
        if(line.rfind(needle,0)==0)return trim(line.substr(needle.size()));
    }
    return "";
}
static std::string v6status(bool force=false){
    if(force||stale(ipv6_cache,60)){
        std::string current=vu::cap("/usr/local/sbin/voider-ipv6-ready client 2>/dev/null");
        if(!current.empty())vu::write1(ipv6_cache,current);
    }
    return read_file(ipv6_cache);
}
static bool hasip(){
    return !ip4().empty();
}
static bool netok(){
    return std::system(("ping -I "+C.wan_if+" -c1 -W1 "+C.wan_check_host+" >/dev/null 2>&1").c_str())==0;
}
static bool pid_alive(){
    auto p=vu::read1(C.wan_dhcp_pid);
    return !p.empty()&&std::system(("kill -0 "+p+" 2>/dev/null").c_str())==0;
}
static bool address_changed(const std::string& previous,const std::string& current){
    return !previous.empty()&&!current.empty()&&previous!=current;
}
static bool record_address(const std::string& current){
    if(current.empty())return false;
    std::string path=C.wan_status+".ip";
    std::string previous=vu::read1(path);
    if(previous==current)return false;
    vu::write1(path,current);
    bool changed=address_changed(previous,current);
    if(changed){
        std::error_code error;
        std::filesystem::remove(C.pubip_file,error);
        error.clear();std::filesystem::remove(C.pubip_runtime,error);
        error.clear();std::filesystem::remove(ipv6_cache,error);
    }
    return changed;
}
static void refresh_public_ip(bool address_changed){
    if(!address_changed&&vu::exists_nonempty(C.pubip_file)&&!stale(public_refresh,900))return;
    vu::write1(public_refresh,"attempted");
    vu::run("/usr/local/sbin/voider-publicip >/run/voider/last-publicip 2>&1 || true");
}
static std::string script(){
    for(auto p:{
        "/usr/share/udhcpc/default.script","/etc/udhcpc/default.script","/lib/udhcpc/default.script"
    }
    )if(access(p,X_OK)==0)return p;
    return "/usr/share/udhcpc/default.script";
}
static void write_status(const std::string& s){
    std::string v6=v6status();
    vr::publish(C.wan_status,vr::stamp()+"STATE "+s+"\nCARRIER "+(carrier()?"up":"down")+"\nIP4 "+ip4()+"\nROUTE "+
        (defroute()?"ok":"missing")+"\nNET "+(netok()?"ok":"bad")+
        "\nIP6 "+v6field(v6,"PUB6")+"\nROUTE6 "+v6field(v6,"ROUTE6")+"\nNET6 "+v6field(v6,"PING6")+
        "\nIPV6_READY "+v6field(v6,"READY")+"\nHP6_REDIRECT "+v6field(v6,"REDIRECT6")+
        "\nPID "+vu::read1(C.wan_dhcp_pid));
}
static int start(){
    std::filesystem::create_directories("/run/voider");
    ensure_ipv6_router_ra();
    vu::run("/usr/local/sbin/voider-tor-netns-socks start");
    if(!C.wan_dhcp_enabled){
        write_status("disabled");
        return 0;
    }
    vu::run("ip link set "+C.wan_if+" up");
    if(pid_alive()){
        write_status("running");
        return 0;
    }
    vu::run("rm -f "+vu::shq(C.wan_dhcp_pid));
    int rc=vu::run("udhcpc -b -i "+C.wan_if+" -p "+vu::shq(C.wan_dhcp_pid)+" -s "+vu::shq(script())+" -t 5 -T 3 -A 3");
    std::this_thread::sleep_for(std::chrono::seconds(2));
    write_status((hasip()&&defroute())?"ready":"starting");
    return rc;
}
static int renew(){
    if(!pid_alive())return start();
    vu::run("kill -USR1 "+vu::read1(C.wan_dhcp_pid)+" 2>/dev/null || true");
    std::this_thread::sleep_for(std::chrono::seconds(2));
    write_status((hasip()&&defroute())?"ready":"renewing");
    return 0;
}
static int replace_stale_lease(){
    auto pid=vu::read1(C.wan_dhcp_pid);
    if(!pid.empty())vu::run("kill "+pid+" 2>/dev/null || true");
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
    vu::run("rm -f "+vu::shq(C.wan_dhcp_pid));
    vu::run("ip -4 addr flush dev "+C.wan_if+" scope global");
    vu::run("ip -4 route del default dev "+C.wan_if+" 2>/dev/null || true");
    return start();
}
// Recovery is idempotent: safe to call after boot, after cable replug, or from the UI.
static int recover(bool prepare=true){
    vr::Lock lock("/run/voider/wan-recovery.lock");
    if(!lock.held())return 0;
    if(prepare){ensure_ipv6_router_ra();vu::run("/usr/local/sbin/voider-tor-netns-socks start");}
    if(!carrier()){
        write_status("link-down");
        return 10;
    }
    if(!pid_alive()||!hasip()||!defroute())renew();
    else if(!gateway_reachable())replace_stale_lease();
    if(hasip()&&defroute()){
        bool changed=record_address(ip4());
        refresh_public_ip(changed);
        write_status(netok()?"ready":"route-only");
        return 0;
    }
    write_status("failed");
    return 11;
}
static int monitor(){
    vr::Lock owner("/run/voider/wan-monitor.lock");if(!owner.held())return 1;
    ensure_ipv6_router_ra();
    vu::run("/usr/local/sbin/voider-tor-netns-socks start");
    while(true){
        recover(false);
        std::this_thread::sleep_for(std::chrono::seconds(C.wan_monitor_sec));
    }
    return 0;
}
static int status(){
    write_status((hasip()&&defroute())?"ready":(carrier()?"degraded":"link-down"));
    std::cout<<std::ifstream(C.wan_status).rdbuf();
    return 0;
}
int main(int ac,char**av){
    C=cfg();
    std::string c=ac>1?av[1]:"status";
    if(c=="--healthcheck")return vr::fresh(C.wan_status,90000)?0:1;
    if(c=="selftest"){
        if(address_changed("","10.0.0.1")||address_changed("10.0.0.1","10.0.0.1")||
           !address_changed("10.0.0.1","10.0.1.1"))return 1;
        if(route_gateway("default via 10.20.30.1 dev eth0 metric 202")!="10.20.30.1"||
           !route_gateway("default dev eth0").empty())return 2;
        std::cout<<"WAN_SELFTEST_OK\n";
        return 0;
    }
    if(c=="start"||c=="renew"){
        vr::Lock lock("/run/voider/wan-recovery.lock");
        return lock.held()?(c=="start"?start():renew()):12;
    }
    if(c=="recover")return recover();
    if(c=="monitor")return monitor();
    if(c=="status")return status();
    std::cerr<<"usage: voider-wan start|renew|recover|monitor|status|selftest\n";
    return 2;
}
