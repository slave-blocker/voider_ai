// voider-phone: phone-side /30 appliance link monitor.
//
// The SIP phone is only accepted at 172.16.19.85. DHCP is convenience, not
// identity. If the phone uses static IP and 172.16.19.85 is reachable, the UI
// reports static-assumed. A different static IP is not accepted as normal.

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include "voider_util.hpp"
#include "voider_runtime.hpp"
static Cfg C;
static bool carrier(){
    return vu::read1("/sys/class/net/"+C.phone_if+"/carrier")=="1";
}
static bool reachable(){
    return std::system(("ping -I "+C.phone_if+" -c1 -W1 "+C.phone_ip+" >/dev/null 2>&1").c_str())==0;
}
static bool lease_seen(){
    return vu::exists_nonempty(C.dhcp_leases);
}
static bool dhcp_alive(){
    std::string pid=vu::read1(C.dhcp_pid);
    return !pid.empty()&&std::system(("kill -0 "+pid+" 2>/dev/null").c_str())==0;
}
static int prepare(){
    std::filesystem::create_directories("/run/voider");
    vu::run("ip link set "+C.phone_if+" up");
    return vu::run("ip addr replace "+C.phone_gw+"/"+std::to_string(C.dhcp_cidr)+" dev "+C.phone_if);
}
static int dhcp(){
    prepare();
    return vu::exit_status(std::system("/usr/local/sbin/voider-dhcp start >/run/voider/last-phone-dhcp 2>&1"));
}
// DHCP lease is useful evidence, but reachability of 172.16.19.85 is decisive.
static void write_status(){
    bool l=lease_seen(),r=reachable();
    vr::publish(C.phone_status,vr::stamp()+
    "CARRIER "+std::string(carrier()?"up":"down")+"\nLEASE "+(l?"yes":"no")+
    "\nREACHABLE "+(r?"yes":"no")+"\nMODE "+((r&&l)?"dhcp":(r?"static-assumed":"unknown"))+
    "\nEXPECTED_IP "+C.phone_ip+"\nACCEPTED_IP "+C.phone_ip+"\nGATEWAY "+C.phone_gw+
    "\nCIDR "+std::to_string(C.dhcp_cidr)+"\nSTRICT_IP yes");
}
static int recover(){
    vr::Lock lock("/run/voider/phone-recovery.lock");
    if(!lock.held())return 0;
    prepare();
    if(C.dhcp_enabled&&!dhcp_alive())dhcp();
    write_status();
    return 0;
}
static int monitor(){
    vr::Lock owner("/run/voider/phone-monitor.lock");if(!owner.held())return 1;
    prepare();
    while(true){
        recover();
        std::this_thread::sleep_for(std::chrono::seconds(C.phone_probe_sec));
    }
    return 0;
}
static int status(){
    write_status();
    std::cout<<std::ifstream(C.phone_status).rdbuf();
    return 0;
}
int main(int ac,char**av){
    C=cfg();
    std::string c=ac>1?av[1]:"status";
    if(c=="--healthcheck")return vr::fresh(C.phone_status,15000)?0:1;
    if(c=="prepare"||c=="dhcp"){
        vr::Lock lock("/run/voider/phone-recovery.lock");return lock.held()?(c=="prepare"?prepare():dhcp()):12;
    }
    if(c=="recover")return recover();
    if(c=="monitor")return monitor();
    if(c=="status")return status();
    std::cerr<<"usage: voider-phone prepare|dhcp|recover|monitor|status\n";
    return 2;
}
