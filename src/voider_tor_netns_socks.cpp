// voider-tor-netns-socks owns the shared dummy SOCKS address.
// OpenRC calls it before Tor binds; WAN startup/recovery calls the same owner.
// Imported-server namespaces reach Tor directly through their veth/brX route.
#include <iostream>
#include <cstdlib>
#include "voider_config.hpp"
#include "voider_util.hpp"

using vu::run;

static Cfg C;
static int start(){
    run("ip link add "+C.tor_netns_socks_if+" type dummy 2>/dev/null || true");
    run("ip addr replace "+C.tor_netns_socks_ip+"/32 dev "+C.tor_netns_socks_if);
    run("ip link set "+C.tor_netns_socks_if+" up");
    return 0;
}
static int status(){ return run("ip addr show "+C.tor_netns_socks_if); }
int main(int ac,char**av){
    C=cfg();
    std::string cmd=ac>1?av[1]:"start";
    if(cmd=="start")return start();
    if(cmd=="stop")return 0;
    if(cmd=="status")return status();
    std::cerr << "usage: voider-tor-netns-socks start|stop|status\n";
    return 2;
}
