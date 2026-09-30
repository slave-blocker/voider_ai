#pragma once

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "voider_config.hpp"

namespace vwan6 {

inline bool global(const std::string& ip){
    in6_addr addr{};
    if(inet_pton(AF_INET6,ip.c_str(),&addr)!=1)return false;
    // IPv6 global unicast is 2000::/3. Exclude ULA, link-local, multicast,
    // loopback, and malformed text even if a stale status file names them.
    if((addr.s6_addr[0]&0xe0)!=0x20)return false;
    // 2001:db8::/32 is documentation space, never a reachable WAN endpoint.
    return !(addr.s6_addr[0]==0x20&&addr.s6_addr[1]==0x01&&
             addr.s6_addr[2]==0x0d&&addr.s6_addr[3]==0xb8);
}

inline bool same_address(const std::string& a,const std::string& b){
    in6_addr left{},right{};
    return inet_pton(AF_INET6,a.c_str(),&left)==1&&
           inet_pton(AF_INET6,b.c_str(),&right)==1&&
           std::equal(std::begin(left.s6_addr),std::end(left.s6_addr),
                      std::begin(right.s6_addr));
}

inline std::string validated(const std::string& status,
                             const std::vector<std::string>& assigned,
                             bool default_route,bool fresh,bool need_redirect){
    if(!fresh||!default_route)return "";
    std::string ready,redirect,ip,key,value;
    std::istringstream lines(status);
    while(lines>>key){
        std::getline(lines,value);
        value=trim(value);
        if(key=="IPV6_READY")ready=value;
        else if(key=="HP6_REDIRECT")redirect=value;
        else if(key=="IP6")ip=value;
    }
    if(ready!="1"||(need_redirect&&redirect!="ok")||!global(ip))return "";
    for(const auto& current:assigned)
        if(same_address(ip,current))return ip;
    return "";
}

inline std::vector<std::string> assigned(const std::string& iface){
    std::vector<std::string> out;
    ifaddrs* list=nullptr;
    if(getifaddrs(&list)!=0)return out;
    for(auto* item=list;item;item=item->ifa_next){
        if(!item->ifa_addr||item->ifa_addr->sa_family!=AF_INET6||
           iface!=item->ifa_name)continue;
        char ip[INET6_ADDRSTRLEN]{};
        auto* addr=reinterpret_cast<sockaddr_in6*>(item->ifa_addr);
        if(inet_ntop(AF_INET6,&addr->sin6_addr,ip,sizeof(ip)))out.emplace_back(ip);
    }
    freeifaddrs(list);
    return out;
}

inline bool default_route(const std::string& iface){
    std::ifstream file("/proc/net/ipv6_route");
    std::string line,destination,prefix,source,source_prefix,next_hop;
    std::string metric,refcount,used,flags,device;
    while(std::getline(file,line)){
        std::istringstream row(line);
        if(row>>destination>>prefix>>source>>source_prefix>>next_hop>>
               metric>>refcount>>used>>flags>>device &&
           destination==std::string(32,'0')&&prefix=="00"&&device==iface)
            return true;
    }
    return false;
}

inline std::string current(const Cfg& config,bool need_redirect=false){
    std::error_code error;
    auto modified=std::filesystem::last_write_time(config.wan_status,error);
    if(error)return "";
    auto age=std::filesystem::file_time_type::clock::now()-modified;
    int max_age=std::max(15,config.wan_monitor_sec*3);
    if(age<decltype(age)::zero()||age>std::chrono::seconds(max_age))return "";
    std::ifstream file(config.wan_status);
    std::string status((std::istreambuf_iterator<char>(file)),
                       std::istreambuf_iterator<char>());
    return validated(status,assigned(config.wan_if),default_route(config.wan_if),
                     true,need_redirect);
}
}
