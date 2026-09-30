#include <cstdio>
#include <array>
#include <map>
#include <regex>
#include <fstream>
#include <iostream>
#include <filesystem>
#include "voider_config.hpp"
#include "voider_util.hpp"

using vu::cap;

namespace fs=std::filesystem;
static bool v4(const std::string&s){
    std::regex r("^([0-9]{1,3}\\.){3}[0-9]{1,3}$");
    if(!std::regex_match(s,r))return false;
    int a,b,c,d;
    if(sscanf(s.c_str(),"%d.%d.%d.%d",&a,&b,&c,&d)!=4)return false;
    return a>0&&a<256&&b>=0&&b<256&&c>=0&&c<256&&d>0&&d<256;
}
static std::string get_url(const std::string&url,int timeout){
    auto s=cap("wget -q -T "+std::to_string(timeout)+" -O - '"+url+"' 2>/dev/null");
    if(v4(s))return s;
    return"";
}
int main(){
    Cfg C=cfg();
    std::string best;
    std::map<std::string,int> votes;
    std::string first;
    for(auto&u:csv(C.pubip_services)){
        auto ip=get_url(u,C.pubip_timeout);
        if(!ip.empty()){
            if(first.empty())first=ip;
            if(++votes[ip]>=2){best=ip;break;}
            std::cerr<<"public-ip-ok "<<u<<" "<<ip<<"\n";
        }
        else std::cerr<<"public-ip-fail "<<u<<"\n";
    }
    if(best.empty())best=first;
    if(best.empty()){
        std::ifstream f(C.pubip_file);
        std::getline(f,best);
        best=trim(best);
    }
    if(!v4(best)){
        std::cerr<<"ERROR no valid public ip\n";
        return 1;
    }
    fs::create_directories("/run/voider");
    std::ofstream(C.pubip_file)<<best<<"\n";
    std::ofstream(C.pubip_runtime)<<best<<"\n";
    std::cout<<best<<"\n";
    return 0;
}
