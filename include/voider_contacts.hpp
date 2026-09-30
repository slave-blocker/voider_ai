#pragma once

#include <array>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "voider_util.hpp"

namespace vc {

using vu::read1;

struct Contact {
    std::string role;
    int slot=0;
    std::string name;
    std::string fingerprint;
    std::string dial_ip;
};


static inline std::string hex_only(std::string s){
    std::string out;
    for(char c:s)if(std::isxdigit((unsigned char)c))out.push_back((char)std::tolower((unsigned char)c));
    return out;
}

static inline std::string connection_name(const std::string&role,int slot){
    return (role=="client"?"CLIENT ":"SERVER ")+std::to_string(slot-1);
}

// Preserve the master Voider split: deterministic 10/8 addresses are dialled
// by the user; per-boot 172.16/12 fake addresses only disguise inbound callers.
static inline std::string dial_ip(const std::string&role,int slot){
    if(role=="client")return "10.1."+std::to_string(slot)+".1";
    return "10."+std::to_string(slot)+".1.1";
}

static inline std::string fingerprint_for(const Cfg&C,const std::string&role,int slot){
    std::string n=std::to_string(slot);
    std::array<std::string,3> candidates{
        C.usb_fp_dir+"/"+(role=="client"?"client-":"import-server-")+n+".sha256",
        C.usb_fp_dir+"/import-"+role+"-"+n+".sha256",
        (role=="client"?C.pc:C.ps)+"/"+n+".conf"
    };
    for(const auto&p:candidates){
        std::string fp=p.size()>5&&p.substr(p.size()-5)==".conf"?val(p,"USB_FP"):read1(p);
        fp=hex_only(fp);
        if(fp.size()==64)return fp;
    }
    return "";
}

static inline std::vector<Contact> contacts(const Cfg&C){
    std::vector<Contact> out;
    for(const auto&role:{std::string("client"),std::string("server")}){
        std::string dir=role=="client"?C.pc:C.ps;
        for(int slot=2;slot<=254;slot++){
            std::string conf=dir+"/"+std::to_string(slot)+".conf";
            if(!std::filesystem::exists(conf))continue;
            Contact x;
            x.role=role;
            x.slot=slot;
            x.fingerprint=fingerprint_for(C,role,slot);
            x.name=connection_name(role,slot);
            x.dial_ip=dial_ip(role,slot);
            out.push_back(x);
        }
    }
    return out;
}

static inline std::string keypad_ip(std::string ip){
    for(char&c:ip)if(c=='.')c='*';
    return ip;
}

} // namespace vc
