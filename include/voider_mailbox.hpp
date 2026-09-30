#pragma once

#include <cctype>
#include <cstdio>
#include <filesystem>
#include <string>

#include "voider_config.hpp"

namespace vmb {

inline bool slot_ok(int slot){ return slot>=2&&slot<=254; }

inline std::string user(int slot){
    char name[16];
    std::snprintf(name,sizeof name,"vmb%03d",slot);
    return name;
}

inline std::filesystem::path root(const Cfg& c,int slot){
    return std::filesystem::path(c.sftp_base)/user(slot);
}

inline std::filesystem::path keys(const Cfg& c,int slot){
    return std::filesystem::path(c.mailbox_key_dir)/(user(slot)+".authorized_keys");
}

inline bool xid(const std::string& value){
    if(value.size()!=32)return false;
    for(unsigned char ch:value)if(!std::isxdigit(ch))return false;
    return true;
}

inline std::filesystem::path record(const Cfg& c,int slot,const std::string& direction,
                                    const std::string& xid_value,const std::string& type){
    return root(c,slot)/direction/(xid_value+'.'+type);
}

} // namespace vmb
