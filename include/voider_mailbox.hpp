#pragma once

#include <cctype>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <string>

#include "voider_config.hpp"

namespace vmb {

inline bool slot_ok(int slot){ return slot>=2&&slot<=254; }

inline bool role_ok(const std::string& role){ return role=="client"||role=="server"; }

inline std::string directory(int slot){
    char name[16];
    std::snprintf(name,sizeof name,"vmb%03d",slot);
    return name;
}

inline std::string user(const std::string& role,int slot){
    char name[16];
    std::snprintf(name,sizeof name,role=="client"?"vmc%03d":"vms%03d",slot);
    return name;
}

inline std::filesystem::path root(const Cfg& c,const std::string& role,int slot){
    return std::filesystem::path(c.sftp_base)/(role=="client"?"clients":"servers")/directory(slot);
}

inline std::filesystem::path keys(const Cfg& c,const std::string& role,int slot){
    return std::filesystem::path(c.mailbox_key_dir)/(user(role,slot)+".authorized_keys");
}

inline bool xid(const std::string& value){
    if(value.size()!=32)return false;
    for(unsigned char ch:value)if(!std::isxdigit(ch))return false;
    return true;
}

inline std::filesystem::path record(const Cfg& c,const std::string& role,int slot,const std::string& direction,
                                    const std::string& xid_value,const std::string& type){
    return root(c,role,slot)/direction/(xid_value+'.'+type);
}

inline void prune_sync(const Cfg& c,const std::string& role,int slot){
    namespace fs=std::filesystem;
    std::error_code error;
    auto now=fs::file_time_type::clock::now();
    for(const auto& entry:fs::directory_iterator(fs::path(c.sync)/role/std::to_string(slot),error)){
        std::string name=entry.path().filename().string();
        if(name.size()<33||!xid(name.substr(0,32))||name[32]!='.')continue;
        auto time=entry.last_write_time(error);
        if(!error&&now-time>std::chrono::seconds(c.mailbox_ttl_sec))fs::remove(entry.path(),error);
        error.clear();
    }
}

} // namespace vmb
