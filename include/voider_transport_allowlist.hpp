#pragma once

#include <array>
#include <set>
#include <sstream>
#include <string>

namespace vta {

static constexpr std::array<const char*,7> TOKENS={
    "lan4","lan6","direct4","direct6","hp4","hp6","tor"
};

static constexpr std::array<const char*,7> LABELS={
    "LOCAL IPV4","LOCAL IPV6","DIRECT IPV4","DIRECT IPV6",
    "PUNCH IPV4","PUNCH IPV6","TOR FALLBACK"
};

inline std::string all(){ return "lan4,lan6,direct4,direct6,hp4,hp6,tor"; }

inline bool known(const std::string& value){
    for(const char* token:TOKENS)if(value==token)return true;
    return false;
}

inline std::set<std::string> parse(const std::string& value){
    std::set<std::string> out;
    std::istringstream input(value);
    std::string item;
    while(std::getline(input,item,','))if(known(item))out.insert(item);
    return out;
}

inline std::string canonical(const std::string& value){
    if(value.empty())return "";
    std::set<std::string> selected;
    std::istringstream input(value);
    std::string item;
    while(std::getline(input,item,','))
        if(!known(item)||!selected.insert(item).second)return "";
    std::string out;
    for(const char* token:TOKENS)if(selected.count(token)){
        if(!out.empty())out+=',';
        out+=token;
    }
    return out;
}

inline bool valid(const std::string& value){
    return !value.empty()&&value==canonical(value);
}

inline bool available(const std::string& value,const std::string& token){
    return valid(value)&&parse(value).count(token)!=0;
}

inline bool common(const std::string& a,const std::string& b,const std::string& token){
    return available(a,token)&&available(b,token);
}

} // namespace vta
