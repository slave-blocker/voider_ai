#pragma once

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <array>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "voider_transport_allowlist.hpp"

namespace vtp {

struct Record {
    std::map<std::string,std::string> fields;
    std::string error;

    std::string get(const std::string& key,const std::string& fallback="") const {
        auto it=fields.find(key);
        return it==fields.end()?fallback:it->second;
    }
    bool ok() const { return error.empty(); }
};

inline bool token_key(const std::string& s){
    if(s.empty())return false;
    for(unsigned char c:s)if(!(std::isupper(c)||std::isdigit(c)||c=='_'))return false;
    return true;
}

inline bool token_value(const std::string& s){
    static const std::string punctuation="._:/,+%=-";
    for(unsigned char c:s)
        if(!std::isalnum(c)&&punctuation.find(static_cast<char>(c))==std::string::npos)return false;
    return true;
}

inline bool hex_string(const std::string& s,size_t length){
    if(s.size()!=length)return false;
    for(unsigned char c:s)if(!std::isxdigit(c))return false;
    return true;
}

inline Record parse_record(const std::string& text){
    Record out;
    std::istringstream in(text);
    std::string word;
    if(!(in>>word)||word!="CAP2"){
        out.error="missing CAP2 marker";
        return out;
    }
    while(in>>word){
        auto at=word.find('=');
        if(at==std::string::npos||!token_key(word.substr(0,at))||
           !token_value(word.substr(at+1))){
            out.error="invalid field";
            return out;
        }
        auto item=std::make_pair(word.substr(0,at),word.substr(at+1));
        if(!out.fields.insert(item).second){
            out.error="duplicate field";
            return out;
        }
    }
    if(out.get("V")!="2")out.error="unsupported version";
    else if(out.get("TYPE")!="OFFER"&&out.get("TYPE")!="ANSWER"&&
            out.get("TYPE")!="READY")out.error="invalid type";
    else if(!hex_string(out.get("XID"),32))out.error="invalid exchange id";
    else {
        std::string slot_text=out.get("CERT_SLOT");
        char* end=nullptr;
        long slot=std::strtol(slot_text.c_str(),&end,10);
        if(!end||*end||slot<2||slot>254)out.error="invalid certificate slot";
    }
    if(out.ok()&&(out.get("TYPE")=="ANSWER"||out.get("TYPE")=="READY")&&
       !hex_string(out.get("OFFER_HASH"),64))out.error="invalid offer digest";
    if(out.ok()&&out.get("TYPE")=="READY"&&
       !hex_string(out.get("ANSWER_HASH"),64))out.error="invalid answer digest";
    if(out.ok()&&(out.get("TYPE")=="OFFER"||out.get("TYPE")=="ANSWER")&&
       (!out.fields.count("AVAILABLE")||!vta::valid(out.get("AVAILABLE"))))
        out.error="invalid available transports";
    if(out.ok()&&out.get("TYPE")=="ANSWER"&&
       (!out.fields.count("PLAN")||
        (!out.get("PLAN").empty()&&!vta::valid(out.get("PLAN")))))
        out.error="invalid transport plan";
    return out;
}

inline std::string serialize(const Record& record){
    std::string out="CAP2";
    for(const auto& field:record.fields){
        if(token_key(field.first)&&token_value(field.second))
            out+=" "+field.first+"="+field.second;
    }
    return out;
}

inline std::string hex(const unsigned char* data,size_t length){
    std::ostringstream out;
    out<<std::hex<<std::setfill('0');
    for(size_t i=0;i<length;i++)out<<std::setw(2)<<(unsigned)data[i];
    return out.str();
}

inline std::string sha256(const std::string& text){
    std::array<unsigned char,SHA256_DIGEST_LENGTH> digest{};
    SHA256(reinterpret_cast<const unsigned char*>(text.data()),text.size(),digest.data());
    return hex(digest.data(),digest.size());
}

inline std::string hmac256(const std::string& secret,const std::string& text){
    std::array<unsigned char,EVP_MAX_MD_SIZE> digest{};
    unsigned length=0;
    HMAC(EVP_sha256(),secret.data(),static_cast<int>(secret.size()),
         reinterpret_cast<const unsigned char*>(text.data()),text.size(),digest.data(),&length);
    return hex(digest.data(),length);
}

inline bool same_mac(const std::string& a,const std::string& b){
    return a.size()==64&&b.size()==64&&CRYPTO_memcmp(a.data(),b.data(),64)==0;
}

inline std::string random_hex(size_t bytes){
    std::vector<unsigned char> data(bytes);
    std::ifstream random("/dev/urandom",std::ios::binary);
    if(!random.read(reinterpret_cast<char*>(data.data()),data.size()))return "";
    return hex(data.data(),data.size());
}

inline bool correlated(const Record& offer,const Record& answer){
    return offer.ok()&&answer.ok()&&offer.get("TYPE")=="OFFER"&&
           answer.get("TYPE")=="ANSWER"&&offer.get("XID")==answer.get("XID")&&
           offer.get("CERT_SLOT")==answer.get("CERT_SLOT")&&
           answer.get("OFFER_HASH")==sha256(serialize(offer));
}

inline bool acknowledged(const Record& offer,const Record& answer,const Record& ready){
    return correlated(offer,answer)&&ready.ok()&&ready.get("TYPE")=="READY"&&
           ready.get("XID")==offer.get("XID")&&
           ready.get("CERT_SLOT")==offer.get("CERT_SLOT")&&
           ready.get("OFFER_HASH")==sha256(serialize(offer))&&
           ready.get("ANSWER_HASH")==sha256(serialize(answer));
}

inline bool listed(const std::string& value,const std::string& wanted){
    std::istringstream in(value);
    std::string item;
    while(std::getline(in,item,','))if(!item.empty()&&item==wanted)return true;
    return false;
}

inline std::string lan_query(const std::string& secret,const std::string& node,
                             const std::string& nonce){
    std::string body="VLD1|Q|"+node+"|"+nonce;
    return "VLD1 Q "+node+" "+nonce+" "+hmac256(secret,body);
}

inline bool verify_lan_query(const std::string& packet,const std::string& secret,
                             std::string& node,std::string& nonce){
    std::istringstream in(packet);
    std::string magic,type,mac,extra;
    if(!(in>>magic>>type>>node>>nonce>>mac)||(in>>extra)||magic!="VLD1"||type!="Q"||
       !hex_string(node,32)||!hex_string(nonce,32)||!hex_string(mac,64))return false;
    return same_mac(mac,hmac256(secret,"VLD1|Q|"+node+"|"+nonce));
}

inline std::string lan_answer(const std::string& secret,const std::string& target_node,
                              const std::string& nonce,const std::string& responder_node,
                              unsigned port){
    std::string p=std::to_string(port);
    std::string body="VLD1|A|"+target_node+"|"+nonce+"|"+responder_node+"|"+p;
    return "VLD1 A "+target_node+" "+nonce+" "+responder_node+" "+p+" "+
           hmac256(secret,body);
}

inline bool verify_lan_answer(const std::string& packet,const std::string& secret,
                              const std::string& local_node,const std::string& wanted_nonce,
                              std::string& responder_node,unsigned& port){
    std::istringstream in(packet);
    std::string magic,type,target,nonce,port_text,mac,extra;
    if(!(in>>magic>>type>>target>>nonce>>responder_node>>port_text>>mac)||(in>>extra)||
       magic!="VLD1"||type!="A"||target!=local_node||nonce!=wanted_nonce||
       !hex_string(responder_node,32)||responder_node==local_node||!hex_string(mac,64))return false;
    char* end=nullptr;
    unsigned long parsed=std::strtoul(port_text.c_str(),&end,10);
    if(!end||*end||parsed<1024||parsed>65535)return false;
    std::string body="VLD1|A|"+target+"|"+nonce+"|"+responder_node+"|"+port_text;
    if(!same_mac(mac,hmac256(secret,body)))return false;
    port=static_cast<unsigned>(parsed);
    return true;
}

} // namespace vtp
