// CAP2 is the remote rendezvous protocol. LAN discovery is deliberately
// separate so a same-LAN call never waits for Tor, SFTP, DNS, or public-IP
// discovery.

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <thread>
#include <vector>

#include "voider_config.hpp"
#include "voider_util.hpp"

#include "voider_mailbox.hpp"
#include "voider_transport_allowlist.hpp"
#include "voider_transport_protocol.hpp"
#include "voider_wan_ipv6.hpp"

using vu::read1;

namespace fs=std::filesystem;
using vtp::Record;
static Cfg C;

static std::string peer_conf(const std::string& role,int id){
    return (role=="client"?C.pc:C.ps)+"/"+std::to_string(id)+".conf";
}

static std::string conf(const std::string& role,int id,const std::string& key,
                        const std::string& fallback=""){
    auto value=val(peer_conf(role,id),key);
    return value.empty()?fallback:value;
}

static int conf_int(const std::string& role,int id,const std::string& key,int fallback){
    return toi(conf(role,id,key),fallback);
}

static std::string pair_secret(const std::string& role,int id){
    std::string path=conf(role,id,"PRESHARED_KEY",
        C.mat+"/"+role+"/"+std::to_string(id)+"/preshared.key");
    return read1(path);
}

static std::string record_mac(const Record& record,const std::string& secret){
    Record unsigned_record=record;
    unsigned_record.fields.erase("AUTH");
    return vtp::hmac256(secret,"voider-cap2-v2|"+vtp::serialize(unsigned_record));
}

static bool authenticate(const Record& record,const std::string& secret){
    return !secret.empty()&&vtp::same_mac(record.get("AUTH"),record_mac(record,secret));
}

static void sign(Record& record,const std::string& role,int id){
    std::string secret=pair_secret(role,id);
    if(secret.empty())record.error="missing pair secret";
    else record.fields["AUTH"]=record_mac(record,secret);
}

static bool ipv4(const std::string& value){
    unsigned a,b,c,d;
    return sscanf(value.c_str(),"%u.%u.%u.%u",&a,&b,&c,&d)==4&&
           a>0&&a<256&&b<256&&c<256&&d>0&&d<256;
}

static int address_index(const std::string& value,int fallback){
    unsigned a,b,c,d;
    if(sscanf(value.c_str(),"%u.%u.%u.%u",&a,&b,&c,&d)==4&&
       a==172&&b==31&&c==0&&d>=2&&d<=254)return static_cast<int>(d);
    return fallback;
}

static int certificate_slot(const std::string& role,int id){
    if(role=="client")return id;
    int saved=conf_int(role,id,"REMOTE_CERT_INDEX",0);
    if(saved>=2&&saved<=254)return saved;
    std::string address=conf(role,id,"LOCAL_ADDR",conf(role,id,"ADDRESS"));
    auto slash=address.find('/');
    if(slash!=std::string::npos)address.resize(slash);
    return address_index(address,id);
}

static unsigned wg_port(const std::string& role,int id){
    if(role=="client")return 51820;
    int port=conf_int(role,id,"PORT",51820+id);
    return port>=1024&&port<=65535?static_cast<unsigned>(port):51820u+id;
}

static unsigned hp_port(const std::string& role,int id){
    return role=="client"?static_cast<unsigned>(20000+certificate_slot(role,id)):
                          wg_port(role,id);
}

static std::string node_onion(){
    auto onion=read1(C.node_onion);
    return onion.empty()?read1(C.sync_onion):onion;
}

static Record local_record(const std::string& type,const std::string& role,int id,
                           const std::string& xid){
    Record out;
    std::string p4=read1(C.pubip_file);
    std::string p6=vwan6::current(C);
    int cert_slot=certificate_slot(role,id);
    std::string available=vta::canonical(C.transports_available);

    // Fixed compatibility descriptors for wire-v8 peers, never configuration.
    out.fields={
        {"AEAD","none"},
        {"AVAILABLE",available},
        {"CERT_SLOT",std::to_string(cert_slot)},
        {"HP4_PORT",std::to_string(hp_port(role,id))},
        {"HP6_PORT",std::to_string(hp_port(role,id))},
        {"PUB4",ipv4(p4)?p4:""},
        {"PUB6",p6},
        {"SCHED","dup"},
        {"SFTP_ONION",node_onion()},
        {"TUNMODE","fp-only"},
        {"TUNPORT",conf(role,id,"TORPORT",std::to_string(C.tundup_torport_base+cert_slot))},
        {"TUN_ONION",node_onion()},
        {"TYPE",type},
        {"V","2"},
        {"WG4",std::to_string(wg_port(role,id))},
        {"WG6",std::to_string(wg_port(role,id))},
        {"XID",xid}
    };
    if(role=="client")out.fields["SERVER_PUBLIC_KEY"]=
        conf(role,id,"SERVER_PUBLIC_KEY",read1("/etc/voider/private/wg0.pub"));
    else out.fields["SERVER_PUBLIC_KEY"]=conf(role,id,"SERVER_PUBLIC_KEY");
    return out;
}

static std::string plan(const Record& offer,const Record& answer){
    std::string out;
    auto add=[&](const std::string& method){
        if(!out.empty())out+=',';
        out+=method;
    };
    std::string a=offer.get("AVAILABLE"),b=answer.get("AVAILABLE");
    for(size_t i=2;i<vta::TOKENS.size();i++)
        if(vta::common(a,b,vta::TOKENS[i]))add(vta::TOKENS[i]);
    return out;
}

static Record make_offer(const std::string& role,int id){
    Record offer=local_record("OFFER",role,id,vtp::random_hex(16));
    sign(offer,role,id);
    return offer;
}

static Record make_answer(const std::string& role,int id,const Record& offer){
    Record answer=local_record("ANSWER",role,id,offer.get("XID"));
    answer.fields["OFFER_HASH"]=vtp::sha256(vtp::serialize(offer));
    answer.fields["PLAN"]=plan(offer,answer);
    sign(answer,role,id);
    return answer;
}

static Record make_ready(const std::string& role,int id,const Record& offer,
                         const Record& answer){
    Record ready;
    ready.fields={{"ANSWER_HASH",vtp::sha256(vtp::serialize(answer))},
                  {"CERT_SLOT",offer.get("CERT_SLOT")},
                  {"OFFER_HASH",vtp::sha256(vtp::serialize(offer))},
                  {"TYPE","READY"},{"V","2"},{"XID",offer.get("XID")}};
    sign(ready,role,id);
    return ready;
}

static int sync_command(const std::string& action,const std::string& role,int id,
                        const std::string& kind,const std::string& xid,
                        const std::string& payload=""){
    pid_t child=fork();
    if(child<0)return 125;
    if(child==0){
        int nullfd=open("/dev/null",O_WRONLY);
        if(nullfd>=0){dup2(nullfd,STDOUT_FILENO);close(nullfd);}
        std::string sid=std::to_string(id);
        if(payload.empty())
            execl("/usr/local/sbin/voider-sync","voider-sync",action.c_str(),role.c_str(),
                  sid.c_str(),kind.c_str(),xid.c_str(),(char*)nullptr);
        else
            execl("/usr/local/sbin/voider-sync","voider-sync",action.c_str(),role.c_str(),
                  sid.c_str(),kind.c_str(),xid.c_str(),payload.c_str(),(char*)nullptr);
        _exit(127);
    }
    int status=0;
    pid_t waited;
    do { waited=waitpid(child,&status,0); } while(waited<0&&errno==EINTR);
    if(waited!=child)return 126;
    return WIFEXITED(status)?WEXITSTATUS(status):126;
}

static fs::path local_sync_file(const std::string& role,int id,const std::string& kind,
                                const std::string& xid){
    return fs::path(C.sync)/role/std::to_string(id)/(xid+'.'+kind+".remote");
}

static fs::path mailbox(const std::string& kind,int cert_slot,const std::string& xid){
    return vmb::record(C,cert_slot,kind=="answer"?"out":"in",xid,kind);
}

static bool already_consumed(const Record& offer,const Record& previous){
    return offer.ok()&&previous.ok()&&offer.get("TYPE")=="OFFER"&&
           previous.get("TYPE")=="OFFER"&&offer.get("XID")==previous.get("XID");
}

static bool old_file(const fs::path& path,int seconds){
    std::error_code error;
    auto changed=fs::last_write_time(path,error);
    return error||fs::file_time_type::clock::now()-changed>std::chrono::seconds(seconds);
}

static bool temporary_name(const std::string& name){
    if(name.size()<57||name.front()!='.'||name.rfind(".tmp")!=name.size()-4)return false;
    size_t first=name.find('.',1),second=name.find('.',first+1),third=name.find('.',second+1);
    if(first!=33||second==std::string::npos||third==std::string::npos)return false;
    std::string kind=name.substr(first+1,second-first-1);
    return vmb::xid(name.substr(1,32))&&(kind=="offer"||kind=="ready")&&
           third==name.size()-4&&second+1<third;
}

static bool regular_bounded(const fs::path& path){
    struct stat status{};
    return lstat(path.c_str(),&status)==0&&S_ISREG(status.st_mode)&&status.st_nlink==1&&
           status.st_size>0&&status.st_size<=C.mailbox_record_bytes;
}

static bool regular_upload(const fs::path& path){
    struct stat status{};
    return lstat(path.c_str(),&status)==0&&S_ISREG(status.st_mode)&&status.st_nlink==1&&
           status.st_size>=0&&status.st_size<=C.mailbox_record_bytes;
}

static Record read_mailbox(const fs::path& path,const std::string& kind,int slot,
                           const std::string& xid){
    Record invalid;invalid.error="invalid mailbox record";
    if(!regular_bounded(path)||path.filename()!=xid+'.'+kind)return invalid;
    Record record=vtp::parse_record(read1(path));
    std::string type=kind=="offer"?"OFFER":kind=="answer"?"ANSWER":"READY";
    if(!record.ok()||record.get("TYPE")!=type||record.get("XID")!=xid||
       record.get("CERT_SLOT")!=std::to_string(slot))return invalid;
    return record;
}

static void remove_transaction(int slot,const std::string& xid){
    for(const auto& kind:{std::string("offer"),std::string("ready"),std::string("answer")}){
        std::error_code error;
        fs::remove(mailbox(kind,slot,xid),error);
    }
}

static std::vector<std::string> pending_offers(int slot){
    std::vector<std::pair<fs::file_time_type,std::string>> found;
    fs::path root=vmb::root(C,slot),incoming=root/"in",outgoing=root/"out";
    std::error_code error;
    if(!fs::is_directory(incoming,error)||!fs::is_directory(outgoing,error))return {};
    int temporary_count=0;
    for(const auto& entry:fs::directory_iterator(incoming,error)){
        if(error)break;
        fs::path path=entry.path();std::string name=path.filename().string();
        if(temporary_name(name)){
            // A fresh zero-byte temporary is a normal SFTP upload between
            // open(2) and write(2).  Keep it until the atomic rename, while
            // still rejecting links, oversized files, stale uploads, and a
            // flood beyond the bounded temporary allowance.
            if(!regular_upload(path)||old_file(path,30)||++temporary_count>C.mailbox_max_pending*2){
                error.clear();
                fs::remove_all(path,error);
            }
            continue;
        }
        size_t dot=name.find('.');
        std::string xid=dot==std::string::npos?"":name.substr(0,dot);
        std::string kind=dot==std::string::npos?"":name.substr(dot+1);
        if(!vmb::xid(xid)||(kind!="offer"&&kind!="ready")||old_file(path,C.mailbox_ttl_sec)||
           !read_mailbox(path,kind,slot,xid).ok()){
            error.clear();
            fs::remove_all(path,error);
            if(vmb::xid(xid))remove_transaction(slot,xid);
            continue;
        }
        if(kind=="ready"&&!read_mailbox(mailbox("offer",slot,xid),"offer",slot,xid).ok()){
            error.clear();fs::remove(path,error);continue;
        }
        if(kind=="offer")found.push_back({fs::last_write_time(path,error),xid});
    }
    error.clear();
    for(const auto& entry:fs::directory_iterator(outgoing,error)){
        if(error)break;
        fs::path path=entry.path();std::string name=path.filename().string();size_t dot=name.find('.');
        std::string xid=dot==std::string::npos?"":name.substr(0,dot);
        if(!vmb::xid(xid)||name.substr(dot+1)!="answer"||old_file(path,C.mailbox_ttl_sec)||
           !read_mailbox(path,"answer",slot,xid).ok()){
            error.clear();fs::remove_all(path,error);
        }
    }
    std::sort(found.begin(),found.end(),[](const auto& a,const auto& b){return a.first>b.first;});
    while(found.size()>(size_t)C.mailbox_max_pending){
        remove_transaction(slot,found.back().second);found.pop_back();
    }
    std::vector<std::string> out;
    for(const auto& item:found)out.push_back(item.second);
    return out;
}

static bool write_mailbox(const fs::path& path,const std::string& line){
    if(line.empty()||line.size()>(size_t)C.mailbox_record_bytes)return false;
    std::error_code error;
    if(!fs::is_directory(path.parent_path(),error)||error)return false;
    std::string nonce=vtp::random_hex(8);if(nonce.empty())return false;
    fs::path temporary=path.parent_path()/("."+path.filename().string()+'.'+nonce+".tmp");
    std::ofstream out(temporary,std::ios::trunc);
    out<<line<<'\n';
    out.close();
    if(!out)return false;
    if(chmod(temporary.c_str(),0444)){fs::remove(temporary);return false;}
    fs::rename(temporary,path,error);
    if(error){fs::remove(temporary);return false;}
    return true;
}

static int exchange(const std::string& role,int id){
    Record offer=make_offer(role,id);
    if(!offer.ok()||offer.get("XID").empty()){
        std::cerr<<"CAP2_ERROR random exchange id unavailable\n";
        return 10;
    }
    fs::create_directories(fs::path(C.sync)/role/std::to_string(id));
    std::ofstream(fs::path(C.sync)/role/std::to_string(id)/"last.offer")
        <<vtp::serialize(offer)<<'\n';
    std::string xid=offer.get("XID");
    int offer_delivery=sync_command("cap2-put",role,id,"offer",xid,vtp::serialize(offer));
    // A bounded SFTP client can time out while its already-delivered record is
    // closing over Tor.  Only a correlated, authenticated ANSWER can advance
    // this exchange, so it is both safer and faster to let that proof decide.
    if(offer_delivery)
        std::cerr<<"CAP2_NOTICE offer SFTP exit="<<offer_delivery
                 <<"; awaiting authenticated answer\n";
    for(int attempt=0;attempt<3;attempt++){
        std::this_thread::sleep_for(std::chrono::milliseconds(350));
        if(sync_command("cap2-get",role,id,"answer",xid))continue;
        Record answer=vtp::parse_record(read1(local_sync_file(role,id,"answer",xid)));
        if(vtp::correlated(offer,answer)&&authenticate(answer,pair_secret(role,id))){
            Record ready=make_ready(role,id,offer,answer);
            if(!ready.ok())return 13;
            int ready_delivery=sync_command("cap2-put",role,id,"ready",xid,vtp::serialize(ready));
            // The responder authenticates READY before trying a transport and
            // this side still requires a real WG/Tor proof before selection.
            // Therefore a late SFTP exit cannot create a false Up state.
            if(ready_delivery)
                std::cerr<<"CAP2_NOTICE ready SFTP exit="<<ready_delivery
                         <<"; deferring confirmation to transport proof\n";
            std::cout<<vtp::serialize(answer)<<'\n';
            return 0;
        }
    }
    std::cerr<<"CAP2_ERROR no correlated answer for xid="<<offer.get("XID")<<"\n";
    return 12;
}

static int respond(const std::string& role,int id){
    int cert_slot=certificate_slot(role,id);
    fs::create_directories("/run/voider/cap2");
    fs::path accepted="/run/voider/cap2/"+role+'-'+std::to_string(id)+".remote";
    Record previous=vtp::parse_record(read1(accepted));
    std::string secret=pair_secret(role,id);
    for(const auto& xid:pending_offers(cert_slot)){
        Record offer=read_mailbox(mailbox("offer",cert_slot,xid),"offer",cert_slot,xid);
        if(!offer.ok())continue;
        if(!authenticate(offer,secret)||already_consumed(offer,previous)){
            remove_transaction(cert_slot,xid);
            continue;
        }
        Record answer=read_mailbox(mailbox("answer",cert_slot,xid),"answer",cert_slot,xid);
        if(!vtp::correlated(offer,answer)||!authenticate(answer,secret)){
            answer=make_answer(role,id,offer);
            if(!write_mailbox(mailbox("answer",cert_slot,xid),vtp::serialize(answer))){
                std::cerr<<"CAP2_ERROR answer mailbox write failed\n";
                return 2;
            }
        }
        Record ready=read_mailbox(mailbox("ready",cert_slot,xid),"ready",cert_slot,xid);
        if(!vtp::acknowledged(offer,answer,ready)||!authenticate(ready,secret))continue;
        Record peer=offer;
        peer.fields["PLAN"]=answer.get("PLAN");
        std::ofstream(accepted)<<vtp::serialize(peer)<<'\n';
        remove_transaction(cert_slot,xid);
        std::cout<<vtp::serialize(peer)<<'\n';
        return 0;
    }
    return 1;
}

static int selftest(){
    Record offer;
    offer.fields={{"AVAILABLE",vta::all()},{"CERT_SLOT","7"},
                  {"TYPE","OFFER"},{"V","2"},
                  {"XID","00112233445566778899aabbccddeeff"}};
    Record parsed=vtp::parse_record(vtp::serialize(offer));
    Record answer=offer;
    answer.fields["TYPE"]="ANSWER";
    answer.fields["OFFER_HASH"]=vtp::sha256(vtp::serialize(offer));
    answer.fields["PLAN"]="direct4,direct6,hp4,hp6,tor";
    if(!parsed.ok()||!vtp::correlated(offer,answer))return 1;
    answer.fields["XID"]="ffeeddccbbaa99887766554433221100";
    if(vtp::correlated(offer,answer))return 2;
    answer.fields["XID"]=offer.get("XID");
    answer.fields["OFFER_HASH"]=std::string(64,'0');
    if(vtp::correlated(offer,answer))return 3;
    if(vtp::parse_record(vtp::serialize(offer)+" XID=00112233445566778899aabbccddeeff").ok())return 4;
    if(vtp::parse_record("CAP2 V=2 TYPE=ANSWER XID=bad CERT_SLOT=7 OFFER_HASH=bad").ok())return 5;
    if(vtp::parse_record(vtp::serialize(offer)+" PUB4=1.2.3.4;command").ok())return 6;
    Record signed_offer=offer;
    signed_offer.fields["AUTH"]=record_mac(signed_offer,"test-pair-secret");
    if(!authenticate(signed_offer,"test-pair-secret")||authenticate(signed_offer,"other-secret"))return 7;
    Record local=offer;
    if(plan(offer,local)!="direct4,direct6,hp4,hp6,tor")return 8;
    local.fields["AVAILABLE"]="tor";
    if(plan(offer,local)!="tor")return 9;
    offer.fields["AVAILABLE"]="lan4";
    if(!plan(offer,local).empty())return 10;
    offer.fields["AVAILABLE"]=vta::all();
    std::string saved=C.ps;
    fs::path directory=fs::path("/tmp")/("voider-cap2-selftest-"+std::to_string(getpid()));
    fs::create_directories(directory);
    C.ps=directory.string();
    std::ofstream(directory/"pair.psk")<<"fixture-pair-secret\n";
    std::ofstream(directory/"42.conf")<<"REMOTE_CERT_INDEX=77\nLOCAL_ADDR=172.31.0.66/24\nPRESHARED_KEY="
                                      <<(directory/"pair.psk").string()<<"\nTUNMODE=secure\nAEAD=AES-256-GCM\n";
    Record imported=local_record("OFFER","server",42,"00112233445566778899aabbccddeeff");
    sign(imported,"server",42);
    bool slot_ok=certificate_slot("server",42)==77&&imported.get("CERT_SLOT")=="77"&&
                 imported.get("TUNMODE")=="fp-only"&&imported.get("AEAD")=="none"&&
                 imported.get("AVAILABLE")==vta::all()&&
                 !imported.fields.count("ALLOW")&&!imported.fields.count("DIRECT4")&&
                 !imported.fields.count("DIRECT6")&&!imported.fields.count("HP4")&&
                 !imported.fields.count("HP6")&&!imported.fields.count("TOR")&&
                 authenticate(imported,"fixture-pair-secret");
    C.ps=saved;
    fs::remove_all(directory);
    if(!slot_ok)return 11;
    if(imported.fields.count("LAN4")||imported.fields.count("LAN6")||
       imported.fields.count("TS")||imported.fields.count("PREFRUN_AT"))return 12;
    Record previous=offer;
    if(!already_consumed(offer,previous))return 13;
    previous.fields["XID"]="ffeeddccbbaa99887766554433221100";
    if(already_consumed(offer,previous))return 14;
    Record good_answer=offer;
    good_answer.fields["TYPE"]="ANSWER";
    good_answer.fields["OFFER_HASH"]=vtp::sha256(vtp::serialize(offer));
    good_answer.fields["PLAN"]="tor";
    Record ready;
    ready.fields={{"ANSWER_HASH",vtp::sha256(vtp::serialize(good_answer))},
                  {"CERT_SLOT",offer.get("CERT_SLOT")},
                  {"OFFER_HASH",vtp::sha256(vtp::serialize(offer))},
                  {"TYPE","READY"},{"V","2"},{"XID",offer.get("XID")}};
    ready=vtp::parse_record(vtp::serialize(ready));
    if(!vtp::acknowledged(offer,good_answer,ready))return 15;
    ready.fields["ANSWER_HASH"]=std::string(64,'0');
    if(vtp::acknowledged(offer,good_answer,ready))return 16;

    std::string saved_base=C.sftp_base;
    int saved_max=C.mailbox_max_pending,saved_bytes=C.mailbox_record_bytes;
    fs::path boxes=fs::path("/tmp")/("voider-cap2-mailbox-"+std::to_string(getpid()));
    fs::remove_all(boxes);C.sftp_base=boxes.string();C.mailbox_max_pending=2;C.mailbox_record_bytes=1024;
    for(int slot:{7,8}){fs::create_directories(vmb::root(C,slot)/"in");fs::create_directories(vmb::root(C,slot)/"out");}
    auto put_offer=[&](int slot,const std::string& xid){
        Record value=offer;value.fields["CERT_SLOT"]=std::to_string(slot);value.fields["XID"]=xid;
        std::ofstream(mailbox("offer",slot,xid))<<vtp::serialize(value)<<'\n';
    };
    std::string xid7="11112222333344445555666677778888",xid8="88887777666655554444333322221111";
    put_offer(7,xid7);put_offer(8,xid8);
    fs::path fresh_upload=vmb::root(C,7)/"in/.11111111111111111111111111111111.offer.0123456789abcdef.tmp";
    std::ofstream(fresh_upload).close();
    auto only7=pending_offers(7);
    if(only7.size()!=1||only7[0]!=xid7||!fs::exists(mailbox("offer",8,xid8))||
       !fs::exists(fresh_upload))return 17;
    fs::remove(fresh_upload);
    fs::path traversal=vmb::root(C,7)/"in/bad.offer";
    fs::create_symlink(mailbox("offer",8,xid8),traversal);
    pending_offers(7);
    if(fs::exists(traversal))return 18;
    put_offer(7,"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    put_offer(7,"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    if(pending_offers(7).size()!=2)return 19;
    fs::path oversized=vmb::root(C,7)/"in/cccccccccccccccccccccccccccccccc.offer";
    std::ofstream(oversized)<<std::string(1025,'x');pending_offers(7);
    if(fs::exists(oversized))return 20;
    C.sftp_base=saved_base;C.mailbox_max_pending=saved_max;C.mailbox_record_bytes=saved_bytes;
    fs::remove_all(boxes);
    std::cout<<"CAP2_SELFTEST_OK mailbox-isolation=2 pending-bound=2\n";
    return 0;
}

int main(int argc,char** argv){
    C=cfg();
    if(argc==2&&std::string(argv[1])=="selftest")return selftest();
    if(argc<4){
        std::cerr<<"usage: voider-cap2 exchange|respond|print ROLE ID | selftest\n";
        return 2;
    }
    std::string action=argv[1],role=argv[2];
    int id=toi(argv[3],0);
    if((role!="client"&&role!="server")||id<2||id>254)return 2;
    if(action=="exchange")return exchange(role,id);
    if(action=="respond")return respond(role,id);
    if(action=="print"){
        Record offer=make_offer(role,id);
        std::cout<<vtp::serialize(offer)<<'\n';
        return offer.ok()&&!offer.get("XID").empty()?0:1;
    }
    return 2;
}
