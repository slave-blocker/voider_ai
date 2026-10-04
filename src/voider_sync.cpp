// Strict, bounded SFTP client for CAP2's per-XID mailbox records.

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "voider_config.hpp"
#include "voider_util.hpp"

#include "voider_mailbox.hpp"
#include "voider_transport_protocol.hpp"

using vu::shq;

namespace fs=std::filesystem;

static std::string peer_conf(const Cfg& c,const std::string& role,int id){
    return (role=="client"?c.pc:c.ps)+"/"+std::to_string(id)+".conf";
}

static int certificate_slot(const Cfg& c,const std::string& role,int id){
    if(role=="client")return id;
    int slot=toi(val(peer_conf(c,role,id),"REMOTE_CERT_INDEX"),0);
    if(vmb::slot_ok(slot))return slot;
    std::string address=val(peer_conf(c,role,id),"LOCAL_ADDR");
    unsigned a,b,d,e;
    if(sscanf(address.c_str(),"%u.%u.%u.%u",&a,&b,&d,&e)==4&&
       a==172&&b==31&&d==0&&e>=2&&e<=254)return static_cast<int>(e);
    return id;
}

static std::string setting(const Cfg& c,const std::string& role,int id,
                           const std::string& key){
    return val(peer_conf(c,role,id),key);
}

static bool regular_private_key(const fs::path& path){
    struct stat status{};
    return lstat(path.c_str(),&status)==0&&S_ISREG(status.st_mode)&&status.st_nlink==1;
}

static int transfer(const Cfg& c,const std::string& role,int id,const std::string& batch){
    int slot=certificate_slot(c,role,id);
    std::string onion=setting(c,role,id,"SFTP_ONION");
    std::string key=setting(c,role,id,"SFTP_KEY");
    std::string hosts=setting(c,role,id,"KNOWN_HOSTS");
    std::string user=setting(c,role,id,"SFTP_USER");
    std::string expected=vmb::user("client",slot);
    if(onion.empty()||!vmb::slot_ok(slot)||user!=expected||!regular_private_key(key)||hosts.empty()){
        std::cerr<<"SYNC_ERROR incomplete pairing-bound SFTP identity for "<<role<<'/'<<id<<'\n';
        return 5;
    }
    fs::path directory=fs::path(c.sync)/role/std::to_string(id);
    fs::create_directories(directory);
    fs::path batch_file=directory/(".batch-"+std::to_string(getpid()));
    std::ofstream(batch_file,std::ios::trunc)<<batch;
    // A Tor onion SFTP round trip can exceed 20 seconds even after the
    // transfer succeeds. Keep the operation bounded without discarding it.
    std::string command="timeout 35 sftp -q -b "+shq(batch_file.string())+
        " -oBatchMode=yes -oConnectTimeout=10 -oConnectionAttempts=1"+
        " -oProxyCommand="+shq("nc -x "+c.socks_host+":"+std::to_string(c.socks_port)+" -X 5 %h %p")+
        " -oStrictHostKeyChecking=yes -oUserKnownHostsFile="+shq(hosts)+
        " -i "+shq(key)+' '+user+'@'+shq(onion);
    int status=std::system(command.c_str());
    fs::remove(batch_file);
    int rc=status>=0&&WIFEXITED(status)?WEXITSTATUS(status):126;
    if(rc)std::cerr<<"SYNC_ERROR SFTP transfer failed for "<<role<<'/'<<id<<'\n';
    return rc;
}

static fs::path local_path(const Cfg& c,const std::string& role,int id,
                           const std::string& xid,const std::string& kind,
                           const std::string& suffix){
    return fs::path(c.sync)/role/std::to_string(id)/(xid+'.'+kind+suffix);
}

static bool validated_record(const Cfg& c,const fs::path& path,const std::string& kind,
                             const std::string& xid,int slot,vtp::Record* parsed=nullptr){
    struct stat status{};
    if(lstat(path.c_str(),&status)||!S_ISREG(status.st_mode)||status.st_nlink!=1||
       status.st_size<=0||status.st_size>c.mailbox_record_bytes)return false;
    std::ifstream file(path,std::ios::binary);
    std::string body{std::istreambuf_iterator<char>(file),std::istreambuf_iterator<char>()};
    body=trim(body);
    auto record=vtp::parse_record(body);
    std::string expected=kind=="offer"?"OFFER":kind=="answer"?"ANSWER":"READY";
    bool ok=record.ok()&&record.get("TYPE")==expected&&record.get("XID")==xid&&
            record.get("CERT_SLOT")==std::to_string(slot);
    if(ok&&parsed)*parsed=record;
    return ok;
}

static int cap2(const Cfg& c,const std::string& action,const std::string& role,int id,
                const std::string& kind,const std::string& xid,const std::string& payload){
    bool put=action=="cap2-put";
    if(!vmb::xid(xid)||(put&&(kind!="offer"&&kind!="ready"))||
       (!put&&kind!="answer"))return 2;
    int slot=certificate_slot(c,role,id);
    if(!vmb::slot_ok(slot))return 2;
    fs::path directory=fs::path(c.sync)/role/std::to_string(id);
    fs::create_directories(directory);
    std::string remote=std::string(put?"/in/":"/out/")+xid+'.'+kind;
    if(put){
        if(payload.empty()||payload.size()>(size_t)c.mailbox_record_bytes||
           payload.find('\n')!=std::string::npos)return 2;
        fs::path local=local_path(c,role,id,xid,kind,".local");
        std::ofstream out(local,std::ios::trunc);out<<payload<<'\n';out.close();
        chmod(local.c_str(),0600);
        if(!validated_record(c,local,kind,xid,slot)){fs::remove(local);return 2;}
        std::string nonce=vtp::random_hex(8);
        if(nonce.empty())return 2;
        std::string temporary="/in/."+xid+'.'+kind+'.'+nonce+".tmp";
        int rc=transfer(c,role,id,"put "+local.string()+' '+temporary+"\nrename "+temporary+' '+remote+"\n");
        fs::remove(local);
        return rc;
    }
    fs::path final=local_path(c,role,id,xid,kind,".remote");
    fs::path temporary=local_path(c,role,id,xid,kind,".partial");
    fs::remove(final);fs::remove(temporary);
    int rc=transfer(c,role,id,"get "+remote+' '+temporary.string()+"\n");
    // A complete, authenticated-shape record can arrive just before the
    // bounded SSH process times out while closing. CAP2 still verifies HMAC
    // and offer/answer correlation before it can advance.
    if(!validated_record(c,temporary,kind,xid,slot)){
        fs::remove(temporary);
        return rc?rc:6;
    }
    std::error_code error;
    fs::rename(temporary,final,error);
    if(error){fs::remove(temporary);return 6;}
    if(rc)std::cerr<<"SYNC_NOTICE validated record survived late SFTP failure for "
                   <<role<<'/'<<id<<'\n';
    return 0;
}

static int selftest(){
    Cfg c;c.mailbox_record_bytes=512;
    fs::path root=fs::path("/tmp")/("voider-sync-selftest-"+std::to_string(getpid()));
    fs::remove_all(root);fs::create_directories(root);
    std::string xid="00112233445566778899aabbccddeeff";
    vtp::Record answer;answer.fields={{"AVAILABLE",vta::all()},{"CERT_SLOT","7"},
        {"OFFER_HASH",std::string(64,'a')},{"PLAN","hp4,tor"},
        {"TYPE","ANSWER"},{"V","2"},{"XID",xid}};
    fs::path path=root/"answer";
    std::ofstream(path)<<vtp::serialize(answer)<<'\n';
    int failures=0;
    if(!validated_record(c,path,"answer",xid,7))failures++;
    fs::path link=root/"link";fs::create_symlink(path,link);
    if(validated_record(c,link,"answer",xid,7))failures++;
    if(validated_record(c,path,"answer",std::string(32,'f'),7))failures++;
    std::ofstream(path,std::ios::trunc)<<std::string(513,'x');
    if(validated_record(c,path,"answer",xid,7))failures++;
    if(vmb::user("client",7)!="vmc007"||vmb::user("server",7)!="vms007"||
       vmb::root(c,"client",7)==vmb::root(c,"server",7)||
       vmb::root(c,"client",7)==vmb::root(c,"client",8)||
       !vmb::xid(xid)||vmb::xid("../bad"))failures++;
    fs::remove_all(root);
    std::cout<<"SYNC_TEST cases=7 fails="<<failures<<"\n";
    return failures?1:0;
}

int main(int argc,char** argv){
    if(argc==2&&std::string(argv[1])=="selftest")return selftest();
    if(argc<6)return 2;
    Cfg c=cfg();
    std::string action=argv[1],role=argv[2],kind=argv[4],xid=argv[5];
    int id=toi(argv[3],0);
    if((role!="client"&&role!="server")||id<2||id>254)return 2;
    if(action=="cap2-put")return argc==7?cap2(c,action,role,id,kind,xid,argv[6]):2;
    if(action=="cap2-get")return argc==6?cap2(c,action,role,id,kind,xid,""):2;
    return 2;
}
