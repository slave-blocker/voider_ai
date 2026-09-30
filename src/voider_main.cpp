#include <array>
#include <cctype>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>

#include "voider_config.hpp"
#include "voider_contacts.hpp"
#include "voider_mailbox.hpp"
#include "voider_transport_allowlist.hpp"
#include "voider_util.hpp"

using vu::cap;
using vu::hex64;
using vu::read1;
using vu::run;
using vu::shq;

namespace fs=std::filesystem;
static Cfg C;

static std::string fingerprint_result(const std::string&p){
    std::ifstream f(p);
    std::string line,fp;
    while(std::getline(f,line)){
        line=trim(line);
        if(hex64(line))fp=line;
    }
    return fp;
}
static std::string field(const std::string&p,const std::string&key){
    std::ifstream f(p);
    std::string line;
    while(std::getline(f,line)){
        auto at=line.find('=');
        if(at==std::string::npos)at=line.find_first_of(" \t");
        if(at!=std::string::npos&&trim(line.substr(0,at))==key)return trim(line.substr(at+1));
    }
    return "";
}
static void log(const std::string&s){
    fs::create_directories("/run/voider");
    std::ofstream("/run/voider/main-action.log",std::ios::app)<<s<<"\n";
}
static void operation(const std::string&state,const std::string&message,const std::string&detail=""){
    fs::create_directories("/run/voider");
    std::ofstream f("/run/voider/operation.status",std::ios::trunc);
    f<<"STATE="<<state<<"\nMESSAGE="<<message<<"\n";
    if(!detail.empty())f<<"DETAIL="<<detail<<"\n";
}
static int root(){
    if(geteuid()!=0){std::cerr<<"MAIN_ERROR root required\n";return 1;}
    return 0;
}
static void ensure(){
    for(auto d:{
        "/etc/voider/peers/clients.d","/etc/voider/peers/servers.d",
        "/etc/voider/peers/material","/etc/voider/certs","/etc/voider/private","/etc/voider/node",
        "/etc/voider/certs/mailboxes","/var/sftp",
        "/etc/voider/certs/rejected","/etc/voider/certs/fingerprints","/etc/voider/imports"
    })fs::create_directories(d);
}
static bool occupied(const std::string&role,int slot){
    return fs::exists((role=="client"?C.pc:C.ps)+"/"+std::to_string(slot)+".conf");
}
static int free_slot(const std::string&role){
    for(int i=2;i<=254;i++)if(!occupied(role,i))return i;
    return 0;
}
static int persist(const std::string&reason=""){ return run("/usr/local/sbin/voider-integrity state-commit "+shq(reason)+" >/run/voider/last-state-commit 2>&1"); }

static std::string usb_error(const std::string&path,const std::string&fallback){
    std::ifstream input(path);std::string line,last;
    while(std::getline(input,line))if(!trim(line).empty())last=trim(line);
    for(const char*message:{"USB NOT READY","USB DISCONNECTED","USB READ FAILED","USB WRITE FAILED","USB IS MOUNTED","USB NOT SAFE","USB CHANGED","USB BUSY",
         "USB MOUNT FAILED","USB UNMOUNT FAILED","USB SYNC FAILED","USB VERIFY FAILED",
         "USB FORMAT FAILED","USB PARTITION FAILED","USB TOOL TIMEOUT","SYSTEM DISK",
         "STATE SAVE FAILED","USB CONFIRMATION REQUIRED","RESTORE PENDING"})
        if(last==message)return message;
    if(last=="USB_AMBIGUOUS")return "ONE USB KEY ONLY";
    if(last=="USB_NONE")return "USB NOT READY";
    if(last.rfind("USB_INVALID",0)==0)return "INVALID BUNDLE";
    if(last=="bundle missing")return "NO BUNDLE";
    return fallback;
}

static int language_save(const std::string&language){
    if(root()||(language!="en"&&language!="de"&&language!="bg"))return 2;
    const std::string path="/etc/voider/node/language";
    bool existed=fs::exists(path);std::string previous=read1(path);
    fs::create_directories(fs::path(path).parent_path());
    {std::ofstream out(path+".new");out<<language<<"\n";out.flush();if(!out)return 72;}
    fs::rename(path+".new",path);
    if(persist("LANGUAGE")){
        if(existed){std::ofstream out(path+".new");out<<previous<<"\n";out.close();fs::rename(path+".new",path);}else fs::remove(path);
        operation("failed","STATE SAVE FAILED");return 72;
    }
    std::ofstream("/run/voider/ui.language")<<language<<"\n";
    operation("done","LANGUAGE SAVED");return 0;
}
static std::string admission_path(const std::string&role,int slot){return "/run/voider/pending-"+role+"-"+std::to_string(slot);}
static bool block_admission(const std::string&role,int slot){
    std::ofstream out(admission_path(role,slot));out<<"pending\n";out.flush();return (bool)out;
}
static int create_mailboxes(int slot){
    return run("/usr/local/sbin/voider-sftp-setup slot "+std::to_string(slot));
}

static void remove_mailboxes(int slot){
    run("/usr/local/sbin/voider-sftp-setup slot-remove "+std::to_string(slot)+" >/dev/null 2>&1 || true");
}

static int create_client(int slot){
    if(!slot)return 70;
    if(run("/usr/local/sbin/voider-peerctl create client "+std::to_string(slot)))return 71;
    if(create_mailboxes(slot))return 72;
    return 0;
}
static void rollback_client(int slot){
    // Keep admission blocked until all unpersisted material has been removed.
    run("/usr/local/sbin/voider-peerctl remove client "+std::to_string(slot)+" >/dev/null 2>&1 || true");
    remove_mailboxes(slot);
    fs::remove(C.usb_fp_dir+"/client-"+std::to_string(slot)+".sha256");
    if(!occupied("client",slot))fs::remove(admission_path("client",slot));
}
static int pair_export(){
    if(root())return 1;
    ensure();
    {
        std::ifstream pending("/run/voider/pairing.pending");
        std::string role;int oldslot=0;pending>>role>>oldslot;
        if(role=="client"&&oldslot>=2&&oldslot<=254){
            // A crash after commit must not delete a saved relationship. Never
            // silently publish an earlier unfinished export on a later SHARE.
            std::string path=C.pc+"/"+std::to_string(oldslot)+".conf";
            std::string saved=cap("tar -xOzf "+shq(C.state_tar)+" "+shq(path.substr(1))+" 2>/dev/null");
            if(saved.empty()||saved!=trim(vu::read_file(path)))rollback_client(oldslot);
            else fs::remove(admission_path("client",oldslot));
        }
        fs::remove("/run/voider/pairing.pending");
    }
    std::string dev=field("/run/voider/usb.selection","DEVICE");
    std::string token=field("/run/voider/usb.selection","TOKEN");
    if(dev.empty()||token.empty()){operation("failed","USB NOT SAFE");return 23;}
    int slot=free_slot("client");
    if(!slot){operation("failed","CONNECTIONS FULL");return 70;}
    std::ofstream("/run/voider/pairing.device",std::ios::trunc)<<dev<<"\n";
    operation("working","MAKING VOIDER KEY","0");
    std::ofstream("/run/voider/pairing.pending")<<"client "<<slot<<"\n";
    if(!block_admission("client",slot)){operation("failed","STATE SAVE FAILED");return 72;}
    const bool had_key=fs::exists("/etc/voider/private/wg0.key");
    const bool had_public=fs::exists("/etc/voider/private/wg0.pub");
    auto fail=[&](int rc,const std::string&message){
        rollback_client(slot);
        // The first SHARE can create this shared identity. Retain any identity
        // that existed before the operation, including one used by other peers.
        if(!had_key)fs::remove("/etc/voider/private/wg0.key");
        if(!had_public)fs::remove("/etc/voider/private/wg0.pub");
        fs::remove("/run/voider/pairing.pending");
        fs::remove("/run/voider/pairing.device");
        operation("failed",message);
        return rc;
    };
    int rc=create_client(slot);
    if(rc)return fail(rc,"PAIRING FAILED");
    operation("working","ERASING VOIDER KEY","25");
    rc=run("/usr/local/sbin/voider-usb export client "+std::to_string(slot)+" "+shq(dev)+" "+shq(token)+
           " >/run/voider/last-usb-export 2>&1");
    if(rc)return fail(rc,usb_error("/run/voider/last-usb-export","USB WRITE FAILED"));
    operation("working","SAVING CONNECTION","90");
    if(persist("PAIRING"))return fail(72,"STATE SAVE FAILED");
    fs::remove(admission_path("client",slot));
    std::ofstream("/run/voider/pairing.slot")<<"client "<<slot<<" "<<(long)time(nullptr)<<"\n";
    fs::remove("/run/voider/pairing.pending");
    operation("remove","SAFE TO REMOVE","100");
    log("pair-export client "+std::to_string(slot));
    return 0;
}

static bool valid_admin_key(const std::string&path){
    std::error_code ec;
    return fs::is_regular_file(path,ec)&&!fs::is_symlink(path,ec)&&
           !cap("ssh-keygen -lf "+shq(path)+" 2>/dev/null").empty();
}
static bool copy_admin_key(const std::string&src,const std::string&dst){
    // Never truncate the active key on a partial copy or permission failure.
    std::error_code ec;std::string next=dst+".new";
    fs::create_directories(fs::path(dst).parent_path(),ec);
    if(ec)return false;
    fs::remove(next,ec);ec.clear();
    fs::copy_file(src,next,fs::copy_options::none,ec);
    if(!ec&&chmod(next.c_str(),0600)==0&&valid_admin_key(next)){
        fs::rename(next,dst,ec);if(!ec)return true;
    }
    fs::remove(next,ec);return false;
}
static int reload_admin_firewall(){
    return run("/usr/local/sbin/voiderctl rules reload >/run/voider/last-admin-firewall 2>&1");
}
static std::string config_path(){
    const char*p=getenv("VOIDER_CONFIG");
    return p&&*p?p:"/etc/voider/voider.conf";
}
static bool set_admin_switch(bool enabled){
    return vu::replace_config_value(config_path(),"ADMIN_SSH_LAN",enabled?"1":"0");
}
static int admin_ssh_set(bool enabled){
    if(root())return 1;
    if(enabled&&!valid_admin_key(C.admin_auth_keys)){
        operation("failed","NO ADMIN KEY");
        return 60;
    }
    bool old=C.admin_ssh_lan!=0;
    if(old==enabled){
        operation("done",enabled?"SSH ALREADY ON":"SSH ALREADY OFF");
        return 0;
    }
    if(!set_admin_switch(enabled)){
        operation("failed","SSH SETTING FAILED");
        return 72;
    }
    auto restore=[&](){set_admin_switch(old);reload_admin_firewall();};
    if(reload_admin_firewall()){
        restore();operation("failed","SSH SWITCH FAILED");return 73;
    }
    if(persist(enabled?"MANAGEMENT SSH ENABLED":"MANAGEMENT SSH DISABLED")){
        restore();operation("failed","STATE SAVE FAILED");return 72;
    }
    operation("done",enabled?"MANAGEMENT SSH ON":"MANAGEMENT SSH OFF");
    log(enabled?"admin-ssh-enable":"admin-ssh-disable");
    return 0;
}
static int admin_key_new(){
    if(root())return 1;
    std::string dev=field("/run/voider/usb.selection","DEVICE");
    std::string token=field("/run/voider/usb.selection","TOKEN");
    if(dev.empty()||token.empty()){operation("failed","USB NOT SAFE");return 23;}
    operation("working","MAKING LOGIN KEY","25");
    int rc=run("/usr/local/sbin/voider-usb admin-new "+shq(dev)+" "+shq(token)+
               " >/run/voider/last-admin-key-new 2>&1");
    const std::string generated="/run/voider/admin-key-new.pub";
    if(rc||!valid_admin_key(generated)){
        fs::remove(generated);operation("failed",rc?usb_error("/run/voider/last-admin-key-new","KEY CREATION FAILED"):"KEY CREATION FAILED");return rc?rc:62;
    }
    const std::string old="/run/voider/admin-key-old.pub";
    fs::remove(old);
    bool had_old=valid_admin_key(C.admin_auth_keys);
    bool old_enabled=C.admin_ssh_lan!=0;
    if(had_old&&!copy_admin_key(C.admin_auth_keys,old)){
        fs::remove(generated);operation("failed","KEY CREATION FAILED");return 63;
    }
    if(!copy_admin_key(generated,C.admin_auth_keys)){
        fs::remove(generated);fs::remove(old);operation("failed","KEY CREATION FAILED");return 63;
    }
    fs::remove(generated);
    if(!set_admin_switch(true)){
        if(had_old)copy_admin_key(old,C.admin_auth_keys);else fs::remove(C.admin_auth_keys);
        fs::remove(old);operation("failed","SSH SETTING FAILED");return 72;
    }
    auto restore=[&](){
        if(had_old)copy_admin_key(old,C.admin_auth_keys);else fs::remove(C.admin_auth_keys);
        set_admin_switch(old_enabled);
        reload_admin_firewall();fs::remove(old);
    };
    if(reload_admin_firewall()){
        restore();operation("failed","SSH START FAILED");return 73;
    }
    if(persist("ADMIN KEY - USB SAFE")){
        restore();operation("failed","STATE SAVE FAILED");return 72;
    }
    fs::remove(old);
    operation("remove","LOGIN KEY ON USB","100");
    log("admin-key-new");
    return 0;
}
static int admin_key_revoke(){
    if(root())return 1;
    bool old_enabled=C.admin_ssh_lan!=0;
    if(!fs::exists(C.admin_auth_keys)){
        if(!old_enabled){operation("done","NO ADMIN KEY");return 0;}
        return admin_ssh_set(false);
    }
    if(!valid_admin_key(C.admin_auth_keys)){operation("failed","ADMIN KEY INVALID");return 60;}
    const std::string old="/run/voider/admin-key-old.pub";
    fs::remove(old);
    if(!copy_admin_key(C.admin_auth_keys,old)){operation("failed","STATE SAVE FAILED");return 72;}
    fs::remove(C.admin_auth_keys);
    if(!set_admin_switch(false)){
        copy_admin_key(old,C.admin_auth_keys);fs::remove(old);operation("failed","SSH SETTING FAILED");return 72;
    }
    int rc=reload_admin_firewall()?73:0;
    if(!rc&&persist("ADMIN SSH KEY REVOKED"))rc=72;
    if(rc){
        copy_admin_key(old,C.admin_auth_keys);set_admin_switch(old_enabled);reload_admin_firewall();fs::remove(old);
        operation("failed",rc==73?"SSH STOP FAILED":"STATE SAVE FAILED");return rc;
    }
    fs::remove(old);
    operation("done","SSH KEY REMOVED");
    log("admin-key-revoke");
    return 0;
}

static bool rejected(const std::string&fp){ return fs::exists(C.usb_reject_dir+"/"+fp); }
static bool duplicate_fp(const std::string&fp){
    if(!fs::exists(C.usb_fp_dir))return false;
    for(const auto&e:fs::directory_iterator(C.usb_fp_dir))
        if(e.is_regular_file()&&read1(e.path().string())==fp)return true;
    return false;
}
static int import_device(const std::string&dev){
    if(root())return 1;
    ensure();
    operation("working","CHECKING VOIDER KEY","10");
    std::string fpfile="/run/voider/usb.fingerprint";
    int probe=run("/usr/local/sbin/voider-usb fingerprint "+shq(dev)+" >"+shq(fpfile)+" 2>/run/voider/last-usb-probe");
    if(probe){
        operation("failed",usb_error("/run/voider/last-usb-probe","USB READ FAILED"));
        return probe;
    }
    std::string fp=fingerprint_result(fpfile);
    if(fp.empty()){operation("failed","INVALID BUNDLE");return 40;}
    if(rejected(fp)){operation("failed","BUNDLE REVOKED");return 73;}
    if(duplicate_fp(fp)){
        operation("remove","ALREADY ADDED","100");
        std::cout<<"PAIR_DUPLICATE\n";
        return 10;
    }
    int slot=free_slot("server");
    if(!slot){operation("failed","CONNECTIONS FULL");return 70;}
    operation("working","ADDING CONNECTION","45");
    if(!block_admission("server",slot)){operation("failed","STATE SAVE FAILED");return 72;}
    auto rollback=[&]{
        run("/usr/local/sbin/voider-peerctl remove server "+std::to_string(slot)+" >/dev/null 2>&1 || true");
        fs::remove(C.usb_fp_dir+"/import-server-"+std::to_string(slot)+".sha256");
        fs::remove("/etc/voider/private/sftp-server-"+std::to_string(slot)+".key");
        fs::remove_all(C.usb_import_dir+"/"+fp);
        if(!occupied("server",slot))fs::remove(admission_path("server",slot));
    };
    int rc=run("/usr/local/sbin/voider-usb import server "+std::to_string(slot)+" "+shq(dev)+" "+shq(fp)+
               " >/run/voider/last-usb-import 2>&1");
    if(rc){
        // A duplicate is detected before importing and belongs to an existing
        // relationship; its shared import directory must remain intact.
        if(rc==10)fs::remove(admission_path("server",slot));else rollback();
        operation("failed",rc==10?"ALREADY ADDED":usb_error("/run/voider/last-usb-import","USB READ FAILED"));return rc;
    }
    operation("working","SAVING CONNECTION","90");
    if(persist("IMPORT")){
        rollback();
        operation("failed","STATE SAVE FAILED");
        return 72;
    }
    fs::remove(admission_path("server",slot));
    std::ofstream("/run/voider/pairing.slot")<<"server "<<slot<<" "<<(long)time(nullptr)<<"\n";
    operation("remove","SAFE TO REMOVE","100");
    log("pair-import server "+std::to_string(slot));
    return 0;
}

static void reject_fp(const std::string&role,int slot){
    std::string fp=vc::fingerprint_for(C,role,slot);
    if(fp.empty())return;
    fs::create_directories(C.usb_reject_dir);
    std::ofstream(C.usb_reject_dir+"/"+fp)<<"REVOKED\n";
}
static int remove_contact(const std::string&role,int slot){
    if(root())return 1;
    if((role!="client"&&role!="server")||slot<2||slot>254||!occupied(role,slot))return 2;
    reject_fp(role,slot);
    if(role=="client"){
        remove_mailboxes(slot);
    }else{
        run("pkill -f "+shq("tundup-v7-secure .* tds"+std::to_string(slot))+" 2>/dev/null || true");
        run("/usr/local/sbin/voider-netns down "+std::to_string(slot)+" >/dev/null 2>&1 || true");
    }
    run("/usr/local/sbin/voider-peerctl remove "+role+" "+std::to_string(slot)+" >/dev/null 2>&1 || true");
    fs::remove_all(C.mat+"/"+role+"/"+std::to_string(slot));
    fs::remove(C.usb_fp_dir+"/"+(role=="client"?"client-":"import-server-")+std::to_string(slot)+".sha256");
    fs::remove(C.usb_fp_dir+"/import-"+role+"-"+std::to_string(slot)+".sha256");
    fs::remove("/etc/voider/private/sftp-"+role+"-"+std::to_string(slot)+".key");
    int rc=persist("REMOVAL");
    operation(rc?"failed":"done",rc?"STATE SAVE FAILED":"CONNECTION REMOVED");
    log("remove "+role+" "+std::to_string(slot));
    return rc;
}

static int network_recover(){
    if(root())return 1;
    operation("working","RETRYING NETWORK","25");
    int a=run("/usr/local/sbin/voider-wan recover");
    operation("working","CHECKING PHONE CABLE","70");
    int b=run("/usr/local/sbin/voider-phone recover");
    bool wan=field(C.wan_status,"CARRIER")=="up"&&field(C.wan_status,"ROUTE")=="ok";
    bool phone=field(C.phone_status,"REACHABLE")=="yes";
    std::string msg=!phone?"PHONE CABLE":(!wan?"NO INTERNET":"NETWORK READY");
    operation((a||b||!wan||!phone)?"failed":"done",msg);
    log("network-recover");
    return (a||b||!wan||!phone)?11:0;
}

static int paths_apply(const std::string& value){
    if(root())return 1;
    if(!vta::valid(value)){
        operation("failed","ONE PATH REQUIRED");
        return 2;
    }
    std::string old=vta::canonical(cfg().transports_available);
    if(old==value){operation("done","PATHS UNCHANGED");return 0;}
    if(!vu::replace_config_value(config_path(),"TRANSPORTS_AVAILABLE",value)){
        operation("failed","PATH SETTING FAILED");
        return 72;
    }
    if(persist("NETWORK PATHS")){
        vu::replace_config_value(config_path(),"TRANSPORTS_AVAILABLE",old);
        operation("failed","STATE SAVE FAILED");
        return 72;
    }
    operation("done","PATHS APPLIED");
    log("paths-apply "+value);
    return 0;
}

static int backup(const std::string&dev,const std::string&token){
    if(root())return 1;
    operation("working","SAVING STATE","20");
    if(persist()){operation("failed","STATE SAVE FAILED");return 72;}
    operation("working","ERASING BACKUP KEY","45");
    int rc=run("/usr/local/sbin/voider-usb backup "+shq(dev)+" "+shq(token)+" >/run/voider/last-backup 2>&1");
    operation(rc?"failed":"remove",rc?usb_error("/run/voider/last-backup","BACKUP FAILED"):"SAFE TO REMOVE",rc?"":"100");
    return rc;
}
static int restore(const std::string&dev,const std::string&token,bool check){
    if(root())return 1;
    operation("working","CHECKING BACKUP","20");
    int rc=run(std::string("/usr/local/sbin/voider-usb ")+(check?"restore-check ":"restore ")+shq(dev)+" "+shq(token)+" >/run/voider/last-restore 2>&1");
    operation(rc?"failed":"done",rc?usb_error("/run/voider/last-restore","BACKUP INVALID"):"RESTORE READY");
    return rc;
}

static int factory_reset(){
    if(root())return 1;
    operation("working","ERASING CONNECTIONS","10");
    run("rc-service voider stop 2>/dev/null || true");
    run("rc-service tor stop 2>/dev/null || true");
    run("rc-service sshd stop 2>/dev/null || true");
    if(!set_admin_switch(false)){
        operation("failed","SSH SETTING FAILED");
        return 72;
    }
    C.admin_ssh_lan=0;
    fs::remove_all(C.pc);fs::remove_all(C.ps);fs::remove_all(C.mat);fs::remove_all(C.sync);
    fs::remove_all(C.cert);fs::remove_all(C.usb_import_dir);fs::remove_all(C.sftp_base);fs::remove_all("/etc/voider/private");
    ensure();
    operation("working","MAKING NEW IDENTITY","35");
    std::string shortid=cap("openssl rand -hex 4"),machine=cap("openssl rand -hex 16");
    if(shortid.size()!=8||machine.size()!=32){operation("failed","RESET FAILED");return 80;}
    std::ofstream("/etc/hostname",std::ios::trunc)<<"voider-"<<shortid<<"\n";
    std::ofstream("/etc/machine-id",std::ios::trunc)<<machine<<"\n";
    std::string keys="/tmp/voider-reset-host";
    if(run("rm -f "+shq(keys)+"*; ssh-keygen -q -t ed25519 -N '' -f "+shq(keys))||
       run("cp "+shq(keys)+" /etc/ssh/ssh_host_ed25519_key && cp "+shq(keys+".pub")+" /etc/ssh/ssh_host_ed25519_key.pub")||
       run("rm -f "+shq(keys)+"*; ssh-keygen -q -t rsa -b 3072 -N '' -f "+shq(keys))||
       run("cp "+shq(keys)+" /etc/ssh/ssh_host_rsa_key && cp "+shq(keys+".pub")+" /etc/ssh/ssh_host_rsa_key.pub")){
        operation("failed","RESET FAILED");return 80;
    }
    if(run("umask 077; openssl rand -hex 32 > /etc/voider/private/tundup_psk.hex")){
        operation("failed","RESET FAILED");return 80;
    }
    operation("working","STARTING PRIVATE LINK","55");
    run("rm -rf "+shq(C.tor_hs_dir)+"/* "+shq(C.tor_dot_dir)+"/* 2>/dev/null || true");
    run("rc-service tor start >/run/voider/reset-tor.log 2>&1");
    for(int i=0;i<45&&!fs::exists(C.tor_hs_dir+"/hostname");i++)sleep(1);
    if(!fs::exists(C.tor_hs_dir+"/hostname")){operation("failed","TOR NOT READY");return 81;}
    operation("working","SAVING CLEAN STATE","90");
    if(run("/usr/local/sbin/voider-sftp-setup publish-identity >/run/voider/reset-sftp.log 2>&1")||
       run("rc-service sshd start >/run/voider/reset-sshd.log 2>&1")||persist("FACTORY RESET")){
        operation("failed","RESET SAVE FAILED");return 82;
    }
    operation("done","RESET COMPLETE");
    return 0;
}

static int safe_poweroff(){
    if(root())return 1;
    operation("working","SAVING AND POWERING OFF","50");
    if(!fs::exists("/run/voider/restore-pending")&&persist()){operation("failed","STATE SAVE FAILED");return 72;}
    run("sync");
    // Fill the physical framebuffer with black and request panel power-down
    // immediately before shutdown. The UI has already shown POWERING OFF
    // while the curated state commit was running.
    run("/usr/local/sbin/voider-ui --blank >/dev/null 2>&1 || true");
    return run("/sbin/poweroff");
}

static int status(){
    auto contacts=vc::contacts(C);
    std::cout<<"PHONE_IF "<<C.phone_if<<"\nWAN_IF "<<C.wan_if<<"\nCONNECTIONS "<<contacts.size()<<"\n";
    std::cout<<"MANAGEMENT_SSH "<<(valid_admin_key(C.admin_auth_keys)?(C.admin_ssh_lan?"ON":"OFF"):"NO_KEY")<<"\n";
    std::cout<<"DHCP "<<C.dhcp_enabled<<"\nWAN_STATE "<<field(C.wan_status,"STATE")<<"\n";
    std::cout<<"PATHS_AVAILABLE "<<vta::canonical(C.transports_available)<<"\n";
    std::cout<<"WAN_CARRIER "<<field(C.wan_status,"CARRIER")<<"\nWAN_ROUTE "<<field(C.wan_status,"ROUTE")<<"\n";
    std::cout<<"IPV6_READY "<<field(C.wan_status,"IPV6_READY")<<"\nPHONE_REACHABLE "<<field(C.phone_status,"REACHABLE")<<"\n";
    for(const auto&x:contacts)
        std::cout<<"CONTACT "<<x.role<<" "<<x.slot<<" "<<x.name<<" DIAL "<<x.dial_ip<<"\n";
    std::cout<<cap("/usr/local/sbin/voider-integrity stateprint 2>/dev/null")<<"\n";
    return 0;
}
static int support(){
    bool os=field("/run/voider/integrity.status","STATE")=="match";
    bool wan=field(C.wan_status,"CARRIER")=="up"&&field(C.wan_status,"ROUTE")=="ok";
    bool phone=field(C.phone_status,"REACHABLE")=="yes";
    int peers=atoi(field(C.status,"total_connected").c_str());
    std::cout<<"SUPPORT_CODE V2-"<<(os?'O':'X')<<(wan?'N':'X')<<(phone?'P':'X')<<"-"<<(peers?"C":"W")<<"\n";
    std::cout<<"OS "<<(os?"OK":"CHECK")<<" NETWORK "<<(wan?"OK":"CHECK")<<" PHONE "<<(phone?"OK":"CHECK")<<"\n";
    return 0;
}

static int selftest(){
    std::string path="/tmp/voider-main-selftest-"+std::to_string((long)getpid());
    std::string expected(64,'a');
    std::ofstream(path)<<"mount diagnostic line\n"<<expected<<"\n";
    bool ok=fingerprint_result(path)==expected;
    std::string config=path+".conf";
    std::ofstream(config)<<"TRANSPORTS_AVAILABLE="<<vta::all()<<"\n";
    bool persisted=vu::replace_config_value(config,"TRANSPORTS_AVAILABLE","hp4,tor")&&
                   cfg(config.c_str()).transports_available=="hp4,tor";
    std::ofstream(config,std::ios::trunc)<<"TRANSPORTS_AVAILABLE=typo\n";
    Cfg invalid=cfg(config.c_str());
    fs::path peers=path+".peers";
    C.pc=(peers/"clients.d").string();C.ps=(peers/"servers.d").string();
    C.usb_fp_dir=(peers/"fingerprints").string();
    fs::create_directories(C.pc);fs::create_directories(C.ps);
    std::ofstream(C.pc+"/2.conf")<<"ROLE=client\nID=2\n";
    std::ofstream(C.pc+"/3.conf")<<"ROLE=client\nID=3\n";
    std::ofstream(C.ps+"/2.conf")<<"ROLE=server\nID=2\nREMOTE_CERT_INDEX=9\n";
    auto contacts=vc::contacts(C);
    bool multiple=free_slot("client")==4&&free_slot("server")==3&&contacts.size()==3&&
                  contacts[0].name=="CLIENT 1"&&contacts[1].name=="CLIENT 2"&&
                  contacts[2].name=="SERVER 1";
    std::ofstream(C.ps+"/10.conf")<<"ROLE=server\nID=10\n";
    std::ofstream(C.pc+"/254.conf")<<"ROLE=client\nID=254\n";
    std::ofstream(C.pc+"/10.conf")<<"ROLE=client\nID=10\n";
    auto ordered=vc::contacts(C);
    bool stable=ordered.size()==6&&ordered[0].slot==2&&ordered[1].slot==3&&ordered[2].slot==10&&ordered[3].slot==254&&ordered[4].role=="server"&&ordered[4].slot==2&&ordered[5].slot==10;
    fs::remove(path);
    fs::remove(config);
    fs::remove_all(peers);
    int failures=(!ok)+(!persisted)+(!vta::valid("hp4,tor"))+vta::valid("")+
        invalid.config_valid+(!invalid.transports_available.empty())+(!multiple)+(!stable);
    std::cout<<"MAIN_TEST cases=8 fails="<<failures<<"\n";
    return failures?1:0;
}

int main(int ac,char**av){
    C=cfg();
    std::string c=ac>1?av[1]:"status";
    if(c=="selftest")return selftest();
    if(c=="status")return status();
    if(c=="support")return support();
    if(c=="restore-reboot"&&fs::exists("/run/voider/restore-pending")){
        if(root())return 1;
        return run("sync")?72:run("/sbin/reboot");
    }
    if(fs::exists("/run/voider/restore-pending")&&c!="poweroff"){
        operation("failed","RESTORE PENDING");return 74;
    }
    if(c=="usb-select"&&ac>=3)return run("/usr/local/sbin/voider-usb select "+shq(av[2]));
    if(c=="language-save"&&ac==3)return language_save(av[2]);
    if(c=="pair-export")return pair_export();
    if(c=="admin-key-new")return admin_key_new();
    if(c=="admin-key-revoke")return admin_key_revoke();
    if(c=="admin-ssh-enable")return admin_ssh_set(true);
    if(c=="admin-ssh-disable")return admin_ssh_set(false);
    if(c=="import-device"&&ac>=3)return import_device(av[2]);
    if(c=="remove"&&ac>=4)return remove_contact(av[2],atoi(av[3]));
    if(c=="network-recover")return network_recover();
    if(c=="paths-apply"&&ac==3)return paths_apply(av[2]);
    if(c=="backup"&&ac>=4)return backup(av[2],av[3]);
    if((c=="restore"||c=="restore-check")&&ac==4)return restore(av[2],av[3],c=="restore-check");
    if(c=="factory-reset")return factory_reset();
    if(c=="poweroff")return safe_poweroff();
    if(c=="show-onion")return std::cout<<read1(C.node_onion)<<"\n",0;
    std::cerr<<"usage: voider-main language-save en|de|bg|status|support|usb-select erase|read|pair-export|"
               "admin-key-new|admin-key-revoke|admin-ssh-enable|admin-ssh-disable|"
               "import-device DEVICE|remove ROLE SLOT|"
               "network-recover|paths-apply LIST|backup DEVICE TOKEN|restore-check DEVICE TOKEN|restore DEVICE TOKEN|factory-reset|poweroff|selftest\n";
    return 2;
}
