// voider-appliance-boot: fail-closed BOOT/SYSTEM/STATE/RAM integration.

#include <array>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <unistd.h>
#include <sys/wait.h>
#include <map>
#include <chrono>
#include <thread>
#include "voider_config.hpp"
#include "voider_util.hpp"

using vu::cap;
using vu::mounted;
using vu::run;
using vu::shq;

namespace fs=std::filesystem;
static Cfg C;

static std::string bylabel(const std::string&l){std::string p="/dev/disk/by-label/"+l;if(fs::exists(p))return cap("readlink -f "+shq(p));return cap("blkid -L "+shq(l)+" 2>/dev/null");}
static std::string bootdev(){if(C.boot_dev!="AUTO")return C.boot_dev;auto d=cap("findmnt -n -o SOURCE /boot 2>/dev/null");return d.empty()?bylabel("BOOT"):d;}
static std::string systemdev(){if(C.system_dev!="AUTO")return C.system_dev;auto d=cap("findmnt -n -o SOURCE / 2>/dev/null");return d.empty()?bylabel("SYSTEM"):d;}
static std::string statedev(){if(C.state_dev!="AUTO")return C.state_dev;auto d=cap("findmnt -n -o SOURCE "+shq(C.state_mount)+" 2>/dev/null");return d.empty()?bylabel("STATE"):d;}
static void failure(const std::string&phase,const std::string&why){
    fs::create_directories("/run/voider");std::ofstream("/run/voider/appliance-failure",std::ios::trunc)<<why<<"\n";
    std::ifstream current("/run/voider/integrity.status");
    std::string body((std::istreambuf_iterator<char>(current)),std::istreambuf_iterator<char>());
    if(body.find("STATE=failure\n")==std::string::npos)
        std::ofstream("/run/voider/integrity.status",std::ios::trunc)
            <<"STATE=failure\nPHASE="<<phase<<"\nPROGRESS=0\nFAILURE="<<why<<"\n";
    std::cerr<<"APPLIANCE_NOT_READY "<<why<<"\nOnly safe power-off is permitted.\n";
}
static int mount_state(){
    fs::create_directories(C.state_mount);if(mounted(C.state_mount))return 0;std::string d=statedev();if(d.empty())return 10;
    return run("mount -o ro,noatime,nosuid,nodev "+shq(d)+" "+shq(C.state_mount));
}
static int set_anchors_readonly(){
    std::string b=bootdev(),s=systemdev();if(b.empty()||s.empty())return 11;
    if(run("blockdev --setro "+shq(b))||run("blockdev --setro "+shq(s)))return 12;
    run("mount -o remount,ro /boot 2>/dev/null || true");run("mount -o remount,ro / 2>/dev/null || true");return 0;
}
static int ram_runtime(){
    fs::create_directories("/run/voider");fs::create_directories(C.ram_state_root);fs::create_directories(C.ram_overlay_root);fs::create_directories("/tmp");
    run("mountpoint -q /tmp || mount -t tmpfs -o mode=1777,nosuid,nodev tmpfs /tmp 2>/dev/null || true");
    run("mkdir -p /var/log; mountpoint -q /var/log || mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /var/log 2>/dev/null || true");return 0;
}
static void ensure_mountpoint(const fs::path&dst,bool dir){if(dir)fs::create_directories(dst);else{fs::create_directories(dst.parent_path());if(!fs::exists(dst))std::ofstream(dst.string()).close();}}
static int bind_state(){
    int rc=run("/usr/local/sbin/voider-integrity state-load >/run/voider/last-state-load 2>&1");if(rc)return 20;
    for(const auto&p:csv(C.state_allowlist)){if(p.empty()||p[0]!='/')continue;fs::path src=fs::path(C.ram_state_root)/p.substr(1),dst=p;if(!fs::exists(src))continue;ensure_mountpoint(dst,fs::is_directory(src));if(!mounted(dst.string())&&run("mount --bind "+shq(src.string())+" "+shq(dst.string())))return 21;}
    for(const auto&p:csv(C.runtime_allowlist)){if(p.empty()||p[0]!='/')continue;fs::path src=fs::path("/run/voider/volatile")/p.substr(1),dst=p;fs::create_directories(src);ensure_mountpoint(dst,true);if(!mounted(dst.string())&&run("mount --bind "+shq(src.string())+" "+shq(dst.string())))return 22;}
    if(run("/usr/local/sbin/voider-sftp-setup slots >/run/voider/last-sftp-slots 2>&1"))return 23;
    return 0;
}
static void normalize_live_tor(){
    fs::create_directories(C.tor_hs_dir);fs::create_directories(C.tor_dot_dir);std::string owner=cap("id -un tor 2>/dev/null");if(owner.empty())owner="tor";
    run("mountpoint -q "+shq(C.tor_dot_dir)+" || mount -t tmpfs -o mode=0700,nosuid,nodev,size="+C.tor_dot_tmpfs_size+" tmpfs "+shq(C.tor_dot_dir)+" 2>/dev/null || true");
    run("chown -R "+owner+":"+owner+" "+shq(C.tor_hs_dir)+" "+shq(C.tor_dot_dir)+" 2>/dev/null || true");run("chmod 700 "+shq(C.tor_hs_dir)+" "+shq(C.tor_dot_dir)+" 2>/dev/null || true");
}
static std::map<std::string,std::string> fields(const std::string&path){
    std::ifstream f(path);std::map<std::string,std::string> m;std::string line;
    while(std::getline(f,line)){auto p=line.find('=');if(p!=std::string::npos)m[line.substr(0,p)]=line.substr(p+1);}return m;
}
static bool checks_passed(){
    auto os=fields("/run/voider/integrity.status"),user=fields("/run/voider/user-integrity.status");
    return os["STATE"]=="match"&&os["PHASE"]=="COMPLETE"&&user["STATE"]=="match"&&
        os["EXTERNAL_STATE_SHA256"].size()==64&&user["EXTERNAL_STATE_SHA256"]==os["EXTERNAL_STATE_SHA256"];
}
// The latch is created only after both checks. Authorized STATE updates do not
// revoke this boot's activation, so established relationships keep running.
static bool gate(){auto os=fields("/run/voider/integrity.status");return fs::exists("/run/voider/appliance-ready")&&fs::exists("/run/voider/checks-passed")&&os["STATE"]=="match"&&os["PHASE"]=="COMPLETE";}
static int start(){
    if(geteuid()!=0)return 1;
    fs::remove("/run/voider/appliance-ready");fs::remove("/run/voider/checks-passed");fs::remove("/run/voider/user-integrity.status");
    int rc=mount_state();if(rc){failure("STATE","STATE mount failed");return rc;}rc=set_anchors_readonly();if(rc){failure("READ ONLY","BOOT or SYSTEM could not be made read-only");return rc;}
    // This is intentionally synchronous. No ready marker or network/call service
    // can exist until both complete raw partitions and the layout match.
    rc=run("/usr/local/sbin/voider-integrity verify >/run/voider/last-integrity-check 2>&1");if(rc){failure("VERIFY","internal integrity verification failed");return rc;}
    ram_runtime();rc=bind_state();if(rc){failure("STATE LOAD","curated STATE load failed");return rc;}normalize_live_tor();run("mount -o remount,ro "+shq(C.state_mount)+" 2>/dev/null || true");
    // Keep the OpenRC dependency unsatisfied while the display owns YOUR CHECK.
    while(!checks_passed()){
        if(fields("/run/voider/user-integrity.status")["STATE"]=="mismatch")return 26;
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    for(const auto&entry:std::map<std::string,std::string>{{"checks-passed","DEVICE=passed\nYOUR=passed\n"},{"appliance-ready","READY\n"}}){
        std::string path="/run/voider/"+entry.first,next=path+".new";
        std::ofstream out(next);out<<entry.second;out.flush();
        if(!out){failure("RAM","activation status write failed");return 27;}out.close();fs::rename(next,path);
    }std::cout<<"APPLIANCE_READY BOOT=ro SYSTEM=ro STATE=curated RAM=runtime INTERNAL_SYSTEM=match\n";return 0;
}
static int status_cmd(){
    std::cout<<"READY "<<(gate()?"yes":"no")<<"\nBOOT_DEVICE "<<bootdev()<<"\nSYSTEM_DEVICE "<<systemdev()<<"\nSTATE_DEVICE "<<statedev()<<"\n";
    if(fs::exists("/run/voider/integrity.status"))std::cout<<std::ifstream("/run/voider/integrity.status").rdbuf();
    return gate()?0:1;
}
int main(int ac,char**av){C=cfg();std::string c=ac>1?av[1]:"start";if(c=="start")return start();if(c=="gate")return gate()?0:1;if(c=="checks")return checks_passed()?0:1;if(c=="status")return status_cmd();std::cerr<<"usage: voider-appliance-boot start|status|gate|checks\n";return 2;}
