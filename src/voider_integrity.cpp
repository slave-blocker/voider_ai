// voider-integrity: BOOT + SYSTEM internal proof and human STATE fingerprint.
// BOOT and SYSTEM are raw-partition anchors. STATE is fingerprinted from the
// complete internal manifest and deterministic curated state, then judged by a human.

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#include <linux/fs.h>
#include <openssl/evp.h>
#include "voider_config.hpp"
#include "voider_util.hpp"

using vu::cap;
using vu::hex64;
using vu::read_file;
using vu::run;
using vu::shq;

namespace fs=std::filesystem;
static Cfg C;
static constexpr const char* MANIFEST_FORMAT="VOIDER_INTEGRITY_1";
static constexpr const char* INTERNAL_DOMAIN="VOIDER-INTERNAL-SYSTEM-DIGEST-V1\n";
static constexpr const char* EXTERNAL_DOMAIN="VOIDER-EXTERNAL-STATE-FINGERPRINT-V1\n";
static std::string status_path(){const char*p=getenv("VOIDER_INTEGRITY_STATUS");return p&&*p?p:"/run/voider/integrity.status";}

static void atomic_write(const std::string&p,const std::string&s,mode_t mode=0600){
    fs::create_directories(fs::path(p).parent_path());std::string t=p+".new."+std::to_string(getpid());
    {std::ofstream f(t,std::ios::binary|std::ios::trunc);f<<s;f.flush();if(!f)throw std::runtime_error("integrity status write failed: "+p);}
    chmod(t.c_str(),mode);fs::rename(t,p);
}
static std::string hexsha(const unsigned char h[32]){static const char*x="0123456789abcdef";std::string s;s.reserve(64);for(int i=0;i<32;i++){s.push_back(x[h[i]>>4]);s.push_back(x[h[i]&15]);}return s;}
static std::string sha_string(const std::string&s){
    std::array<unsigned char,32> h{};unsigned n=0;
    EVP_MD_CTX* c=EVP_MD_CTX_new();
    bool ok=c&&EVP_DigestInit_ex(c,EVP_sha256(),nullptr)==1&&
        EVP_DigestUpdate(c,s.data(),s.size())==1&&EVP_DigestFinal_ex(c,h.data(),&n)==1&&n==h.size();
    EVP_MD_CTX_free(c);
    return ok?hexsha(h.data()):"";
}
static unsigned long long byte_size(const std::string&p){int fd=open(p.c_str(),O_RDONLY|O_CLOEXEC);if(fd<0)return 0;unsigned long long n=0;struct stat st{};if(fstat(fd,&st)==0){if(S_ISBLK(st.st_mode))ioctl(fd,BLKGETSIZE64,&n);else if(S_ISREG(st.st_mode))n=(unsigned long long)st.st_size;}close(fd);return n;}
static std::string sha_file(const std::string&p,const std::function<void(unsigned long long,unsigned long long)>&progress={}){
    int fd=open(p.c_str(),O_RDONLY|O_CLOEXEC);if(fd<0)return "";unsigned long long total=byte_size(p),done=0;std::array<unsigned char,1024*1024>b{};std::array<unsigned char,32>h{};unsigned size=0;
    EVP_MD_CTX* c=EVP_MD_CTX_new();bool ok=c&&EVP_DigestInit_ex(c,EVP_sha256(),nullptr)==1;
    for(;ok;){ssize_t n=read(fd,b.data(),b.size());if(n<0){if(errno==EINTR)continue;ok=false;break;}if(!n)break;if(EVP_DigestUpdate(c,b.data(),(size_t)n)!=1){ok=false;break;}done+=(unsigned long long)n;if(progress)progress(done,total);}
    if(ok)ok=EVP_DigestFinal_ex(c,h.data(),&size)==1&&size==h.size();
    EVP_MD_CTX_free(c);close(fd);return ok?hexsha(h.data()):"";
}
static std::string short_code(const std::string&hex){
    // Crockford-style: 31 unambiguous alphanumerics plus its '*' check symbol.
    static const char alphabet[]="23456789ABCDEFGHJKMNPQRSTUVWXYZ*";if(!hex64(hex))return "";std::string raw;
    for(size_t i=0;i<26;i+=2)raw.push_back((char)strtoul(hex.substr(i,2).c_str(),nullptr,16));
    std::string out;unsigned acc=0,bits=0;
    for(unsigned char ch:raw){acc=(acc<<8)|ch;bits+=8;while(bits>=5&&out.size()<20){bits-=5;out.push_back(alphabet[(acc>>bits)&31]);}}
    std::string grouped;for(size_t i=0;i<out.size();i++){if(i&&i%4==0)grouped+='-';grouped+=out[i];}return grouped;
}
static std::string internal_digest(const std::string&boot,const std::string&system){return sha_string(std::string(INTERNAL_DOMAIN)+"BOOT_SHA256="+boot+"\nSYSTEM_SHA256="+system+"\n");}

struct Layout{std::string parent,ptuuid,boot,system,state,boot_uuid,system_uuid,state_uuid,boot_label,system_label,state_label;unsigned long long boot_size=0,system_size=0,state_size=0;};
static std::string bylabel(const std::string&label){std::string p="/dev/disk/by-label/"+label;if(fs::exists(p))return cap("readlink -f "+shq(p));return cap("blkid -L "+shq(label)+" 2>/dev/null");}
static std::string mounted_source(const std::string&p){return cap("findmnt -n -o SOURCE "+shq(p)+" 2>/dev/null");}
static std::string parent_of(const std::string&d){std::string p=cap("lsblk -ndo PKNAME "+shq(d)+" 2>/dev/null");return p.empty()?"":"/dev/"+p;}
static std::string prop(const std::string&d,const std::string&k){return cap("blkid -s "+k+" -o value "+shq(d)+" 2>/dev/null");}
static bool production_layout(Layout&l,std::string&why){
    l.boot=C.boot_dev=="AUTO"?mounted_source("/boot"):C.boot_dev;l.system=C.system_dev=="AUTO"?mounted_source("/"):C.system_dev;l.state=C.state_dev=="AUTO"?mounted_source(C.state_mount):C.state_dev;
    if(l.boot.empty())l.boot=bylabel("BOOT");
    if(l.system.empty())l.system=bylabel("SYSTEM");
    if(l.state.empty())l.state=bylabel("STATE");
    if(l.boot.empty()||l.system.empty()||l.state.empty()){why="BOOT, SYSTEM, or STATE device missing";return false;}
    std::string bp=parent_of(l.boot),sp=parent_of(l.system),tp=parent_of(l.state);if(bp.empty()||bp!=sp||bp!=tp){why="partitions do not have one common parent device";return false;}l.parent=bp;
    if(cap("lsblk -ndo PARTN "+shq(l.boot))!="1"||cap("lsblk -ndo PARTN "+shq(l.system))!="2"||cap("lsblk -ndo PARTN "+shq(l.state))!="3"){why="partition order is not BOOT=1, SYSTEM=2, STATE=3";return false;}
    l.ptuuid=prop(l.parent,"PTUUID");l.boot_uuid=prop(l.boot,"UUID");l.system_uuid=prop(l.system,"UUID");l.state_uuid=prop(l.state,"UUID");l.boot_label=prop(l.boot,"LABEL");l.system_label=prop(l.system,"LABEL");l.state_label=prop(l.state,"LABEL");l.boot_size=byte_size(l.boot);l.system_size=byte_size(l.system);l.state_size=byte_size(l.state);
    if(l.boot_label!="BOOT"||l.system_label!="SYSTEM"||l.state_label!="STATE"){why="partition labels are not BOOT, SYSTEM, STATE";return false;}if(l.ptuuid.empty()||l.boot_uuid.empty()||l.system_uuid.empty()||l.state_uuid.empty()||!l.boot_size||!l.system_size||!l.state_size){why="layout identity is incomplete";return false;}return true;
}
static std::string manifest_body(const Layout&l,const std::string&boot,const std::string&system){
    std::ostringstream o;o<<"FORMAT="<<MANIFEST_FORMAT<<"\nINTEGRITY_SCHEMA=1\nLAYOUT_SCHEMA=1\nPARENT_PTUUID="<<l.ptuuid<<"\n"
      <<"BOOT_PARTITION=1\nBOOT_LABEL="<<l.boot_label<<"\nBOOT_UUID="<<l.boot_uuid<<"\nBOOT_SIZE_BYTES="<<l.boot_size<<"\nBOOT_SHA256="<<boot<<"\n"
      <<"SYSTEM_PARTITION=2\nSYSTEM_LABEL="<<l.system_label<<"\nSYSTEM_UUID="<<l.system_uuid<<"\nSYSTEM_SIZE_BYTES="<<l.system_size<<"\nSYSTEM_SHA256="<<system<<"\n"
      <<"STATE_PARTITION=3\nSTATE_LABEL="<<l.state_label<<"\nSTATE_UUID="<<l.state_uuid<<"\nSTATE_SIZE_BYTES="<<l.state_size<<"\nCOMBINED_DIGEST_VERSION=1\nCOMBINED_SHA256="<<internal_digest(boot,system)<<"\n";return o.str();
}
static std::map<std::string,std::string> parse_manifest(const std::string&body){std::map<std::string,std::string>m;std::istringstream s(body);std::string line;while(std::getline(s,line)){auto at=line.find('=');if(at==std::string::npos||at==0||m.count(line.substr(0,at)))return {};m[line.substr(0,at)]=line.substr(at+1);}return m;}
static bool canonical_manifest(const std::string&body,std::map<std::string,std::string>&m){
    m=parse_manifest(body);if(m["FORMAT"]!=MANIFEST_FORMAT||m["INTEGRITY_SCHEMA"]!="1"||m["LAYOUT_SCHEMA"]!="1"||m["BOOT_PARTITION"]!="1"||m["SYSTEM_PARTITION"]!="2"||m["STATE_PARTITION"]!="3"||m["COMBINED_DIGEST_VERSION"]!="1"||!hex64(m["BOOT_SHA256"])||!hex64(m["SYSTEM_SHA256"])||!hex64(m["COMBINED_SHA256"]))return false;
    Layout l;l.ptuuid=m["PARENT_PTUUID"];l.boot_label=m["BOOT_LABEL"];l.boot_uuid=m["BOOT_UUID"];l.boot_size=strtoull(m["BOOT_SIZE_BYTES"].c_str(),nullptr,10);l.system_label=m["SYSTEM_LABEL"];l.system_uuid=m["SYSTEM_UUID"];l.system_size=strtoull(m["SYSTEM_SIZE_BYTES"].c_str(),nullptr,10);l.state_label=m["STATE_LABEL"];l.state_uuid=m["STATE_UUID"];l.state_size=strtoull(m["STATE_SIZE_BYTES"].c_str(),nullptr,10);
    return body==manifest_body(l,m["BOOT_SHA256"],m["SYSTEM_SHA256"])&&m["COMBINED_SHA256"]==internal_digest(m["BOOT_SHA256"],m["SYSTEM_SHA256"]);
}
static std::string external_fingerprint(const std::string&manifest,const std::string&state){
    std::map<std::string,std::string>m;if(!canonical_manifest(manifest,m))return "";if(!hex64(state))return "";std::ostringstream o;
    o<<EXTERNAL_DOMAIN<<"INTEGRITY_SCHEMA="<<m["INTEGRITY_SCHEMA"]<<"\nLAYOUT_SCHEMA="<<m["LAYOUT_SCHEMA"]<<"\nINTEGRITY_MANIFEST_BYTES="<<manifest.size()<<"\nINTEGRITY_MANIFEST_SHA256="<<sha_string(manifest)<<"\nSTATE_ARCHIVE_FORMAT=DETERMINISTIC_GNU_TAR_GZIP_1\nSTATE_TAR_SHA256="<<state<<"\n";return sha_string(o.str());
}
static void status(const std::string&state,const std::string&phase,int progress,const std::string&failure="",const std::map<std::string,std::string>&extra={}){
    std::ostringstream body;body<<"STATE="<<state<<"\nPHASE="<<phase<<"\nPROGRESS="<<progress<<"\n";
    if(!failure.empty())body<<"FAILURE="<<failure<<"\n";
    for(const auto&x:extra)body<<x.first<<"="<<x.second<<"\n";
    atomic_write(status_path(),body.str());
}
static std::map<std::string,std::string> recognition(const std::map<std::string,std::string>&m,const std::string&state=""){
    std::map<std::string,std::string>x={{"BOOT_SHA256",m.at("BOOT_SHA256")},{"BOOT_CODE",short_code(m.at("BOOT_SHA256"))},{"SYSTEM_SHA256",m.at("SYSTEM_SHA256")},{"SYSTEM_CODE",short_code(m.at("SYSTEM_SHA256"))},{"COMBINED_SHA256",m.at("COMBINED_SHA256")},{"COMBINED_CODE",short_code(m.at("COMBINED_SHA256"))}};if(!state.empty()){x["EXTERNAL_STATE_SHA256"]=state;x["EXTERNAL_STATE_CODE"]=short_code(state);}return x;
}
static void publish_current_state(const std::string&fingerprint){
    if(!hex64(fingerprint))return;
    const std::string path=status_path(),body=read_file(path);
    const auto fields=parse_manifest(body);
    // A STATE commit never grants a failed or incomplete BOOT/SYSTEM check.
    if(fields.find("STATE")==fields.end()||fields.at("STATE")!="match"||
       fields.find("PHASE")==fields.end()||fields.at("PHASE")!="COMPLETE")return;
    std::istringstream in(body);std::ostringstream out;std::string line;bool sha=false,code=false;
    while(std::getline(in,line)){
        if(line.rfind("EXTERNAL_STATE_SHA256=",0)==0){line="EXTERNAL_STATE_SHA256="+fingerprint;sha=true;}
        else if(line.rfind("EXTERNAL_STATE_CODE=",0)==0){line="EXTERNAL_STATE_CODE="+short_code(fingerprint);code=true;}
        out<<line<<"\n";
    }
    if(!sha)out<<"EXTERNAL_STATE_SHA256="<<fingerprint<<"\n";
    if(!code)out<<"EXTERNAL_STATE_CODE="<<short_code(fingerprint)<<"\n";
    atomic_write(path,out.str());
}
static bool layout_matches(const Layout&l,const std::map<std::string,std::string>&m,std::string&why){
    const std::pair<std::string,std::string> checks[]={{"PARENT_PTUUID",l.ptuuid},{"BOOT_LABEL",l.boot_label},{"BOOT_UUID",l.boot_uuid},{"BOOT_SIZE_BYTES",std::to_string(l.boot_size)},{"SYSTEM_LABEL",l.system_label},{"SYSTEM_UUID",l.system_uuid},{"SYSTEM_SIZE_BYTES",std::to_string(l.system_size)},{"STATE_LABEL",l.state_label},{"STATE_UUID",l.state_uuid},{"STATE_SIZE_BYTES",std::to_string(l.state_size)}};
    for(const auto&x:checks)if(m.at(x.first)!=x.second){why=x.first+" expected "+m.at(x.first)+" got "+x.second;return false;}
    return true;
}
static int verify_paths(const std::string&boot_path,const std::string&system_path,const std::string&manifest_path,const Layout* production){
    std::string body=read_file(manifest_path);std::map<std::string,std::string>m;if(!canonical_manifest(body,m)){status("failure","MANIFEST",0,"integrity manifest invalid");std::cerr<<"INTEGRITY_FAILURE MANIFEST invalid\n";return 20;}
    if(production){std::string why;if(!layout_matches(*production,m,why)){status("failure","LAYOUT",0,why,recognition(m));std::cerr<<"INTEGRITY_FAILURE LAYOUT "<<why<<"\n";return 21;}}
    auto extra=recognition(m);unsigned long long last=~0ull;status("calculating","BOOT",0,"",extra);
    std::string bh=sha_file(boot_path,[&](auto d,auto t){unsigned p=t?d*100/t:0;if(p!=last){last=p;status("calculating","BOOT",(int)p,"",extra);}});if(bh!=m["BOOT_SHA256"]){extra["BOOT_CURRENT_SHA256"]=bh;status("failure","BOOT",100,"BOOT digest mismatch",extra);std::cerr<<"INTEGRITY_FAILURE BOOT digest mismatch\n";return 22;}
    last=~0ull;status("calculating","SYSTEM",0,"",extra);std::string sh=sha_file(system_path,[&](auto d,auto t){unsigned p=t?d*100/t:0;if(p!=last){last=p;status("calculating","SYSTEM",(int)p,"",extra);}});if(sh!=m["SYSTEM_SHA256"]){extra["SYSTEM_CURRENT_SHA256"]=sh;status("failure","SYSTEM",100,"SYSTEM digest mismatch",extra);std::cerr<<"INTEGRITY_FAILURE SYSTEM digest mismatch\n";return 23;}
    std::string combined=internal_digest(bh,sh);if(combined!=m["COMBINED_SHA256"]){status("failure","COMBINED",100,"combined SYSTEM digest mismatch",extra);return 24;}
    std::string efp=external_fingerprint(body,sha_file(C.state_tar));if(production&&!hex64(efp)){status("failure","STATE",100,"external STATE fingerprint unavailable",extra);return 25;}if(!efp.empty()){extra["EXTERNAL_STATE_SHA256"]=efp;extra["EXTERNAL_STATE_CODE"]=short_code(efp);}status("match","COMPLETE",100,"",extra);std::cout<<"INTERNAL_SYSTEM_MATCH\n";for(const auto&x:extra)std::cout<<x.first<<" "<<x.second<<"\n";return 0;
}

static fs::path rooted(const fs::path&root,const std::string&abs){fs::path p(abs);return root.empty()?p:(root/p.relative_path());}
static void ensure_tor_runtime(const fs::path&root=fs::path()){fs::path dot=rooted(root,C.tor_dot_dir);fs::create_directories(dot);std::string z=shq(dot.string());run("mountpoint -q "+z+" || mount -t tmpfs -o mode=0700,nosuid,nodev,size="+C.tor_dot_tmpfs_size+" tmpfs "+z+" 2>/dev/null || true");}
static void normalize_identity_state(const fs::path&root=fs::path()){
    fs::path hs=rooted(root,C.tor_hs_dir);fs::create_directories(hs);std::string h=shq(hs.string());std::string owner=cap("id -un tor 2>/dev/null");if(owner.empty())owner="tor";run("chown -R "+owner+":"+owner+" "+h+" 2>/dev/null || chown -R "+owner+" "+h+" 2>/dev/null || true");run("chmod 700 "+h);run("find "+h+" -type f -exec chmod 600 {} + 2>/dev/null || true");
    fs::path keys=rooted(root,C.mailbox_key_dir);if(fs::exists(keys)){std::string z=shq(keys.string());run("chown root:root "+z);run("chmod 711 "+z);run("find "+z+" -type f -exec chown root:root {} + -exec chmod 644 {} + 2>/dev/null || true");}
    fs::path admin=rooted(root,C.admin_auth_keys);if(fs::is_regular_file(admin)){run("chown root:root "+shq(admin.string()));run("chmod 600 "+shq(admin.string()));}
}
static int state_load(){fs::create_directories(C.ram_state_root);ensure_tor_runtime(C.ram_state_root);if(!fs::exists(C.state_tar)){std::cerr<<"STATE_ERROR state.tar.gz missing\n";return 30;}int rc=run("tar -C "+shq(C.ram_state_root)+" -xzf "+shq(C.state_tar));normalize_identity_state(C.ram_state_root);return rc;}
static int save_archive(const std::string&archive,const std::string&reason,bool restore){
    fs::create_directories("/run/voider");
    int lock=open("/run/voider/state-commit.lock",O_CREAT|O_RDWR|O_CLOEXEC|O_NOFOLLOW,0600);
    if(lock<0||flock(lock,LOCK_EX|LOCK_NB)){if(lock>=0)close(lock);return 34;}
    struct Unlock{int fd;~Unlock(){close(fd);}} unlock{lock};
    if(fs::exists("/run/voider/restore-pending"))return 36;
    std::string before=fs::exists(C.state_tar)?sha_file(C.state_tar):"",after=sha_file(archive);
    std::string fp=external_fingerprint(read_file(C.integrity_manifest),after);
    if(!hex64(after)||(!hex64(fp)&&reason!="INSTALLATION"))return 33;
    const std::string next=C.state_tar+".new",backup="/run/voider/state-previous.tar.gz";
    const std::string oldstatus=read_file(status_path()),olduser=read_file("/run/voider/user-integrity.status"),oldupdate=read_file("/run/voider/state-updated.status");
    bool replaced=false,had=fs::exists(C.state_tar);
    auto checked=[](const std::string&cmd){if(run("timeout -k 2 15 sh -c "+shq(cmd)))throw std::runtime_error("STATE storage operation failed");};
    auto sync_path=[](const std::string&path){
        int fd=open(path.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
        if(fd<0)throw std::runtime_error("open STATE");
        int rc=fsync(fd);if(close(fd))rc=-1;
        if(rc)throw std::runtime_error("sync STATE");
    };
    try{
        fs::remove(backup);
        if(had){fs::copy_file(C.state_tar,backup);chmod(backup.c_str(),0600);if(sha_file(backup)!=before)throw std::runtime_error("STATE rollback copy differs");}
        fs::create_directories(C.state_dir);
        checked("mount -o remount,rw "+shq(C.state_mount));
        fs::remove(next);fs::copy_file(archive,next);
        if(chmod(next.c_str(),0600))throw std::runtime_error("STATE permissions");
        sync_path(next);
        if(sha_file(next)!=after)throw std::runtime_error("staged STATE differs");
        // This RAM marker blocks every subsequent old-state save until reboot.
        if(restore)atomic_write("/run/voider/restore-pending",after+"\n");
        fs::rename(next,C.state_tar);replaced=true;
        sync_path(C.state_dir);
        checked("sync -f "+shq(C.state_dir));
        checked("mount -o remount,ro "+shq(C.state_mount));
        if(sha_file(C.state_tar)!=after)throw std::runtime_error("saved STATE differs");
        if(hex64(fp))publish_current_state(fp);
        if(!reason.empty()&&(restore||before!=after)&&hex64(fp)){
            atomic_write("/run/voider/state-updated.status","STATE=updated\nREASON="+reason+"\nEXTERNAL_STATE_SHA256="+fp+"\nEXTERNAL_STATE_CODE="+short_code(fp)+"\n");
            fs::remove("/run/voider/user-integrity.status");
        }
    }catch(const std::exception&e){
        try{
            checked("mount -o remount,rw "+shq(C.state_mount));
            if(replaced){
                if(had){fs::copy_file(backup,next,fs::copy_options::overwrite_existing);sync_path(next);fs::rename(next,C.state_tar);}
                else fs::remove(C.state_tar);
            }
            std::error_code ec;fs::remove(next,ec);
            sync_path(C.state_dir);checked("sync -f "+shq(C.state_dir));
            checked("mount -o remount,ro "+shq(C.state_mount));
            for(const auto&v:std::vector<std::pair<std::string,std::string>>{{status_path(),oldstatus},{"/run/voider/user-integrity.status",olduser},{"/run/voider/state-updated.status",oldupdate}}){
                if(read_file(v.first)==v.second)continue;
                if(v.second.empty())fs::remove(v.first);else atomic_write(v.first,v.second);
            }
            fs::remove("/run/voider/restore-pending");fs::remove(backup);
        }catch(const std::exception&rollback){
            // Keep old RAM from overwriting uncertain storage. The display
            // closes normal operations; retain the private RAM rollback copy.
            atomic_write("/run/voider/restore-pending","STORAGE FAILURE\n");
            status("failure","STATE",100,"STATE rollback failed; power off and recover");
            std::cerr<<"STATE_ROLLBACK_FAILED "<<rollback.what()<<"\n";
        }
        std::cerr<<"STATE_ERROR "<<e.what()<<"\n";return 35;
    }
    fs::remove(backup);
    std::cout<<"STATE_TAR_SHA256 "<<after<<"\n";
    if(hex64(fp))std::cout<<"EXTERNAL_STATE_SHA256 "<<fp<<"\nEXTERNAL_STATE_CODE "<<short_code(fp)<<"\n";
    if(!reason.empty()&&(restore||before!=after)&&hex64(fp))std::cout<<"STATE UPDATED\nREASON "<<reason<<"\n";
    return 0;
}
static int state_commit(const std::string&reason){
    if(fs::exists("/run/voider/restore-pending"))return 36;
    if(system("tar --version 2>/dev/null | grep -qi 'gnu tar'")!=0)return 31;
    fs::create_directories("/run/voider");normalize_identity_state();std::string inc;
    for(const auto&p:csv(C.state_allowlist))if(fs::exists(p))inc+=shq(p.substr(1))+" ";
    if(inc.empty())return 32;
    // Unique private staging, so another save cannot replace our input.
    std::string pattern="/run/voider/state-save.XXXXXX";
    int fd=mkstemp(pattern.data());if(fd<0)return 35;close(fd);
    struct Remove{std::string p;~Remove(){std::error_code ec;fs::remove(p,ec);}} remove{pattern};
    int rc=run("tar --sort=name --owner=0 --group=0 --numeric-owner --mtime='UTC 1970-01-01' --pax-option=delete=atime,delete=ctime -C / -czf "+shq(pattern)+" "+inc);
    return rc?rc:save_archive(pattern,reason,false);
}
static int state_restore(const std::string&path){
    // The USB owner supplies only its validated, private RAM staging file.
    std::error_code ec;std::string actual=fs::canonical(path,ec).string();
    if(geteuid()!=0||ec||actual!=path||actual.rfind("/run/voider/usb-work.",0)!=0||
       fs::path(actual).filename()!="state.tar.gz"||!fs::is_regular_file(path))return 37;
    return save_archive(path,"RESTORE",true);
}
static int mark_updated(const std::string&reason){
    std::string fp=external_fingerprint(read_file(C.integrity_manifest),sha_file(C.state_tar));if(!hex64(fp))return 33;
    publish_current_state(fp);
    fs::remove("/run/voider/user-integrity.status");atomic_write("/run/voider/state-updated.status","STATE=updated\nREASON="+reason+"\nEXTERNAL_STATE_SHA256="+fp+"\nEXTERNAL_STATE_CODE="+short_code(fp)+"\n");
    std::cout<<"STATE UPDATED\nREASON "<<reason<<"\nEXTERNAL_STATE_SHA256 "<<fp<<"\nEXTERNAL_STATE_CODE "<<short_code(fp)<<"\n";return 0;
}
static int freeze(){
    Layout l;std::string why;if(!production_layout(l,why)){std::cerr<<"INTEGRITY_SEAL_ERROR "<<why<<"\n";return 40;}run("sync");if(run("mount -o remount,ro /boot")||run("mount -o remount,ro /")){std::cerr<<"INTEGRITY_SEAL_ERROR BOOT or SYSTEM not read-only\n";return 41;}
    std::string bo=","+cap("findmnt -n -o OPTIONS /boot")+",",so=","+cap("findmnt -n -o OPTIONS /")+",";if(bo.find(",ro,")==std::string::npos||so.find(",ro,")==std::string::npos)return 42;run("blockdev --setro "+shq(l.boot));run("blockdev --setro "+shq(l.system));std::cout<<"HASHING BOOT\n";std::string bh=sha_file(l.boot);std::cout<<"HASHING SYSTEM\n";std::string sh=sha_file(l.system);if(!hex64(bh)||!hex64(sh))return 43;
    std::string body=manifest_body(l,bh,sh);run("mount -o remount,rw "+shq(C.state_mount)+" 2>/dev/null || true");atomic_write(C.integrity_manifest,body);atomic_write(C.integrity_freeze_meta,"MODEL=BOOT_ro_SYSTEM_ro_STATE_curated_RAM_runtime\nNO_INSTALLED_APKOVL=1\n");run("sync");run("mount -o remount,ro "+shq(C.state_mount)+" 2>/dev/null || true");
    std::map<std::string,std::string>m;canonical_manifest(body,m);std::string fp=external_fingerprint(body,sha_file(C.state_tar));auto x=recognition(m,fp);for(const auto&e:x)std::cout<<e.first<<" "<<e.second<<"\n";if(hex64(fp))atomic_write("/run/voider/state-updated.status","STATE=updated\nREASON=INSTALLATION\nEXTERNAL_STATE_SHA256="+fp+"\nEXTERNAL_STATE_CODE="+short_code(fp)+"\n");return hex64(fp)?0:44;
}
static int stateprint(){std::string body=read_file(C.integrity_manifest),fp=external_fingerprint(body,sha_file(C.state_tar));std::map<std::string,std::string>m;if(!canonical_manifest(body,m)||!hex64(fp)){std::cerr<<"INTEGRITY_ERROR fingerprint unavailable\n";return 50;}auto x=recognition(m,fp);std::cout<<"INTERNAL SYSTEM\nBOOT "<<x["BOOT_CODE"]<<"\nSYSTEM "<<x["SYSTEM_CODE"]<<"\nCOMBINED "<<x["COMBINED_CODE"]<<"\nEXTERNAL STATE\nSTATE "<<x["EXTERNAL_STATE_CODE"]<<"\nCOMPARE WITH YOUR COPY\n";for(const auto&e:x)if(e.first.find("SHA256")!=std::string::npos)std::cout<<e.first<<" "<<e.second<<"\n";return 0;}
static int fixture_manifest(const std::string&boot,const std::string&system,const std::string&state,const std::string&out){Layout l;l.ptuuid="564f4944";l.boot_label="BOOT";l.boot_uuid="564F-4944";l.boot_size=byte_size(boot);l.system_label="SYSTEM";l.system_uuid="11111111-1111-4111-8111-111111111111";l.system_size=byte_size(system);l.state_label="STATE";l.state_uuid="22222222-2222-4222-8222-222222222222";l.state_size=byte_size(state);std::string bh=sha_file(boot),sh=sha_file(system);if(!hex64(bh)||!hex64(sh)||!l.state_size)return 60;atomic_write(out,manifest_body(l,bh,sh));return 0;}
int main(int ac,char**av){
    C=cfg();std::string cmd=ac>1?av[1]:"status";if(cmd=="freeze")return freeze();if(cmd=="verify"){Layout l;std::string why;if(!production_layout(l,why)){status("failure","LAYOUT",0,why);std::cerr<<"INTEGRITY_FAILURE LAYOUT "<<why<<"\n";return 21;}return verify_paths(l.boot,l.system,C.integrity_manifest,&l);}if(cmd=="state-load")return state_load();if(cmd=="state-restore"&&ac==3)return state_restore(av[2]);if(cmd=="state-commit")return state_commit(ac>2?trim(av[2]):"");if(cmd=="mark-updated"&&ac>2)return mark_updated(trim(av[2]));if(cmd=="stateprint"||cmd=="status")return stateprint();
    if(cmd=="recognize"&&ac==3&&hex64(av[2]))return std::cout<<short_code(av[2])<<"\n",0;
    if(cmd=="fixture-manifest"&&ac==6)return fixture_manifest(av[2],av[3],av[4],av[5]);
    if(cmd=="fixture-verify"&&ac==5)return verify_paths(av[2],av[3],av[4],nullptr);
    if(cmd=="fixture-external"&&ac==4){std::string fp=external_fingerprint(read_file(av[2]),sha_file(av[3]));if(!hex64(fp))return 61;std::cout<<fp<<"\n"<<short_code(fp)<<"\n";return 0;}
    if(cmd=="fixture-publish-current"&&ac==4){std::string fp=external_fingerprint(read_file(av[2]),sha_file(av[3]));if(!hex64(fp))return 61;publish_current_state(fp);return 0;}
    std::cerr<<"usage: voider-integrity freeze|verify|state-load|state-restore ARCHIVE|state-commit [REASON]|mark-updated REASON|stateprint|status|recognize SHA256\n";return 2;
}
