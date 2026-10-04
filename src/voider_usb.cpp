// USB operations share one bounded readiness check and one checked mount owner.
// Pairing bundle v1, per-slot secrets, and curated STATE remain compatible.
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <set>
#include <vector>
#include <chrono>
#include <thread>
#include <stdexcept>
#include <functional>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/resource.h>
#include <linux/magic.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include "voider_config.hpp"
#include "voider_util.hpp"
#include "voider_mailbox.hpp"

namespace fs = std::filesystem;
using vu::read_file;
using vu::shq;
static Cfg C;
static const std::string selection_file="/run/voider/usb.selection";
static const std::string mount_record="/run/voider/usb.mount-id";
static constexpr auto ready_timeout=std::chrono::seconds(8);

struct Failure : std::runtime_error {
    int code;
    Failure(int value,const std::string&message):std::runtime_error(message),code(value){}
};
static void require(bool ok,const std::string&message,int code=23){
    if(!ok)throw Failure(code,message);
}
// Bound external tools too; a stuck child must not leave the display waiting forever.
static std::string capture(const std::string&command,const std::string&error="USB TOOL FAILED"){
    std::string output;
    FILE*pipe=popen(("timeout -k 2 15 sh -c "+shq(command)).c_str(),"r");
    require(pipe,"USB TOOL FAILED");
    char buffer[4096];
    while(fgets(buffer,sizeof buffer,pipe))output+=buffer;
    int result=vu::exit_status(pclose(pipe));
    require(result==0,result==124||result==137?"USB TOOL TIMEOUT":error);
    return trim(output);
}
static void command(const std::string&cmd,const std::string&error,int seconds=15){
    int rc=vu::run("timeout -k 2 "+std::to_string(seconds)+" sh -c "+shq(cmd),false);
    require(rc==0,error);
}
static std::string text_val(const std::string&text,const std::string&key){
    std::istringstream input(text);return key_value(input,key);
}
static void write_file(const fs::path&path,const std::string&body,mode_t mode=0600){
    fs::create_directories(path.parent_path());
    int fd=open(path.c_str(),O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC|O_NOFOLLOW,mode?mode:0600);
    require(fd>=0,"USB WRITE FAILED");
    size_t done=0;
    while(done<body.size()){
        ssize_t n=write(fd,body.data()+done,body.size()-done);
        if(n<0&&errno==EINTR)continue;
        if(n<=0)break;
        done+=static_cast<size_t>(n);
    }
    bool ok=done==body.size()&&(!mode||fchmod(fd,mode)==0)&&fsync(fd)==0;
    if(close(fd))ok=false;
    require(ok,"USB WRITE FAILED");
}
struct WorkDir {
    std::string path;
    explicit WorkDir(const std::string&root="/run/voider"){
        fs::create_directories(root);
        std::string name=root+"/usb-work.XXXXXX";
        char*created=mkdtemp(name.data());require(created,"USB TEMP FAILED");path=created;
    }
    ~WorkDir(){std::error_code ec;fs::remove_all(path,ec);}
};
struct UsbLock {
    int fd;
    UsbLock(){
        fs::create_directories("/run/voider");
        fd=open("/run/voider/usb.lock",O_CREAT|O_RDWR|O_CLOEXEC|O_NOFOLLOW,0600);
        if(fd<0||flock(fd,LOCK_EX|LOCK_NB)){if(fd>=0)close(fd);throw Failure(23,"USB BUSY");}
    }
    ~UsbLock(){close(fd);}
};
static std::string pconf(const std::string&role,const std::string&id){
    return (role=="client"?C.pc:C.ps)+"/"+id+".conf";
}
static bool slot_valid(const std::string&id){
    int n=toi(id,0);return n>=2&&n<=254&&std::to_string(n)==id;
}
static std::string base_name(const std::string&path){return fs::path(path).filename().string();}
static std::string canonical(const std::string&path){
    std::error_code ec;auto p=fs::canonical(path,ec);return ec?"":p.string();
}
static std::string part(const std::string&dev){
    return dev+(std::isdigit(static_cast<unsigned char>(dev.back()))?"p1":"1");
}
static std::string sys_value(const std::string&dev,const std::string&field){
    return trim(read_file("/sys/class/block/"+base_name(dev)+"/"+field));
}
static bool env_yes(const char*name){const char*v=getenv(name);return v&&std::string(v)=="1";}
static bool valid_hex(const std::string&s,size_t n){
    return s.size()==n&&std::all_of(s.begin(),s.end(),[](unsigned char c){return std::isxdigit(c);});
}
static std::string sha(const std::string&path,const std::string&error="USB VERIFY FAILED"){
    std::istringstream line(capture("sha256sum "+shq(path),error));std::string hash;line>>hash;
    require(valid_hex(hash,64),"USB VERIFY FAILED");return hash;
}
static void copy_file(const std::string&from,const std::string&to){
    require(!fs::is_symlink(to),"USB NOT SAFE");
    command("cp -- "+shq(from)+" "+shq(to),"USB WRITE FAILED");
}
static void copy_verified(const std::string&from,const std::string&to,bool reading=false){
    std::string expected=sha(from,reading?"USB READ FAILED":"USB VERIFY FAILED");
    command("cp -- "+shq(from)+" "+shq(to),reading?"USB READ FAILED":"USB WRITE FAILED");
    command("sync -f "+shq(to),"USB SYNC FAILED");
    require(sha(to)==expected,"USB VERIFY FAILED");
}

struct MountInfo {std::string id,device,path;};
static std::string unescape_mount(const std::string&input){
    std::string out;
    for(size_t i=0;i<input.size();i++){
        if(input[i]=='\\'&&i+3<input.size()&&input[i+1]>='0'&&input[i+1]<='7'&&
           input[i+2]>='0'&&input[i+2]<='7'&&input[i+3]>='0'&&input[i+3]<='7'){
            out+=char((input[i+1]-'0')*64+(input[i+2]-'0')*8+input[i+3]-'0');i+=3;
        }else out+=input[i];
    }
    return out;
}
static std::vector<MountInfo> mounts(){
    std::ifstream file("/proc/self/mountinfo");require(file.good(),"USB MOUNT CHECK FAILED");
    std::vector<MountInfo> rows;std::string line;
    while(std::getline(file,line)){
        MountInfo m;std::string parent,root;std::istringstream in(line);
        if(in>>m.id>>parent>>m.device>>root>>m.path){m.path=unescape_mount(m.path);rows.push_back(m);}
    }
    return rows;
}
static std::string mounted_id(){
    for(const auto&m:mounts())if(m.path==C.usb_mount)return m.id;
    return "";
}
static void unmount_usb(){
    // Only unmount a mount this binary owns. Never detach another user's mount.
    std::string id=mounted_id();
    if(id.empty()){fs::remove(mount_record);return;}
    require(id==trim(read_file(mount_record)),"USB IS MOUNTED");
    command("umount -- "+shq(C.usb_mount),"USB UNMOUNT FAILED");
    require(mounted_id().empty(),"USB UNMOUNT FAILED");fs::remove(mount_record);
}

struct Media {std::string dev,identity,model;};
static Media inspect_media(const std::string&device,bool allow_loop=false){
    Media media;media.dev=canonical(device);
    require(media.dev.rfind("/dev/",0)==0,"USB NOT READY");
    struct stat node{};require(!stat(media.dev.c_str(),&node)&&S_ISBLK(node.st_mode),"USB NOT READY");
    std::string name=base_name(media.dev),sys=canonical("/sys/class/block/"+name);
    require(!sys.empty(),"USB NOT READY");
    require(!fs::exists(sys+"/partition"),"USB NOT SAFE");
    bool loop=name.rfind("loop",0)==0;
    require(!loop||(allow_loop&&env_yes("VOIDER_USB_TEST_ALLOW_LOOP")),"USB NOT SAFE");
    require(name.rfind("mmcblk",0)!=0&&name.rfind("nvme",0)!=0,"SYSTEM DISK");
    require(loop||(sys.find("/usb")!=std::string::npos&&sys_value(media.dev,"removable")=="1"),"USB NOT SAFE");
    std::string sequence=sys_value(media.dev,"diskseq"),devnum=sys_value(media.dev,"dev");
    require(!sequence.empty()&&devnum==std::to_string(major(node.st_rdev))+":"+std::to_string(minor(node.st_rdev)),"USB NOT READY");
    media.identity=sys+"|"+devnum+"|"+sequence;
    unsigned long long sectors=0;try{sectors=std::stoull(sys_value(media.dev,"size"));}catch(...){ }
    require(sectors!=0,"USB NOT READY");
    require(loop||(sectors>=131072&&sectors<=268435456),"USB NOT SAFE");
    std::set<std::string> numbers{devnum};
    for(const auto&entry:fs::directory_iterator(sys))if(fs::exists(entry.path()/"partition")){
        numbers.insert(trim(read_file(entry.path()/"dev")));
        require(!fs::exists(entry.path()/"holders")||fs::is_empty(entry.path()/"holders"),"USB NOT SAFE");
    }
    for(const auto&m:mounts())if(numbers.count(m.device))
        require(false,m.path=="/"||m.path=="/boot"||m.path==C.state_mount?"SYSTEM DISK":"USB IS MOUNTED");
    require(fs::exists(sys+"/holders")&&fs::is_empty(sys+"/holders"),"USB NOT SAFE");
    std::ifstream swaps("/proc/swaps");require(swaps.good(),"USB NOT SAFE");std::string swap;
    while(std::getline(swaps,swap)){
        std::istringstream row(swap);std::string path;row>>path;struct stat st{};
        if(!stat(path.c_str(),&st)&&S_ISBLK(st.st_mode))
            require(!numbers.count(std::to_string(major(st.st_rdev))+":"+std::to_string(minor(st.st_rdev))),"USB NOT SAFE");
    }
    std::string model=trim(read_file(sys+"/device/model"));
    for(unsigned char c:model)if(std::isalnum(c)||c==' '||c=='-'||c=='_')media.model+=c;
    media.model=trim(media.model).substr(0,24);if(media.model.empty())media.model="USB KEY";
    return media;
}
// Disk sequence changes only on a new physical insertion, not repartitioning.
static Media active_media;
static bool reading_media=false;
static void identity_present(const Media&m){
    std::string sys=canonical("/sys/class/block/"+base_name(m.dev));
    require(!sys.empty()&&fs::exists(m.dev),"USB DISCONNECTED",24);
    std::string identity=sys+"|"+sys_value(m.dev,"dev")+"|"+sys_value(m.dev,"diskseq");
    require(identity==m.identity,"USB CHANGED",24);
}
static bool retryable(const std::string&error){return error=="USB NOT READY"||error=="USB_NONE";}
static Media wait_media(const std::function<Media()>&probe,bool rescan=false){
    auto deadline=std::chrono::steady_clock::now()+ready_timeout;
    bool rescanned=false;
    for(;;){
        try{return probe();}catch(const Failure&e){
            if(!retryable(e.what())||std::chrono::steady_clock::now()>=deadline)throw;
        }
        if(rescan&&!rescanned&&access("/sbin/mdev",X_OK)==0){
            command("/sbin/mdev -s","USB DEVICE SCAN FAILED",2);rescanned=true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}
static Media discover(){
    std::vector<Media> found;std::string rejected;size_t candidates=0;
    for(const auto&e:fs::directory_iterator("/sys/class/block")){
        if(fs::exists(e.path()/"partition")||canonical(e.path().string()).find("/usb")==std::string::npos)continue;
        candidates++;
        try{found.push_back(inspect_media("/dev/"+e.path().filename().string()));}
        catch(const Failure&error){rejected=error.what();}
    }
    require(candidates<=1,"USB_AMBIGUOUS",21);
    if(found.empty())throw Failure(20,rejected.empty()?"USB_NONE":rejected);
    return found.front();
}
static int select_media(bool destructive){
    fs::remove(selection_file);unmount_usb();
    Media m=wait_media([&]{return discover();},true);
    std::string token=capture("openssl rand -hex 16");require(valid_hex(token,32),"USB TOKEN FAILED");
    write_file(selection_file,"DEVICE="+m.dev+"\nIDENTITY="+m.identity+"\nTOKEN="+token+
               "\nMODEL="+m.model+"\nPURPOSE="+(destructive?"erase":"read")+"\n");
    std::cout<<"USB_READY DEVICE="<<m.dev<<" TOKEN="<<token<<" MODEL="<<m.model<<"\n";return 0;
}
static void confirmed_selection(const Media&media,const std::string&token,const std::string&purpose){
    std::string selected=read_file(selection_file);
    require(!token.empty()&&text_val(selected,"TOKEN")==token&&text_val(selected,"DEVICE")==media.dev&&
            text_val(selected,"PURPOSE")==purpose,"USB CONFIRMATION REQUIRED",24);
    require(text_val(selected,"IDENTITY")==media.identity,"USB CHANGED",24);
}
static Media ready_media(const std::string&dev,bool destructive,const std::string&token="",bool test=false){
    unmount_usb();
    std::string selected=read_file(selection_file);
    if(!selected.empty())identity_present({text_val(selected,"DEVICE"),text_val(selected,"IDENTITY"),""});
    Media m=wait_media([&]{return inspect_media(dev,test);},true);
    if(!token.empty())confirmed_selection(m,token,destructive?"erase":"read");
    else require(!destructive||test,"USB CONFIRMATION REQUIRED",24);
    active_media=m;reading_media=!destructive;return m;
}
static void same_media(const Media&m,bool test=false){
    identity_present(m);
    if(!test)require(discover().dev==m.dev,"USB CHANGED",24);
    require(inspect_media(m.dev,test).identity==m.identity,"USB CHANGED",24);
}
static void wait_partition(const Media&m,bool test=false){
    wait_media([&]{
        same_media(m,test);
        std::string sys=canonical("/sys/class/block/"+base_name(part(m.dev)));
        require(!sys.empty()&&fs::path(sys).parent_path()==canonical("/sys/class/block/"+base_name(m.dev)),"USB NOT READY");
        struct stat node{};std::string number=sys_value(part(m.dev),"dev");
        require(!stat(part(m.dev).c_str(),&node)&&S_ISBLK(node.st_mode)&&number==
                std::to_string(major(node.st_rdev))+":"+std::to_string(minor(node.st_rdev)),"USB NOT READY");
        return m;
    },true);
}
static void format_usb(const Media&m,bool test=false){
    same_media(m,test);
    command("printf 'label: dos\\n, , c, *\\n' | sfdisk --wipe always "+shq(m.dev),"USB FORMAT FAILED");
    command("partprobe "+shq(m.dev),"USB PARTITION FAILED");
    try{wait_partition(m,test);}catch(const Failure&e){if(retryable(e.what()))throw Failure(23,"USB PARTITION FAILED");throw;}
    same_media(m,test);
    command((C.usb_fs=="ext4"?"mkfs.ext4 -F -L ":"mkfs.vfat -F 32 -n ")+shq(C.usb_label)+" "+shq(part(m.dev)),"USB FORMAT FAILED");
}
struct UsbMount {
    bool active=false;
    Media media;
    UsbMount(const Media&m,bool readonly):media(m){
        try{wait_partition(m);}catch(const Failure&e){if(retryable(e.what()))throw Failure(23,readonly?"USB READ FAILED":"USB WRITE FAILED");throw;}
        fs::create_directories(C.usb_mount);
        require(canonical(C.usb_mount)==C.usb_mount&&C.usb_mount.rfind("/run/voider/",0)==0,"USB NOT SAFE");
        require(mounted_id().empty(),"USB IS MOUNTED");
        std::string type=capture("blkid -s TYPE -o value "+shq(part(m.dev)),"USB READ FAILED");
        require(type=="vfat"||type=="ext4","USB NOT SAFE");
        std::string options=readonly?(type=="ext4"?"ro,noload":"ro"):"rw";
        command("mount -o "+options+",nosuid,nodev,noexec "+shq(part(m.dev))+" "+shq(C.usb_mount),readonly?"USB READ FAILED":"USB WRITE FAILED");
        active=true;
        try{std::string id=mounted_id();require(!id.empty(),"USB MOUNT FAILED");write_file(mount_record,id+"\n");}
        catch(...){vu::run("timeout -k 2 15 umount -- "+shq(C.usb_mount),false);throw;}
    }
    void close(){identity_present(media);unmount_usb();active=false;identity_present(media);}
    ~UsbMount(){if(active)try{unmount_usb();}catch(const std::exception&e){std::cerr<<e.what()<<"\n";}}
};
// Reopen read-only after sync/unmount so verification crosses the filesystem
// flush boundary. Verify every output, including metadata and instructions.
static void finish_write(const Media&m,UsbMount&mount,const std::vector<std::string>&files){
    std::vector<std::string> hashes;
    for(const auto&file:files)hashes.push_back(sha(C.usb_mount+"/"+file));
    command("sync -f "+shq(C.usb_mount),"USB SYNC FAILED");
    mount.close();
    command("blockdev --flushbufs "+shq(part(m.dev)),"USB SYNC FAILED");
    UsbMount readback(m,true);
    for(size_t i=0;i<files.size();i++)require(sha(C.usb_mount+"/"+files[i])==hashes[i],"USB VERIFY FAILED");
    readback.close();
}
static void safe_to_remove(){fs::remove(selection_file);std::cout<<"SAFE_TO_REMOVE\n";}

static std::string current_system_digest(){return text_val(read_file(C.integrity_manifest),"COMBINED_SHA256");}
static bool valid_wg_key(const std::string&value){
    std::string s=trim(value);
    return s.size()==44&&s.back()=='='&&std::all_of(s.begin(),s.end()-1,[](unsigned char c){return std::isalnum(c)||c=='+'||c=='/';});
}
static bool valid_ed25519_pub(const std::string&value){
    std::string s=trim(value),type,blob;
    if(s.find_first_of("\r\n")!=std::string::npos)return false;
    std::istringstream in(s);in>>type>>blob;
    return type=="ssh-ed25519"&&blob.size()>=40&&std::all_of(blob.begin(),blob.end(),[](unsigned char c){return std::isalnum(c)||c=='+'||c=='/'||c=='=';});
}
static bool valid_onion(const std::string&value){
    std::string s=trim(value);
    return s.size()==62&&s.substr(56)==".onion"&&std::all_of(s.begin(),s.begin()+56,[](char c){return (c>='a'&&c<='z')||(c>='2'&&c<='7');});
}
static bool valid_host_pin(const std::string&value){
    // publish-identity writes a known_hosts line: onion, key type, key blob.
    // Older bundles can carry just the public key.
    std::string line=trim(value);if(valid_ed25519_pub(line))return true;
    auto at=line.find_first_of(" \t");
    return at!=std::string::npos&&valid_onion(line.substr(0,at))&&valid_ed25519_pub(line.substr(at+1));
}
static std::string cap2_val(const std::string&txt,const std::string&key){
    std::istringstream in(txt);std::string word;
    while(in>>word)if(word.rfind(key+"=",0)==0)return word.substr(key.size()+1);
    return "";
}
static void set_conf_value(const std::string&path,const std::string&key,const std::string&value){
    std::istringstream in(read_file(path));std::string body,line;bool replaced=false;
    while(std::getline(in,line)){
        auto at=line.find('=');
        if(at!=std::string::npos&&trim(line.substr(0,at))==key){
            if(!replaced)body+=key+"="+value+"\n";
            replaced=true;
        }else body+=line+"\n";
    }
    if(!replaced)body+=key+"="+value+"\n";
    write_file(path+".tmp",body);fs::rename(path+".tmp",path);
}
static void ensure_secret(const std::string&role,const std::string&id){
    std::string dir=C.mat+"/"+role+"/"+id;fs::create_directories(dir);
    for(const auto*name:{"usb_secret.hex","tundup_psk.hex"})if(!fs::exists(dir+"/"+name))
        write_file(dir+"/"+name,capture("openssl rand -hex 32")+"\n");
    if(!fs::exists(dir+"/private.key"))write_file(dir+"/private.key",capture("wg genkey")+"\n");
    if(!fs::exists(dir+"/public.key"))write_file(dir+"/public.key",capture("wg pubkey < "+shq(dir+"/private.key"))+"\n");
    if(!fs::exists(dir+"/preshared.key"))write_file(dir+"/preshared.key",capture("wg genpsk")+"\n");
    for(const auto*name:{"usb_secret.hex","tundup_psk.hex","private.key","preshared.key"})
        require(chmod((dir+"/"+name).c_str(),0600)==0,"USB KEY PERMISSIONS FAILED");
}
static void make_bundle(const std::string&role,const std::string&id,const std::string&out,const std::string&tmp){
    require(role=="client"&&slot_valid(id),"USB INVALID SLOT",2);ensure_secret(role,id);
    std::string material=tmp+"/etc/voider/peers/material/client/"+id;
    fs::create_directories(material);fs::create_directories(tmp+"/etc/voider/peers/clients.d");fs::create_directories(tmp+"/meta");
    command("cp -a "+shq(C.mat+"/client/"+id)+"/. "+shq(material),"USB BUNDLE FAILED");
    copy_file(pconf(role,id),tmp+"/etc/voider/peers/clients.d/"+id+".conf");
    command("ssh-keygen -q -t ed25519 -N '' -f "+shq(tmp+"/meta/sftp_key"),"USB KEY FAILED");
    command("/usr/local/sbin/voider-cap2 print client "+id+" > "+shq(tmp+"/meta/CAP2"),"USB BUNDLE FAILED");
    copy_file(C.node_onion,tmp+"/meta/node_onion");copy_file(C.sftp_host_pub,tmp+"/meta/host.pub");
    copy_file("/etc/voider/private/wg0.pub",tmp+"/meta/server_wg0.pub");
    write_file(tmp+"/meta/manifest.txt","VOIDER_USB_BUNDLE=1\nROLE=client\nID="+id+"\nCREATED="+
        std::to_string(time(nullptr))+"\nFINGERPRINT_STORED_ON_USB=0\nSFTP_FP_PROOF=0\nTUNDUP_HMAC_FP_PROOF=1\nONE_ONION=1\nPIVPN=0\nWG_OWNED=1\n");
    command("tar --sort=name --owner=0 --group=0 --numeric-owner --mtime='UTC 1970-01-01' -C "+shq(tmp)+" -cf "+shq(out)+" .","USB BUNDLE FAILED");
}
static std::string archive_path(std::string path){
    while(path.rfind("./",0)==0)path.erase(0,2);
    if(path==".")return "";
    while(!path.empty()&&path.back()=='/')path.pop_back();
    return path;
}
static bool clean_member(const std::string&path){
    if(path.empty()||path.front()=='/'||path.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./-")!=std::string::npos)return false;
    std::istringstream in(path);std::string segment;
    while(std::getline(in,segment,'/'))if(segment.empty()||segment==".."||segment==".")return false;
    return true;
}
static bool safe_member(std::string path){
    path=archive_path(path);if(path.empty())return true;
    if(!clean_member(path))return false;
    for(const auto*allowed:{"meta","etc/voider/peers/clients.d","etc/voider/peers/material/client","etc/voider/certs"}){
        std::string prefix=allowed;
        if(path==prefix||path.rfind(prefix+"/",0)==0||prefix.rfind(path+"/",0)==0)return true;
    }
    return false;
}
static bool safe_state_member(std::string path){
    path=archive_path(path);if(!clean_member(path))return false;
    for(std::string allowed:csv(C.state_allowlist)){
        allowed=trim(allowed);if(!allowed.empty()&&allowed.front()=='/')allowed.erase(0,1);
        if(path==allowed||path.rfind(allowed+"/",0)==0||allowed.rfind(path+"/",0)==0)return true;
    }
    return false;
}
static void check_archive(const std::string&archive,bool state){
    require(fs::is_regular_file(archive)&&!fs::is_symlink(archive)&&fs::file_size(archive)<=(state?512ull:4ull)*1024*1024,
            state?"BACKUP_INVALID file":"USB_INVALID bundle file",40);
    std::string flag=state?"z":"",listing=capture("tar -t"+flag+"f "+shq(archive));
    require(!listing.empty(),"USB_INVALID archive",41);
    std::istringstream names(listing);std::set<std::string> seen;std::string member;
    while(std::getline(names,member)){
        require(state?safe_state_member(member):safe_member(member),"USB_INVALID archive path",42);
        require(seen.insert(archive_path(member)).second,"USB_INVALID duplicate member",42);
    }
    std::istringstream types(capture("tar -tv"+flag+"f "+shq(archive)));
    while(std::getline(types,member))require(!member.empty()&&(member[0]=='-'||member[0]=='d'),"USB_INVALID archive link",43);
}
struct Bundle {std::string fp,id,dir;};
static Bundle validate_bundle(const std::string&archive,const std::string&probe){
    check_archive(archive,false);fs::create_directories(probe);
    // Reject oversized sparse members as well as links and traversal paths.
    command("ulimit -f 8192; tar --no-same-owner --no-same-permissions --keep-old-files -C "+shq(probe)+" -xf "+shq(archive),"USB_INVALID extraction");
    Bundle bundle{sha(archive),text_val(read_file(probe+"/meta/manifest.txt"),"ID"),probe};
    require(slot_valid(bundle.id),"USB_INVALID slot",46);
    std::string manifest=read_file(probe+"/meta/manifest.txt"),conf=probe+"/etc/voider/peers/clients.d/"+bundle.id+".conf";
    std::string body=read_file(conf),material=probe+"/etc/voider/peers/material/client/"+bundle.id;
    require(text_val(manifest,"VOIDER_USB_BUNDLE")=="1"&&text_val(manifest,"ROLE")=="client"&&
       text_val(body,"ROLE")=="client"&&text_val(body,"ID")==bundle.id&&
       text_val(body,"LOCAL_ADDR")=="172.31.0."+bundle.id+"/24"&&
       valid_wg_key(text_val(body,"PUBLIC_KEY"))&&valid_wg_key(text_val(body,"SERVER_PUBLIC_KEY"))&&
       valid_wg_key(text_val(body,"PRESHARED_KEY_VALUE"))&&
       valid_ed25519_pub(read_file(probe+"/meta/sftp_key.pub"))&&valid_host_pin(read_file(probe+"/meta/host.pub"))&&
       valid_wg_key(read_file(probe+"/meta/server_wg0.pub")),"USB_INVALID manifest",46);
    for(const auto*file:{"private.key","public.key","preshared.key","usb_secret.hex","tundup_psk.hex"})
        require(fs::is_regular_file(material+"/"+file)&&fs::file_size(material+"/"+file)>0,"USB_INVALID material",46);
    for(const auto*file:{"meta/sftp_key","meta/CAP2"})
        require(fs::is_regular_file(probe+"/"+file)&&fs::file_size(probe+"/"+file)>0,"USB_INVALID manifest",46);
    return bundle;
}
static bool valid_state_archive(const std::string&archive){
    try{check_archive(archive,true);return true;}catch(const Failure&){return false;}
}
static Bundle read_bundle(const std::string&dev,const std::string&work){
    Media media=ready_media(dev,false);
    std::string selected=read_file(selection_file);
    if(!selected.empty())confirmed_selection(media,text_val(selected,"TOKEN"),"read");
    UsbMount mount(media,true);
    std::string file=C.usb_mount+"/"+C.usb_bundle;
    require(fs::exists(file),"bundle missing",5);
    require(fs::is_regular_file(file)&&!fs::is_symlink(file)&&fs::file_size(file)<=4*1024*1024,"USB_INVALID bundle file",40);
    copy_verified(file,work+"/bundle.tar",true);mount.close();
    return validate_bundle(work+"/bundle.tar",work+"/bundle");
}
static void register_server_key(const std::string&role,const std::string&id,const Bundle&bundle){
    int slot=toi(id,0);require(role=="client"&&vmb::slot_ok(slot),"USB INVALID SLOT",2);
    std::string pub=trim(read_file(bundle.dir+"/meta/sftp_key.pub"));
    require(valid_ed25519_pub(pub),"USB_INVALID public key",34);
    fs::path path=vmb::keys(C,"client",slot),temporary=path.string()+".new";
    write_file(temporary,"restrict,no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty "+pub+
        " voider-"+role+"-"+id+"-"+bundle.fp.substr(0,12)+"\n",0644);
    require(chown(temporary.c_str(),0,0)==0,"USB KEY OWNER FAILED");
    fs::rename(temporary,path);
}
static void install_imported_server_conf(const Bundle&bundle,const std::string&id){
    std::string body=read_file(bundle.dir+"/etc/voider/peers/clients.d/"+bundle.id+".conf");
    std::string material=C.mat+"/server/"+id,cap2=read_file(bundle.dir+"/meta/CAP2");
    fs::create_directories(material);
    command("cp -a "+shq(bundle.dir+"/etc/voider/peers/material/client/"+bundle.id)+"/. "+shq(material),"USB IMPORT FAILED");
    copy_file(bundle.dir+"/meta/host.pub",material+"/host.pub");
    std::string server_pub=trim(read_file(bundle.dir+"/meta/server_wg0.pub"));
    std::string onion=cap2_val(cap2,"SFTP_ONION");if(onion.empty())onion=cap2_val(cap2,"ONION");
    std::string sftp_user=cap2_val(cap2,"MAILBOX_USER");
    require(sftp_user==vmb::user("client",toi(bundle.id,0)),"USB_INVALID mailbox account",46);
    std::string tun_onion=cap2_val(cap2,"TUN_ONION");if(tun_onion.empty())tun_onion=onion;
    std::string local=text_val(body,"LOCAL_ADDR");
    write_file(pconf("server",id),"ROLE=server\nID="+id+"\nIMPORTED_FROM_CLIENT_SLOT="+bundle.id+
        "\nREMOTE_CERT_INDEX="+bundle.id+"\nLOCAL_ADDR="+local+"\nADDRESS="+local+
        "\nPRIVATE_KEY="+material+"/private.key\nPRESHARED_KEY="+material+"/preshared.key\nPRESHARED_KEY_VALUE="+
        text_val(body,"PRESHARED_KEY_VALUE")+"\nSERVER_PUBLIC_KEY="+server_pub+"\nWG_PEER_PUBLIC_KEY="+server_pub+
        "\nIMPORTED_CLIENT_PUBLIC_KEY="+text_val(body,"PUBLIC_KEY")+"\nPUBLIC_KEY="+text_val(body,"PUBLIC_KEY")+
        "\nPORT="+std::to_string(51820+toi(id,0))+"\nTORPORT="+std::to_string(C.tundup_torport_base+toi(bundle.id,0))+
        "\nSFTP_ONION="+(valid_onion(onion)?onion:"")+"\nSFTP_USER="+sftp_user+"\nONION="+(valid_onion(onion)?onion:"")+
        "\nTUN_ONION="+(valid_onion(tun_onion)?tun_onion:"")+"\nKNOWN_HOSTS="+material+"/host.pub\n");
}

static int export_usb(const std::string&role,const std::string&id,const std::string&dev,const std::string&token){
    require(role=="client"&&slot_valid(id),"USB INVALID SLOT",2);
    Media media=ready_media(dev,true,token);WorkDir work;
    make_bundle(role,id,work.path+"/bundle.tar",work.path+"/source");
    Bundle bundle=validate_bundle(work.path+"/bundle.tar",work.path+"/checked");
    require(bundle.id==id,"USB_INVALID slot",25);
    format_usb(media);UsbMount mount(media,false);
    copy_verified(work.path+"/bundle.tar",C.usb_mount+"/"+C.usb_bundle);
    write_file(C.usb_mount+"/README.txt","Voider pairing key. Move this key to the other Voider. Keep it private.\n",0);
    finish_write(media,mount,{C.usb_bundle,"README.txt"});
    register_server_key(role,id,bundle);
    write_file(C.usb_fp_dir+"/"+role+"-"+id+".sha256",bundle.fp+"\n");
    set_conf_value(pconf(role,id),"USB_FP",bundle.fp);
    std::cout<<"FINGERPRINT "<<bundle.fp<<"\n";safe_to_remove();return 0;
}
static int fingerprint(const std::string&dev){
    WorkDir work;Bundle bundle=read_bundle(dev,work.path);
    std::string selected=read_file(selection_file),expected=text_val(selected,"BUNDLE_SHA256");
    require(expected.empty()||expected==bundle.fp,"USB_INVALID changed bundle");
    if(!selected.empty())set_conf_value(selection_file,"BUNDLE_SHA256",bundle.fp);
    std::cout<<bundle.fp<<"\n";return 0;
}
static int import_usb(const std::string&role,const std::string&id,const std::string&dev,const std::string&expected){
    require(role=="server"&&slot_valid(id),"USB INVALID SLOT",2);
    WorkDir work;Bundle bundle=read_bundle(dev,work.path);
    require(expected.empty()||bundle.fp==expected,"USB_INVALID changed bundle",24);
    if(fs::exists(C.usb_fp_dir))for(const auto&entry:fs::directory_iterator(C.usb_fp_dir))
        if(entry.is_regular_file()&&trim(read_file(entry.path()))==bundle.fp){
            std::cout<<"USB_DUPLICATE FINGERPRINT "<<bundle.fp<<"\n";safe_to_remove();return 10;
        }
    install_imported_server_conf(bundle,id);
    std::string key="/etc/voider/private/sftp-"+role+"-"+id+".key";
    copy_file(bundle.dir+"/meta/sftp_key",key);require(chmod(key.c_str(),0600)==0,"USB KEY PERMISSIONS FAILED");
    set_conf_value(pconf(role,id),"SFTP_KEY",key);set_conf_value(pconf(role,id),"USB_FP",bundle.fp);
    fs::create_directories(C.usb_import_dir);
    std::string imported=C.usb_import_dir+"/"+bundle.fp;
    // Validated private staging is copied only after the USB mount is closed.
    fs::remove_all(imported);
    command("cp -a "+shq(bundle.dir)+" "+shq(imported),"USB IMPORT FAILED");
    write_file(C.usb_fp_dir+"/import-"+role+"-"+id+".sha256",bundle.fp+"\n");
    std::cout<<"FINGERPRINT "<<bundle.fp<<"\n";safe_to_remove();return 0;
}
static int admin_key_new(const std::string&dev,const std::string&token){
    const std::string output="/run/voider/admin-key-new.pub";
    fs::remove(output);Media media=ready_media(dev,true,token);WorkDir work;
    struct statfs memory{};
    require(statfs(work.path.c_str(),&memory)==0&&memory.f_type==TMPFS_MAGIC,"USB NOT SAFE");
    std::string key=work.path+"/voider-admin";
    command("ssh-keygen -q -t ed25519 -N '' -C voider-admin -f "+shq(key),"USB KEY FAILED");
    capture("ssh-keygen -lf "+shq(key+".pub"));
    format_usb(media);UsbMount mount(media,false);
    copy_verified(key,C.usb_mount+"/voider-admin");copy_verified(key+".pub",C.usb_mount+"/voider-admin.pub");
    write_file(C.usb_mount+"/README.txt","Voider admin login key. Keep voider-admin private, run chmod 600 voider-admin, then use: ssh -i voider-admin root@VOIDER_ADDRESS\n",0);
    finish_write(media,mount,{"voider-admin","voider-admin.pub","README.txt"});copy_file(key+".pub",output);
    std::cout<<"ADMIN_LOGIN_KEY_READY\n";safe_to_remove();return 0;
}
static int backup_usb(const std::string&dev,const std::string&token){
    Media media=ready_media(dev,true,token);WorkDir work;
    require(fs::is_regular_file(C.state_tar),"BACKUP_STATE_MISSING",50);
    std::string system=current_system_digest();require(valid_hex(system,64),"BACKUP_INVALID system",55);
    copy_verified(C.state_tar,work.path+"/state.tar.gz");
    require(valid_state_archive(work.path+"/state.tar.gz"),"BACKUP_INVALID state",55);
    std::string hash=sha(work.path+"/state.tar.gz");
    format_usb(media);UsbMount mount(media,false);
    copy_verified(work.path+"/state.tar.gz",C.usb_mount+"/voider-backup.tar.gz");
    write_file(C.usb_mount+"/voider-backup.meta","FORMAT=VOIDER_BACKUP_2\nSTATE_TAR_SHA256="+hash+"\nSYSTEM_SHA256="+system+"\n",0);
    finish_write(media,mount,{"voider-backup.tar.gz","voider-backup.meta"});std::cout<<"BACKUP_OK\n";safe_to_remove();return 0;
}
static int restore_usb(const std::string&dev,const std::string&token,bool check){
    require(!token.empty(),"USB CONFIRMATION REQUIRED",24);
    Media media=ready_media(dev,false,token);WorkDir work;UsbMount mount(media,true);
    std::string archive=C.usb_mount+"/voider-backup.tar.gz",metadata=C.usb_mount+"/voider-backup.meta";
    require(fs::is_regular_file(metadata)&&!fs::is_symlink(metadata)&&fs::file_size(metadata)<=4096,"BACKUP_INVALID",53);
    std::ifstream input(metadata);require(input.good(),"USB READ FAILED");
    std::string meta((std::istreambuf_iterator<char>(input)),std::istreambuf_iterator<char>());require(!input.bad(),"USB READ FAILED");
    require(text_val(meta,"FORMAT")=="VOIDER_BACKUP_2"&&valid_hex(text_val(meta,"STATE_TAR_SHA256"),64)&&
        valid_hex(text_val(meta,"SYSTEM_SHA256"),64)&&text_val(meta,"SYSTEM_SHA256")==current_system_digest()&&
        fs::is_regular_file(archive)&&!fs::is_symlink(archive)&&fs::file_size(archive)<=512ull*1024*1024,"BACKUP_INVALID",53);
    copy_verified(archive,work.path+"/state.tar.gz",true);mount.close();
    require(sha(work.path+"/state.tar.gz")==text_val(meta,"STATE_TAR_SHA256")&&valid_state_archive(work.path+"/state.tar.gz"),"BACKUP_INVALID",53);
    std::string selected=read_file(selection_file),hash=sha(work.path+"/state.tar.gz");
    if(check){set_conf_value(selection_file,"BACKUP_SHA256",hash);std::cout<<"BACKUP_VALID\n";return 0;}
    require(text_val(selected,"BACKUP_SHA256")==hash,"BACKUP_INVALID",53);
    command("/usr/local/sbin/voider-integrity state-restore "+shq(work.path+"/state.tar.gz"),"STATE SAVE FAILED",45);std::cout<<"RESTORE_OK\n";safe_to_remove();return 0;
}
static int test_format(const std::string&dev){
    require(base_name(dev).rfind("loop",0)==0&&env_yes("VOIDER_USB_TEST_ALLOW_LOOP"),"TEST_REQUIRES_LOOP",60);
    Media media=ready_media(dev,true,"",true);format_usb(media,true);
    std::cout<<"LOOP_FORMAT_OK "<<part(media.dev)<<"\n";return 0;
}
static int selftest(){
    int cases=0;auto want=[&](bool ok,const std::string&label){cases++;require(ok,"USB_TEST FAIL "+label,1);};
    want(safe_member("./meta/manifest.txt"),"bundle allowlist");
    want(!safe_member("../../etc/shadow")&&!safe_member("meta/../shadow"),"bundle traversal");
    want(safe_state_member("etc/hostname")&&!safe_state_member("etc/shadow"),"curated state");
    want(valid_wg_key(std::string(43,'A')+"=")&&valid_onion(std::string(56,'a')+".onion"),"key shapes");
    std::string public_key="ssh-ed25519 "+std::string(44,'A');
    want(valid_host_pin(public_key)&&valid_host_pin(std::string(56,'a')+".onion "+public_key)&&
         !valid_host_pin("untrusted.example "+public_key),"current and legacy host pins");
    want(C.usb_mount.rfind("/run/voider/",0)==0,"RAM mountpoint");
    want(unescape_mount("/run/a\\040b")=="/run/a b","mountinfo escaping");
    int probes=0;Media m=wait_media([&]{if(++probes<3)throw Failure(20,"USB NOT READY");return Media{"ready","1","test"};});
    want(probes==3&&m.dev=="ready","delayed enumeration retries");
    probes=0;try{wait_media([&]()->Media{probes++;throw Failure(23,"USB IS MOUNTED");});}catch(const Failure&e){want(probes==1&&std::string(e.what())=="USB IS MOUNTED","exact rejection retained");}
    WorkDir work("/tmp");fs::create_directories(work.path+"/src/etc");write_file(work.path+"/src/etc/hostname","test\n");
    command("tar -C "+shq(work.path+"/src")+" -czf "+shq(work.path+"/state.tar.gz")+" etc/hostname","TEST TAR FAILED");
    want(valid_state_archive(work.path+"/state.tar.gz"),"valid restore archive");
    command("tar -C "+shq(work.path+"/src")+" --transform='s#^etc#../etc#' -czf "+shq(work.path+"/bad.tar.gz")+" etc/hostname","TEST TAR FAILED");
    want(!valid_state_archive(work.path+"/bad.tar.gz"),"restore traversal rejected");
    std::string conf=work.path+"/peer.conf";write_file(conf,"ROLE=client\nUSB_FP=old\nUSB_FP=older\n");set_conf_value(conf,"USB_FP","new");
    want(read_file(conf)=="ROLE=client\nUSB_FP=new\n","fingerprint replacement");
    try{capture("exit 9");want(false,"command failure hidden");}catch(const Failure&e){want(std::string(e.what())=="USB TOOL FAILED","command failure propagates");}
    std::cout<<"USB_TEST cases="<<cases<<" fails=0\n";return 0;
}
int main(int argc,char**argv){
    C=cfg();umask(0077);
    struct rlimit no_core{0,0};setrlimit(RLIMIT_CORE,&no_core);
    try{
        std::string cmd=argc>1?argv[1]:"";
        if(cmd=="selftest")return selftest();
        require(geteuid()==0,"USB ROOT REQUIRED",1);UsbLock lock;
        require(!fs::exists("/run/voider/restore-pending"),"RESTORE PENDING");
        // A killed predecessor may leave private staging in RAM. The exclusive
        // lock proves no live USB operation owns any of these work directories.
        for(const auto&entry:fs::directory_iterator("/run/voider"))
            if(entry.path().filename().string().rfind("usb-work.",0)==0)fs::remove_all(entry.path());
        if(cmd=="select"&&argc==3){require(std::string(argv[2])=="erase"||std::string(argv[2])=="read","USB INVALID PURPOSE",2);return select_media(std::string(argv[2])=="erase");}
        if(cmd=="export"&&argc==6)return export_usb(argv[2],argv[3],argv[4],argv[5]);
        if(cmd=="import"&&(argc==5||argc==6))return import_usb(argv[2],argv[3],argv[4],argc==6?argv[5]:"");
        if(cmd=="fingerprint"&&argc==3)return fingerprint(argv[2]);
        if(cmd=="admin-new"&&argc==4)return admin_key_new(argv[2],argv[3]);
        if(cmd=="backup"&&argc==4)return backup_usb(argv[2],argv[3]);
        if((cmd=="restore"||cmd=="restore-check")&&argc==4)return restore_usb(argv[2],argv[3],cmd=="restore-check");
        if(cmd=="test-format"&&argc==3)return test_format(argv[2]);
        if(cmd=="bundle"&&argc==5){WorkDir work;make_bundle(argv[2],argv[3],argv[4],work.path+"/source");return 0;}
        std::cerr<<"usage: voider-usb select erase|read | export ROLE ID DEVICE TOKEN | import ROLE ID DEVICE [FINGERPRINT] | fingerprint DEVICE | admin-new DEVICE TOKEN | bundle ROLE ID OUT.tar | backup DEVICE TOKEN | restore-check DEVICE TOKEN | restore DEVICE TOKEN | selftest\n";
        return 2;
    }catch(const Failure&e){
        if(!active_media.dev.empty())try{identity_present(active_media);}catch(const Failure&changed){std::cerr<<changed.what()<<"\n";return changed.code;}
        std::cerr<<e.what()<<"\n";return e.code;
    }
    catch(const std::exception&e){
        std::cerr<<"USB IO: "<<e.what()<<"\n";
        if(!active_media.dev.empty())try{identity_present(active_media);}catch(const Failure&changed){std::cerr<<changed.what()<<"\n";return changed.code;}
        std::cerr<<(reading_media?"USB READ FAILED":"USB WRITE FAILED")<<"\n";return 23;
    }
}
