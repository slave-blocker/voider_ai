#include <array>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
#include "voider_util.hpp"

using vu::cap;
using vu::read_file;
using vu::shq;

namespace fs = std::filesystem;

static const fs::path offline_marker="/opt/voider-installer/offline.ready";
static const fs::path installed_marker="/etc/voider/.installed";
static const fs::path install_status_path="/run/voider/factory-install.status";
static const fs::path factory_admin_key="/boot/voider-authorized_keys";
static const fs::path installed_admin_key="/etc/voider/certs/admin_authorized_keys";

static void install_status(const std::string&state,const std::string&phase,int progress,const std::string&detail=""){
    fs::create_directories("/run/voider");
    std::ofstream f(install_status_path,std::ios::trunc);
    f<<"STATE="<<state<<"\nPHASE="<<phase<<"\nPROGRESS="<<progress<<"\n";
    if(!detail.empty())f<<"DETAIL="<<detail<<"\n";
}
static int install_fail(int rc,const std::string&detail){install_status("FAILED","FAILED",0,detail);return rc?rc:1;}

static std::vector<std::string> manifest(const fs::path& path){
    std::vector<std::string> out;
    std::ifstream file(path);
    std::string line;
    while(std::getline(file,line)){line=trim(line);if(!line.empty()&&line[0]!='#')out.push_back(line);}
    return out;
}

static bool ends_with(const std::string& s,const std::string& suffix){
    return s.size()>=suffix.size() &&
           s.compare(s.size()-suffix.size(),suffix.size(),suffix)==0;
}

static void write_file(const fs::path& p,const std::string& body,mode_t mode=0644){
    fs::create_directories(p.parent_path());
    fs::path tmp=p;
    tmp += ".new";
    std::ofstream out(tmp,std::ios::binary|std::ios::trunc);
    out<<body;
    out.close();
    chmod(tmp.c_str(),mode);
    fs::rename(tmp,p);
}

static void cp(const fs::path& src,const fs::path& dst){
    fs::create_directories(dst.parent_path());
    fs::path tmp=dst;
    tmp += ".new";
    fs::copy_file(src,tmp,fs::copy_options::overwrite_existing);
    fs::rename(tmp,dst);
}

static int run_or_fail(const std::string& cmd,const std::string& what){
    int rc=vu::run(cmd);
    if(rc){std::cerr<<"voider-install: "<<what<<" failed\n";install_status("FAILED","FAILED",0,what);}
    return rc;
}

static bool valid_admin_public_key(std::string&normalized){
    std::error_code ec;
    if(!fs::is_regular_file(factory_admin_key,ec)||fs::is_symlink(factory_admin_key,ec))return false;
    std::ifstream in(factory_admin_key);
    std::string line;
    int keys=0;
    while(std::getline(in,line)){
        line=trim(line);
        if(line.empty()||line[0]=='#')continue;
        normalized=line;
        keys++;
    }
    if(keys!=1)return false;
    std::istringstream row(normalized);
    std::string type;
    row>>type;
    if(type!="ssh-ed25519"&&type!="sk-ssh-ed25519@openssh.com"&&
       type!="ecdsa-sha2-nistp256"&&type!="sk-ecdsa-sha2-nistp256@openssh.com"&&type!="ssh-rsa")return false;
    std::string info=cap("ssh-keygen -lf "+shq(factory_admin_key.string())+" 2>/dev/null");
    if(info.empty())return false;
    if(type=="ssh-rsa"){
        std::istringstream parsed(info);
        int bits=0;
        if(!(parsed>>bits)||bits<3072)return false;
    }
    return true;
}

static int set_root_unknown_password(){
    std::string hash=cap("p=$(openssl rand -hex 32) && openssl passwd -6 \"$p\" 2>/dev/null");
    if(hash.rfind("$6$",0)!=0)return 62;
    std::ifstream in("/etc/shadow");
    if(!in.good())return 62;
    std::string body,line;
    bool found=false;
    while(std::getline(in,line)){
        if(line.rfind("root:",0)==0){
            size_t end=line.find(':',5);
            if(end==std::string::npos)return 62;
            line="root:"+hash+line.substr(end);
            found=true;
        }
        body+=line+"\n";
    }
    if(!found)return 62;
    write_file("/etc/shadow",body,0600);
    return 0;
}

static int configure_installed_admin(bool&enabled){
    enabled=false;
    if(!fs::exists(factory_admin_key)){
        fs::remove(installed_admin_key);
        return set_root_unknown_password();
    }
    std::string key;
    if(!valid_admin_public_key(key)){
        std::cerr<<"voider-install: injected admin public key is invalid\n";
        return 63;
    }
    write_file(installed_admin_key,key+"\n",0600);
    if(set_root_unknown_password()){
        std::cerr<<"voider-install: could not enable key-only root administration\n";
        return 64;
    }
    enabled=true;
    return 0;
}

static int configure_admin_switch(bool enabled){
    if(vu::replace_config_value("/etc/voider/voider.conf","ADMIN_SSH_LAN",enabled?"1":"0"))return 0;
    std::cerr<<"voider-install: could not set the management SSH state\n";
    return 65;
}

static bool supported_display_hardware(){
    std::string hat=read_file("/proc/device-tree/hat/product");
    return hat.find("PiTFT")!=std::string::npos ||
           hat.find("ILI9340")!=std::string::npos;
}

static int verify_factory_layout(){
    std::string root=cap("findmnt -n -o SOURCE / 2>/dev/null");
    std::string boot=cap("findmnt -n -o SOURCE /boot 2>/dev/null");
    std::string state=cap("findmnt -n -o SOURCE /mnt/voider-state 2>/dev/null");
    if(root.empty()||boot.empty()||state.empty()){
        std::cerr<<"voider-install: expected /, /boot, and /mnt/voider-state mounts are missing\n";
        return 20;
    }
    auto parent=[](const std::string& dev){
        return cap("lsblk -ndo PKNAME "+shq(dev)+" 2>/dev/null");
    };
    std::string rp=parent(root), bp=parent(boot), sp=parent(state);
    if(rp.empty()||rp!=bp||rp!=sp){
        std::cerr<<"voider-install: the three appliance partitions are not on one card\n";
        return 21;
    }
    std::string rpart=cap("lsblk -ndo PARTN "+shq(root)+" 2>/dev/null");
    std::string bpart=cap("lsblk -ndo PARTN "+shq(boot)+" 2>/dev/null");
    std::string spart=cap("lsblk -ndo PARTN "+shq(state)+" 2>/dev/null");
    if(bpart!="1"||rpart!="2"||spart!="3"){
        std::cerr<<"voider-install: expected BOOT=partition 1, SYSTEM=partition 2, STATE=partition 3\n";
        return 22;
    }
    auto property=[](const std::string&dev,const std::string&name){return cap("blkid -s "+name+" -o value "+shq(dev)+" 2>/dev/null");};
    if(property(boot,"LABEL")!="BOOT"||property(root,"LABEL")!="SYSTEM"||property(state,"LABEL")!="STATE"){
        std::cerr<<"voider-install: partition labels must be BOOT, SYSTEM, STATE\n";return 23;
    }
    std::string ptuuid=property("/dev/"+rp,"PTUUID");
    std::string boot_uuid=property(boot,"UUID"),system_uuid=property(root,"UUID"),state_uuid=property(state,"UUID");
    if((ptuuid!="564f4944"&&ptuuid!="564F4944")||boot_uuid!="564F-4944"||
       system_uuid!="11111111-1111-4111-8111-111111111111"||
       state_uuid!="22222222-2222-4222-8222-222222222222"){
        std::cerr<<"voider-install: partition-table and filesystem UUIDs do not match the factory image\n";return 24;
    }
    // Exact byte sizes and 512-byte-sector starts from config/release-layout.
    // Equality checks avoid arithmetic on untrusted device output; only the
    // parent capacity needs parsing, with full uint64 overflow/trailing checks.
    const std::array<std::array<std::string,3>,3> partitions{{
        {boot,"134217728","2048"}, {root,"536870912","264192"},
        {state,"268435456","1312768"}
    }};
    for(const auto& p:partitions){
        if(cap("blockdev --getsize64 "+shq(p[0]))!=p[1]||
           cap("lsblk -ndo START "+shq(p[0]))!=p[2]){
            std::cerr<<"voider-install: partition boundaries do not match the appliance layout\n";return 25;
        }
    }
    std::string disk="/dev/"+rp, capacity=cap("blockdev --getsize64 "+shq(disk));
    std::uint64_t bytes=0;
    auto parsed=std::from_chars(capacity.data(),capacity.data()+capacity.size(),bytes);
    if(parsed.ec!=std::errc{}||parsed.ptr!=capacity.data()+capacity.size()||bytes<940572672ULL||
       cap("blockdev --getss "+shq(disk))!="512"||property(disk,"PTTYPE")!="dos"||
       cap("lsblk -nr -o TYPE "+shq(disk))!="disk\npart\npart\npart"){
        std::cerr<<"voider-install: card capacity or partition table does not match the appliance layout\n";return 25;
    }
    std::cout<<"Layout verified: /dev/"<<rp<<" partitions 1=BOOT, 2=SYSTEM, 3=STATE\n";
    return 0;
}

static int dependencies(){
    const char* commands[]={
        "ip","iptables","ip6tables","wg","tor","sshd","ssh-keygen","openssl",
        "conntrack","brctl","curl","tar","gpiomon","chronyc","chronyd","nc",
        "rc-service","rc-update","findmnt","lsblk"
    };
    for(const char* c:commands){
        if(vu::run(std::string("command -v ")+c+" >/dev/null 2>&1")){
            std::cerr<<"voider-install: offline payload is missing runtime command "<<c<<"\n";
            return 31;
        }
    }
    if(vu::run("tar --version 2>/dev/null | grep -qi 'gnu tar'")){
        std::cerr<<"voider-install: GNU tar is required for deterministic state archives\n";
        return 32;
    }
    return 0;
}

static void configure_boot_display(){
    const fs::path p="/boot/usercfg.txt";
    std::vector<std::string> lines;
    std::ifstream in(p);
    std::string line;
    bool spi=false;
    while(std::getline(in,line)){
        std::string t=trim(line);
        if(t.rfind("dtoverlay=pitft28-resistive",0)==0) continue;
        if(t=="dtparam=spi=on") spi=true;
        lines.push_back(line);
    }
    if(!spi) lines.push_back("dtparam=spi=on");
    lines.push_back("dtoverlay=pitft28-resistive,rotate=270,speed=32000000,fps=20");
    std::string body;
    for(const auto& l:lines) body+=l+"\n";
    write_file(p,body);
}

static int seal_fstab(){
    std::ifstream in("/etc/fstab");
    if(!in.good()){
        std::cerr<<"voider-install: /etc/fstab is missing\n";
        return 23;
    }
    std::string out,line;
    bool root=false,boot=false,state=false;
    while(std::getline(in,line)){
        std::istringstream row(line);
        std::string source,mountpoint,type,options,dump,pass;
        if(!(row>>source>>mountpoint>>type>>options>>dump>>pass) || line.empty() || line[0]=='#'){
            out+=line+"\n";
            continue;
        }
        if(mountpoint=="/"||mountpoint=="/boot"||mountpoint=="/mnt/voider-state"){
            std::vector<std::string> kept;
            std::istringstream option_stream(options);
            std::string option;
            while(std::getline(option_stream,option,','))
                if(option!="rw"&&option!="ro"&&!option.empty()) kept.push_back(option);
            options="ro";
            for(const auto& x:kept) options+=","+x;
            root|=mountpoint=="/";
            boot|=mountpoint=="/boot";
            state|=mountpoint=="/mnt/voider-state";
            out+=source+" "+mountpoint+" "+type+" "+options+" "+dump+" "+pass+"\n";
        }else out+=line+"\n";
    }
    if(!root||!boot||!state){
        std::cerr<<"voider-install: fstab must contain /, /boot, and /mnt/voider-state\n";
        return 24;
    }
    write_file("/etc/fstab",out);
    return 0;
}

static int create_clean_identity(){
    std::string id=cap("openssl rand -hex 4");
    std::string machine=cap("openssl rand -hex 16");
    if(id.size()!=8||machine.size()!=32){
        std::cerr<<"voider-install: could not generate unique device identity\n";
        return 40;
    }
    std::string hostname="voider-"+id;
    write_file("/etc/hostname",hostname+"\n");
    write_file("/etc/machine-id",machine+"\n",0444);
    write_file("/etc/network/interfaces",
        "auto lo\niface lo inet loopback\n\n"
        "auto eth0\niface eth0 inet manual\n\n"
        "auto eth1\niface eth1 inet static\n"
        "  address 172.16.19.86\n  netmask 255.255.255.252\n");
    for(const auto& e:fs::directory_iterator("/etc/ssh")){
        std::string n=e.path().filename().string();
        if(n.rfind("ssh_host_",0)==0 && (ends_with(n,"_key")||ends_with(n,"_key.pub")))
            fs::remove(e.path());
    }
    int rc=run_or_fail("ssh-keygen -A","unique SSH host-key generation");
    if(rc) return rc;
    fs::remove("/etc/ssh/ssh_host_ecdsa_key");
    fs::remove("/etc/ssh/ssh_host_ecdsa_key.pub");
    std::cout<<"Identity generated: "<<hostname<<"\n";
    return 0;
}

static int configure_runtime_dns(){
    // Alpine's udhcpc hook creates a temporary file beside RESOLV_CONF before
    // renaming it. Keep both files in RAM so DHCP never writes sealed SYSTEM.
    write_file("/etc/udhcpc/udhcpc.conf","RESOLV_CONF=/run/resolv.conf\n");
    std::error_code ec;
    fs::remove("/etc/resolv.conf",ec);
    ec.clear();
    fs::create_symlink("/run/resolv.conf","/etc/resolv.conf",ec);
    if(ec){
        std::cerr<<"voider-install: could not configure RAM-backed DNS: "<<ec.message()<<"\n";
        return 41;
    }
    // DHCP can become usable just after chronyd's one-shot initstepslew DNS
    // lookup.  Permit a bounded number of early updates to correct a Pi with
    // no RTC; later operation remains slew-only so an established call is not
    // disrupted by an arbitrary wall-clock jump.
    write_file("/etc/chrony/chrony.conf",
        "# Voider: recover time after delayed DHCP/DNS on RTC-less hardware.\n"
        "pool pool.ntp.org iburst\n"
        "initstepslew 10 pool.ntp.org\n"
        "makestep 10 5\n"
        "driftfile /var/lib/chrony/chrony.drift\n"
        "rtcsync\n"
        "cmdport 0\n");
    return 0;
}

static int copy_payload(bool fresh){
    fs::create_directories("/usr/share/voider");
    cp("assets/fonts/OFL.txt","/usr/share/voider/DINish-OFL.txt");
    for(const auto& d:{
        "/etc/voider/peers/clients.d","/etc/voider/peers/servers.d",
        "/etc/voider/peers/material","/etc/voider/private","/etc/voider/sync","/etc/voider/certs",
        "/etc/voider/node","/etc/voider/certs/fingerprints","/etc/voider/certs/rejected",
        "/etc/voider/certs/mailboxes",
        "/etc/voider/imports","/etc/voider/dhcp","/mnt/voider-state/voider",
        "/var/sftp","/etc/ssh/sshd_config.d"
    }) fs::create_directories(d);
    if(fresh||!fs::exists("/etc/voider/voider.conf")){
        cp("config/voider.conf","/etc/voider/voider.conf");
    }
    cp("scripts/pitft-bridge","/usr/local/sbin/pitft-bridge");
    cp("scripts/voider-tor","/usr/local/sbin/voider-tor");
    chmod("/usr/local/sbin/voider-tor",0755);
    cp("openrc/01-quiet-pitft-console.start","/etc/local.d/01-quiet-pitft-console.start");

    auto binaries=manifest("config/release-binaries");
    auto services=manifest("config/release-services");
    if(binaries.empty()||services.empty())return 50;
    for(const auto& x:binaries){
        fs::path src=fs::path("build")/x;
        if(!fs::exists(src)){
            std::cerr<<"voider-install: payload binary missing: "<<src<<"\n";
            return 50;
        }
        cp(src,fs::path("/usr/local/sbin")/x);
    }
    // Keep native providers during factory identity creation. Their installed
    // versions require the integrity seal that this installation will create.
    for(const auto& s:services){
        if(s=="tor"||s=="sshd"||s=="chronyd")continue;
        cp(fs::path("openrc")/s,fs::path("/etc/init.d")/s);
    }

    vu::run("chmod 600 /etc/voider/private/* 2>/dev/null || true");
    return run_or_fail(
        "chmod 755 /etc/init.d/voider* /usr/local/sbin/voider* /usr/local/sbin/tundup-v7* "
        "/usr/local/sbin/pitft-bridge 2>/dev/null",
        "installed-file permission setup");
}

static int enable_services(){
    vu::run("rc-update del networking boot 2>/dev/null || true");
    vu::run("rc-update del networking default 2>/dev/null || true");
    int rc=run_or_fail(
        "rc-update add voider-appliance boot && "
        "rc-update add voider-wan default && "
        "rc-update add voider-phone default && "
        "rc-update add voider-firewall default && "
        "rc-update add voider-nfqd default && "
        "rc-update add chronyd default && "
        "rc-update add tor default && "
        "rc-update add sshd default && "
        "rc-update add local default && "
        "rc-update add voider default",
        "OpenRC service enablement");
    if(rc) return rc;
    vu::run("rc-update del pitft-bridge default 2>/dev/null || true");
    vu::run("rc-update del voider-tor-netns-socks boot 2>/dev/null || true");
    vu::run("rc-update del voider-tor-netns-socks default 2>/dev/null || true");
    vu::run("rm -f /etc/runlevels/default/pitft-bridge /etc/init.d/pitft-bridge");
    return run_or_fail("rc-update add voider-display boot","display service enablement");
}

static void stop_factory_ssh(){
    vu::run("test ! -s /run/voider-factory/sshd.pid || kill $(cat /run/voider-factory/sshd.pid) 2>/dev/null || true");
}

static int remove_factory_bootstrap(bool admin_enabled){
    vu::run("rc-update del voider-factory-bootstrap default 2>/dev/null || true");
    for(const auto&p:{"/boot/voider-authorized_keys","/etc/init.d/voider-factory-bootstrap","/usr/local/sbin/voider-factory-bootstrap","/usr/local/sbin/voider-factory-dhcp","/etc/sysctl.d/90-voider-factory-lan.conf","/usr/local/bin/install","/etc/profile.d/voider-install.sh"})
        fs::remove(p);
    write_file("/etc/motd",admin_enabled?
        "VOIDER APPLIANCE\nPrivate-LAN administration: public key only.\n":
        "VOIDER APPLIANCE\nNo administrative SSH key installed.\n");
    return 0;
}

static int finalize_identity_and_state(bool fresh){
    if(!fs::exists("/etc/voider/private/tundup_psk.hex")){
        int rc=run_or_fail("umask 077; openssl rand -hex 32 > /etc/voider/private/tundup_psk.hex","tundup secret generation");
        if(rc) return rc;
    }
    fs::create_directories("/run/voider");
    install_status("INSTALLING","GENERATING PRIVATE LINK",60);
    bool admin_enabled=fs::is_regular_file(installed_admin_key);
    if(fresh){
        int admin_rc=configure_installed_admin(admin_enabled);
        if(admin_rc)return admin_rc;
        admin_rc=configure_admin_switch(admin_enabled);
        if(admin_rc)return admin_rc;
    }
    int rc=run_or_fail("/usr/local/sbin/voider-sftp-setup accounts >/run/voider/last-sftp-accounts 2>&1","fixed mailbox account setup");
    if(rc) return rc;
    rc=run_or_fail("/usr/local/sbin/voider-sftp-setup apply >/run/voider/last-sftp-setup 2>&1","strict SFTP/Tor setup");
    if(rc) return rc;
    if(fresh){
        for(int i=0;i<30 && !fs::exists("/var/lib/tor/voider/hostname");i++) sleep(1);
        if(!fs::exists("/var/lib/tor/voider/hostname")){
            std::cerr<<"voider-install: Tor did not create the appliance onion identity\n";
            return 60;
        }
        rc=run_or_fail("/usr/local/sbin/voider-sftp-setup publish-identity >/run/voider/last-sftp-setup 2>&1","SFTP identity publication");
        if(rc) return rc;
        write_file(installed_marker,"VOIDER_INSTALL_COMPLETE=1\n",0600);
    }
    rc=seal_fstab();
    if(rc) return rc;
    install_status("INSTALLING","VERIFYING CONFIGURATION",72);
    rc=run_or_fail("/usr/local/sbin/voider-selftest config","installed configuration self-test");
    if(rc) return rc;
    vu::run("rc-service voider stop 2>/dev/null || true");
    // The factory display must remain visible through sealing and the reboot decision.
    if(!fresh)vu::run("rc-service voider-display stop 2>/dev/null || true");
    vu::run("rc-service tor stop 2>/dev/null || true");
    vu::run("rc-service sshd stop 2>/dev/null || true");
    vu::run("rc-service chronyd stop 2>/dev/null || true");
    vu::run("rc-service crond stop 2>/dev/null || true");
    vu::run("rc-service syslog stop 2>/dev/null || true");
    for(const auto& name:{"tor","sshd","chronyd"}){
        cp(fs::path("openrc")/name,fs::path("/etc/init.d")/name);
        if(::chmod((std::string("/etc/init.d/")+name).c_str(),0755))return 50;
    }
    // Seal the installed-boot dependencies after the existing factory identity
    // generation has finished; it cannot use a not-yet-created integrity seal.
    for(const auto& name:{"networking","sshd","tor","chronyd"}){
        std::string path=std::string("/etc/conf.d/")+name;
        std::ifstream in(path);std::string body((std::istreambuf_iterator<char>(in)),{});
        body+="\n# Voider activation: DEVICE CHECK + YOUR CHECK\nrc_need=\"voider-appliance voider-firewall\"\n";
        write_file(path,body);
    }
    vu::run("sync");
    rc=remove_factory_bootstrap(admin_enabled);
    if(rc) return rc;
    install_status("INSTALLING","SAVING STATE",82);
    rc=run_or_fail("/usr/local/sbin/voider-integrity state-commit INSTALLATION","curated STATE commit");
    if(rc) return rc;
    vu::run("mount -o remount,ro /boot 2>/dev/null || true");
    install_status("INSTALLING","HASHING BOOT AND SYSTEM",90);
    rc=run_or_fail("/usr/local/sbin/voider-integrity freeze","BOOT and SYSTEM seal");
    if(rc) return rc;
    stop_factory_ssh();
    return 0;
}

int main(int argc,char** argv){
    if(geteuid()!=0){
        std::cerr<<"voider-install: run install as root\n";
        return 1;
    }
    for(int i=1;i<argc;i++){
        std::string a=argv[i];
        if(a=="--display") {}
        else{
            std::cerr<<"usage: install [--display]\n";
            return 2;
        }
    }
    bool fresh=fs::exists(offline_marker)&&!fs::exists(installed_marker);
    install_status("INSTALLING","VERIFYING IMAGE",2);
    if(fresh){
        int rc=verify_factory_layout();
        if(rc) return install_fail(rc,"FACTORY IMAGE LAYOUT");
    }
    install_status("INSTALLING","CHECKING OFFLINE PAYLOAD",8);
    int rc=dependencies();
    if(rc) return install_fail(rc,"OFFLINE PAYLOAD");

    bool display=supported_display_hardware();
    if(!display)return install_fail(4,"DISPLAY NOT DETECTED");
    std::cout<<"Display hardware: attached\n";
    install_status("INSTALLING","CONFIGURING HARDWARE",15);
    configure_boot_display();
    if(fresh){
        rc=create_clean_identity();
        if(rc) return install_fail(rc,"IDENTITY GENERATION");
    }
    rc=configure_runtime_dns();
    if(rc) return install_fail(rc,"RUNTIME DNS");
    install_status("INSTALLING","INSTALLING VOIDER",25);
    rc=copy_payload(fresh);
    if(rc) return install_fail(rc,"INSTALLER PAYLOAD");

    fs::create_directories("/etc/sysctl.d");
    write_file("/etc/sysctl.d/90-voider-ipv6-router.conf",
        "net.ipv6.conf.all.forwarding=1\nnet.ipv6.conf.eth0.accept_ra=2\n");
    install_status("INSTALLING","CONFIGURING SERVICES",40);
    rc=enable_services();
    if(rc) return install_fail(rc,"SERVICE CONFIGURATION");
    install_status("INSTALLING","GENERATING PRIVATE IDENTITY",55);
    rc=finalize_identity_and_state(fresh);
    if(rc) return install_fail(rc,"FINAL VERIFICATION");

    std::string updated=read_file("/run/voider/state-updated.status");
    install_status("COMPLETE","INSTALL COMPLETE",100,updated.find("EXTERNAL_STATE_CODE=")!=std::string::npos?"RECORD STATE FINGERPRINT":"RECORD FINGERPRINT");
    std::cout<<"\nVOIDER INSTALL COMPLETE\n";
    vu::run("/usr/local/sbin/voider-integrity stateprint");
    std::cout<<"REBOOT REQUIRED 1\nReboot exactly once. BOOT and SYSTEM are read-only; runtime is in RAM; curated state is on STATE.\n";
    return 0;
}
