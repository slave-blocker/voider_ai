#include <filesystem>
#include <fstream>
#include <iostream>
#include <cstdlib>
#include <cstdio>
#include <array>
#include <sstream>
#include <iterator>
#include <vector>
#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>
#include "voider_config.hpp"
#include "voider_util.hpp"

#include "voider_mailbox.hpp"

using vu::cap;
using vu::read_file;
using vu::run;
namespace fs=std::filesystem;
static Cfg C;
static std::string strip_old_voider_torrc_blocks(const std::string&in){
    // fix25: Tor config must be idempotent. Runtime evidence showed repeated
    // installs left duplicate SocksPort 127.0.0.1:9050, duplicate
    // SocksPort 172.30.255.1:19050, and duplicate HiddenServiceDir
    // /var/lib/tor/voider blocks. Tor then starts, binds the first pair of
    // SOCKS listeners, tries the duplicates, and crashes with address-in-use.
    std::stringstream src(in);
    std::string out,line;
    bool skip_managed=false;
    bool skip_hs=false;
    std::string socks1="SocksPort "+C.socks_host+":"+std::to_string(C.socks_port);
    std::string socks2="SocksPort "+C.tor_netns_socks_ip+":"+std::to_string(C.tor_netns_socks_port);
    auto is_hs_dir=[&](const std::string&l){
        std::string t=trim(l);
        std::string a="HiddenServiceDir "+C.tor_hs_dir;
        std::string b=a+"/";
        return t==a || t==b;
    };
    auto is_voider_socks=[&](const std::string&l){
        std::string t=trim(l);
        return t==socks1 || t==socks2;
    };
    while(std::getline(src,line)){
        std::string t=trim(line);
        if(t.find("BEGIN voider managed torrc")!=std::string::npos ||
           t.find("voider managed block BEGIN")!=std::string::npos){
            skip_managed=true;
            continue;
        }
        if(skip_managed){
            if(t.find("END voider managed torrc")!=std::string::npos ||
               t.find("voider managed block END")!=std::string::npos) skip_managed=false;
            continue;
        }
        if(is_voider_socks(line)) continue;
        if(t=="SocksPolicy accept 127.0.0.1" ||
           t=="SocksPolicy accept 172.30.0.0/16" ||
           t=="SocksPolicy reject *") continue;
        if(is_hs_dir(line)){
            skip_hs=true;
            continue;
        }
        if(skip_hs){
            if(t.rfind("HiddenServicePort ",0)==0 ||
               t.rfind("HiddenServiceVersion ",0)==0 ||
               t.rfind("HiddenServiceAuthorizeClient ",0)==0) continue;
            skip_hs=false;
        }
        if(t.find("voider node hidden service")!=std::string::npos ||
           t.find("same onion: port 22=SFTP")!=std::string::npos ||
           t.find("Managed by voider-sftp-setup")!=std::string::npos) continue;
        out += line + "\n";
    }
    return out;
}
static void write_file(const std::string&p,const std::string&s,int mode=0644){
    fs::create_directories(fs::path(p).parent_path());
    std::ofstream(p)<<s;
    chmod(p.c_str(),mode);
}

static bool mailbox_name(const std::string& name){
    if(name.size()!=6||(name.rfind("vmc",0)!=0&&name.rfind("vms",0)!=0))return false;
    int slot=toi(name.substr(3),0);
    std::string role=name.rfind("vmc",0)==0?"client":"server";
    return vmb::slot_ok(slot)&&name==vmb::user(role,slot);
}
static bool make_mailbox_accounts_pubkey_only(){
    // OpenSSH rejects a shadow-locked account before public-key processing.
    // "NP" is not a usable hash; global password authentication is also off,
    // and every account has nologin plus a forced internal-SFTP command.
    std::ifstream in("/etc/shadow");
    if(!in.good())return false;
    std::vector<std::string> lines;
    std::string l;
    bool changed=false;
    while(std::getline(in,l)){
        size_t a=l.find(':');
        std::string name=a==std::string::npos?"":l.substr(0,a);
        if(mailbox_name(name)){
            size_t b=l.find(':',a+1);
            std::string field=(a!=std::string::npos&&b!=std::string::npos)?l.substr(a+1,b-a-1):"";
            if(field!="NP"&&b!=std::string::npos){
                l=name+":NP"+l.substr(b);
                changed=true;
            }
        }
        lines.push_back(l);
    }
    if(changed){
        std::ofstream out("/etc/shadow.new");
        for(auto&s:lines)out<<s<<"\n";
        out.close();
        if(!out||chmod("/etc/shadow.new",0600)||run("mv /etc/shadow.new /etc/shadow"))return false;
    }
    return true;
}

static bool mailbox_shadow_is_np(const std::string&name){
    std::ifstream in("/etc/shadow");
    std::string line;
    while(std::getline(in,line)){
        size_t a=line.find(':');
        if(a==std::string::npos||line.substr(0,a)!=name)continue;
        size_t b=line.find(':',a+1);
        return b!=std::string::npos&&line.substr(a+1,b-a-1)=="NP";
    }
    return false;
}
static bool mailbox_account_valid(const std::string& role,int slot){
    std::string name=vmb::user(role,slot);
    auto* account=getpwnam(name.c_str());
    auto* group=getgrnam(C.mailbox_group.c_str());
    return account&&group&&account->pw_dir&&account->pw_shell&&account->pw_gid==group->gr_gid&&
           std::string(account->pw_dir)==vmb::root(C,role,slot).string()&&
           std::string(account->pw_shell)=="/sbin/nologin"&&
           mailbox_shadow_is_np(name);
}
static int setup_accounts(){
    if(run("getent group "+C.mailbox_group+" >/dev/null 2>&1 || addgroup -S "+C.mailbox_group))return 2;
    for(const std::string role:{"client","server"})for(int slot=2;slot<=254;slot++){
        std::string user=vmb::user(role,slot);
        if(!getpwnam(user.c_str())&&run("adduser -S -D -H -h "+vmb::root(C,role,slot).string()+
            " -s /sbin/nologin -G "+C.mailbox_group+' '+user))return 2;
    }
    if(!make_mailbox_accounts_pubkey_only())return 2;
    for(const std::string role:{"client","server"})for(int slot=2;slot<=254;slot++)
        if(!mailbox_account_valid(role,slot))return 2;
    return 0;
}
static bool configured_client_slot(int slot){
    return fs::is_regular_file(fs::path(C.pc)/(std::to_string(slot)+".conf"));
}
static bool provisioned_client_slot(int slot){
    fs::path material=fs::path(C.mat)/"client"/std::to_string(slot);
    return configured_client_slot(slot)&&fs::is_regular_file(material/"private.key")&&
           fs::is_regular_file(material/"public.key")&&fs::is_regular_file(material/"preshared.key");
}
static bool authorized_client_slot(int slot){
    fs::path material=fs::path(C.mat)/"client"/std::to_string(slot);
    return provisioned_client_slot(slot)&&fs::is_regular_file(material/"usb_secret.hex")&&
           fs::is_regular_file(material/"tundup_psk.hex")&&fs::is_regular_file(vmb::keys(C,"client",slot));
}
static bool plain_directory(const fs::path&path){
    std::error_code error;
    auto status=fs::symlink_status(path,error);
    return !error&&fs::is_directory(status)&&!fs::is_symlink(status);
}
static bool active_client_slot(int slot){
    fs::path root=vmb::root(C,"client",slot);
    return authorized_client_slot(slot)&&plain_directory(root)&&plain_directory(root/"in")&&
           plain_directory(root/"out");
}
static bool safe_directory(const fs::path& path){
    std::error_code error;
    auto status=fs::symlink_status(path,error);
    if(!error&&fs::exists(status)&&(!fs::is_directory(status)||fs::is_symlink(status)))
        fs::remove_all(path,error);
    fs::create_directories(path,error);
    return !error&&fs::is_directory(fs::symlink_status(path,error))&&!error;
}
static bool setup_slot(const std::string& role,int slot,bool clean){
    if(!vmb::role_ok(role)||!vmb::slot_ok(slot)||!mailbox_account_valid(role,slot))return false;
    std::string user=vmb::user(role,slot);
    auto* account=getpwnam(user.c_str());
    if(!account)return false;
    fs::path parent=fs::path(C.sftp_base)/(role=="client"?"clients":"servers");
    fs::path root=vmb::root(C,role,slot),incoming=root/"in",outgoing=root/"out";
    if(!safe_directory(C.sftp_base)||!safe_directory(parent)||!safe_directory(root)||
       !safe_directory(incoming)||!safe_directory(outgoing))return false;
    if(clean){
        for(const auto& dir:{incoming,outgoing})for(const auto& entry:fs::directory_iterator(dir)){
            std::error_code error;
            fs::remove_all(entry.path(),error);
        }
    }
    if(chown(C.sftp_base.c_str(),0,0)||chmod(C.sftp_base.c_str(),0755)||
       chown(parent.c_str(),0,0)||chmod(parent.c_str(),0755)||
       chown(root.c_str(),0,0)||chmod(root.c_str(),0755)||
       chown(incoming.c_str(),account->pw_uid,account->pw_gid)||chmod(incoming.c_str(),0700)||
       chown(outgoing.c_str(),0,0)||chmod(outgoing.c_str(),0755))return false;
    return true;
}
static bool remove_slot_resources(const std::string& role,int slot){
    std::error_code root_error,key_error;
    fs::remove_all(vmb::root(C,role,slot),root_error);
    fs::remove(vmb::keys(C,role,slot),key_error);
    return !root_error&&!key_error;
}
static int setup_slots(bool clean=true){
    fs::create_directories(C.sftp_base);
    int failures=0;
    for(const std::string role:{"client","server"})for(int slot=2;slot<=254;slot++){
        bool authorized=role=="client"&&authorized_client_slot(slot);
        if(!authorized){
            std::error_code error;
            fs::remove(vmb::keys(C,role,slot),error);
            if(error)failures++;
        }
        if(!setup_slot(role,slot,clean))failures++;
        else if(authorized&&!active_client_slot(slot))failures++;
    }
    return failures?2:0;
}

static void cleanup_legacy_shared_identity(){
    fs::create_directories(C.node_dir);
    if(!fs::exists(C.sftp_host_pub)&&fs::exists("/etc/voider/self/host.pub"))
        fs::copy_file("/etc/voider/self/host.pub",C.sftp_host_pub);
    for(const auto& path:{"/etc/voider/certs/usb_authorized_keys",
                          "/etc/voider/private/sftp_key","/etc/voider/private/sftp_key.pub",
                          "/etc/ssh/sshd_config.d/voider-self.conf",
                          "/etc/ssh/sshd_config.d/voider-mailboxes.conf",
                          "/etc/ssh/sshd_config.d/00-voider-security.conf",
                          "/etc/security/limits.d/voider-self.conf"}){
        std::error_code error;fs::remove(path,error);
    }
    std::error_code error;
    fs::remove_all(fs::path(C.sftp_base)/"self",error);
    fs::remove_all("/home/self",error);
    fs::remove_all("/etc/voider/self",error);
    if(getpwnam("self"))run("deluser self >/dev/null 2>&1 || true");
}
static void setup_keys(){
    fs::create_directories(C.mailbox_key_dir);
    fs::create_directories(C.node_dir);
    run("chown root:root "+C.mailbox_key_dir+' '+C.node_dir);
    // sshd opens AuthorizedKeysFile after adopting the mailbox account.
    // Public keys therefore need read/traverse access, but remain root-owned
    // and never writable by mailbox users.
    run("chmod 711 "+C.mailbox_key_dir);
    run("chmod 755 "+C.node_dir);
    run("find "+C.mailbox_key_dir+" -type f -exec chown root:root {} + -exec chmod 644 {} + 2>/dev/null || true");
}
static void setup_limits(){
    write_file(C.sftp_limits,"# Per-pairing CAP2 mailbox bounds (kilobyte fsize).\n@"+
        C.mailbox_group+" hard nproc 4\n@"+C.mailbox_group+" hard maxlogins 2\n@"+
        C.mailbox_group+" hard fsize 8\n",0644);
}
static void setup_sshd(){
    const std::string include_line="Include /etc/ssh/sshd_config.d/*.conf";
    std::stringstream current(read_file("/etc/ssh/sshd_config"));
    std::string cleaned,line;
    while(std::getline(current,line)){
        std::string t=trim(line), key;
        std::istringstream row(t);
        row>>key;
        std::transform(key.begin(),key.end(),key.begin(),
                       [](unsigned char c){ return (char)std::tolower(c); });
        std::string lower=t;
        std::transform(lower.begin(),lower.end(),lower.begin(),
                       [](unsigned char c){ return (char)std::tolower(c); });
        if(lower=="include /etc/ssh/sshd_config.d/*.conf") continue;
        if(!t.empty()&&t[0]!='#'&&
           (key=="passwordauthentication"||key=="kbdinteractiveauthentication"||
            key=="challengeresponseauthentication"||key=="permitrootlogin"||key=="pubkeyauthentication"||
            key=="authenticationmethods"||key=="authorizedkeysfile"||key=="allowusers"||
            key=="x11forwarding"||key=="allowtcpforwarding"||key=="allowagentforwarding"||
            key=="permittunnel"||key=="gatewayports"||key=="maxstartups"||
            key=="persourcemaxstartups"||key=="channeltimeout"||
            key=="unusedconnectiontimeout")) continue;
        cleaned+=line+"\n";
    }
    write_file("/etc/ssh/sshd_config",
        "# Voider policy is loaded first so OpenSSH's first-value rule is deterministic.\n"+
        include_line+"\n"+cleaned,0644);
    write_file("/etc/ssh/sshd_config.d/10-voider-security.conf",
        "# Voider shipping SSH policy: keys only.\n"
        "PasswordAuthentication no\n"
        "KbdInteractiveAuthentication no\n"
        "ChallengeResponseAuthentication no\n"
        "PermitRootLogin prohibit-password\n"
        "PubkeyAuthentication yes\n"
        "AuthenticationMethods publickey\n"
        "AuthorizedKeysFile " + C.admin_auth_keys + "\n"
        // Firewall rules restrict the ingress interface. This second gate
        // also denies root when a phone or inner-tunnel source is spoofed.
        "DenyUsers root@172.16.19.84/30 root@172.29.0.0/16 "
        "root@172.30.0.0/16 root@172.31.0.0/16\n"
        "AllowUsers root@10.0.0.0/8 root@172.16.0.0/12 root@192.168.0.0/16 vmc??? vms???\n"
        "X11Forwarding no\n"
        "AllowTcpForwarding no\n"
        "AllowAgentForwarding no\n"
        "PermitTunnel no\n"
        "GatewayPorts no\n"
        "MaxStartups 8:30:16\n"
        "PerSourceMaxStartups 8\n"
        "ChannelTimeout session=30\n"
        "UnusedConnectionTimeout 30\n",0644);
    std::string block =
        "# One key, account, and chroot per CAP2 pairing slot.\n"
        "Match Group " + C.mailbox_group + "\n"
        " ChrootDirectory %h\n"
        // Peers may write transaction records into /in, but cannot read them
        // back after close; root-owned /out records remain peer-readable.
        " ForceCommand internal-sftp -d / -u 477 -p realpath,stat,lstat,fstat,open,close,read,write,rename\n"
        " PasswordAuthentication no\n"
        " PubkeyAuthentication yes\n"
        " AuthenticationMethods publickey\n"
        " AuthorizedKeysFile " + C.mailbox_key_dir + "/%u.authorized_keys\n"
        " X11Forwarding no\n"
        " AllowTcpForwarding no\n"
        " AllowAgentForwarding no\n"
        " PermitTTY no\n"
        " PermitTunnel no\n"
        " MaxSessions 1\n"
        "Match all\n";
    write_file(C.sftp_sshd_snippet, block, 0644);
}
static void setup_tor(){
    fs::create_directories(C.tor_hs_dir);
    fs::create_directories(C.tor_dot_dir);
    // Ensure the dummy IP exists before Tor tries to bind the netns SOCKS port.
    run("/usr/local/sbin/voider-tor-netns-socks start 2>/dev/null || true");

    // Preserve existing onion identity files; only repair owner/perms.
    run("chown -R tor:tor /var/lib/tor 2>/dev/null || chown -R tor /var/lib/tor 2>/dev/null || true");
    run("chmod 700 /var/lib/tor 2>/dev/null || true");
    run("chmod 700 "+C.tor_dot_dir+" 2>/dev/null || true");
    run("find "+C.tor_dot_dir+" -mindepth 1 -type d -exec chmod 700 {} + 2>/dev/null || true");
    run("find "+C.tor_dot_dir+" -type f -exec chmod 600 {} + 2>/dev/null || true");
    run("chmod 700 "+C.tor_hs_dir+" 2>/dev/null || true");

    std::string block;
    block += "# BEGIN voider managed torrc\n";
    block += "# voider node hidden service: SFTP control + tundup fallback\n";
    block += "# Managed by voider-sftp-setup; old voider Tor blocks are replaced on every apply.\n";
    block += "DataDirectory "+C.tor_dot_dir+"\n";
    block += "SocksPort "+C.socks_host+":"+std::to_string(C.socks_port)+" IsolateSOCKSAuth\n";
    block += "SocksPort "+C.tor_netns_socks_ip+":"+std::to_string(C.tor_netns_socks_port)+" IsolateSOCKSAuth\n";
    block += "SocksPolicy accept 127.0.0.1\n";
    block += "SocksPolicy accept 172.30.0.0/16\n";
    block += "SocksPolicy reject *\n";
    block += "HiddenServiceDir "+C.tor_hs_dir+"\n";
    block += "HiddenServiceVersion 3\n";
    block += "HiddenServicePort 22 127.0.0.1:22\n";
    for(int p=7002;p<=7254;p++) block += "HiddenServicePort "+std::to_string(p)+" 127.0.0.1:"+std::to_string(p)+"\n";
    block += "# same onion: port 22=SFTP, 7002..7254=tundup fallback\n";
    block += "# END voider managed torrc\n";

    std::string cleaned=strip_old_voider_torrc_blocks(read_file(C.torrc));
    if(!cleaned.empty() && cleaned.back()!='\n') cleaned += "\n";
    write_file(C.torrc, cleaned + "\n" + block, 0644);

    // OpenRC runlevels are owned by the integrity-gated installer. Do not make
    // Tor or SSH independently startable before BOOT/SYSTEM verification.
    run("rc-service tor restart 2>/dev/null || /etc/init.d/tor restart 2>/dev/null || true");
    std::string onion=cap("cat "+C.tor_hs_dir+"/hostname 2>/dev/null");
    if(!onion.empty()){
        write_file(C.node_onion,onion+"\n",0600);
        write_file(C.sync_onion,onion+"\n",0600);
    }
    std::string hostpub=cap("cat /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null");
    if(!onion.empty()&&!hostpub.empty())write_file(C.sftp_host_pub,onion+" "+hostpub+"\n",0644);
}
static int publish_identity(){
    std::string onion=cap("cat "+C.tor_hs_dir+"/hostname 2>/dev/null");
    std::string hostpub=cap("cat /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null");
    if(onion.empty()||hostpub.empty())return 2;
    write_file(C.node_onion,onion+"\n",0600);
    write_file(C.sync_onion,onion+"\n",0600);
    write_file(C.sftp_host_pub,onion+" "+hostpub+"\n",0644);
    return fs::is_regular_file(C.node_onion)&&fs::is_regular_file(C.sftp_host_pub)?0:2;
}
static int apply(){
    cleanup_legacy_shared_identity();
    for(const std::string role:{"client","server"})for(int slot=2;slot<=254;slot++)
        if(!mailbox_account_valid(role,slot))return 2;
    setup_keys();
    if(setup_slots())return 2;
    setup_limits();
    setup_sshd();
    if(run("sshd -t")) return 3;
    if(run("sshd -T | grep -qx 'passwordauthentication no'")) return 4;
    if(run("sshd -T | grep -qx 'kbdinteractiveauthentication no'")) return 5;
    if(run("sshd -T | grep -qx 'allowtcpforwarding no'")) return 6;
    if(run("sshd -T | grep -qx 'authenticationmethods publickey'")) return 7;
    if(run("sshd -T | grep -qx 'authorizedkeysfile "+C.admin_auth_keys+"'")) return 8;
    if(run("sshd -T | grep -Eq '^permitrootlogin (prohibit-password|without-password)$'")) return 9;
    if(run("sshd -T | grep -qx 'maxstartups 8:30:16'"))return 10;
    if(run("sshd -T | grep -qx 'persourcemaxstartups 8'"))return 11;
    std::string context=" -C user=vmc002,host=localhost,addr=127.0.0.1";
    if(run("sshd -T"+context+" | grep -qx 'maxsessions 1'"))return 12;
    if(run("sshd -T"+context+" | grep -q '^forcecommand internal-sftp '"))return 13;
    if(run("sshd -T"+context+" | grep -q '^authorizedkeysfile "+C.mailbox_key_dir+"/'"))return 14;
    setup_tor();
    run("rc-service sshd restart 2>/dev/null || /etc/init.d/sshd restart 2>/dev/null || true");
    return 0;
}
static void status(){
    std::cout<<"group="<<C.mailbox_group<<"\nbase="<<C.sftp_base<<
    "\nkeys="<<C.mailbox_key_dir<<"\nsync_onion="<<C.sync_onion<<"\n";
    run("ls -ld "+C.sftp_base+" "+C.sftp_base+"/clients/vmb* "+C.sftp_base+"/servers/vmb* 2>/dev/null | head");
    run("grep -R \"Match Group "+C.mailbox_group+"\" /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null || true");
}
static int selftest(){
    fs::path work=fs::path("/tmp")/("voider-sftp-selftest-"+std::to_string((long)getpid()));
    fs::remove_all(work);
    C.pc=(work/"peers/clients.d").string();
    C.mat=(work/"peers/material").string();
    C.sftp_base=(work/"sftp").string();
    C.mailbox_key_dir=(work/"certs/mailboxes").string();
    int cases=0,failures=0,slot=7;
    auto want=[&](bool ok){cases++;if(!ok)failures++;};
    fs::create_directories(fs::path(C.pc));
    fs::path material=fs::path(C.mat)/"client"/std::to_string(slot);
    fs::create_directories(material);
    want(!provisioned_client_slot(slot)&&!authorized_client_slot(slot)&&!active_client_slot(slot));
    std::ofstream(fs::path(C.pc)/"7.conf")<<"ROLE=client\nID=7\n";
    for(const auto&name:{"private.key","public.key","preshared.key"})std::ofstream(material/name)<<"test\n";
    want(provisioned_client_slot(slot)&&!authorized_client_slot(slot)&&!active_client_slot(slot));
    std::ofstream(material/"usb_secret.hex")<<"test\n";
    std::ofstream(material/"tundup_psk.hex")<<"test\n";
    fs::create_directories(C.mailbox_key_dir);
    std::ofstream(vmb::keys(C,"client",slot))<<"restrict ssh-ed25519 test\n";
    want(authorized_client_slot(slot)&&!active_client_slot(slot));
    fs::path root=vmb::root(C,"client",slot);
    want(safe_directory(root)&&safe_directory(root/"in")&&safe_directory(root/"out")&&active_client_slot(slot));
    std::ofstream(root/"in/volatile.offer")<<"test\n";
    want(vmb::root(C,"client",slot)!=vmb::root(C,"server",slot)&&
         remove_slot_resources("client",slot)&&!fs::exists(root)&&!fs::exists(vmb::keys(C,"client",slot))&&
         provisioned_client_slot(slot)&&!authorized_client_slot(slot)&&!active_client_slot(slot));
    fs::remove_all(work);
    std::cout<<"SFTP_LIFECYCLE_TEST cases="<<cases<<" fails="<<failures<<"\n";
    return failures?1:0;
}
int main(int ac,char**av){
    C=cfg();
    std::string cmd=ac>1?av[1]:"apply";
    if(cmd=="apply")return apply();
    else if(cmd=="accounts")return setup_accounts();
    else if(cmd=="status")status();
    else if(cmd=="slots")return setup_slots();
    else if(cmd=="slot"&&ac==4){std::string role=av[2];int slot=toi(av[3],0);return role=="client"&&provisioned_client_slot(slot)&&setup_slot(role,slot,false)?0:2;}
    else if(cmd=="slot-remove"&&ac==4){
        std::string role=av[2];int slot=toi(av[3],0);
        return vmb::role_ok(role)&&vmb::slot_ok(slot)&&remove_slot_resources(role,slot)&&
               setup_slot(role,slot,false)?0:2;
    }
    else if(cmd=="publish-identity")return publish_identity();
    else if(cmd=="selftest")return selftest();
    else return 2;
    return 0;
}
