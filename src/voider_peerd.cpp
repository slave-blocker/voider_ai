// One small per-slot state machine:
//   authenticated LAN -> direct WireGuard -> WireGuard hole punch -> Tor.

#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "voider_config.hpp"
#include "voider_util.hpp"

#include "voider_wan_ipv6.hpp"
#include "voider_transport_allowlist.hpp"
#include "voider_transport_protocol.hpp"

using vu::cap;
using vu::read1;
using vu::shq;

namespace fs=std::filesystem;
using Clock=std::chrono::steady_clock;
using vtp::Record;
static Cfg C;
static constexpr unsigned LAN_PORT=45820;
static constexpr int TOR_PROOF_SECONDS=90;
static constexpr int TOR_PING_SECONDS=5;

enum class Phase { Lan, Remote, RemoteJob, Choose, Proof, HoleJob, TorProof, Up, Backoff };
enum class Method { None, Lan4, Lan6, Direct4, Direct6, Hole4, Hole6, Tor };
static constexpr Method REMOTE_ORDER[]={
    Method::Direct4,Method::Direct6,Method::Hole4,Method::Hole6,Method::Tor
};

struct Job {
    pid_t pid=0;
    std::string output;
};

struct Peer {
    std::string role;
    int id=0;
    int cert_slot=0;
    std::string secret;
    std::string peer_key;
    std::string nonce;
    std::string lan_endpoint;
    std::string last_xid;
    std::string error;
    Record remote;
    Phase phase=Phase::Lan;
    Method candidate=Method::None;
    Method selected=Method::None;
    size_t next_method=0;
    bool remote_attempted=false;
    Clock::time_point deadline=Clock::now();
    Clock::time_point next_action=Clock::now();
    Job job;
    pid_t tor_pid=0;
    bool tun_configured=false;
    int health_failures=0;
};

static int run(const std::string& command){ return vu::run(command,false); }

static bool local_ntp_ready(const std::string& tracking){
    bool selected=false,normal=false;
    std::istringstream lines(tracking);
    std::string line;
    while(std::getline(lines,line)){
        if(line.rfind("Reference ID",0)==0){
            auto colon=line.find(':');
            std::string reference=colon==std::string::npos?"":trim(line.substr(colon+1));
            selected=!reference.empty()&&reference.rfind("00000000",0)!=0;
        }else if(line.rfind("Leap status",0)==0){
            auto colon=line.find(':');
            normal=colon!=std::string::npos&&trim(line.substr(colon+1))=="Normal";
        }
    }
    // This is chronyd's independent local synchronization state.  It does not
    // compare the two Voiders, inspect NTP packet delay, or impose an offset.
    return selected&&normal;
}

static bool remote_clock_ready(){
    static Clock::time_point next_check=Clock::time_point::min();
    static bool ready=false;
    auto now=Clock::now();
    if(now>=next_check){
        ready=local_ntp_ready(cap("chronyc tracking 2>/dev/null"));
        next_check=now+std::chrono::seconds(1);
    }
    return ready;
}

static void log(const Peer& peer,const std::string& message){
    fs::create_directories("/run/voider");
    std::ofstream("/run/voider/peerd.log",std::ios::app)
        <<peer.role<<'/'<<peer.id<<' '<<message<<'\n';
}

static std::string peer_conf(const Peer& peer){
    return (peer.role=="client"?C.pc:C.ps)+"/"+std::to_string(peer.id)+".conf";
}

static std::string conf(const Peer& peer,const std::string& key,
                        const std::string& fallback=""){
    auto value=val(peer_conf(peer),key);
    return value.empty()?fallback:value;
}

static bool address(const std::string& value,int family){
    unsigned char bytes[sizeof(in6_addr)]{};
    return inet_pton(family,value.c_str(),bytes)==1;
}

static bool port(const std::string& value){
    char* end=nullptr;
    unsigned long number=std::strtoul(value.c_str(),&end,10);
    return end&&!*end&&number>=1024&&number<=65535;
}

static int imported_index(const Peer& peer){
    if(peer.role=="client")return peer.id;
    int saved=toi(conf(peer,"REMOTE_CERT_INDEX"),0);
    if(saved>=2&&saved<=254)return saved;
    std::string address=conf(peer,"LOCAL_ADDR",conf(peer,"ADDRESS"));
    unsigned a,b,c,d;
    if(sscanf(address.c_str(),"%u.%u.%u.%u",&a,&b,&c,&d)==4&&
       a==172&&b==31&&c==0&&d>=2&&d<=254)return static_cast<int>(d);
    return peer.id;
}

static std::string secret_path(const Peer& peer){
    auto path=conf(peer,"PRESHARED_KEY");
    return path.empty()?C.mat+"/"+peer.role+"/"+std::to_string(peer.id)+"/preshared.key":path;
}

static std::string key_for(const Peer& peer){
    for(const auto& key:{peer.role=="client"?"PUBLIC_KEY":"SERVER_PUBLIC_KEY",
                         "WG_PEER_PUBLIC_KEY","PEER_PUBLIC_KEY"}){
        auto value=conf(peer,key);
        if(!value.empty())return value;
    }
    return "";
}

static std::string fingerprint(const Peer& peer){
    auto value=conf(peer,"USB_FP");
    if(!value.empty())return value;
    value=read1(C.usb_fp_dir+"/import-"+peer.role+"-"+std::to_string(peer.id)+".sha256");
    if(!value.empty())return value;
    return read1(C.usb_fp_dir+"/"+peer.role+"-"+std::to_string(peer.id)+".sha256");
}

static std::string tundup_key(const Peer& peer){
    std::string path=C.mat+"/"+peer.role+"/"+std::to_string(peer.id)+"/tundup_psk.hex";
    return fs::is_regular_file(path)&&!read1(path).empty()?path:"";
}

static unsigned wireguard_port(const Peer& peer){
    if(peer.role=="client")return 51820;
    int port=toi(conf(peer,"PORT"),51820+peer.id);
    return port>=1024&&port<=65535?static_cast<unsigned>(port):51820u+peer.id;
}

static pid_t spawn(const std::vector<std::string>& args,const std::string& output,bool group){
    if(args.empty())return 0;
    pid_t child=fork();
    if(child<0)return 0;
    if(child!=0){if(child>0&&group)setpgid(child,child);return child;}
    if(group)setpgid(0,0);
    int fd=open(output.c_str(),O_WRONLY|O_CREAT|O_TRUNC,0600);
    if(fd>=0){dup2(fd,STDOUT_FILENO);dup2(fd,STDERR_FILENO);close(fd);}
    std::vector<char*> raw;
    for(const auto& arg:args)raw.push_back(const_cast<char*>(arg.c_str()));
    raw.push_back(nullptr);
    execvp(raw[0],raw.data());
    _exit(127);
}

static void start_job(Peer& peer,const std::vector<std::string>& args,const std::string& name){
    fs::create_directories("/run/voider/jobs");
    peer.job.output="/run/voider/jobs/"+peer.role+"-"+std::to_string(peer.id)+"-"+name;
    peer.job.pid=spawn(args,peer.job.output,true);
}

static int poll_job(Peer& peer){
    if(!peer.job.pid)return 0;
    int status=0;
    pid_t result=waitpid(peer.job.pid,&status,WNOHANG);
    if(result==0)return -1;
    peer.job.pid=0;
    return result>0&&WIFEXITED(status)&&WEXITSTATUS(status)==0?1:0;
}

static void cancel_job(Peer& peer){
    if(!peer.job.pid)return;
    kill(-peer.job.pid,SIGTERM);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    kill(-peer.job.pid,SIGKILL);
    waitpid(peer.job.pid,nullptr,0);
    peer.job.pid=0;
}

static Record record_from_file(const std::string& path){
    std::ifstream file(path);
    std::string line;
    while(std::getline(file,line)){
        Record record=vtp::parse_record(trim(line));
        if(record.ok())return record;
    }
    return {};
}

static long handshake(const Peer& peer){
    std::string command=peer.role=="client"?"wg show wg0 latest-handshakes":
        "ip netns exec netns"+std::to_string(peer.id)+" wg show wg"+
        std::to_string(peer.id)+" latest-handshakes";
    std::istringstream lines(cap(command+" 2>/dev/null"));
    std::string key;
    long timestamp=0;
    while(lines>>key>>timestamp)if(key==peer.peer_key)return timestamp;
    return 0;
}

static int endpoint_family(const std::string& endpoint){
    if(!endpoint.empty()&&endpoint.front()=='['){
        size_t close=endpoint.find("]:");
        if(close==std::string::npos)return AF_UNSPEC;
        std::string ip=endpoint.substr(1,close-1);
        size_t scope=ip.find('%');
        if(scope!=std::string::npos){
            if(scope==0||scope+1==ip.size())return AF_UNSPEC;
            ip.resize(scope);
        }
        return address(ip,AF_INET6)&&port(endpoint.substr(close+2))?AF_INET6:AF_UNSPEC;
    }
    size_t colon=endpoint.rfind(':');
    return colon!=std::string::npos&&address(endpoint.substr(0,colon),AF_INET)&&
           port(endpoint.substr(colon+1))?AF_INET:AF_UNSPEC;
}

static int method_family(Method method){
    switch(method){
        case Method::Lan4:case Method::Direct4:case Method::Hole4:return AF_INET;
        case Method::Lan6:case Method::Direct6:case Method::Hole6:return AF_INET6;
        default:return AF_UNSPEC;
    }
}

static int wireguard_endpoint_family(const Peer& peer){
    std::string command=peer.role=="client"?"wg show wg0 endpoints":
        "ip netns exec netns"+std::to_string(peer.id)+" wg show wg"+
        std::to_string(peer.id)+" endpoints";
    std::istringstream lines(cap(command+" 2>/dev/null"));
    std::string key,endpoint;
    while(lines>>key>>endpoint)if(key==peer.peer_key)return endpoint_family(endpoint);
    return AF_UNSPEC;
}

static void call_route(Peer& peer,bool enable){
    std::string id=std::to_string(peer.id);
    if(peer.role=="client"){
        std::string route="172.29."+id+".1/32";
        if(enable)run("ip route replace "+route+" via 172.31.0."+id+" dev wg0 2>/dev/null || "
                      "ip route replace "+route+" dev wg0 2>/dev/null || true");
        else run("ip route del "+route+" 2>/dev/null || true");
    }else{
        std::string prefix="ip netns exec netns"+id+' ';
        if(enable)run(prefix+"ip route replace 172.29.1.1/32 via 172.31.0.1 dev wg"+id+" 2>/dev/null || true");
        else run(prefix+"ip route del 172.29.1.1/32 2>/dev/null || true");
    }
}

static bool configure_wireguard(Peer& peer){
    if(peer.peer_key.empty()||peer.secret.empty())return false;
    std::string id=std::to_string(peer.id),psk=shq(secret_path(peer));
    if(peer.role=="client"){
        run("wg set wg0 peer "+peer.peer_key+" remove 2>/dev/null || true");
        run("wg set wg0 private-key /etc/voider/private/wg0.key listen-port 51820 2>/dev/null || true");
        run("wg set wg0 peer "+peer.peer_key+" preshared-key "+psk+
            " allowed-ips 172.31.0."+id+"/32,172.29."+id+".1/32 persistent-keepalive 5");
    }else{
        std::string ns="ip netns exec netns"+id+' ',wg="wg"+id;
        std::string private_key=conf(peer,"PRIVATE_KEY",
            C.mat+"/server/"+id+"/private.key");
        run(ns+"wg set "+wg+" peer "+peer.peer_key+" remove 2>/dev/null || true");
        run(ns+"wg set "+wg+" private-key "+shq(private_key)+
            " listen-port "+std::to_string(wireguard_port(peer)));
        run(ns+"wg set "+wg+" peer "+peer.peer_key+" preshared-key "+psk+
            " allowed-ips 172.31.0.1/32,172.29.1.1/32 persistent-keepalive 5");
    }
    call_route(peer,false);
    return true;
}

static void disable_wireguard(Peer& peer){
    std::string id=std::to_string(peer.id);
    if(peer.role=="client")run("wg set wg0 peer "+peer.peer_key+" remove 2>/dev/null || true");
    else run("ip netns exec netns"+id+" wg set wg"+id+" peer "+peer.peer_key+" remove 2>/dev/null || true");
    call_route(peer,false);
}

static void set_endpoint(Peer& peer,const std::string& endpoint){
    if(endpoint.empty())return;
    std::string id=std::to_string(peer.id);
    std::string command=peer.role=="client"?"wg set wg0 peer "+peer.peer_key:
        "ip netns exec netns"+id+" wg set wg"+id+" peer "+peer.peer_key;
    run(command+" endpoint "+shq(endpoint)+" persistent-keepalive 5");
}

static bool wireguard_ping(const Peer& peer){
    std::string id=std::to_string(peer.id);
    if(peer.role=="client")
        return run("ping -I wg0 -c1 -W1 172.31.0."+id+" >/dev/null 2>&1")==0;
    return run("ip netns exec netns"+id+" ping -I wg"+id+
               " -c1 -W1 172.31.0.1 >/dev/null 2>&1")==0;
}

static bool health_lost(int& failures,bool healthy){
    if(healthy){failures=0;return false;}
    return ++failures>=3;
}

static void cleanup_hole(Peer& peer){
    run("/usr/local/sbin/voider-holepunch cleanup "+peer.role+' '+
        std::to_string(peer.id)+" >/dev/null 2>&1 || true");
}

static std::string tor_interface(const Peer& peer){
    return peer.role=="client"?"tcs"+std::to_string(peer.cert_slot):
                               "tds"+std::to_string(peer.id);
}

static std::string tor_pid_file(const Peer& peer){
    return "/run/voider/tor-"+peer.role+'-'+std::to_string(peer.id)+".pid";
}

static bool interface_exists(const Peer& peer,const std::string& name){
    std::string command=peer.role=="client"?"ip link show "+name:
        "ip netns exec netns"+std::to_string(peer.id)+" ip link show "+name;
    return run(command+" >/dev/null 2>&1")==0;
}

static void stop_tor(Peer& peer){
    std::string id=std::to_string(peer.id),name=tor_interface(peer);
    if(!peer.tor_pid){
        int saved=toi(read1(tor_pid_file(peer)),0);
        std::string command=saved>1?read1("/proc/"+std::to_string(saved)+"/cmdline"):"";
        if(command.find("tundup-v7-secure")!=std::string::npos&&
           command.find(name)!=std::string::npos)peer.tor_pid=saved;
    }
    if(peer.tor_pid){
        kill(peer.tor_pid,SIGTERM);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        kill(peer.tor_pid,SIGKILL);
        waitpid(peer.tor_pid,nullptr,0);
        peer.tor_pid=0;
    }
    fs::remove(tor_pid_file(peer));
    if(peer.role=="client"){
        run("ip route del 172.29."+std::to_string(peer.cert_slot)+".1/32 dev "+name+" 2>/dev/null || true");
        run("ip link del "+name+" 2>/dev/null || true");
    }else{
        run("ip netns exec netns"+id+" ip route del 172.29.1.1/32 dev "+name+" 2>/dev/null || true");
        run("ip netns exec netns"+id+" ip link del "+name+" 2>/dev/null || true");
    }
    peer.tun_configured=false;
}

static bool start_tor(Peer& peer){
    std::string psk=tundup_key(peer),fp=fingerprint(peer),name=tor_interface(peer);
    if(psk.empty()||fp.empty()){peer.error="missing per-pair Tor identity";return false;}
    fs::create_directories("/dev/net");
    run("modprobe tun 2>/dev/null || true; test -c /dev/net/tun || mknod /dev/net/tun c 10 200; chmod 600 /dev/net/tun");
    stop_tor(peer);
    std::vector<std::string> args;
    if(peer.role=="client"){
        args={"/usr/local/sbin/tundup-v7-secure","server",psk,
              conf(peer,"TORPORT",std::to_string(C.tundup_torport_base+peer.cert_slot)),
              fp,name};
    }else{
        std::string onion=peer.remote.get("TUN_ONION");
        if(onion.empty()){peer.error="CAP2 answer missing Tor onion";return false;}
        args={"ip","netns","exec","netns"+std::to_string(peer.id),
              "/usr/local/sbin/tundup-v7-secure","client",psk,onion,
              peer.remote.get("TUNPORT",std::to_string(C.tundup_torport_base+peer.cert_slot)),
              C.tor_netns_socks_ip,std::to_string(C.tor_netns_socks_port),fp,name};
    }
    peer.tor_pid=spawn(args,"/run/voider/tor-"+peer.role+'-'+std::to_string(peer.id)+".log",false);
    if(peer.tor_pid>0)std::ofstream(tor_pid_file(peer),std::ios::trunc)<<peer.tor_pid<<'\n';
    return peer.tor_pid>0;
}

static void configure_tun(Peer& peer){
    if(peer.tun_configured)return;
    std::string id=std::to_string(peer.id),s=std::to_string(peer.cert_slot),name=tor_interface(peer);
    if(!interface_exists(peer,name))return;
    if(peer.role=="client")
        run("ip addr replace 172.27."+s+".1/30 dev "+name+" && ip link set "+name+" up");
    else
        run("ip -n netns"+id+" addr replace 172.27."+s+".2/30 dev "+name+
            " && ip -n netns"+id+" link set "+name+" up");
    peer.tun_configured=true;
}

static bool tor_ping(Peer& peer){
    std::string id=std::to_string(peer.id),s=std::to_string(peer.cert_slot),name=tor_interface(peer);
    if(peer.role=="client")
        return run("ping -I "+name+" -c1 -W"+std::to_string(TOR_PING_SECONDS)+
                   " 172.27."+s+".2 >/dev/null 2>&1")==0;
    return run("ip netns exec netns"+id+" ping -I "+name+
               " -c1 -W"+std::to_string(TOR_PING_SECONDS)+
               " 172.27."+s+".1 >/dev/null 2>&1")==0;
}

static void select_tor_route(Peer& peer){
    std::string id=std::to_string(peer.id),s=std::to_string(peer.cert_slot),name=tor_interface(peer);
    if(peer.role=="client")run("ip route replace 172.29."+s+".1/32 dev "+name);
    else run("ip netns exec netns"+id+" ip route replace 172.29.1.1/32 dev "+name);
}

static std::string method_name(Method method){
    switch(method){
        case Method::Lan4:return "lan4";
        case Method::Lan6:return "lan6";
        case Method::Direct4:return "direct4";
        case Method::Direct6:return "direct6";
        case Method::Hole4:return "holepunch4";
        case Method::Hole6:return "holepunch6";
        case Method::Tor:return "tor";
        default:return "down";
    }
}

static std::string method_token(Method method){
    if(method==Method::Hole4)return "hp4";
    if(method==Method::Hole6)return "hp6";
    return method_name(method);
}

static bool available(Method method){
    return method!=Method::None&&vta::available(C.transports_available,method_token(method));
}

class LanDiscovery {
    int ipv4_=-1,ipv6_=-1;
    unsigned interface_=0;
    std::string node_=vtp::random_hex(16);

    int open_socket(int family){
        int fd=socket(family,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
        if(fd<0)return -1;
        int one=1;
        setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
        setsockopt(fd,SOL_SOCKET,SO_BINDTODEVICE,C.wan_if.c_str(),C.wan_if.size()+1);
        if(family==AF_INET){
            setsockopt(fd,SOL_SOCKET,SO_BROADCAST,&one,sizeof one);
            sockaddr_in address{};address.sin_family=AF_INET;address.sin_port=htons(LAN_PORT);
            address.sin_addr.s_addr=htonl(INADDR_ANY);
            if(bind(fd,reinterpret_cast<sockaddr*>(&address),sizeof address)<0){close(fd);return -1;}
        }else{
            setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY,&one,sizeof one);
            sockaddr_in6 address{};address.sin6_family=AF_INET6;address.sin6_port=htons(LAN_PORT);
            address.sin6_addr=in6addr_any;
            if(bind(fd,reinterpret_cast<sockaddr*>(&address),sizeof address)<0){close(fd);return -1;}
            ipv6_mreq group{};inet_pton(AF_INET6,"ff02::114",&group.ipv6mr_multiaddr);
            group.ipv6mr_interface=interface_;
            setsockopt(fd,IPPROTO_IPV6,IPV6_JOIN_GROUP,&group,sizeof group);
        }
        return fd;
    }

    std::string endpoint(const sockaddr_storage& address,unsigned port) const {
        char text[INET6_ADDRSTRLEN]{};
        if(address.ss_family==AF_INET){
            auto* a=reinterpret_cast<const sockaddr_in*>(&address);
            inet_ntop(AF_INET,&a->sin_addr,text,sizeof text);
            return std::string(text)+':'+std::to_string(port);
        }
        auto* a=reinterpret_cast<const sockaddr_in6*>(&address);
        inet_ntop(AF_INET6,&a->sin6_addr,text,sizeof text);
        std::string host=text;
        // wgX is configured inside netnsX, but its UDP socket belongs to
        // the uplink namespace. Pass the received numeric scope unchanged.
        if(a->sin6_scope_id)host+='%'+std::to_string(a->sin6_scope_id);
        return '['+host+"]:"+std::to_string(port);
    }

    void receive(int fd,std::map<std::string,Peer>& peers){
        if(fd<0)return;
        Method family_method=fd==ipv4_?Method::Lan4:Method::Lan6;
        for(;;){
            sockaddr_storage source{};
            socklen_t length=sizeof source;
            char buffer[512];
            ssize_t count=recvfrom(fd,buffer,sizeof buffer-1,0,
                                   reinterpret_cast<sockaddr*>(&source),&length);
            if(count<0)return;
            buffer[count]=0;
            std::string packet(buffer);
            if(packet.rfind("VLD1 Q ",0)==0){
                for(auto& item:peers){
                    Peer& peer=item.second;
                    std::string sender,nonce;
                    if(!available(family_method)||peer.secret.empty()||
                       !vtp::verify_lan_query(packet,peer.secret,sender,nonce)||sender==node_)continue;
                    std::string answer=vtp::lan_answer(peer.secret,sender,nonce,node_,wireguard_port(peer));
                    sendto(fd,answer.data(),answer.size(),0,reinterpret_cast<sockaddr*>(&source),length);
                    break;
                }
            }else if(packet.rfind("VLD1 A ",0)==0){
                for(auto& item:peers){
                    Peer& peer=item.second;
                    if(peer.phase!=Phase::Lan||peer.nonce.empty()||!available(family_method))continue;
                    std::string responder;
                    unsigned port=0;
                    if(vtp::verify_lan_answer(packet,peer.secret,node_,peer.nonce,responder,port)){
                        peer.lan_endpoint=endpoint(source,port);
                        break;
                    }
                }
            }
        }
    }

public:
    LanDiscovery(){
        interface_=if_nametoindex(C.wan_if.c_str());
        ipv4_=open_socket(AF_INET);
        ipv6_=open_socket(AF_INET6);
    }
    ~LanDiscovery(){if(ipv4_>=0)close(ipv4_);if(ipv6_>=0)close(ipv6_);}

    void poll(std::map<std::string,Peer>& peers){receive(ipv4_,peers);receive(ipv6_,peers);}

    void query(Peer& peer){
        peer.nonce=vtp::random_hex(16);
        if(peer.nonce.empty())return;
        std::string packet=vtp::lan_query(peer.secret,node_,peer.nonce);
        if(ipv4_>=0&&available(Method::Lan4)){
            sockaddr_in target{};target.sin_family=AF_INET;target.sin_port=htons(LAN_PORT);
            target.sin_addr.s_addr=htonl(INADDR_BROADCAST);
            sendto(ipv4_,packet.data(),packet.size(),0,reinterpret_cast<sockaddr*>(&target),sizeof target);
        }
        if(ipv6_>=0&&interface_&&available(Method::Lan6)){
            sockaddr_in6 target{};target.sin6_family=AF_INET6;target.sin6_port=htons(LAN_PORT);
            target.sin6_scope_id=interface_;inet_pton(AF_INET6,"ff02::114",&target.sin6_addr);
            sendto(ipv6_,packet.data(),packet.size(),0,reinterpret_cast<sockaddr*>(&target),sizeof target);
        }
    }
};

static void reset(Peer& peer,const std::string& reason){
    cancel_job(peer);
    cleanup_hole(peer);
    stop_tor(peer);
    peer.health_failures=0;
    peer.remote={};peer.candidate=Method::None;peer.selected=Method::None;
    peer.next_method=0;peer.remote_attempted=false;peer.nonce.clear();peer.lan_endpoint.clear();peer.error.clear();
    peer.secret=read1(secret_path(peer));peer.peer_key=key_for(peer);
    if(!configure_wireguard(peer)){
        peer.phase=Phase::Backoff;peer.error="missing WireGuard pair material";
        peer.deadline=Clock::now()+std::chrono::seconds(15);
    }else{
        peer.phase=Phase::Lan;peer.deadline=Clock::now()+
            std::chrono::seconds(available(Method::Lan4)||available(Method::Lan6)?3:0);
        peer.next_action=Clock::now();
    }
    if(!reason.empty())log(peer,"reset "+reason);
}

static void initialize(Peer& peer){
    peer.cert_slot=imported_index(peer);
    run("/usr/local/sbin/voider-netns "+peer.role+"-up "+std::to_string(peer.id)+" >/dev/null 2>&1");
    reset(peer,"slot-start");
}

static void begin_proof(Peer& peer,Method method,const std::string& endpoint){
    peer.candidate=method;
    set_endpoint(peer,endpoint);
    peer.deadline=Clock::now()+std::chrono::seconds(10);
    peer.next_action=Clock::now();
    peer.phase=Phase::Proof;
    log(peer,"try "+method_name(method)+(endpoint.empty()?" passive":" endpoint="+endpoint));
}

static void promote(Peer& peer,Method method){
    if(method==Method::Hole4||method==Method::Hole6){}
    else cleanup_hole(peer);
    stop_tor(peer);
    call_route(peer,true);
    peer.selected=method;peer.candidate=Method::None;peer.phase=Phase::Up;
    peer.next_action=Clock::now()+std::chrono::seconds(5);peer.health_failures=0;
    log(peer,"selected "+method_name(method));
}

static void retry_later(Peer& peer,const std::string& error){
    cancel_job(peer);cleanup_hole(peer);stop_tor(peer);call_route(peer,false);
    peer.phase=Phase::Backoff;peer.selected=Method::None;peer.candidate=Method::None;
    peer.error=error;peer.deadline=Clock::now()+std::chrono::seconds(10);
    log(peer,"backoff "+error);
}

static std::string cap2_reply(Peer& peer){
    return cap("/usr/local/sbin/voider-cap2 respond client "+std::to_string(peer.id)+" 2>/dev/null");
}

static bool accept_remote(Peer& peer,const Record& record){
    if(!record.ok()||record.get("CERT_SLOT")!=std::to_string(peer.cert_slot)||
       !record.fields.count("PLAN")||record.get("XID")==peer.last_xid)return false;
    peer.remote=record;peer.last_xid=record.get("XID");peer.next_method=0;
    peer.phase=Phase::Choose;peer.error.clear();
    log(peer,"CAP2 correlated xid="+peer.last_xid);
    return true;
}

static void next_remote_method(Peer& peer){
    std::string plan=peer.remote.get("PLAN");
    while(peer.next_method<sizeof REMOTE_ORDER/sizeof REMOTE_ORDER[0]){
        Method method=REMOTE_ORDER[peer.next_method++];
        std::string token=method_token(method);
        if(!available(method)||!vtp::listed(plan,token))continue;
        // reset() already installed a clean peer before LAN/CAP2.  Preserve it
        // for the first remote method: the other side may have completed the
        // correlated exchange and handshaken just before this side enters
        // Choose.  Later methods get a new peer and therefore new proof.
        if(peer.remote_attempted&&!configure_wireguard(peer)){
            retry_later(peer,"WireGuard reconfiguration failed");return;
        }
        peer.remote_attempted=true;
        if(method==Method::Direct4){
            std::string endpoint=address(peer.remote.get("PUB4"),AF_INET)&&
                                 port(peer.remote.get("WG4"))?
                peer.remote.get("PUB4")+':'+peer.remote.get("WG4","51820"):"";
            begin_proof(peer,method,endpoint);
            return;
        }
        if(method==Method::Direct6){
            if(vwan6::current(C,true).empty())continue;
            std::string endpoint=address(peer.remote.get("PUB6"),AF_INET6)&&
                                 port(peer.remote.get("WG6"))?
                '['+peer.remote.get("PUB6")+"]:"+peer.remote.get("WG6","51820"):"";
            if(endpoint.empty())continue;
            begin_proof(peer,method,endpoint);
            return;
        }
        if(method==Method::Hole4||method==Method::Hole6){
            bool six=method==Method::Hole6;
            std::string ip=peer.remote.get(six?"PUB6":"PUB4");
            std::string port=peer.remote.get(six?"HP6_PORT":"HP4_PORT");
            if(!address(ip,six?AF_INET6:AF_INET)||!::port(port))continue;
            if(six&&vwan6::current(C,true).empty())continue;
            peer.candidate=method;
            start_job(peer,{"/usr/local/sbin/voider-holepunch","run",peer.role,
                std::to_string(peer.id),six?"6":"4",ip,port,peer.peer_key},six?"hp6":"hp4");
            peer.phase=Phase::HoleJob;peer.deadline=Clock::now()+std::chrono::seconds(40);
            log(peer,"try "+method_name(method));
            return;
        }
        disable_wireguard(peer);
        if(start_tor(peer)){
            peer.candidate=Method::Tor;peer.phase=Phase::TorProof;
            peer.deadline=Clock::now()+std::chrono::seconds(TOR_PROOF_SECONDS);peer.next_action=Clock::now();
            log(peer,"pref try tor role="+peer.role+" id="+std::to_string(peer.id));
            return;
        }
    }
    retry_later(peer,"transport order exhausted");
}

static void step(Peer& peer,LanDiscovery& lan){
    auto now=Clock::now();
    if(peer.phase==Phase::Lan){
        if(!peer.lan_endpoint.empty()){
            Method method=peer.lan_endpoint.front()=='['?Method::Lan6:Method::Lan4;
            if(available(method))begin_proof(peer,method,peer.lan_endpoint);
            else peer.lan_endpoint.clear();
        }else if(now>=peer.deadline){
            if(!remote_clock_ready()){
                if(peer.error!="waiting for local NTP synchronization")
                    log(peer,"waiting for local NTP synchronization");
                peer.error="waiting for local NTP synchronization";
                peer.deadline=now+std::chrono::seconds(1);
                return;
            }
            peer.error.clear();
            peer.phase=Phase::Remote;peer.deadline=now+std::chrono::seconds(190);peer.next_action=now;
            log(peer,"LAN unavailable; starting CAP2");
        }else if(now>=peer.next_action){
            lan.query(peer);peer.next_action=now+std::chrono::milliseconds(800);
        }
        return;
    }
    if(peer.phase==Phase::Remote){
        if(peer.role=="server"){
            start_job(peer,{"/usr/local/sbin/voider-cap2","exchange",peer.role,std::to_string(peer.id)},"cap2");
            peer.phase=Phase::RemoteJob;peer.deadline=now+std::chrono::seconds(190);
        }else if(now>=peer.next_action){
            Record record=vtp::parse_record(cap2_reply(peer));
            accept_remote(peer,record);
            peer.next_action=now+std::chrono::milliseconds(750);
        }
        if(peer.phase==Phase::Remote&&now>=peer.deadline)retry_later(peer,"CAP2 offer wait expired");
        return;
    }
    if(peer.phase==Phase::RemoteJob){
        int result=poll_job(peer);
        if(result<0&&now<peer.deadline)return;
        if(result<0){cancel_job(peer);retry_later(peer,"CAP2 exchange timed out");return;}
        if(result==0||!accept_remote(peer,record_from_file(peer.job.output)))
            retry_later(peer,"CAP2 exchange failed");
        return;
    }
    if(peer.phase==Phase::Choose){next_remote_method(peer);return;}
    if(peer.phase==Phase::Proof){
        long current=handshake(peer);
        // configure_wireguard() removes and re-adds the peer before every
        // attempt, so any non-zero handshake belongs to this attempt.  This
        // also accepts a valid handshake that arrives while the other side is
        // still finishing its correlated CAP2 exchange.
        if(current>0&&wireguard_endpoint_family(peer)==method_family(peer.candidate)){
            promote(peer,peer.candidate);return;
        }
        if(now>=peer.next_action){wireguard_ping(peer);peer.next_action=now+std::chrono::seconds(1);}
        if(now>=peer.deadline){
            log(peer,"no fresh handshake for "+method_name(peer.candidate));
            cleanup_hole(peer);configure_wireguard(peer);peer.phase=Phase::Choose;
        }
        return;
    }
    if(peer.phase==Phase::HoleJob){
        int result=poll_job(peer);
        if(result<0&&now<peer.deadline)return;
        if(result<0)cancel_job(peer);
        if(result>0){peer.phase=Phase::Proof;peer.deadline=now+std::chrono::seconds(10);peer.next_action=now;}
        else {cleanup_hole(peer);configure_wireguard(peer);peer.phase=Phase::Choose;}
        return;
    }
    if(peer.phase==Phase::TorProof){
        configure_tun(peer);
        if(peer.tun_configured&&now>=peer.next_action){
            if(tor_ping(peer)){
                select_tor_route(peer);peer.selected=Method::Tor;peer.phase=Phase::Up;
                peer.next_action=now+std::chrono::seconds(5);peer.health_failures=0;
                log(peer,"selected tor");return;
            }
            peer.next_action=now+std::chrono::seconds(1);
        }
        if(now>=peer.deadline){stop_tor(peer);peer.phase=Phase::Choose;}
        return;
    }
    if(peer.phase==Phase::Up&&now>=peer.next_action){
        peer.next_action=now+std::chrono::seconds(5);
        bool healthy=peer.selected==Method::Tor?tor_ping(peer):wireguard_ping(peer);
        if(health_lost(peer.health_failures,healthy)){
            if(peer.selected==Method::Tor&&peer.tor_pid>0&&kill(peer.tor_pid,0)==0){
                // Tor may report the two ends' disconnects at different times.
                // Let tundup expire stale streams and authenticate a fresh epoch
                // within the existing proof window before replacing its worker.
                peer.phase=Phase::TorProof;peer.selected=Method::None;
                peer.candidate=Method::Tor;
                peer.deadline=Clock::now()+std::chrono::seconds(TOR_PROOF_SECONDS);
                peer.next_action=Clock::now();
                log(peer,"waiting for tundup stream recovery");
            }else reset(peer,peer.selected==Method::Tor?"Tor health lost":"WireGuard health lost");
        }
        return;
    }
    if(peer.phase==Phase::Backoff&&now>=peer.deadline)reset(peer,"retry");
}

static std::string peer_id(const std::string& role,int id){return role+'-'+std::to_string(id);}

static void reconcile(std::map<std::string,Peer>& peers){
    std::set<std::string> present;
    for(const auto& role:{std::string("client"),std::string("server")}){
        fs::path directory=role=="client"?C.pc:C.ps;
        std::error_code error;
        for(const auto& entry:fs::directory_iterator(directory,error)){
            if(error||!entry.is_regular_file(error))continue;
            std::string name=entry.path().filename().string();
            if(name.size()<6||name.substr(name.size()-5)!=".conf")continue;
            std::string number=name.substr(0,name.size()-5);
            char* end=nullptr;long parsed=std::strtol(number.c_str(),&end,10);
            if(!end||*end||parsed<2||parsed>254||number!=std::to_string(parsed))continue;
            present.insert(peer_id(role,(int)parsed));
        }
    }
    for(const auto& key:present){
        size_t dash=key.find('-');
        std::string role=key.substr(0,dash);
        int id=toi(key.substr(dash+1),0);
        auto found=peers.find(key);
        if(found==peers.end()){
            // Admission only: an authorized new relationship becomes visible
            // after its atomic STATE commit; existing peers continue unchanged.
            if(fs::exists("/run/voider/pending-"+role+"-"+std::to_string(id)))continue;
            Peer peer;peer.role=role;peer.id=id;
            initialize(peer);peers.emplace(key,std::move(peer));
        }else{
            int cert=imported_index(found->second);
            std::string key_now=key_for(found->second);
            std::string secret_now=read1(secret_path(found->second));
            if(cert!=found->second.cert_slot||key_now!=found->second.peer_key||
               secret_now!=found->second.secret){
                disable_wireguard(found->second);
                found->second.cert_slot=cert;
                reset(found->second,"pair material changed");
            }
        }
    }
    for(auto found=peers.begin();found!=peers.end();){
        if(!present.count(found->first)){
            cancel_job(found->second);cleanup_hole(found->second);stop_tor(found->second);
            disable_wireguard(found->second);
            found=peers.erase(found);
        }else ++found;
    }
}

static void requested_resets(std::map<std::string,Peer>& peers){
    const fs::path directory="/run/voider/peer-reset";
    std::error_code error;
    for(const auto& entry:fs::directory_iterator(directory,error)){
        if(error||!entry.is_regular_file(error)||entry.path().extension()!=".req")continue;
        std::string role,extra;int id=0;
        std::ifstream input(entry.path());input>>role>>id;
        bool valid=input&&! (input>>extra)&&(role=="client"||role=="server")&&id>=2&&id<=254;
        auto found=valid?peers.find(peer_id(role,id)):peers.end();
        bool ok=found!=peers.end()&&fs::exists(peer_conf(found->second));
        if(ok)reset(found->second,"operator request");
        fs::path done=entry.path().string()+".done",temporary=done.string()+".tmp";
        {std::ofstream out(temporary);out<<(ok?"OK":"MISSING")<<'\n';}
        fs::rename(temporary,done);
        fs::remove(entry.path(),error);
    }
}

static void write_status(const std::map<std::string,Peer>& peers){
    int clients=0,servers=0,d4=0,d6=0,l4=0,l6=0,h4=0,h6=0,tor=0;
    for(const auto& item:peers){
        const Peer& peer=item.second;
        if(peer.phase!=Phase::Up)continue;
        if(peer.role=="client")clients++;else servers++;
        if(peer.selected==Method::Direct4)d4++;
        else if(peer.selected==Method::Direct6)d6++;
        else if(peer.selected==Method::Lan4)l4++;
        else if(peer.selected==Method::Lan6)l6++;
        else if(peer.selected==Method::Hole4)h4++;
        else if(peer.selected==Method::Hole6)h6++;
        else if(peer.selected==Method::Tor)tor++;
    }
    fs::create_directories(fs::path(C.status).parent_path());
    std::string temporary=C.status+".tmp";
    std::ofstream out(temporary,std::ios::trunc);
    out<<"clients_connected="<<clients<<"\nservers_connected="<<servers
       <<"\ntotal_connected="<<clients+servers<<"\nmax_clients="<<C.maxc
       <<"\nmax_servers="<<C.maxs<<"\nmax_peers="<<C.maxp
       <<"\ndirect_ipv6="<<d6<<"\ndirect_ipv4="<<d4
       <<"\nlan_direct_ipv4="<<l4<<"\nlan_direct_ipv6="<<l6
       <<"\nholepunch_ipv6="<<h6<<"\nholepunch_ipv4="<<h4<<"\ntor="<<tor<<'\n';
    for(const auto& item:peers){
        const Peer& peer=item.second;
        out<<peer.role<<'_'<<peer.id<<'='<<(peer.phase==Phase::Up?method_name(peer.selected):"down")<<'\n';
        out<<peer.role<<'_'<<peer.id<<"_state="<<(peer.phase==Phase::Up?"connected":(peer.phase==Phase::Backoff?"offline":"connecting"))<<'\n';
    }
    out.close();
    fs::rename(temporary,C.status);
}

static int selftest(){
    std::string secret="pair-wireguard-preshared-key";
    std::string node="00112233445566778899aabbccddeeff";
    std::string other="ffeeddccbbaa99887766554433221100";
    std::string nonce="0123456789abcdeffedcba9876543210";
    std::string sender,seen_nonce,responder;
    unsigned port=0;
    std::string query=vtp::lan_query(secret,node,nonce);
    if(!vtp::verify_lan_query(query,secret,sender,seen_nonce)||sender!=node||seen_nonce!=nonce)return 1;
    if(vtp::verify_lan_query(query,"wrong",sender,seen_nonce))return 2;
    std::string answer=vtp::lan_answer(secret,node,nonce,other,51820);
    if(!vtp::verify_lan_answer(answer,secret,node,nonce,responder,port)||responder!=other||port!=51820)return 3;
    if(vtp::verify_lan_answer(answer,secret,other,nonce,responder,port))return 4;
    if(vtp::verify_lan_answer(vtp::lan_answer(secret,node,nonce,node,51820),secret,node,nonce,responder,port))return 5;
    answer.back()=answer.back()=='0'?'1':'0';
    if(vtp::verify_lan_answer(answer,secret,node,nonce,responder,port))return 6;
    if(query.find(secret)!=std::string::npos||answer.find(secret)!=std::string::npos||
       query.find("USB_FP")!=std::string::npos||answer.find("USB_FP")!=std::string::npos)return 7;
    std::string order="lan";
    for(Method method:REMOTE_ORDER)order+=','+method_name(method);
    if(order!="lan,direct4,direct6,holepunch4,holepunch6,tor")return 8;
    if(!local_ntp_ready("Reference ID    : 53899587 (ntp3.duocast.net)\n"
                        "System time     : 28.000000000 seconds fast of NTP time\n"
                        "Leap status     : Normal\n"))return 9;
    if(local_ntp_ready("Reference ID    : 00000000 ()\n"
                       "Leap status     : Normal\n"))return 10;
    if(local_ntp_ready("Reference ID    : 53899587 (ntp3.duocast.net)\n"
                       "Leap status     : Not synchronised\n"))return 11;
    if(local_ntp_ready("Leap status     : Normal\n"))return 12;
    int failures=0;
    if(health_lost(failures,true)||failures!=0)return 13;
    if(health_lost(failures,false)||failures!=1)return 14;
    if(health_lost(failures,false)||failures!=2)return 15;
    if(!health_lost(failures,false)||failures!=3)return 16;
    if(health_lost(failures,true)||failures!=0)return 17;
    C.transports_available=vta::all();
    if(!available(Method::Lan4)||!available(Method::Direct6)||!available(Method::Tor))return 18;
    C.transports_available="hp4,tor";
    if(available(Method::Lan4)||!available(Method::Hole4)||!available(Method::Tor))return 19;
    Peer sticky;sticky.phase=Phase::Up;sticky.selected=Method::Hole4;
    if(!available(sticky.selected))return 20;
    C.transports_available="tor";
    if(available(sticky.selected)||!available(Method::Tor))return 21;
    if(vta::canonical("tor,hp4")!="hp4,tor"||vta::valid("")||vta::valid("tor,tor")||
       !vta::canonical("typo").empty())return 22;
    if(endpoint_family("23.254.230.83:51822")!=AF_INET||
       endpoint_family("[2a0d:7c40:3000:124::171]:51822")!=AF_INET6||
       endpoint_family("[fe80::ba27:ebff:feb1:3517%2]:51820")!=AF_INET6||
       endpoint_family("[fe80::1%]:51820")!=AF_UNSPEC||
       endpoint_family("(none)")!=AF_UNSPEC||
       method_family(Method::Direct6)==endpoint_family("23.254.230.83:51822"))return 23;
    std::cout<<"LAN_DISCOVERY_SELFTEST_OK order=lan,direct,holepunch,tor available=7\n";
    return 0;
}

int main(int argc,char** argv){
    C=cfg();
    C.transports_available=vta::canonical(C.transports_available);
    if(argc==2&&std::string(argv[1])=="--selftest")return selftest();
    std::map<std::string,Peer> peers;
    reconcile(peers);
    LanDiscovery lan;
    auto next_reconcile=Clock::now(),next_status=Clock::now();
    for(;;){
        auto now=Clock::now();
        lan.poll(peers);
        if(now>=next_reconcile){
            reconcile(peers);
            std::string current_available=vta::canonical(cfg().transports_available);
            if(current_available!=C.transports_available){
                C.transports_available=current_available;
                for(auto& item:peers){
                    Peer& peer=item.second;
                    if(peer.phase==Phase::Up&&available(peer.selected))
                        log(peer,"available paths changed; keeping healthy "+method_name(peer.selected));
                    else reset(peer,"available paths changed");
                }
            }
            requested_resets(peers);
            next_reconcile=now+std::chrono::seconds(1);
        }
        for(auto& item:peers)step(item.second,lan);
        if(now>=next_status){write_status(peers);next_status=now+std::chrono::seconds(1);}
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}
