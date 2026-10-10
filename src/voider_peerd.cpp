// One small per-slot state machine:
//   authenticated LAN -> direct WireGuard -> WireGuard hole punch -> Tor.

#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <spawn.h>
#include <atomic>
#include <memory>
#include <mutex>
#include <condition_variable>
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
#include "voider_runtime.hpp"

#include "voider_wan_ipv6.hpp"
#include "voider_transport_allowlist.hpp"
#include "voider_transport_protocol.hpp"
#include "voider_mailbox.hpp"

using vu::cap;
using vu::read1;
using vu::shq;

namespace fs=std::filesystem;
using Clock=std::chrono::steady_clock;
using vtp::Record;
static Cfg C; // Immutable after startup; only the path mask changes.
static std::atomic<unsigned> paths{0};
static std::atomic<bool> ntp_ready{false},running{true};
static std::mutex setup_mutex,log_mutex;
extern char** environ;
static constexpr unsigned LAN_PORT=45820;
static constexpr int TOR_PROOF_SECONDS=90;
static constexpr int TOR_PING_SECONDS=5;

enum class Phase { Lan, Remote, Job, Choose, Proof, TorProof, Up, Backoff };
enum class Method { None, Lan4, Lan6, Direct4, Direct6, Hole4, Hole6, Tor };
static constexpr Method REMOTE_ORDER[]={
    Method::Direct4,Method::Direct6,Method::Hole4,Method::Hole6,Method::Tor
};

static std::atomic<int> cap2_jobs{0};
struct Job {
    pid_t pid=0;
    bool cap2=false;
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
    pid_t translator_pid=0;
    Clock::time_point translator_retry=Clock::now();
    bool tun_configured=false;
    int health_failures=0;
    Clock::time_point next_recovery=Clock::now();
    Method proven_method=Method::None;
    bool was_up=false;
    // Only this short handoff is shared. The worker owns all fields above.
    struct Shared {
        std::mutex mutex;
        std::condition_variable wake;
        std::string secret,nonce,endpoint,request;
        unsigned port=0;
        bool discovering=false,stop_request=false;
        Method method=Method::None;
        std::string state="connecting";
        Clock::time_point updated=Clock::now();
    } shared;
    std::atomic<bool> stop{false},done{false};
    std::thread worker;
    ~Peer(){if(worker.joinable())worker.join();}
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

static void log(const Peer& peer,const std::string& message){
    std::lock_guard<std::mutex> guard(log_mutex);
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
    // posix_spawn never runs C++ allocation/stdio after fork in a threaded daemon.
    std::vector<char*> raw;
    for(const auto& arg:args)raw.push_back(const_cast<char*>(arg.c_str()));
    raw.push_back(nullptr);
    posix_spawn_file_actions_t files;
    posix_spawn_file_actions_init(&files);
    posix_spawn_file_actions_addopen(&files,STDOUT_FILENO,output.c_str(),O_WRONLY|O_CREAT|O_TRUNC,0600);
    posix_spawn_file_actions_adddup2(&files,STDOUT_FILENO,STDERR_FILENO);
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    if(group){posix_spawnattr_setflags(&attr,POSIX_SPAWN_SETPGROUP);posix_spawnattr_setpgroup(&attr,0);}
    pid_t child=0;
    std::vector<char*> environment;
    for(char** value=environ;*value;value++)if(std::string(*value).rfind("VOIDER_OWNED_CHILD=",0)!=0)environment.push_back(*value);
    char owned[]="VOIDER_OWNED_CHILD=1";
    environment.push_back(owned);environment.push_back(nullptr);
    int result=posix_spawnp(&child,raw[0],&files,&attr,raw.data(),environment.data());
    posix_spawnattr_destroy(&attr);posix_spawn_file_actions_destroy(&files);
    return result?0:child;
}

static bool start_job(Peer& peer,const std::vector<std::string>& args,const std::string& name){
    if(name=="cap2"){
        if(cap2_jobs.fetch_add(1)>=8){--cap2_jobs;return false;}
        peer.job.cap2=true;
    }
    fs::create_directories("/run/voider/jobs");
    peer.job.output="/run/voider/jobs/"+peer.role+"-"+std::to_string(peer.id)+"-"+name;
    peer.job.pid=spawn(args,peer.job.output,true);
    if(!peer.job.pid&&peer.job.cap2){--cap2_jobs;peer.job.cap2=false;}
    return true;
}

static int poll_job(Peer& peer){
    if(!peer.job.pid)return 0;
    int status=0;
    pid_t result=waitpid(peer.job.pid,&status,WNOHANG);
    if(result==0)return -1;
    peer.job.pid=0;
    if(peer.job.cap2){--cap2_jobs;peer.job.cap2=false;}
    return result>0&&WIFEXITED(status)&&WEXITSTATUS(status)==0?1:0;
}

static void cancel_job(Peer& peer){
    if(!peer.job.pid)return;
    vr::stop_child(peer.job.pid,true);
    if(peer.job.cap2){--cap2_jobs;peer.job.cap2=false;}
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

static std::string wg_command(const Peer& peer,const std::string& action){
    return peer.role=="client"?"wg "+action+" wg0":
        "ip netns exec netns"+std::to_string(peer.id)+" wg "+action+" wg"+std::to_string(peer.id);
}
static std::string wg_value(const Peer& peer,const std::string& field){
    std::istringstream lines(cap(wg_command(peer,"show")+' '+field+" 2>/dev/null"));
    std::string key,value;
    while(lines>>key>>value)if(key==peer.peer_key)return value;
    return "";
}
static long handshake(const Peer& peer){return std::strtol(wg_value(peer,"latest-handshakes").c_str(),nullptr,10);}

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

static int wireguard_endpoint_family(const Peer& peer){return endpoint_family(wg_value(peer,"endpoints"));}

static std::string netns(const Peer& peer){return peer.role=="client"?"":"ip netns exec netns"+std::to_string(peer.id)+' ';}
static bool call_route(Peer& peer,bool enable){
    bool client=peer.role=="client";std::string id=std::to_string(peer.id);
    std::string target=client?"172.29."+id+".1/32":"172.29.1.1/32";
    std::string command=netns(peer)+"ip route "+(enable?"replace ":"del ")+target;
    if(enable)command+=" via "+(client?"172.31.0."+id:"172.31.0.1")+" dev "+(client?"wg0":"wg"+id);
    return run(command+" 2>/dev/null"+(enable?"":" || true"))==0;
}

static bool configure_wireguard(Peer& peer){
    if(peer.peer_key.empty()||peer.secret.empty())return false;
    bool client=peer.role=="client";std::string id=std::to_string(peer.id),command=wg_command(peer,"set");
    std::string key=client?"/etc/voider/private/wg0.key":conf(peer,"PRIVATE_KEY",C.mat+"/server/"+id+"/private.key");
    run(command+" peer "+peer.peer_key+" remove 2>/dev/null || true");
    if(run(command+" private-key "+shq(key)+" listen-port "+std::to_string(wireguard_port(peer))))return false;
    int result=run(command+" peer "+peer.peer_key+" preshared-key "+shq(secret_path(peer))+
        " allowed-ips "+(client?"172.31.0."+id+"/32,172.29."+id+".1/32":"172.31.0.1/32,172.29.1.1/32")+
        " persistent-keepalive 5");
    call_route(peer,false);return result==0;
}
static void disable_wireguard(Peer& peer){
    run(wg_command(peer,"set")+" peer "+peer.peer_key+" remove 2>/dev/null || true");call_route(peer,false);
}
static void set_endpoint(Peer& peer,const std::string& endpoint){
    if(!endpoint.empty())run(wg_command(peer,"set")+" peer "+peer.peer_key+" endpoint "+shq(endpoint)+" persistent-keepalive 5");
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

static void stop_tor(Peer& peer){
    std::string name=tor_interface(peer);
    if(!peer.tor_pid){
        int saved=toi(read1(tor_pid_file(peer)),0);
        std::string command=saved>1?read1("/proc/"+std::to_string(saved)+"/cmdline"):"";
        if(command.find("tundup-v7-secure")!=std::string::npos&&command.find(name)!=std::string::npos)peer.tor_pid=saved;
    }
    if(peer.tor_pid){
        vr::stop_child(peer.tor_pid);
    }
    fs::remove(tor_pid_file(peer));
    std::string target=peer.role=="client"?"172.29."+std::to_string(peer.cert_slot)+".1/32":"172.29.1.1/32";
    run(netns(peer)+"ip route del "+target+" dev "+name+" 2>/dev/null || true");
    run(netns(peer)+"ip link del "+name+" 2>/dev/null || true");peer.tun_configured=false;
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
    std::string name=tor_interface(peer),prefix=netns(peer);
    if(run(prefix+"ip link show "+name+" >/dev/null 2>&1"))return;
    std::string address="172.27."+std::to_string(peer.cert_slot)+(peer.role=="client"?".1/30":".2/30");
    peer.tun_configured=run(prefix+"ip addr replace "+address+" dev "+name+" && "+prefix+"ip link set "+name+" up")==0;
}

static bool tunnel_ping(const Peer& peer,bool tor){
    bool client=peer.role=="client";std::string id=std::to_string(peer.id);
    std::string iface=tor?tor_interface(peer):(client?"wg0":"wg"+id);
    std::string target=tor?"172.27."+std::to_string(peer.cert_slot)+(client?".2":".1"):
        (client?"172.31.0."+id:"172.31.0.1");
    return run(netns(peer)+"ping -I "+iface+" -c1 -W"+std::to_string(tor?TOR_PING_SECONDS:1)+' '+target+" >/dev/null 2>&1")==0;
}

static bool select_tor_route(Peer& peer){
    std::string target=peer.role=="client"?"172.29."+std::to_string(peer.cert_slot)+".1/32":"172.29.1.1/32";
    return run(netns(peer)+"ip route replace "+target+" dev "+tor_interface(peer))==0;
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

static std::string method_token(Method method){return method==Method::None?"":vta::TOKENS[unsigned(method)-1];}

static unsigned path_mask(const std::string& value){
    unsigned mask=0;
    if(vta::valid(value))for(unsigned i=0;i<vta::TOKENS.size();++i)
        if(vta::available(value,vta::TOKENS[i]))mask|=1u<<(i+1);
    return mask;
}
static bool available(Method method){return method!=Method::None&&(paths.load()&(1u<<unsigned(method)));}
using Peers=std::map<std::string,std::unique_ptr<Peer>>;

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

    void receive(int fd,Peers& peers){
        if(fd<0)return;
        Method family_method=fd==ipv4_?Method::Lan4:Method::Lan6;
        auto until=Clock::now()+std::chrono::milliseconds(10);
        for(int packets=0;packets<32&&Clock::now()<until;++packets){
            sockaddr_storage source{};
            socklen_t length=sizeof source;
            char buffer[512];
            ssize_t count=recvfrom(fd,buffer,sizeof buffer-1,0,
                                   reinterpret_cast<sockaddr*>(&source),&length);
            if(count<0)return;
            buffer[count]=0;
            std::string packet(buffer);
            if(packet.rfind("VLD1 Q "+node_+" ",0)==0)continue;
            if(packet.rfind("VLD1 Q ",0)==0){
                for(auto& item:peers){
                    Peer& peer=*item.second;
                    std::lock_guard<std::mutex> guard(peer.shared.mutex);
                    std::string sender,nonce;
                    if(peer.stop||!available(family_method)||peer.shared.secret.empty()||
                       !vtp::verify_lan_query(packet,peer.shared.secret,sender,nonce)||sender==node_)continue;
                    std::string answer=vtp::lan_answer(peer.shared.secret,sender,nonce,node_,peer.shared.port);
                    sendto(fd,answer.data(),answer.size(),0,reinterpret_cast<sockaddr*>(&source),length);
                    break;
                }
            }else if(packet.rfind("VLD1 A ",0)==0){
                for(auto& item:peers){
                    Peer& peer=*item.second;
                    std::lock_guard<std::mutex> guard(peer.shared.mutex);
                    if(peer.stop||!peer.shared.discovering||peer.shared.nonce.empty()||!available(family_method))continue;
                    std::string responder;
                    unsigned port=0;
                    if(vtp::verify_lan_answer(packet,peer.shared.secret,node_,peer.shared.nonce,responder,port)){
                        peer.shared.endpoint=endpoint(source,port);
                        peer.shared.wake.notify_one();
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

    void poll(Peers& peers){receive(ipv4_,peers);receive(ipv6_,peers);}

    void query(Peer& peer){
        peer.nonce=vtp::random_hex(16);
        if(peer.nonce.empty())return;
        {std::lock_guard<std::mutex> guard(peer.shared.mutex);peer.shared.nonce=peer.nonce;}
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
    {std::lock_guard<std::mutex> guard(peer.shared.mutex);
     peer.shared.method=Method::None;peer.shared.state=peer.was_up?"offline":"connecting";
     peer.shared.discovering=false;peer.shared.updated=Clock::now();}
    cancel_job(peer);
    cleanup_hole(peer);
    stop_tor(peer);
    peer.health_failures=0;
    peer.remote={};peer.candidate=Method::None;peer.selected=Method::None;
    peer.next_method=0;peer.remote_attempted=false;peer.nonce.clear();peer.lan_endpoint.clear();peer.error.clear();
    peer.secret=read1(secret_path(peer));peer.peer_key=key_for(peer);
    {std::lock_guard<std::mutex> guard(peer.shared.mutex);
     peer.shared.secret=peer.secret;peer.shared.port=wireguard_port(peer);
     peer.shared.nonce.clear();peer.shared.endpoint.clear();}
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
    {std::lock_guard<std::mutex> guard(setup_mutex);
     run("/usr/local/sbin/voider-netns "+peer.role+"-up "+std::to_string(peer.id)+" >/dev/null 2>&1");}
    reset(peer,"slot-start");
}

static bool translator_ready(Peer& peer){
    if(peer.role=="client")return vr::fresh("/run/voider/nfqd.status",5000);
    std::string status="/run/voider/nfqd-server-"+std::to_string(peer.id)+".status";
    if(peer.translator_pid>0){
        int result=waitpid(peer.translator_pid,nullptr,WNOHANG);
        if(result==peer.translator_pid||(result<0&&errno==ECHILD)){
            peer.translator_pid=0;fs::remove(status);peer.translator_retry=Clock::now()+std::chrono::seconds(2);
        }else if(!vr::fresh(status,10000)&&Clock::now()>=peer.translator_retry){
            vr::stop_child(peer.translator_pid);fs::remove(status);
            peer.translator_retry=Clock::now()+std::chrono::seconds(2);
        }
    }
    if(!peer.translator_pid&&Clock::now()>=peer.translator_retry){
        fs::remove(status);
        peer.translator_pid=spawn({"ip","netns","exec","netns"+std::to_string(peer.id),
            "/usr/local/sbin/voider-nfqd","--netns-server",std::to_string(peer.id),std::to_string(peer.cert_slot)},
            "/run/voider/nfqd-server-"+std::to_string(peer.id)+".log",false);
        peer.translator_retry=Clock::now()+std::chrono::seconds(10);
    }
    return vr::fresh("/run/voider/nfqd.status",5000)&&vr::fresh(status,5000);
}

static void begin_proof(Peer& peer,Method method,const std::string& endpoint){
    peer.candidate=method;peer.proven_method=method;
    set_endpoint(peer,endpoint);
    peer.deadline=Clock::now()+std::chrono::seconds(10);
    peer.next_action=Clock::now();
    peer.phase=Phase::Proof;
    log(peer,"try "+method_name(method)+(endpoint.empty()?" passive":" endpoint="+endpoint));
}

static bool promote(Peer& peer,Method method){
    if(method==Method::Tor){if(!select_tor_route(peer))return false;}
    else {
        if(method!=Method::Hole4&&method!=Method::Hole6)cleanup_hole(peer);
        stop_tor(peer);if(!call_route(peer,true))return false;
    }
    peer.selected=method;peer.proven_method=method;peer.was_up=true;
    peer.candidate=Method::None;peer.phase=Phase::Up;
    peer.next_action=Clock::now()+std::chrono::seconds(5);peer.health_failures=0;
    log(peer,"selected "+method_name(method));return true;
}

static void retry_later(Peer& peer,const std::string& error){
    cancel_job(peer);cleanup_hole(peer);stop_tor(peer);call_route(peer,false);
    peer.phase=Phase::Backoff;peer.selected=Method::None;peer.candidate=Method::None;
    peer.error=error;peer.deadline=Clock::now()+std::chrono::seconds(10);
    log(peer,"backoff "+error);
}

static std::string cap2_reply(Peer& peer){
    // Idle mailboxes need no process. Keep responding even while our tunnel is
    // healthy so the other endpoint can finish its own setup/recovery.
    std::error_code error;
    bool pending=false;
    for(const auto& entry:fs::directory_iterator(vmb::root(C,"client",peer.cert_slot)/"in",error))
        if(entry.path().extension()==".offer"){pending=true;break;}
    if(!pending)return "";
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
        if(method==Method::Direct4||method==Method::Direct6){
            bool six=method==Method::Direct6;
            std::string ip=peer.remote.get(six?"PUB6":"PUB4"),p=peer.remote.get(six?"WG6":"WG4");
            if(!address(ip,six?AF_INET6:AF_INET)||!port(p)||(six&&vwan6::current(C,true).empty()))continue;
            begin_proof(peer,method,(six?'['+ip+"]":ip)+':'+p);return;
        }
        if(method==Method::Hole4||method==Method::Hole6){
            bool six=method==Method::Hole6;
            std::string ip=peer.remote.get(six?"PUB6":"PUB4");
            std::string port=peer.remote.get(six?"HP6_PORT":"HP4_PORT");
            if(!address(ip,six?AF_INET6:AF_INET)||!::port(port))continue;
            if(six&&vwan6::current(C,true).empty())continue;
            peer.candidate=method;peer.proven_method=method;
            start_job(peer,{"/usr/local/sbin/voider-holepunch","run",peer.role,
                std::to_string(peer.id),six?"6":"4",ip,port,peer.peer_key},six?"hp6":"hp4");
            peer.phase=Phase::Job;peer.deadline=Clock::now()+std::chrono::seconds(40);
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

static bool wireguard_alive(const Peer& peer,Method method){
    return available(method)&&method_family(method)!=AF_UNSPEC&&
        !peer.peer_key.empty()&&!peer.secret.empty()&&tunnel_ping(peer,false)&&
        handshake(peer)>0&&wireguard_endpoint_family(peer)==method_family(method);
}
static bool recover_wireguard(Peer& peer){
    Method method=peer.proven_method;
    if(method==Method::None){
        for(Method candidate:REMOTE_ORDER)if(candidate!=Method::Tor&&available(candidate)){
            if(method!=Method::None)return false; // Never guess Direct vs Punch.
            method=candidate;
        }
    }
    if(!wireguard_alive(peer,method)||!promote(peer,method))return false;
    cancel_job(peer);log(peer,"recovered live WireGuard peer");return true;
}

static void step(Peer& peer,LanDiscovery& lan){
    auto now=Clock::now();
    if((peer.phase==Phase::Remote||(peer.phase==Phase::Job&&peer.candidate==Method::None)||peer.phase==Phase::Backoff)&&
       now>=peer.next_recovery){
        peer.next_recovery=now+std::chrono::seconds(5);
        if(recover_wireguard(peer))return;
    }
    if(peer.phase==Phase::Lan){
        if(now>=peer.next_action){
            lan.query(peer);peer.next_action=now+std::chrono::milliseconds(800);
        }
        if(!peer.lan_endpoint.empty()){
            Method method=peer.lan_endpoint.front()=='['?Method::Lan6:Method::Lan4;
            if(available(method))begin_proof(peer,method,peer.lan_endpoint);
            else peer.lan_endpoint.clear();
        }else if(now>=peer.deadline){
            if(!ntp_ready.load()){
                if(peer.error!="waiting for local NTP synchronization")
                    log(peer,"waiting for local NTP synchronization");
                peer.error="waiting for local NTP synchronization";
                peer.deadline=now+std::chrono::seconds(1);
                return;
            }
            peer.error.clear();
            peer.phase=Phase::Remote;peer.deadline=now+std::chrono::seconds(190);peer.next_action=now;
            log(peer,"LAN unavailable; starting CAP2");
        }
        return;
    }
    if(peer.phase==Phase::Remote){
        if(peer.role=="server"){
            if(!start_job(peer,{"/usr/local/sbin/voider-cap2","exchange",peer.role,std::to_string(peer.id)},"cap2"))return;
            peer.phase=Phase::Job;peer.deadline=now+std::chrono::seconds(190);
        }else if(now>=peer.next_action){
            Record record=vtp::parse_record(cap2_reply(peer));
            accept_remote(peer,record);
            peer.next_action=now+std::chrono::milliseconds(750);
        }
        if(peer.phase==Phase::Remote&&now>=peer.deadline)retry_later(peer,"CAP2 offer wait expired");
        return;
    }
    if(peer.phase==Phase::Job){
        int result=poll_job(peer);
        if(result<0&&now<peer.deadline)return;
        if(result<0)cancel_job(peer);
        if(peer.candidate==Method::None){
            if(result<=0||!accept_remote(peer,record_from_file(peer.job.output)))retry_later(peer,"CAP2 exchange failed or timed out");
        }else if(result>0)begin_proof(peer,peer.candidate,"");
        else {cleanup_hole(peer);configure_wireguard(peer);peer.phase=Phase::Choose;}
        return;
    }
    if(peer.phase==Phase::Choose){next_remote_method(peer);return;}
    if(peer.phase==Phase::Proof){
        if(now>=peer.next_action){
            peer.next_action=now+std::chrono::seconds(1);
            if(wireguard_alive(peer,peer.candidate)){promote(peer,peer.candidate);return;}
        }
        if(now>=peer.deadline){
            log(peer,"no tunnel proof for "+method_name(peer.candidate));
            // Keep the peer until a different method is tried: a late handshake
            // can still prove this attempt during backoff.
            peer.phase=Phase::Choose;
        }
        return;
    }
    if(peer.phase==Phase::TorProof){
        configure_tun(peer);
        if(peer.tun_configured&&now>=peer.next_action){
            if(tunnel_ping(peer,true)){
                promote(peer,Method::Tor);return;
            }
            peer.next_action=now+std::chrono::seconds(1);
        }
        if(now>=peer.deadline){stop_tor(peer);peer.phase=Phase::Choose;}
        return;
    }
    if(peer.phase==Phase::Up&&now>=peer.next_action){
        if(peer.role=="client")cap2_reply(peer);
        peer.next_action=now+std::chrono::seconds(5);
        bool healthy=tunnel_ping(peer,peer.selected==Method::Tor);
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

static void acknowledge(const fs::path& request,bool ok){
    fs::path done=request.string()+".done",temporary=done.string()+".tmp";
    {std::ofstream out(temporary);out<<(ok?"OK":"MISSING")<<'\n';}
    fs::rename(temporary,done);
}

static void worker(Peer& peer,LanDiscovery& lan){
    std::string stopped_request;
    try {
        initialize(peer);
        auto check=Clock::now();unsigned mask=paths.load();
        // Spread periodic probes instead of waking every connection together.
        std::this_thread::sleep_for(std::chrono::milliseconds((peer.id*37+(peer.role=="server"?137:0))%1000));
        while(running&& !peer.stop){
            std::string request;bool stop_request=false;
            {std::lock_guard<std::mutex> guard(peer.shared.mutex);
             request.swap(peer.shared.request);stop_request=peer.shared.stop_request;peer.shared.stop_request=false;
             if(!peer.shared.endpoint.empty()){peer.lan_endpoint=std::move(peer.shared.endpoint);peer.shared.endpoint.clear();}}
            if(!request.empty()){
                if(stop_request){stopped_request=request;break;}
                peer.proven_method=Method::None;reset(peer,"operator request");acknowledge(request,true);
            }
            auto now=Clock::now();
            if(now>=check){
                int cert=imported_index(peer);
                if(cert!=peer.cert_slot||key_for(peer)!=peer.peer_key||read1(secret_path(peer))!=peer.secret){
                    if(cert!=peer.cert_slot)vr::stop_child(peer.translator_pid);
                    disable_wireguard(peer);peer.cert_slot=cert;peer.proven_method=Method::None;
                    reset(peer,"pair material changed");
                }
                unsigned current=paths.load();
                if(current!=mask){
                    mask=current;
                    if(peer.phase==Phase::Up&&available(peer.selected))log(peer,"available paths changed; keeping healthy "+method_name(peer.selected));
                    else {peer.proven_method=Method::None;reset(peer,"available paths changed");}
                }
                check=now+std::chrono::seconds(1);
            }
            bool sip_ready=translator_ready(peer);
            step(peer,lan);
            std::unique_lock<std::mutex> guard(peer.shared.mutex);
            peer.shared.discovering=peer.phase==Phase::Lan;
            peer.shared.method=peer.phase==Phase::Up&&sip_ready?peer.selected:Method::None;
            peer.shared.state=peer.phase==Phase::Up&&sip_ready?"connected":(peer.was_up||peer.phase==Phase::Backoff?"offline":"connecting");
            peer.shared.updated=Clock::now();
            peer.shared.wake.wait_for(guard,std::chrono::milliseconds(100),[&]{return peer.stop||!running||!peer.shared.request.empty();});
        }
    }catch(const std::exception& e){log(peer,std::string("worker error: ")+e.what());}
    cancel_job(peer);cleanup_hole(peer);stop_tor(peer);disable_wireguard(peer);
    vr::stop_child(peer.translator_pid);
    if(peer.role=="server")fs::remove("/run/voider/nfqd-server-"+std::to_string(peer.id)+".status");
    if(!stopped_request.empty()||!fs::exists(peer_conf(peer))){
        std::lock_guard<std::mutex> guard(setup_mutex);
        run("/usr/local/sbin/voider-netns "+peer.role+"-down "+std::to_string(peer.id)+" >/dev/null 2>&1");
    }
    if(!stopped_request.empty())acknowledge(stopped_request,true);
    peer.done=true;
}

static void reconcile(Peers& peers,LanDiscovery& lan){
    std::set<std::string> present;
    for(const auto& role:{std::string("client"),std::string("server")}){
        std::error_code error;
        for(const auto& entry:fs::directory_iterator(role=="client"?C.pc:C.ps,error)){
            if(error||!entry.is_regular_file(error)||entry.path().extension()!=".conf")continue;
            std::string number=entry.path().stem();int id=toi(number,0);
            if(id<2||id>254||number!=std::to_string(id))continue;
            std::string key=peer_id(role,id);present.insert(key);
            if(peers.count(key)||fs::exists("/run/voider/pending-"+role+"-"+number))continue;
            auto peer=std::make_unique<Peer>();peer->role=role;peer->id=id;
            try{peer->worker=std::thread(worker,std::ref(*peer),std::ref(lan));}
            catch(const std::system_error& e){log(*peer,e.what());continue;}
            peers.emplace(key,std::move(peer));
        }
    }
    for(auto it=peers.begin();it!=peers.end();){
        Peer& peer=*it->second;
        if(!present.count(it->first)){peer.stop=true;peer.shared.wake.notify_one();}
        if(peer.done)it=peers.erase(it);else ++it;
    }
}

static void requested_resets(Peers& peers){
    std::error_code error;
    for(const auto& entry:fs::directory_iterator("/run/voider/peer-reset",error)){
        if(error||!entry.is_regular_file(error)||entry.path().extension()!=".req")continue;
        std::string role,action,extra;int id=0;std::ifstream input(entry.path());input>>role>>id;
        bool valid=bool(input)&&(role=="client"||role=="server")&&id>=2&&id<=254;
        if(input>>action)valid=valid&&action=="stop"&&!(input>>extra);
        auto found=valid?peers.find(peer_id(role,id)):peers.end();
        bool ok=found!=peers.end()&&!found->second->stop&&fs::exists(peer_conf(*found->second));
        if(ok){
            auto& shared=found->second->shared;std::lock_guard<std::mutex> guard(shared.mutex);
            if(!shared.request.empty())continue;
            shared.request=entry.path();shared.stop_request=action=="stop";
            shared.method=Method::None;shared.state="connecting";shared.wake.notify_one();
        }else if(valid&&action=="stop"){
            std::lock_guard<std::mutex> guard(setup_mutex);
            acknowledge(entry.path(),run("/usr/local/sbin/voider-netns "+role+"-down "+std::to_string(id)+" >/dev/null 2>&1")==0);
        }else acknowledge(entry.path(),false);
        fs::remove(entry.path(),error);
    }
}

static void write_status(const Peers& peers){
    int clients=0,servers=0,counts[8]={};std::ostringstream rows;
    auto now=Clock::now();
    for(const auto& item:peers){
        Peer& peer=*item.second;auto& shared=peer.shared;
        std::lock_guard<std::mutex> guard(shared.mutex);
        Method method=!peer.stop&&!peer.done&&available(shared.method)&&now-shared.updated<std::chrono::seconds(15)?shared.method:Method::None;
        if(method!=Method::None){(peer.role=="client"?clients:servers)++;counts[unsigned(method)]++;}
        rows<<peer.role<<'_'<<peer.id<<'='<<method_name(method)<<'\n'
            <<peer.role<<'_'<<peer.id<<"_state="<<(method!=Method::None?"connected":
                (shared.method!=Method::None?"offline":shared.state))<<'\n';
    }
    fs::create_directories(fs::path(C.status).parent_path());
    std::string temporary=C.status+".tmp";std::ofstream out(temporary,std::ios::trunc);
    out<<"clients_connected="<<clients<<"\nservers_connected="<<servers
       <<"\ntotal_connected="<<clients+servers<<"\nmax_clients="<<C.maxc
       <<"\nmax_servers="<<C.maxs<<"\nmax_peers="<<C.maxp;
    for(const auto& item:std::vector<std::pair<Method,const char*>>{
        {Method::Direct6,"direct_ipv6"},{Method::Direct4,"direct_ipv4"},
        {Method::Lan4,"lan_direct_ipv4"},{Method::Lan6,"lan_direct_ipv6"},
        {Method::Hole4,"holepunch_ipv4"},{Method::Hole6,"holepunch_ipv6"},{Method::Tor,"tor"}})
        out<<'\n'<<item.second<<'='<<counts[unsigned(item.first)];
    out<<"\nupdated_monotonic_ms="<<std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count()
       <<'\n'<<rows.str();out.close();fs::rename(temporary,C.status);
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
    paths=path_mask(vta::all());
    if(!available(Method::Lan4)||!available(Method::Direct6)||!available(Method::Tor))return 18;
    paths=path_mask("hp4,tor");
    if(available(Method::Lan4)||!available(Method::Hole4)||!available(Method::Tor))return 19;
    Peer sticky;sticky.phase=Phase::Up;sticky.selected=Method::Hole4;
    if(!available(sticky.selected))return 20;
    paths=path_mask("tor");
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
    C=cfg();paths=path_mask(vta::canonical(C.transports_available));
    if(argc==2&&std::string(argv[1])=="--selftest")return selftest();
    if(argc==2&&std::string(argv[1])=="--healthcheck")return vr::fresh(C.status,10000)?0:1;
    vr::Lock owner("/run/voider/peerd.lock");if(!owner.held())return 1;
    signal(SIGTERM,[](int){running=false;});signal(SIGINT,[](int){running=false;});
    LanDiscovery lan;Peers peers;
    auto next=Clock::now();
    while(running){
        lan.poll(peers);
        if(Clock::now()>=next){
            paths=path_mask(vta::canonical(cfg().transports_available));
            ntp_ready=local_ntp_ready(cap("timeout 2 chronyc tracking 2>/dev/null"));
            if(ntp_ready&&!fs::exists("/run/voider/clock-initialized"))vr::publish("/run/voider/clock-initialized","synchronized\n");
            reconcile(peers,lan);requested_resets(peers);write_status(peers);
            next=Clock::now()+std::chrono::seconds(1);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    for(auto& item:peers){item.second->stop=true;item.second->shared.wake.notify_one();}
    peers.clear();
    fs::remove(C.status);
    return 0;
}
