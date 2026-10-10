#pragma once
#include <chrono>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <sys/file.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <thread>
#include <fcntl.h>
#include <unistd.h>

namespace vr {
inline long long monotonic_ms(){
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}
inline bool publish(const std::string& path,const std::string& body){
    std::filesystem::create_directories(std::filesystem::path(path).parent_path());
    std::string temporary=path+".new."+std::to_string(getpid());
    std::ofstream out(temporary);out<<body;out.close();
    std::error_code error;
    if(out)std::filesystem::rename(temporary,path,error);
    if(!out||error){std::filesystem::remove(temporary,error);return false;}
    return true;
}
inline std::string stamp(){return "updated_monotonic_ms="+std::to_string(monotonic_ms())+"\n";}
inline bool fresh(const std::string& path,long long age_ms){
    std::ifstream input(path);std::string line;
    while(std::getline(input,line))if(line.rfind("updated_monotonic_ms=",0)==0){
        char* end=nullptr;long long when=std::strtoll(line.c_str()+21,&end,10),now=monotonic_ms();
        return end&&!*end&&when>0&&when<=now&&now-when<=age_ms;
    }
    return false;
}
class Lock {
    int fd_=-1;
public:
    explicit Lock(const std::string& path){
        std::filesystem::create_directories(std::filesystem::path(path).parent_path());
        fd_=open(path.c_str(),O_CREAT|O_RDWR|O_CLOEXEC|O_NOFOLLOW,0600);
        if(fd_>=0&&flock(fd_,LOCK_EX|LOCK_NB)){close(fd_);fd_=-1;}
    }
    Lock(const Lock&)=delete;
    ~Lock(){if(fd_>=0)close(fd_);}
    bool held()const{return fd_>=0;}
};
inline void terminate_owned_group(int){
    signal(SIGTERM,SIG_DFL);
    if(getpgrp()==getpid())kill(0,SIGTERM);
    _exit(128+SIGTERM);
}
inline bool guard_parent(){
    if(!std::getenv("VOIDER_OWNED_CHILD"))return true;
    pid_t parent=getppid();
    if(getpgrp()==getpid())signal(SIGTERM,terminate_owned_group);
    return parent>1&&prctl(PR_SET_PDEATHSIG,SIGTERM)==0&&getppid()==parent;
}
inline void stop_child(pid_t& child,bool group=false){
    if(child<=1){child=0;return;}
    kill(group?-child:child,SIGTERM);
    auto deadline=monotonic_ms()+2000;
    bool reaped=false,adopted=false;
    while(monotonic_ms()<deadline){
        pid_t result=waitpid(child,nullptr,WNOHANG);
        reaped=reaped||result==child;
        adopted=adopted||(result<0&&errno==ECHILD);
        if((reaped&&!group)||((reaped||adopted)&&kill(group?-child:child,0)<0)){child=0;return;}
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    kill(group?-child:child,SIGKILL);
    if(!reaped&&!adopted)while(waitpid(child,nullptr,0)<0&&errno==EINTR){}
    child=0;
}
}
