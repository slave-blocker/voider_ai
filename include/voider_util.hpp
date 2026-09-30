// voider_util.hpp: tiny shared helpers.
//
// These helpers keep the small binaries readable without pulling in a framework.
// They are intentionally boring wrappers around shell quoting, command capture,
// one-line file IO, and simple status-file parsing.

#pragma once
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include "voider_config.hpp"
namespace vu {
    namespace fs = std::filesystem;
    inline std::string shq(const std::string& s){
        std::string r="'";
        for(char c:s)r+=(c=='\'')?"'\\''":std::string(1,c);
        return r+"'";
    }
    // system() returns an encoded wait status. Never return that from main:
    // exit(256) would otherwise report success for a child that exited 1.
    inline int exit_status(int status){
        return status>=0&&WIFEXITED(status)?WEXITSTATUS(status):1;
    }
    inline int run(const std::string& s,bool echo=true){
        if(echo)std::cout<<s<<"\n";
        return exit_status(std::system(s.c_str()));
    }
    inline std::string cap(const std::string& cmd){
        std::array<char,1024>b{
        }
        ;
        std::string r;
        FILE*f=popen(cmd.c_str(),"r");
        if(!f)return r;
        while(fgets(b.data(),b.size(),f))r+=b.data();
        pclose(f);
        return trim(r);
    }
    inline std::string read1(const fs::path& p){
        std::ifstream f(p);
        std::string s;
        std::getline(f,s);
        return trim(s);
    }
    inline std::string read_file(const fs::path& p){
        std::ifstream f(p,std::ios::binary);
        return {std::istreambuf_iterator<char>(f),std::istreambuf_iterator<char>()};
    }
    inline bool hex64(const std::string& s){
        if(s.size()!=64)return false;
        for(unsigned char c:s)if(!std::isxdigit(c))return false;
        return true;
    }
    inline void write1(const std::string& p,const std::string& s){
        fs::create_directories(fs::path(p).parent_path());
        std::ofstream(p)<<s<<"\n";
    }
    inline bool exists_nonempty(const std::string& p){
        return fs::exists(p)&&fs::file_size(p)>0;
    }
    inline bool mounted(const std::string& p){
        return std::system(("mountpoint -q "+shq(p)).c_str())==0;
    }
    inline bool replace_config_value(const std::string& p,const std::string& key,const std::string& value){
        std::error_code ec;
        if(fs::is_symlink(p,ec)||!fs::is_regular_file(p,ec))return false;
        struct stat st{};
        if(::stat(p.c_str(),&st)!=0)return false;
        std::ifstream in(p);
        if(!in.good())return false;
        std::string body,line;
        int matches=0;
        while(std::getline(in,line)){
            std::string t=trim(line);
            auto at=t.find('=');
            if(!t.empty()&&t[0]!='#'&&at!=std::string::npos&&trim(t.substr(0,at))==key){
                line=key+"="+value;
                matches++;
            }
            body+=line+"\n";
        }
        if(matches!=1)return false;
        std::string tmp=p+".tmp."+std::to_string((long long)getpid());
        {
            std::ofstream out(tmp,std::ios::trunc);
            if(out.good()){
                out<<body;
                out.flush();
                if(!out.good()){out.close();fs::remove(tmp,ec);return false;}
                out.close();
                if(::chmod(tmp.c_str(),st.st_mode&0777)!=0){fs::remove(tmp,ec);return false;}
                fs::rename(tmp,p,ec);
                if(!ec)return true;
                fs::remove(tmp,ec);
            }
        }
        // Curated STATE files are individual bind mounts over a read-only OS.
        // Their parent directory cannot hold a sibling temporary and a mount
        // point cannot be replaced by rename(2).  The mounted file itself is
        // writable, so use one bounded write plus fsync as the required
        // appliance fallback.  The state commit immediately snapshots it.
        int fd=::open(p.c_str(),O_WRONLY|O_TRUNC|O_CLOEXEC|O_NOFOLLOW);
        if(fd<0)return false;
        size_t done=0;
        while(done<body.size()){
            ssize_t n=::write(fd,body.data()+done,body.size()-done);
            if(n<0&&errno==EINTR)continue;
            if(n<=0){::close(fd);return false;}
            done+=(size_t)n;
        }
        bool ok=::fsync(fd)==0&&::fchmod(fd,st.st_mode&0777)==0;
        if(::close(fd)!=0)ok=false;
        if(!ok)return false;
        std::ifstream verify(p,std::ios::binary);
        std::string current{std::istreambuf_iterator<char>(verify),std::istreambuf_iterator<char>()};
        return current==body;
    }
}
