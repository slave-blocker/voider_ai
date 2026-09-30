#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <cstdlib>
static volatile sig_atomic_t run=1;
static void sig(int){
    run=0;
}
static pid_t st(const char*c){
    pid_t p=fork();
    if(!p){
        execl("/bin/sh","sh","-c",c,(char*)0);
        _exit(127);
    }
    return p;
}
int main(){
    signal(SIGTERM,sig);
    signal(SIGINT,sig);
    if(system("/usr/local/sbin/voiderctl sysctl")!=0)return 1;
    if(system("/usr/local/sbin/voiderctl rules reload")!=0)return 1;
    pid_t n=st("exec /usr/local/sbin/voider-nfqd"),p=st("exec /usr/local/sbin/voider-peerd");
    while(run){
        int s;
        pid_t x=waitpid(-1,&s,WNOHANG);
        if(x==n&&run){
            sleep(1);
            n=st("exec /usr/local/sbin/voider-nfqd");
        }
        if(x==p&&run){
            sleep(1);
            p=st("exec /usr/local/sbin/voider-peerd");
        }
        sleep(1);
    }
    kill(n,SIGTERM);
    kill(p,SIGTERM);
    return system("/usr/local/sbin/voiderctl rules clear")==0?0:1;
}
