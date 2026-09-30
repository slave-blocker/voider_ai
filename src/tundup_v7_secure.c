/* Voider tundup wire v8 (binary name retained for installed launchers).
 * Two independently progressing TCP streams, one authenticated packet sequence.
 * See README for the protocol, bounds, authenticated plaintext and limitations.
 * No wire-v7 fallback. No threads: all descriptors belong to this poll loop.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define STREAMS 2
#define CONNECTIONS 6                 /* two streams plus four admission slots */
#define MAX_FRAME 4096
#define HEADER 44                     /* length, type, format, session, sequence */
#define FORMAT 3                      /* existing wire-v8 fp-only format */
#define TAG 32
#define WIRE_MAX (HEADER+MAX_FRAME+TAG)
#define WINDOW 1024
#define QUEUE 32
#define QUEUE_MS 250
#define WRITE_MS 1000
#define READ_MS 3000
#define HANDSHAKE_MS 45000
#define IDLE_MS 20000
#define HEARTBEAT_MS 5000
#define HELLO 80

enum phase { CLOSED, CONNECTING, SOCKS_METHOD, SOCKS_AUTH, SOCKS_REPLY,
             SOCKS_ADDRESS, SERVER_HELLO, CLIENT_HELLO, CLIENT_PROOF,
             SERVER_PROOF, ACK_WRITE, READY };
struct packet { unsigned char data[WIRE_MAX]; size_t size; int64_t born; };
struct connection {
    int fd, slot, phase, retry;
    int64_t deadline, next_try, last_rx, read_started, write_started;
    unsigned char transcript[2*HELLO], in[WIRE_MAX], out[WIRE_MAX];
    size_t have, need, sent, size;
    struct packet queue[QUEUE];
    unsigned head, count;
    uint64_t last_sequence;
};
struct counters { uint64_t delivered, duplicates, rejected, expired, dropped,
                          sessions, attempts, closes;
                  uint64_t tx[STREAMS], rx[STREAMS], connected[STREAMS]; };
static struct connection con[CONNECTIONS];
static struct counters stats;
static volatile sig_atomic_t running=1;
static int tunfd=-1, listener=-1, server, session_set;
static const char *onion, *socks_host, *tun_name="tun0";
static int onion_port, socks_port;
/* Process epochs never leave memory as secrets; they are fresh CSPRNG nonces.
 * Session traffic keys depend on both epochs, the pair PSK and USB fingerprint.
 */
static unsigned char root_key[32], epoch[32], remote_epoch[32], session[32];
static unsigned char txkey[32], rxkey[32];
static uint64_t txseq=1, rx_high, received[WINDOW];
static int64_t next_heartbeat, next_status, next_accept;
static unsigned diagnostics;

static int64_t now_ms(void){
    struct timespec t;
    if(clock_gettime(CLOCK_MONOTONIC,&t))abort();
    return (int64_t)t.tv_sec*1000+t.tv_nsec/1000000;
}
static void stop(int signo){ (void)signo; running=0; }
static void diagnostic(const char *why){
    /* Status counters remain available after the bounded diagnostic budget. */
    if(diagnostics<32){diagnostics++;fprintf(stderr,"tundup v8: %s\n",why);}
}
static void put64(unsigned char *p,uint64_t n){
    for(int i=7;i>=0;i--){p[i]=(unsigned char)n;n>>=8;}
}
static uint64_t get64(const unsigned char *p){
    uint64_t n=0;
    for(int i=0;i<8;i++)n=(n<<8)|p[i];
    return n;
}
static void hex(const unsigned char *p,size_t n,char *out){
    const char *h="0123456789abcdef";
    for(size_t i=0;i<n;i++){out[i*2]=h[p[i]>>4];out[i*2+1]=h[p[i]&15];}
    out[n*2]=0;
}
static int hkdf(const unsigned char *key,size_t kl,const void *salt,size_t sl,
                const char *label,unsigned char out[32]){
    EVP_KDF *kdf=EVP_KDF_fetch(NULL,"HKDF",NULL);
    EVP_KDF_CTX *ctx=kdf?EVP_KDF_CTX_new(kdf):NULL;
    OSSL_PARAM p[]={
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,"SHA256",0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,(void*)key,kl),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,(void*)salt,sl),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,(void*)label,strlen(label)),
        OSSL_PARAM_construct_end()
    };
    int ok=ctx&&EVP_KDF_derive(ctx,out,32,p)>0;
    EVP_KDF_CTX_free(ctx);EVP_KDF_free(kdf);
    return ok;
}
static int mac(const unsigned char key[32],const void *a,size_t al,
               const void *b,size_t bl,unsigned char out[32]){
    EVP_MAC *m=EVP_MAC_fetch(NULL,"HMAC",NULL);
    EVP_MAC_CTX *ctx=m?EVP_MAC_CTX_new(m):NULL;
    OSSL_PARAM p[]={OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,"SHA256",0),
                    OSSL_PARAM_construct_end()};
    size_t len=0;
    int ok=ctx&&EVP_MAC_init(ctx,key,32,p)>0&&EVP_MAC_update(ctx,a,al)>0&&
        EVP_MAC_update(ctx,b,bl)>0&&EVP_MAC_final(ctx,out,&len,32)>0&&len==32;
    EVP_MAC_CTX_free(ctx);EVP_MAC_free(m);
    return ok;
}
static int load_psk(const char *path,const char *fp){
    if(strlen(fp)!=64)return 0;
    for(int i=0;i<64;i++)if(!strchr("0123456789abcdefABCDEF",fp[i]))return 0;
    FILE *f=fopen(path,"rb");
    if(!f)return 0;
    unsigned char buf[513];
    size_t n=fread(buf,1,sizeof buf,f);
    int ok=!ferror(f)&&n>=16&&n<sizeof buf&&memcmp(buf,"CHANGE-ME",9);
    fclose(f);
    if(ok)ok=hkdf(buf,n,fp,64,"voider tundup v8 paired root",root_key);
    OPENSSL_cleanse(buf,sizeof buf);
    return ok;
}
static int active_except(const struct connection *c){
    int n=0;
    for(int i=0;i<CONNECTIONS;i++)
        if(&con[i]!=c&&(con[i].phase==READY||con[i].phase==ACK_WRITE))n++;
    return n;
}
static int bind_session(struct connection *c){
    const unsigned char *peer=c->transcript+(server?0:HELLO)+16;
    if(CRYPTO_memcmp(c->transcript+(server?HELLO:0)+16,epoch,32))return 0;
    for(int i=0;i<CONNECTIONS;i++)if(&con[i]!=c&&
       (con[i].phase==READY||con[i].phase==ACK_WRITE)&&con[i].slot==c->slot)return 0;
    if(session_set&&!CRYPTO_memcmp(remote_epoch,peer,32))return 1;
    if(active_except(c))return 0; /* A new process cannot replace a healthy pair. */
    unsigned char salt[64],ctos[32],stoc[32],sid[32];
    memcpy(salt,c->transcript+16,32);memcpy(salt+32,c->transcript+HELLO+16,32);
    const char *cl="v8 fp-only client to server";
    const char *sl="v8 fp-only server to client";
    if(!hkdf(root_key,32,salt,64,cl,ctos)||!hkdf(root_key,32,salt,64,sl,stoc)||
       !hkdf(root_key,32,salt,64,"v8 session identity",sid))return 0;
    memcpy(txkey,server?stoc:ctos,32);memcpy(rxkey,server?ctos:stoc,32);
    memcpy(session,sid,32);memcpy(remote_epoch,peer,32);
    OPENSSL_cleanse(ctos,32);OPENSSL_cleanse(stoc,32);
    txseq=1;rx_high=0;memset(received,0,sizeof received);
    session_set=1;stats.sessions++;
    return 1;
}
static int proof(struct connection *c,const char *label,unsigned char out[32]){
    return mac(root_key,label,strlen(label),c->transcript,sizeof c->transcript,out);
}
static int seal_packet(const unsigned char *pt,size_t n,int type,struct packet *p){
    if(!session_set||n>MAX_FRAME||!txseq||txseq==UINT64_MAX)return 0;
    size_t len=HEADER+n+TAG;
    p->data[0]=len>>8;p->data[1]=len;p->data[2]=type;p->data[3]=FORMAT;
    memcpy(p->data+4,session,32);put64(p->data+36,txseq++);
    p->size=len;p->born=now_ms();
    memcpy(p->data+HEADER,pt,n);
    return mac(txkey,p->data,HEADER,p->data+HEADER,n,p->data+HEADER+n);
}
static int open_packet(const unsigned char *in,size_t len,unsigned char *pt,uint64_t *seq){
    if(!session_set||len<HEADER+TAG||len>WIRE_MAX||
       ((size_t)in[0]*256+in[1])!=len||in[3]!=FORMAT||
       (in[2]!=1&&in[2]!=2)||CRYPTO_memcmp(in+4,session,32))return -1;
    size_t n=len-HEADER-TAG;
    *seq=get64(in+36);
    if(!*seq||n>MAX_FRAME||(in[2]==1&&!n)||(in[2]==2&&n))return -1;
    unsigned char tag[TAG];
    if(!mac(rxkey,in,HEADER,in+HEADER,n,tag)||CRYPTO_memcmp(tag,in+HEADER+n,TAG))return -1;
    memcpy(pt,in+HEADER,n);return (int)n;
}
/* Called only after authentication. Exact sequence membership, never payload equality. */
static int fresh(uint64_t seq){
    if(!seq||(seq<=rx_high&&rx_high-seq>=WINDOW)||received[seq%WINDOW]==seq)return 0;
    received[seq%WINDOW]=seq;
    if(seq>rx_high)rx_high=seq;
    return 1;
}
static void close_connection(struct connection *c,const char *why){
    if(c->fd>=0){close(c->fd);stats.closes++;}
    if(why)diagnostic(why);
    stats.expired+=c->count+(c->phase==READY&&c->size!=0);
    c->fd=-1;c->phase=CLOSED;c->count=c->head=0;c->have=c->size=c->sent=0;
    c->read_started=0;c->last_sequence=0;
    /* Bounded reconnect, with per-slot skew. Only this stream is affected. */
    c->next_try=now_ms()+c->retry+(c->slot+1)*73;
    if(c->retry<8000)c->retry*=2;
}
static void expect(struct connection *c,int phase,size_t bytes){
    c->phase=phase;c->have=0;c->need=bytes;c->read_started=0;
}
static void send_bytes(struct connection *c,const void *p,size_t n){
    memcpy(c->out,p,n);c->size=n;c->sent=0;c->write_started=now_ms();
}
static void hello(unsigned char *p,int slot){
    memset(p,0,HELLO);memcpy(p,"VTUNDUP8",8);p[8]=FORMAT;p[9]=slot;
    memcpy(p+16,epoch,32);
}
static int valid_hello(const unsigned char *p){
    if(memcmp(p,"VTUNDUP8",8)||p[8]!=FORMAT||p[9]>=STREAMS)return 0;
    for(int i=10;i<16;i++)if(p[i])return 0;
    return 1;
}
static int start_client_hello(struct connection *c){
    hello(c->transcript,c->slot);
    if(RAND_bytes(c->transcript+48,32)!=1)return 0;
    send_bytes(c,c->transcript,HELLO);expect(c,SERVER_HELLO,HELLO+32);
    return 1;
}
static int handshake_step(struct connection *c){
    unsigned char out[300],want[32],token[32];
    size_t n;
    switch(c->phase){
    case SOCKS_METHOD:
        if(c->in[0]!=5||c->in[1]!=2)return 0; /* Never fall back to no isolation. */
        /* A reconnect must not keep selecting the same impaired Tor circuit. */
        if(RAND_bytes(token,sizeof token)!=1)return 0;
        out[0]=1;out[1]=66;hex(token,sizeof token,(char*)out+2);out[66]='-';out[67]='0'+c->slot;
        out[68]=1;out[69]='x';send_bytes(c,out,70);expect(c,SOCKS_AUTH,2);return 1;
    case SOCKS_AUTH:
        if(c->in[0]!=1||c->in[1])return 0;
        n=strlen(onion);out[0]=5;out[1]=1;out[2]=0;out[3]=3;out[4]=n;
        memcpy(out+5,onion,n);out[n+5]=onion_port>>8;out[n+6]=onion_port;
        send_bytes(c,out,n+7);expect(c,SOCKS_REPLY,4);return 1;
    case SOCKS_REPLY:
        if(c->in[0]!=5||c->in[1]||c->in[2])return 0;
        if(c->in[3]==1)n=6;
        else if(c->in[3]==4)n=18;
        else if(c->in[3]==3)n=1;
        else return 0;
        expect(c,SOCKS_ADDRESS,n);return 1;
    case SOCKS_ADDRESS:
        if(c->need==1){if(!c->in[0])return 0;expect(c,SOCKS_ADDRESS,c->in[0]+2);return 1;}
        return start_client_hello(c);
    case CLIENT_HELLO:
        if(!valid_hello(c->in)){diagnostic("incompatible protocol (wire v8 authenticated plaintext required; upgrade both appliances)");return 0;}
        memcpy(c->transcript,c->in,HELLO);c->slot=c->in[9];
        hello(c->transcript+HELLO,c->slot);
        if(RAND_bytes(c->transcript+HELLO+48,32)!=1||!proof(c,"v8 server proof",want))return 0;
        memcpy(out,c->transcript+HELLO,HELLO);memcpy(out+HELLO,want,32);
        send_bytes(c,out,HELLO+32);expect(c,CLIENT_PROOF,32);return 1;
    case SERVER_HELLO:
        if(!valid_hello(c->in)||c->in[9]!=c->slot){diagnostic("incompatible protocol (wire v8 authenticated plaintext required; upgrade both appliances)");return 0;}
        memcpy(c->transcript+HELLO,c->in,HELLO);
        if(!proof(c,"v8 server proof",want)||CRYPTO_memcmp(want,c->in+HELLO,32)||
           !proof(c,"v8 client proof",out))return 0;
        send_bytes(c,out,32);expect(c,SERVER_PROOF,32);return 1;
    case CLIENT_PROOF:
        if(!proof(c,"v8 client proof",want)||CRYPTO_memcmp(want,c->in,32)||
           !proof(c,"v8 accepted",out)||!bind_session(c))return 0;
        send_bytes(c,out,32);expect(c,ACK_WRITE,0);return 1;
    case SERVER_PROOF:
        if(!proof(c,"v8 accepted",want)||CRYPTO_memcmp(want,c->in,32)||!bind_session(c))return 0;
        expect(c,READY,2);c->last_rx=c->deadline=now_ms();stats.connected[c->slot]++;return 1;
    default:return 0;
    }
}
static int receive_packet(struct connection *c){
    unsigned char pt[MAX_FRAME+16];
    uint64_t seq;
    int n=open_packet(c->in,c->need,pt,&seq);
    if(n<0){stats.rejected++;return 0;}
    if(seq>c->last_sequence){c->last_rx=now_ms();c->last_sequence=seq;}
    stats.rx[c->slot]++;
    if(!fresh(seq))stats.duplicates++;
    else if(n){
        ssize_t wr=write(tunfd,pt,n);
        if(wr==n)stats.delivered++;else stats.dropped++;
    }
    expect(c,READY,2);return 1;
}
static void queue_packet(struct connection *c,const struct packet *p){
    if(c->count==QUEUE){c->head=(c->head+1)%QUEUE;c->count--;stats.expired++;}
    c->queue[(c->head+c->count)%QUEUE]=*p;c->count++;
}
static void broadcast_packet(const unsigned char *p,size_t n,int type){
    if(!active_except(NULL)){stats.dropped+=(type==1);return;}
    struct packet pkt;
    if(!seal_packet(p,n,type,&pkt)){diagnostic("cryptographic failure or sequence exhaustion");running=0;return;}
    for(int i=0;i<CONNECTIONS;i++)if(con[i].phase==READY)queue_packet(&con[i],&pkt);
}
static void load_output(struct connection *c,int64_t now){
    while(!c->size&&c->count){
        struct packet *p=&c->queue[c->head];
        c->head=(c->head+1)%QUEUE;c->count--;
        if(now-p->born>QUEUE_MS){stats.expired++;continue;}
        send_bytes(c,p->data,p->size);
    }
}
static int progress(struct connection *c,short events){
    if(c->phase==CONNECTING){
        if(!(events&POLLOUT))return 1;
        int error=0;socklen_t size=sizeof error;
        if(getsockopt(c->fd,SOL_SOCKET,SO_ERROR,&error,&size)||error)return 0;
        unsigned char greeting[]={5,1,2};
        send_bytes(c,greeting,sizeof greeting);expect(c,SOCKS_METHOD,2);
    }
    /* Bounded work per descriptor, so a busy peer cannot starve the other. */
    for(int step=0;step<8;step++){
        if(c->size){
            ssize_t n=send(c->fd,c->out+c->sent,c->size-c->sent,MSG_NOSIGNAL);
            if(n<0&&errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR)return 0;
            if(n==0)return 0;
            if(n>0)c->sent+=n;
            if(c->sent==c->size){
                if(c->phase==READY)stats.tx[c->slot]++;
                c->size=c->sent=0;
                if(c->phase==ACK_WRITE){expect(c,READY,2);c->last_rx=c->deadline=now_ms();stats.connected[c->slot]++;}
            }
        }
        if(c->phase==READY)load_output(c,now_ms());
        /* Read independently even when the socket's write side is blocked. */
        if(c->phase!=READY&&c->size)break;
        ssize_t n=recv(c->fd,c->in+c->have,c->need-c->have,0);
        if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR)){
            if(c->size)continue;
            break;
        }
        if(n<=0)return 0;
        if(!c->have)c->read_started=now_ms();
        c->have+=n;
        if((c->phase==CLIENT_HELLO||c->phase==SERVER_HELLO)&&
           c->have>=8&&memcmp(c->in,"VTUNDUP8",8)){
            diagnostic("incompatible protocol (wire v8 required on both appliances)");return 0;
        }
        if(c->have<c->need)continue;
        if(c->phase==READY){
            if(c->need==2){
                size_t len=(size_t)c->in[0]*256+c->in[1];
                if(len<HEADER+TAG||len>HEADER+MAX_FRAME+TAG)return 0;
                c->need=len;
            }else if(!receive_packet(c))return 0;
        }else if(!handshake_step(c))return 0;
    }
    (void)events;
    return 1;
}
static int socket_new(void){
    int fd=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
    if(fd>=0){
        int size=16384;
        setsockopt(fd,SOL_SOCKET,SO_SNDBUF,&size,sizeof size);
        setsockopt(fd,SOL_SOCKET,SO_RCVBUF,&size,sizeof size);
    }
    return fd;
}
static void connect_stream(struct connection *c){
    c->fd=socket_new();stats.attempts++;
    if(c->fd<0){close_connection(c,NULL);return;}
    struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(socks_port)};
    if(inet_pton(AF_INET,socks_host,&a.sin_addr)!=1||
       (connect(c->fd,(void*)&a,sizeof a)<0&&errno!=EINPROGRESS)){
        close_connection(c,"SOCKS connect failed");return;
    }
    c->deadline=now_ms()+HANDSHAKE_MS;expect(c,CONNECTING,0);
}
static void accept_stream(void){
    int64_t now=now_ms();
    if(now<next_accept)return;
    next_accept=now+100; /* admission at most ten per second */
    int fd=accept4(listener,NULL,NULL,SOCK_NONBLOCK|SOCK_CLOEXEC);
    if(fd<0)return;
    int pending=0;
    for(int i=0;i<CONNECTIONS;i++)
        pending+=con[i].phase!=CLOSED&&con[i].phase!=READY&&con[i].phase!=ACK_WRITE;
    if(pending>=4){close(fd);stats.rejected++;return;}
    for(int i=0;i<CONNECTIONS;i++)if(con[i].phase==CLOSED){
        con[i].fd=fd;con[i].deadline=now+HANDSHAKE_MS;
        expect(&con[i],CLIENT_HELLO,HELLO);stats.attempts++;return;
    }
    close(fd);stats.rejected++;
}
static void status_write(void){
    char path[128],tmp[160];
    snprintf(path,sizeof path,"/run/voider/tundup-%s.status",tun_name);
    snprintf(tmp,sizeof tmp,"%s.%ld",path,(long)getpid());
    int fd=open(tmp,O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC|O_NOFOLLOW,0600);
    if(fd<0)return;
    FILE *f=fdopen(fd,"w");
    if(!f){close(fd);unlink(tmp);return;}
    fprintf(f,"protocol=8\nmode=fp-only\npayload_encryption=none\nauthentication=HMAC-SHA256\ntarget=2\nactive=%d\n"
        "sessions=%"PRIu64"\ndelivered=%"PRIu64"\nduplicates=%"PRIu64"\n"
        "rejected=%"PRIu64"\nexpired=%"PRIu64"\ndropped=%"PRIu64"\n"
        "attempts=%"PRIu64"\ncloses=%"PRIu64"\n",
        active_except(NULL),stats.sessions,stats.delivered,stats.duplicates,
        stats.rejected,stats.expired,stats.dropped,stats.attempts,stats.closes);
    for(int slot=0;slot<STREAMS;slot++){
        unsigned pending=0;int up=0;
        for(int i=0;i<CONNECTIONS;i++)if(con[i].slot==slot){
            pending+=con[i].count;up|=con[i].phase==READY;
        }
        fprintf(f,"stream%d_up=%d\nstream%d_tx=%"PRIu64"\nstream%d_rx=%"PRIu64
            "\nstream%d_reconnects=%"PRIu64"\nstream%d_pending=%u\n",
            slot,up,slot,stats.tx[slot],slot,stats.rx[slot],
            slot,stats.connected[slot]?stats.connected[slot]-1:0,slot,pending);
    }
    int bad=ferror(f);
    if(fclose(f)||bad||rename(tmp,path))unlink(tmp);
}
static void retire_session(void){
    if(!session_set||active_except(NULL))return;
    /* Total loss retires the epoch and every pending handshake. Never return to
     * an old key with a reset sequence, even if an old proof arrives much later. */
    for(int i=0;i<CONNECTIONS;i++)if(con[i].phase!=CLOSED)close_connection(&con[i],NULL);
    session_set=0;
    OPENSSL_cleanse(txkey,32);OPENSSL_cleanse(rxkey,32);
    if(RAND_bytes(epoch,32)!=1){diagnostic("epoch RNG failure");running=0;}
}
static void event_loop(void){
    for(int i=0;i<CONNECTIONS;i++){con[i].fd=-1;con[i].slot=server?-1:i;con[i].retry=500;}
    while(running){
        retire_session();
        int64_t now=now_ms();
        if(!server)for(int i=0;i<STREAMS;i++)
            if(con[i].phase==CLOSED&&now>=con[i].next_try)connect_stream(&con[i]);
        if(now>=next_heartbeat){broadcast_packet((const unsigned char*)"",0,2);next_heartbeat=now+HEARTBEAT_MS;}
        if(now>=next_status){status_write();next_status=now+1000;}
        struct pollfd pf[CONNECTIONS+2];
        pf[0]=(struct pollfd){.fd=tunfd,.events=POLLIN};
        pf[1]=(struct pollfd){.fd=now>=next_accept?listener:-1,.events=POLLIN};
        for(int i=0;i<CONNECTIONS;i++){
            struct connection *c=&con[i];
            if(c->phase==READY){
                if(now-c->deadline>=HEARTBEAT_MS)c->retry=500;
                if((c->size&&now-c->write_started>WRITE_MS)||
                   (c->have&&now-c->read_started>READ_MS)||now-c->last_rx>IDLE_MS)
                    close_connection(c,"stream deadline");
                else load_output(c,now);
            }else if(c->phase!=CLOSED&&now>c->deadline)close_connection(c,"handshake deadline");
            pf[i+2]=(struct pollfd){.fd=c->fd,.events=POLLIN};
            if(c->size||c->phase==CONNECTING)pf[i+2].events|=POLLOUT;
        }
        int rc=poll(pf,CONNECTIONS+2,50);
        if(rc<0){if(errno==EINTR)continue;break;}
        if(pf[1].revents&POLLIN)accept_stream();
        for(int i=0;i<CONNECTIONS;i++)if(pf[i+2].revents){
            struct connection *c=&con[i];
            if((pf[i+2].revents&(POLLERR|POLLNVAL))||!progress(c,pf[i+2].revents)){
                stats.rejected+=(c->phase!=READY);close_connection(c,"stream closed or authentication rejected");
            }
        }
        if(pf[0].revents&(POLLERR|POLLHUP|POLLNVAL)){running=0;break;}
        if(pf[0].revents&POLLIN)for(int i=0;i<8;i++){
            unsigned char buf[MAX_FRAME+1];ssize_t n=read(tunfd,buf,sizeof buf);
            if(n<0&&(errno==EAGAIN||errno==EINTR))break;
            if(n<=0){running=0;break;}
            if(n<=MAX_FRAME)broadcast_packet(buf,n,1);else stats.dropped++;
        }
    }
    for(int i=0;i<CONNECTIONS;i++)close_connection(&con[i],NULL);
    status_write();
}
static int tun_open(const char *name){
    int fd=open("/dev/net/tun",O_RDWR|O_NONBLOCK|O_CLOEXEC);
    struct ifreq ifr={0};ifr.ifr_flags=IFF_TUN|IFF_NO_PI;
    snprintf(ifr.ifr_name,sizeof ifr.ifr_name,"%s",name);
    if(fd>=0&&ioctl(fd,TUNSETIFF,&ifr)<0){close(fd);return -1;}
    return fd;
}
static int listen_local(int port){
    int fd=socket_new(),yes=1;
    if(fd<0)return -1;
    setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof yes);
    struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(port),.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    if(bind(fd,(void*)&a,sizeof a)||listen(fd,8)){close(fd);return -1;}
    return fd;
}
static int port_number(const char *s){
    char *end;long n=strtol(s,&end,10);
    return *s&&!*end&&n>0&&n<=65535?(int)n:0;
}
int main(int argc,char **argv){
    if(argc<2)return 2;
    server=!strcmp(argv[1],"server");
    if((!server&&strcmp(argv[1],"client"))||(argc!=(server?5:8)&&argc!=(server?6:9))){
        fprintf(stderr,"usage: %s server PSK PORT USB_FP [TUN_NAME] | "
            "client PSK ONION PORT SOCKS_HOST SOCKS_PORT USB_FP [TUN_NAME]\n"
            "authenticated plaintext only; obsolete stream/cipher arguments rejected\n",argv[0]);return 2;
    }
    const char *fp=argv[server?4:7];
    if(argc==(server?6:9))tun_name=argv[server?5:8];
    if(!*tun_name||strlen(tun_name)>=IFNAMSIZ||strspn(tun_name,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")!=strlen(tun_name))return 2;
    onion_port=port_number(argv[server?3:4]);
    if(!onion_port)return 2;
    if(!server){
        onion=argv[3];socks_host=argv[5];socks_port=port_number(argv[6]);
        struct in_addr address;
        if(!socks_port||!strlen(onion)||strlen(onion)>255||inet_pton(AF_INET,socks_host,&address)!=1)return 2;
    }
    if(!load_psk(argv[2],fp)||RAND_bytes(epoch,32)!=1){fprintf(stderr,"invalid paired identity or RNG failure\n");return 3;}
    signal(SIGPIPE,SIG_IGN);signal(SIGINT,stop);signal(SIGTERM,stop);
    tunfd=tun_open(tun_name);
    if(tunfd<0){perror("tun");return 1;}
    if(server&&(listener=listen_local(onion_port))<0){perror("listen");close(tunfd);return 1;}
    fprintf(stderr,"tundup wire=8 %s tun=%s streams=2 authenticated plaintext (Tor provides encryption)\n",
            server?"server":"client",tun_name);
    event_loop();
    if(listener>=0)close(listener);
    close(tunfd);OPENSSL_cleanse(root_key,32);OPENSSL_cleanse(txkey,32);OPENSSL_cleanse(rxkey,32);
    return 0;
}
