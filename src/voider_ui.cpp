// voider-ui: table-driven 320x240 four-button consumer interface.

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <linux/fb.h>
#include <linux/kd.h>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <thread>
#include <unistd.h>
#include <fcntl.h>
#include <vector>

#include "voider_config.hpp"
#include "voider_util.hpp"

#include "voider_contacts.hpp"
#include "voider_transport_allowlist.hpp"
#include "voider_ui_font.hpp"
#include "voider_ui_strings.hpp"

using vu::read1;
using vu::shq;

namespace fs=std::filesystem;
static Cfg C;

struct RGB{ unsigned char r,g,b; };
static constexpr RGB NAVY{13,43,55},BLUE{28,116,179},GREEN{45,166,93};
static constexpr RGB YELLOW{246,194,40},RED{211,54,61},ORANGE{239,116,42};
static constexpr RGB CREAM{247,244,232},WHITE{255,255,255},BLACK{10,16,19},GREY{104,116,120};
static constexpr RGB OFF{0,0,0};

static std::map<std::string,std::string> fields(const std::string&p){
    std::map<std::string,std::string> out;
    std::ifstream f(p);
    std::string line;
    while(std::getline(f,line)){
        line=trim(line);
        if(line.empty())continue;
        auto eq=line.find('=');
        auto sp=line.find_first_of(" \t");
        size_t at=eq!=std::string::npos&&(sp==std::string::npos||eq<sp)?eq:sp;
        if(at!=std::string::npos)out[trim(line.substr(0,at))]=trim(line.substr(at+1));
    }
    return out;
}
static void write_text(const std::string&p,const std::string&body){
    fs::create_directories(fs::path(p).parent_path());
    const std::string next=p+".new."+std::to_string(getpid());
    {std::ofstream f(next,std::ios::binary|std::ios::trunc);f<<body;f.flush();if(!f)throw std::runtime_error("UI status write failed: "+p);}
    fs::rename(next,p);
}
static void write_fields(const std::string&p,const std::map<std::string,std::string>&m){
    std::ostringstream body;for(const auto&x:m)body<<x.first<<"="<<x.second<<"\n";
    write_text(p,body.str());
}
static void write1(const std::string&p,const std::string&s){
    write_text(p,s+"\n");
}
static std::string upper(std::string s){for(char&c:s)c=(char)std::toupper((unsigned char)c);return s;}
static int language=0;
static std::string lang_code(int n){return std::array<std::string,3>{"en","de","bg"}[n];}
static int lang_index(const std::string&v){return v=="de"?1:(v=="bg"?2:0);}
static void load_language(){
    auto active=read1("/run/voider/ui.language");
    language=lang_index(active.empty()?read1("/etc/voider/node/language"):active);
}
static std::string tr(const std::string&key){
    auto i=ui_strings.find(key);if(i==ui_strings.end())throw std::runtime_error("Missing translation: "+key);
    return i->second[language];
}

struct State{
    bool boot=false,os_ok=false,os_checking=false,wan_carrier=false,wan=false,net=false;
    bool phone_carrier=false,phone=false,ipv6=false,admin_key=false,admin_ssh=false,state_update_pending=false,restore_pending=false;
    int peers=0,os_progress=0, cursor=-1,language_choice=-1;
    std::string method="WAIT",operation_state,operation_message,operation_detail;
    std::string integrity_state,integrity_phase,integrity_failure,user_integrity;
    std::string boot_sha,system_sha,combined_sha,external_sha;
    std::string boot_code,system_code,combined_code,external_code;
    std::string state_update_reason,usb_model;
    std::string paths_available,paths_committed;
    int path_index=0;
    bool paths_dirty=false;
    std::vector<vc::Contact> contacts;
    std::map<std::string,std::string> peer_modes;
};
static State snapshot(){
    State s;
    auto peer=fields(C.status),wan=fields(C.wan_status),phone=fields(C.phone_status);
    // A frozen daemon must not leave CONNECTED on the physical display.
    auto stamp=peer.find("updated_monotonic_ms");
    if(stamp!=peer.end()){
        char* end=nullptr;long long updated=std::strtoll(stamp->second.c_str(),&end,10);
        auto now=std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        if(!end||*end||updated<=0||updated>now||now-updated>5000)peer.clear();
    }else{
        std::error_code error;auto changed=fs::last_write_time(C.status,error);
        if(error||fs::file_time_type::clock::now()-changed>std::chrono::seconds(5))peer.clear();
    }
    auto os=fields("/run/voider/integrity.status"),op=fields("/run/voider/operation.status");
    auto user=fields("/run/voider/user-integrity.status"),updated=fields("/run/voider/state-updated.status");
    s.boot=fs::exists("/run/voider/appliance-ready")&&fs::exists("/run/voider/checks-passed");
    s.integrity_state=os["STATE"];s.integrity_phase=os["PHASE"];s.integrity_failure=os["FAILURE"];
    s.os_ok=os["STATE"]=="match";s.os_checking=os["STATE"]=="calculating";
    s.os_progress=atoi(os["PROGRESS"].c_str());
    s.boot_sha=os["BOOT_SHA256"];s.system_sha=os["SYSTEM_SHA256"];s.combined_sha=os["COMBINED_SHA256"];s.external_sha=os["EXTERNAL_STATE_SHA256"];
    s.boot_code=os["BOOT_CODE"];s.system_code=os["SYSTEM_CODE"];s.combined_code=os["COMBINED_CODE"];s.external_code=os["EXTERNAL_STATE_CODE"];
    s.user_integrity=user["STATE"];s.state_update_reason=updated["REASON"];
    s.state_update_pending=updated["STATE"]=="updated";
    if(!updated["EXTERNAL_STATE_SHA256"].empty()){s.external_sha=updated["EXTERNAL_STATE_SHA256"];s.external_code=updated["EXTERNAL_STATE_CODE"];}
    s.wan_carrier=wan["CARRIER"]=="up";s.wan=s.wan_carrier&&wan["ROUTE"]=="ok";
    s.net=wan["NET"]=="ok";s.phone_carrier=phone["CARRIER"]=="up";s.phone=phone["REACHABLE"]=="yes";
    s.ipv6=wan["IPV6_READY"]=="1";s.peers=atoi(peer["total_connected"].c_str());
    Cfg live=cfg();
    s.restore_pending=fs::exists("/run/voider/restore-pending");
    s.admin_key=fs::is_regular_file(live.admin_auth_keys);
    s.admin_ssh=s.admin_key&&live.admin_ssh_lan!=0;
    s.paths_committed=vta::canonical(live.transports_available);
    std::string staged=read1(C.ui_paths_stage);
    s.paths_available=vta::valid(staged)?staged:s.paths_committed;
    s.path_index=atoi(read1(C.ui_paths_cursor).c_str());
    if(s.path_index<0||s.path_index>=(int)vta::TOKENS.size())s.path_index=0;
    s.paths_dirty=s.paths_available!=s.paths_committed;
    if(atoi(peer["lan_direct_ipv4"].c_str()))s.method="LAN";
    else if(atoi(peer["lan_direct_ipv6"].c_str()))s.method="LAN";
    else if(atoi(peer["direct_ipv4"].c_str())||atoi(peer["direct_ipv6"].c_str()))s.method="DIRECT";
    else if(atoi(peer["holepunch_ipv4"].c_str())||atoi(peer["holepunch_ipv6"].c_str()))s.method="PRIVATE";
    else if(atoi(peer["tor"].c_str()))s.method="TOR";
    s.operation_state=op["STATE"];s.operation_message=op["MESSAGE"];s.operation_detail=op["DETAIL"];
    auto choice=read1("/run/voider/ui.language.choice");s.language_choice=choice.empty()?language:lang_index(choice);
    s.usb_model=fields("/run/voider/usb.selection")["MODEL"];
    s.peer_modes=peer;
    s.contacts=vc::contacts(C);
    return s;
}

class Canvas{
public:
    static constexpr int W=320,H=240;
    std::vector<RGB> p=std::vector<RGB>(W*H,CREAM);
    bool clipped=false;
    struct Ink {std::string value;int x,y,w,h;};
    std::vector<Ink> ink;
    std::vector<std::string> errors;
    void record(const std::string&v,int x,int y,int w,int h,int bx,int by,int bw,int bh){
        if(v.empty())return;
        if(x<bx||y<by||x+w>bx+bw||y+h>by+bh)errors.push_back("overflow: "+v);
        for(const auto&i:ink){
            if(i.value==v)errors.push_back("duplicate: "+v);
            if(x<i.x+i.w&&x+w>i.x&&y<i.y+i.h&&y+h>i.y)errors.push_back("overlap: "+v+" / "+i.value);
        }
        ink.push_back({v,x,y,w,h});
    }
    void clear(RGB c){std::fill(p.begin(),p.end(),c);clipped=false;ink.clear();errors.clear();}
    void pixel(int x,int y,RGB c){
        if(x<0||y<0||x>=W||y>=H){clipped=true;return;}
        p[(size_t)y*W+x]=c;
    }
    void rect(int x,int y,int w,int h,RGB c){
        if(x<0||y<0||x+w>W||y+h>H)clipped=true;
        int x0=std::max(0,x),y0=std::max(0,y),x1=std::min(W,x+w),y1=std::min(H,y+h);
        for(int yy=y0;yy<y1;yy++)for(int xx=x0;xx<x1;xx++)p[(size_t)yy*W+xx]=c;
    }
    bool ppm(const std::string&path)const{
        std::ofstream f(path,std::ios::binary|std::ios::trunc);
        if(!f)return false;
        f<<"P6\n320 240\n255\n";
        for(const auto&c:p)f.write((const char*)&c,3);
        return f.good();
    }
};

class Framebuffer{
    int fd_=-1;unsigned char*mem_=nullptr;size_t size_=0;fb_fix_screeninfo fix_{};fb_var_screeninfo var_{};
public:
    ~Framebuffer(){if(mem_&&mem_!=MAP_FAILED)munmap(mem_,size_);if(fd_>=0)close(fd_);}
    bool open_panel(const std::string&dev){
        fd_=open(dev.c_str(),O_RDWR|O_CLOEXEC);if(fd_<0)return false;
        if(ioctl(fd_,FBIOGET_FSCREENINFO,&fix_)<0||ioctl(fd_,FBIOGET_VSCREENINFO,&var_)<0)return false;
        if(var_.xres<320||var_.yres<240||(var_.bits_per_pixel!=16&&var_.bits_per_pixel!=24&&var_.bits_per_pixel!=32))return false;
        size_=fix_.smem_len;mem_=(unsigned char*)mmap(nullptr,size_,PROT_READ|PROT_WRITE,MAP_SHARED,fd_,0);
        return mem_!=MAP_FAILED;
    }
    int width()const{return (int)var_.xres;}int height()const{return (int)var_.yres;}int bpp()const{return (int)var_.bits_per_pixel;}
    uint32_t packed(RGB c)const{
        auto channel=[](unsigned v,unsigned n)->uint32_t{return n?(uint32_t)((v*((1u<<n)-1u)+127u)/255u):0;};
        return (channel(c.r,var_.red.length)<<var_.red.offset)|(channel(c.g,var_.green.length)<<var_.green.offset)|
               (channel(c.b,var_.blue.length)<<var_.blue.offset);
    }
    void show(const Canvas&c){
        int bytes=(int)var_.bits_per_pixel/8;
        for(int y=0;y<Canvas::H;y++)for(int x=0;x<Canvas::W;x++){
            size_t off=(size_t)(y+var_.yoffset)*fix_.line_length+(size_t)(x+var_.xoffset)*bytes;
            uint32_t v=packed(c.p[(size_t)y*Canvas::W+x]);
            if(off+(size_t)bytes<=size_)for(int i=0;i<bytes;i++)mem_[off+i]=(unsigned char)(v>>(8*i));
        }
        msync(mem_,size_,MS_ASYNC);
    }
    bool matches(const Canvas&c)const{
        int bytes=(int)var_.bits_per_pixel/8;
        for(int y=0;y<240;y++)for(int x=0;x<320;x++){
            size_t off=(size_t)(y+var_.yoffset)*fix_.line_length+(size_t)(x+var_.xoffset)*bytes;
            uint32_t v=packed(c.p[y*320+x]);
            if(off+bytes>size_)return false;
            for(int i=0;i<bytes;i++)if(mem_[off+i]!=(unsigned char)(v>>(8*i)))return false;
        }return true;
    }
    void blank(){if(fd_>=0)ioctl(fd_,FBIOBLANK,FB_BLANK_POWERDOWN);}
    void unblank(){if(fd_>=0)ioctl(fd_,FBIOBLANK,FB_BLANK_UNBLANK);}
};

class ConsoleGuard{
    std::vector<int> fds_;
public:
    void acquire(){
        std::vector<std::string> ttys{C.ui_tty,"/dev/tty1","/dev/tty2"};
        std::sort(ttys.begin(),ttys.end());ttys.erase(std::unique(ttys.begin(),ttys.end()),ttys.end());
        for(const auto&tty:ttys){
            int fd=open(tty.c_str(),O_RDWR|O_CLOEXEC|O_NOCTTY);
            if(fd<0)continue;
            const char hide[]="\033[?25l\033[2J\033[H";
            ssize_t ignored=write(fd,hide,sizeof(hide)-1);(void)ignored;
            if(ioctl(fd,KDSETMODE,KD_GRAPHICS)==0)fds_.push_back(fd);else close(fd);
        }
    }
    size_t count()const{return fds_.size();}
    bool graphics()const{
        if(fds_.empty())return false;
        for(int fd:fds_){int mode=KD_TEXT;if(ioctl(fd,KDGETMODE,&mode)<0||mode!=KD_GRAPHICS)return false;}
        return true;
    }
    ~ConsoleGuard(){for(int fd:fds_){ioctl(fd,KDSETMODE,KD_TEXT);close(fd);}}
};

class ButtonLock{
    int fd_=-1;
public:
    ButtonLock(){
        fs::path dir=fs::path(C.ui_page_file).parent_path();
        fs::create_directories(dir);
        fd_=open((dir/"ui-button.lock").c_str(),O_CREAT|O_RDWR|O_CLOEXEC,0600);
        if(fd_>=0&&flock(fd_,LOCK_EX|LOCK_NB)!=0){close(fd_);fd_=-1;}
    }
    bool held()const{return fd_>=0;}
    ~ButtonLock(){if(fd_>=0){flock(fd_,LOCK_UN);close(fd_);}}
};

static std::string sys_name(const std::string&fb){return read1("/sys/class/graphics/"+fs::path(fb).filename().string()+"/name");}
static bool panel_name(std::string s){s=upper(s);return s.find("ILI9340")!=std::string::npos||s.find("PITFT")!=std::string::npos||s.find("ST7789")!=std::string::npos;}
static bool physical_panel_hat(){std::string p=upper(read1("/proc/device-tree/hat/product"));return p.find("PITFT")!=std::string::npos||p.find("ILI9340")!=std::string::npos;}
static std::string display_device(){
    if(!physical_panel_hat())return "";
    for(const auto&d:{C.ui_fb,std::string("/dev/fb0"),std::string("/dev/fb1")})
        if(!d.empty()&&access(d.c_str(),R_OK|W_OK)==0&&panel_name(sys_name(d)))return d;
    return "";
}

static std::vector<unsigned> codepoints(const std::string&s){
    std::vector<unsigned> out;
    for(size_t i=0;i<s.size();){unsigned c=(unsigned char)s[i++];
        if(c>=128){int n=c<224?1:(c<240?2:3);c&=(1u<<(6-n))-1;
            while(n--){if(i==s.size()||((unsigned char)s[i]&192)!=128)throw std::runtime_error("Invalid UTF-8");c=(c<<6)|((unsigned char)s[i++]&63);}}
        out.push_back(c);
    }return out;
}
static const ui_font::Glyph& glyph(unsigned code,int size){
    for(const auto&g:ui_font::glyphs)if(g.code==(int)code&&g.size==size)return g;
    throw std::runtime_error("Missing font glyph: "+std::to_string(code));
}
static int text_width(const std::string&s,int size){int n=0;for(auto c:codepoints(s))n+=glyph(c,size).advance;return n;}
// Every line is measured against its own component. No truncation or wrapping.
static void line(Canvas&c,int x,int y,int w,int h,const std::string&value,int wanted,RGB ink,bool center=true){
    if(value.empty())return;
    int size=16;for(int n:{48,40,32,28,24,20,16})if(n<=wanted&&text_width(value,n)<=w){size=n;break;}
    int width=text_width(value,size),left=center?x+(w-width)/2:x,baseline=y+(h-size)/2+size*4/5;
    int xx=left,minx=left,maxx=left,miny=y+h,maxy=y;
    for(auto code:codepoints(value)){const auto&g=glyph(code,size);int px=0;
        for(int j=0;j<g.length;j++){unsigned run=ui_font::pixels[g.offset+j];int alpha=(run&15)*17;
            for(unsigned k=0;k<(run>>4)+1;k++,px++)if(alpha){int dx=xx+g.left+px%g.w,dy=baseline+g.top+px/g.w;
                minx=std::min(minx,dx);maxx=std::max(maxx,dx+1);miny=std::min(miny,dy);maxy=std::max(maxy,dy+1);
                if(dx>=0&&dx<320&&dy>=0&&dy<240){auto bg=c.p[dy*320+dx];c.pixel(dx,dy,{(unsigned char)((ink.r*alpha+bg.r*(255-alpha))/255),(unsigned char)((ink.g*alpha+bg.g*(255-alpha))/255),(unsigned char)((ink.b*alpha+bg.b*(255-alpha))/255)});}else c.clipped=true;
            }}
        xx+=g.advance;
    }
    c.record(value,minx,miny,maxx-minx,maxy-miny,x,y,w,h);
}
static std::string fitted_value(const std::string&value,int width){
    std::string clean;for(unsigned char ch:value)if(ch>=32&&ch<127)clean+=(char)ch;
    if(clean.empty())clean="USB";
    if(text_width(clean,16)<=width)return clean;
    while(!clean.empty()&&text_width(clean+"...",16)>width)clean.pop_back();
    return clean+"...";
}
static void label(Canvas&c,int x,int y,int w,int h,const std::string&key,int size,RGB ink,bool center=true){line(c,x,y,w,h,tr(key),size,ink,center);}
static void header(Canvas&c,const std::string&title,const State&,bool=true){c.rect(0,0,320,40,NAVY);label(c,12,2,296,36,title,24,WHITE,false);}

enum class Action{
    None,UsbDone,Home,Contacts,ContactOpen,Previous,Next,PairStart,AddStart,PairScan,PairRun,AddScan,AddRun,
    Check,CheckRun,Network,NetworkConfirm,NetworkRun,System,SystemMore,Support,PowerConfirm,PowerRun,RebootConfirm,RebootRun,
    BackupStart,BackupScan,BackupRun,RestoreStart,RestoreScan,RestoreRun,RestoreReboot,ResetWarn,ResetConfirm,ResetRun,
    Manage,RemoveConfirm,RemoveRun,ConnectionResetConfirm,ConnectionResetRun,Operation,
    Integrity,IntegrityBoot,IntegritySystem,IntegrityCombined,IntegrityState,
    FullBoot,FullSystem,FullCombined,FullState,FullStateBack,UserMatch,UserMismatch,RecordCode,UpdatedReview,
    Admin,AdminEnableConfirm,AdminEnableRun,AdminDisableConfirm,AdminDisableRun,
    AdminNewStart,AdminNewConfirm,AdminNewScan,AdminNewRun,AdminRevokeConfirm,AdminRevokeRun,
    Language,LanguageBack,LanguageNext,LanguageTry,LanguageSave,PathsOpen,PathsBack,PathsUp,PathsDown,PathsToggle,PathsCancel,PathsApply
};
struct Button{std::string label;Action short_action=Action::None,long_action=Action::None;RGB color=BLUE;bool held=false;};
struct PageSpec{std::string id,title;std::array<Button,4> buttons;};
static Button b(std::string label,Action s,Action l=Action::None,RGB color=BLUE){return {std::move(label),s,l==Action::None?s:l,color};}
static Button hold(std::string label,Action l,RGB color=RED){return {std::move(label),Action::None,l,color,true};}
static Button blank(){return {"",Action::None,Action::None,GREY};}
static vc::Contact selected_contact(const State&s);

static PageSpec spec(const std::string&page,const State&s){
    if(page=="home")return {page,"VOIDER",{b("POWER",Action::PowerConfirm,Action::None,NAVY),b("LINKS",Action::Contacts),b("CHECK",Action::Integrity),b("NET",Action::Network)}};
    if(page=="contacts"&&s.contacts.empty())return {page,"CONNECTIONS",{b("HOME",Action::Home,Action::None,NAVY),b("SHARE",Action::PairStart,Action::None,GREEN),b("ADD",Action::AddStart),b("SYSTEM",Action::System,Action::None,ORANGE)}};
    // Creating another relationship must remain reachable after the first
    // contact exists. Browsing belongs on the opened contact page, where the
    // existing PREV/NEXT controls remain available.
    if(page=="contacts")return {page,"CONNECTIONS",{b("HOME",Action::Home,Action::None,NAVY),b("SHARE",Action::PairStart,Action::None,GREEN),b("ADD",Action::AddStart),b("OPEN",Action::ContactOpen,Action::None,GREEN)}};
    if(page=="contact")return {page,"DIAL",{b("HOME",Action::Home,Action::None,NAVY),b("PREV",Action::Previous),b("NEXT",Action::Next),b("MORE",Action::Manage,Action::None,ORANGE)}};
    if(page=="manage")return {page,"CONNECTION",{b("HOME",Action::Home,Action::None,NAVY),b("RETRY",Action::ConnectionResetConfirm,Action::None,ORANGE),b("REMOVE",Action::RemoveConfirm,Action::None,RED),b("BACK",Action::ContactOpen)}};
    if(page=="pair_insert")return {page,"USB KEY",{b("CANCEL",Action::Contacts,Action::None,NAVY),b("RETRY",Action::PairScan,Action::None,GREEN),blank(),blank()}};
    if(page=="pair_erase")return {page,"USB KEY",{b("CANCEL",Action::Contacts,Action::None,NAVY),hold("ERASE",Action::PairRun,RED),blank(),blank()}};
    if(page=="add_insert")return {page,"ADD LINK",{b("CANCEL",Action::Contacts,Action::None,NAVY),blank(),b("RETRY",Action::AddScan,Action::None,GREEN),blank()}};
    if(page=="add_confirm")return {page,"ADD LINK",{b("CANCEL",Action::Contacts,Action::None,NAVY),blank(),hold("ADD",Action::AddRun,GREEN),blank()}};
    if(page=="usb_remove")return {page,"USB KEY",{blank(),blank(),blank(),b("DONE",Action::UsbDone,Action::None,GREEN)}};
    if(page=="pair_wait")return {page,"PAIRING",{b("HOME",Action::Home,Action::None,NAVY),b("LINKS",Action::Contacts),blank(),b("HELP",Action::Support,Action::None,ORANGE)}};
    if(page=="check")return {page,"SYSTEM CHECK",{b("HOME",Action::Home,Action::None,NAVY),b("DETAIL",Action::IntegrityBoot,Action::None,GREEN),b("HELP",Action::Support),b("SYSTEM",Action::System,Action::None,ORANGE)}};
    if(page=="language")return {page,"LANGUAGE",{b("BACK",Action::LanguageBack,Action::None,NAVY),b("NEXT",Action::LanguageNext),b("TRY",Action::LanguageTry,Action::None,ORANGE),s.boot?hold("SAVE",Action::LanguageSave,GREEN):blank()}};
    if(page=="integrity_verify")return {page,"DEVICE CHECK",{b("POWER",Action::PowerConfirm,Action::None,NAVY),s.integrity_state=="failure"?blank():b("LANGUAGE",Action::Language),blank(),s.integrity_state=="match"?b("NEXT",Action::IntegrityState,Action::None,GREEN):blank()}};
    if(page=="integrity_boot")return {page,"BOOT",{s.state_update_pending?b("BACK",Action::UpdatedReview,Action::None,NAVY):b("HOME",Action::Home,Action::None,NAVY),b("FULL",Action::FullBoot),blank(),b("NEXT",Action::IntegritySystem,Action::None,GREEN)}};
    if(page=="integrity_system")return {page,"SYSTEM OS",{s.state_update_pending?b("BACK",Action::IntegrityBoot,Action::None,NAVY):b("HOME",Action::Home,Action::None,NAVY),b("FULL",Action::FullSystem),blank(),b("NEXT",Action::IntegrityCombined,Action::None,GREEN)}};
    if(page=="integrity_combined")return {page,"SYS COMBINED",{s.state_update_pending?b("BACK",Action::IntegritySystem,Action::None,NAVY):b("HOME",Action::Home,Action::None,NAVY),b("FULL",Action::FullCombined),blank(),b("NEXT",Action::IntegrityState,Action::None,GREEN)}};
    if(page=="integrity_state")return {page,"YOUR CHECK",{b("POWER",Action::PowerConfirm,Action::None,NAVY),b("FULL",Action::FullState),hold("DIFFER",Action::UserMismatch,RED),b("MATCH",Action::UserMatch,Action::None,GREEN)}};
    if(page=="integrity_user_ok")return {page,"STATE MATCH",{b("POWER",Action::PowerConfirm,Action::None,NAVY),blank(),blank(),b("HOME",Action::Home,Action::None,GREEN)}};
    if(page=="integrity_user_fail")return {page,"STATE FAILED",{hold("POWER",Action::PowerRun,RED),blank(),blank(),blank()}};
    if(page=="full_boot")return {page,"BOOT SHA256",{b("BACK",Action::IntegrityBoot,Action::None,NAVY),blank(),blank(),blank()}};
    if(page=="full_system")return {page,"SYSTEM SHA256",{b("BACK",Action::IntegritySystem,Action::None,NAVY),blank(),blank(),blank()}};
    if(page=="full_combined")return {page,"COMBINED SHA",{b("BACK",Action::IntegrityCombined,Action::None,NAVY),blank(),blank(),blank()}};
    if(page=="full_state")return {page,"STATE SHA256",{b("BACK",Action::FullStateBack,Action::None,NAVY),blank(),blank(),blank()}};
    if(page=="state_updated")return {page,"STATE UPDATED",{b("POWER",Action::PowerConfirm,Action::None,NAVY),b("FULL",Action::FullState),blank(),b("I RECORDED IT",Action::RecordCode,Action::None,GREEN)}};
    if(page=="network")return {page,"NETWORK",{b("HOME",Action::Home,Action::None,NAVY),b("RETRY",Action::NetworkConfirm,Action::None,ORANGE),b("PATHS",Action::PathsOpen),b("SYSTEM",Action::System)}};
    if(page=="network_confirm")return {page,"NETWORK",{b("CANCEL",Action::Network,Action::None,NAVY),hold("RETRY",Action::NetworkRun,ORANGE),blank(),blank()}};
    if(page=="paths")return {page,"AVAILABLE",{b("BACK",Action::PathsBack,Action::None,NAVY),b("UP",Action::PathsUp),b("DOWN",Action::PathsDown),b(vta::available(s.paths_available,vta::TOKENS[(size_t)s.path_index])?"REMOVE":"ADD",Action::PathsToggle,Action::None,ORANGE)}};
    if(page=="paths_apply")return {page,"APPLY PATHS",{b("CANCEL",Action::PathsCancel,Action::None,NAVY),blank(),blank(),hold("APPLY",Action::PathsApply,GREEN)}};
    if(page=="system")return {page,"SYSTEM",{b("HOME",Action::Home,Action::None,NAVY),b("LANGUAGE",Action::Language),b("BACKUP",Action::BackupStart,Action::None,ORANGE),b("MORE",Action::SystemMore)}};
    if(page=="system_more")return {page,"SYSTEM",{b("HOME",Action::Home,Action::None,NAVY),b("RESTOR",Action::RestoreStart,Action::None,ORANGE),b("SSH",Action::Admin),b("RESET",Action::ResetWarn,Action::None,RED)}};
    if(page=="admin")return {page,"ADMIN SSH",{b("BACK",Action::SystemMore,Action::None,NAVY),b("LOGIN KEY",Action::AdminNewStart,Action::None,ORANGE),s.admin_key?b("REMOVE",Action::AdminRevokeConfirm,Action::None,RED):blank(),s.admin_key?(s.admin_ssh?b("OFF",Action::AdminDisableConfirm,Action::None,RED):b("ON",Action::AdminEnableConfirm,Action::None,GREEN)):blank()}};
    if(page=="admin_new_confirm")return {page,"LOGIN KEY",{b("CANCEL",Action::Admin,Action::None,NAVY),blank(),blank(),hold("CONFIRM",Action::AdminNewConfirm,ORANGE)}};
    if(page=="admin_enable")return {page,"ADMIN SSH",{b("CANCEL",Action::Admin,Action::None,NAVY),blank(),blank(),hold("ON",Action::AdminEnableRun,GREEN)}};
    if(page=="admin_disable")return {page,"ADMIN SSH",{b("CANCEL",Action::Admin,Action::None,NAVY),blank(),blank(),hold("OFF",Action::AdminDisableRun,RED)}};
    if(page=="admin_new_insert")return {page,"LOGIN KEY",{b("CANCEL",Action::Admin,Action::None,NAVY),blank(),b("CHECK",Action::AdminNewScan,Action::None,GREEN),blank()}};
    if(page=="admin_new_erase")return {page,"LOGIN KEY",{b("CANCEL",Action::Admin,Action::None,NAVY),blank(),blank(),hold("ERASE",Action::AdminNewRun,RED)}};
    if(page=="admin_revoke")return {page,"REMOVE SSH",{b("CANCEL",Action::Admin,Action::None,NAVY),blank(),blank(),hold("REMOVE",Action::AdminRevokeRun,RED)}};
    if(page=="power_confirm")return {page,"POWER OFF",{hold("POWER",Action::PowerRun,RED),b("REBOOT",Action::RebootConfirm,Action::None,ORANGE),blank(),b("CANCEL",Action::Home,Action::None,NAVY)}};
    if(page=="reboot_confirm")return {page,"RESTART DEVICE",{b("CANCEL",Action::PowerConfirm,Action::None,NAVY),hold("REBOOT",Action::RebootRun,ORANGE),blank(),blank()}};
    if(page=="rebooting")return {page,"RESTARTING",{blank(),blank(),blank(),blank()}};
    if(page=="connection_reset_confirm")return {page,"RETRY LINK",{b("CANCEL",Action::Manage,Action::None,NAVY),hold("RETRY",Action::ConnectionResetRun,ORANGE),blank(),blank()}};
    if(page=="powering_off")return {page,"POWERING OFF",{blank(),blank(),blank(),blank()}};
    if(page=="backup_insert")return {page,"BACKUP TITLE",{b("CANCEL",Action::System,Action::None,NAVY),blank(),hold("BACKUP",Action::BackupScan,ORANGE),blank()}};
    if(page=="backup_erase")return {page,"BACKUP TITLE",{b("CANCEL",Action::System,Action::None,NAVY),blank(),hold("ERASE",Action::BackupRun,RED),blank()}};
    if(page=="restore_insert")return {page,"RESTORE",{b("CANCEL",Action::System,Action::None,NAVY),b("CHECK",Action::RestoreScan,Action::None,ORANGE),blank(),blank()}};
    if(page=="restore_ready")return {page,"RESTORE",{b("POWER",Action::PowerConfirm,Action::None,NAVY),blank(),blank(),hold("REBOOT",Action::RestoreReboot,GREEN)}};
    if(page=="restore_confirm")return {page,"RESTORE",{b("CANCEL",Action::System,Action::None,NAVY),hold("RESTOR",Action::RestoreRun,RED),blank(),blank()}};
    if(page=="reset_warn")return {page,"RESET DEVICE",{b("CANCEL",Action::System,Action::None,NAVY),blank(),blank(),b("NEXT",Action::ResetConfirm,Action::None,RED)}};
    if(page=="reset_confirm")return {page,"RESET DEVICE",{b("CANCEL",Action::System,Action::None,NAVY),blank(),blank(),hold("RESET",Action::ResetRun,RED)}};
    if(page=="remove_confirm")return {page,"REMOVE TITLE",{b("CANCEL",Action::ContactOpen,Action::None,NAVY),blank(),hold("REMOVE",Action::RemoveRun,RED),blank()}};
    if(page=="support")return {page,"SUPPORT",{b("HOME",Action::Home,Action::None,NAVY),b("CHECK",Action::Check),b("NET",Action::Network),b("SYSTEM",Action::System)}};
    if(page=="operation")return {page,"WORKING",{b("HOME",Action::Home,Action::None,NAVY),blank(),blank(),blank()}};
    if(page=="result")return {page,"RESULT",{b("HOME",Action::Home,Action::None,NAVY),b("LINKS",Action::Contacts),b("CHECK",Action::Check),b("NET",Action::Network)}};
    return spec("home",s);
}

static void buttons(Canvas&c,const PageSpec&p){
    for(int i=0;i<4;i++){
        const auto&b=p.buttons[i];int x=i*80;
        c.rect(x,200,80,40,b.label.empty()?NAVY:b.color);c.rect(x,200,2,40,CREAM);
        if(b.label.empty())continue;
        if(b.label=="I RECORDED IT"){
            // Deliberate two-line confirmation within its one physical button cell.
            label(c,x+4,201,72,19,"RECORDED LINE 1",20,NAVY);
            label(c,x+4,220,72,19,"RECORDED LINE 2",20,NAVY);
            continue;
        }
        // A bar above the label distinguishes a held action without extra copy.
        bool held=b.held;
        if(held){c.rect(x+25,204,30,3,WHITE);c.rect(x+25,208,30,2,WHITE);}
        label(c,x+4,held?213:204,72,held?24:32,b.label,20,(b.color.r==GREEN.r||b.color.r==ORANGE.r||b.color.r==YELLOW.r)?NAVY:WHITE);
    }
}
static int selected_index(const State&s){
    if(s.contacts.empty())return 0;
    int i=s.cursor>=0?s.cursor:atoi(read1("/run/voider/ui.contact").c_str());
    if(i<0)i=0;
    if(i>=(int)s.contacts.size())i=(int)s.contacts.size()-1;
    return i;
}
static vc::Contact selected_contact(const State&s){return s.contacts.empty()?vc::Contact{}:s.contacts[selected_index(s)];}
static std::string contact_method(const State&s,const vc::Contact&x){
    auto it=s.peer_modes.find(x.role+"_"+std::to_string(x.slot));if(it==s.peer_modes.end())return "";
    const auto&m=it->second;
    if(m=="lan4"||m=="lan_direct_ipv4")return "LAN4";
    if(m=="lan6"||m=="lan_direct_ipv6")return "LAN6";
    if(m=="direct4"||m=="direct_ipv4")return "DIRECT4";
    if(m=="direct6"||m=="direct_ipv6")return "DIRECT6";
    if(m=="holepunch4"||m=="holepunch6"||m=="hp4"||m=="hp6"||m=="holepunch_ipv4"||m=="holepunch_ipv6")return "PRIVATE";
    return m=="tor"?"TOR":"";
}
static bool contact_connected(const State&s,const vc::Contact&x){return !contact_method(s,x).empty();}
static std::string contact_name(const vc::Contact&x){return tr(x.role=="client"?"CLIENT":"SERVER")+" "+std::to_string(x.slot-1);}
static std::string contact_status(const State&s,const vc::Contact&x){
    if(contact_connected(s,x))return "CONNECTED";
    auto status=s.peer_modes.find(x.role+"_"+std::to_string(x.slot)+"_state");
    return s.wan&&status!=s.peer_modes.end()&&status->second=="connecting"?"CONNECTING":"OFFLINE";
}
static std::string failure_reason(const State&s){
    if(!s.boot)return "STARTING";
    if(!s.os_ok&&!s.os_checking)return "SYSTEM NOT SAFE";
    if(!s.phone_carrier||!s.phone)return "PHONE CABLE";
    if(!s.wan_carrier)return "NETWORK CABLE";
    if(!s.wan||!s.net)return "NO INTERNET";
    if(!s.contacts.empty()&&!s.peers)return "OTHER VOIDER OFFLINE";
    return "READY";
}
static std::string support_code(const State&s){
    return std::string("V2-")+(s.os_ok?"O":"X")+(s.wan?"N":"X")+(s.phone?"P":"X")+"-"+(s.peers?"C":"W");
}
static State diagnostic_fixture(State s,int issue){
    if(issue==0)s.boot=false;
    if(issue==1)s.os_ok=false;
    if(issue==2)s.phone=false;
    if(issue==3)s.wan_carrier=false;
    if(issue==4)s.wan=false;
    if(issue==5)s.peers=0;
    return s;
}
static void message(Canvas&c,const std::string&key,RGB color=CREAM){
    c.rect(0,44,320,150,color);label(c,12,72,296,84,key,40,(color.r==NAVY.r||color.r==RED.r||color.r==GREEN.r||color.r==BLUE.r)?WHITE:NAVY);
}
static void digest_seal(Canvas&c,const std::string&digest,const std::string&code){
    static constexpr std::array<RGB,6> palette={RED,BLUE,GREEN,YELLOW,ORANGE,NAVY};
    for(int y=0;y<6;y++)for(int x=0;x<3;x++){unsigned v=digest.size()==64?(unsigned char)digest[y*3+x]:0;RGB color=palette[v%palette.size()];c.rect(124+x*12,50+y*12,12,12,color);c.rect(124+(5-x)*12,50+y*12,12,12,color);}
    if(code.empty())label(c,12,143,296,42,"NOT AVAILABLE",24,BLUE);
    else line(c,12,140,296,48,code,24,BLUE);
}
static std::string grouped16(const std::string&h,size_t at){std::string r;for(size_t i=0;i<16&&at+i<h.size();i++){if(i&&i%4==0)r+=' ';r+=(char)std::toupper((unsigned char)h[at+i]);}return r;}
static void full_digest(Canvas&c,const std::string&digest){for(int row=0;row<4;row++)line(c,12,44+row*38,296,36,grouped16(digest,row*16),24,NAVY);}
static void render(Canvas&c,const std::string&page,const State&s){
    PageSpec p=spec(page,s);c.clear(CREAM);header(c,p.title,s);
    if(page=="home"){
        int clients=0,servers=0,cc=0,sc=0;
        for(const auto&x:s.contacts){bool up=contact_connected(s,x);if(x.role=="client"){clients++;cc+=up;}else{servers++;sc+=up;}}
        c.rect(8,48,304,66,BLUE);c.rect(8,122,304,66,GREEN);
        label(c,20,56,150,48,"CLIENTS",32,WHITE,false);line(c,176,56,124,48,std::to_string(cc)+"/"+std::to_string(clients),40,WHITE);c.ink.back().value=tr("CLIENTS")+" "+c.ink.back().value;
        label(c,20,130,150,48,"SERVERS",32,WHITE,false);line(c,176,130,124,48,std::to_string(sc)+"/"+std::to_string(servers),40,WHITE);c.ink.back().value=tr("SERVERS")+" "+c.ink.back().value;
    }else if(page=="contacts"||page=="contact"||page=="manage"){
        if(s.contacts.empty())message(c,"NO CONNECTIONS",YELLOW);
        else {auto x=selected_contact(s);bool up=contact_connected(s,x);c.rect(8,48,304,54,up?GREEN:BLUE);
            line(c,16,51,288,48,contact_name(x),32,WHITE);
            label(c,12,108,296,32,contact_status(s,x),28,NAVY);
            if(up)label(c,12,143,296,24,contact_method(s,x),20,BLUE);
            if(page!="contacts")line(c,12,170,296,26,x.dial_ip,24,NAVY);
        }
    }else if(page=="language"){
        int selected=s.language_choice<0?language:s.language_choice;
        static const std::array<std::string,3> names={"English","Deutsch","Български"};
        c.rect(8,60,304,104,BLUE);line(c,16,76,288,64,names[selected],40,WHITE);
    }else if(page=="pair_insert"||page=="add_insert"||page=="backup_insert"||page=="restore_insert")message(c,"USB MISSING");
    else if(page=="admin_new_insert")message(c,"INSERT USB STICK");
    else if(page=="pair_erase"||page=="backup_erase"||page=="admin_new_erase"){message(c,"ERASE USB",RED);line(c,12,164,296,28,fitted_value(s.usb_model,296),16,WHITE);}
    else if(page=="usb_remove")message(c,"SAFE TO REMOVE",GREEN);
    else if(page=="add_confirm")message(c,"VALID VOIDER KEY",GREEN);
    else if(page=="pair_wait"){
        std::string role;int slot=0;long started=0;std::ifstream("/run/voider/pairing.slot")>>role>>slot>>started;
        bool up=slot>0&&contact_connected(s,{role,slot,"","",""});
        message(c,up?"CONNECTED":(!s.wan?"NO INTERNET":(started>0&&time(nullptr)-started>180?"OTHER VOIDER OFFLINE":"KEY TRANSFER")),up?GREEN:YELLOW);
    }else if(page=="check"||page=="integrity_verify"){
        bool ok=s.integrity_state=="match",failed=s.integrity_state=="failure";
        c.rect(8,52,304,82,ok?GREEN:(failed?RED:YELLOW));label(c,16, 60,288, 64,ok?"PASSED":(failed?"FAILED":"CHECKING"),40,ok||failed?WHITE:NAVY);
        if(!ok&&!failed){int progress=std::clamp(s.os_progress,0,100);if(s.integrity_phase=="BOOT")progress/=2;else if(s.integrity_phase=="SYSTEM")progress=50+progress/2;
            c.rect(16,154,288,8,NAVY);c.rect(16,154,288*progress/100,8,BLUE);line(c,12,166,296,28,std::to_string(progress)+"%",24,NAVY);}
    }else if(page=="integrity_boot")digest_seal(c,s.boot_sha,s.boot_code);
    else if(page=="integrity_system")digest_seal(c,s.system_sha,s.system_code);
    else if(page=="integrity_combined")digest_seal(c,s.combined_sha,s.combined_code);
    else if(page=="integrity_state")digest_seal(c,s.external_sha,s.external_code);
    else if(page=="state_updated"){
        label(c,12,60,296,36,"WRITE THIS DOWN",28,NAVY);
        line(c,12,112,296,48,s.external_code,28,BLUE);
    }
    else if(page=="integrity_user_ok")message(c,"PASSED",GREEN);
    else if(page=="integrity_user_fail")message(c,"FAILED",RED);
    else if(page=="full_boot")full_digest(c,s.boot_sha);
    else if(page=="full_system")full_digest(c,s.system_sha);
    else if(page=="full_combined")full_digest(c,s.combined_sha);
    else if(page=="full_state")full_digest(c,s.external_sha);
    else if(page=="network"){
        label(c,12,54,174,42,"INTERNET",28,NAVY,false);label(c,188,54,120,42,s.wan?"READY":"OFFLINE",24,s.wan?GREEN:RED);
        label(c,12,103,174,42,"PHONE",28,NAVY,false);label(c,188,103,120,42,s.phone?"CONNECTED":"NOT AVAILABLE",24,s.phone?GREEN:RED);
        label(c,12,157,296,32,s.ipv6?"IPV6 READY":"IPV4 READY",24,BLUE);
    }else if(page=="paths"){
        // One path per view keeps all seven controls readable in every language.
        static const std::array<std::string,7> names={"LAN IPv4","LAN IPv6","DIRECT IPv4","DIRECT IPv6","PRIVATE IPv4","PRIVATE IPv6","TOR"};
        std::string n=names[s.path_index];auto split=n.find(' ');std::string display=tr(n.substr(0,split))+(split==std::string::npos?"":n.substr(split));
        line(c,12,60,296,56,display,40,NAVY);label(c,12,128,296,42,vta::available(s.paths_available,vta::TOKENS[s.path_index])?"ON":"OFF",32,BLUE);
        line(c,270,175,38,22,std::to_string(s.path_index+1)+"/7",16,NAVY);
    }else if(page=="network_confirm")message(c,"RETRY NETWORK?",YELLOW);
    else if(page=="paths_apply")message(c,"APPLY PATH CHANGES?",YELLOW);
    else if(page=="system"||page=="system_more")message(c,s.admin_ssh?"MANAGEMENT ON":"MANAGEMENT OFF",BLUE);
    else if(page=="admin")message(c,s.admin_ssh?"MANAGEMENT ON":"MANAGEMENT OFF",s.admin_ssh?GREEN:YELLOW);
    else if(page=="admin_enable")message(c,"ENABLE SSH?",YELLOW);
    else if(page=="admin_disable")message(c,"DISABLE SSH?",RED);
    else if(page=="admin_new_confirm"){
        c.rect(0,44,320,152,YELLOW);
        label(c,12,66,296,48,s.admin_key?"REPLACE LOGIN KEY?":"CREATE LOGIN KEY?",28,NAVY);
        if(s.admin_key){label(c,12,120,296,32,"OLD KEY WILL",24,NAVY);label(c,12,154,296,32,"STOP WORKING",24,NAVY);}
    }
    else if(page=="admin_revoke")message(c,"REMOVE LOGIN KEY?",RED);
    else if(page=="power_confirm")message(c,"VOIDER",NAVY);
    else if(page=="connection_reset_confirm"){auto x=selected_contact(s);line(c,12,70,296,80,contact_name(x),40,ORANGE);}
    else if(page=="reboot_confirm")message(c,"RESTART DEVICE?",ORANGE);
    else if(page=="rebooting"||page=="powering_off")message(c,"PLEASE WAIT",NAVY);
    else if(page=="restore_confirm"){
        c.rect(0,44,320,152,RED);
        label(c,12,64,296,48,"RESTORE BACKUP?",28,WHITE);
        label(c,12,120,296,32,"REPLACES SETTINGS",24,WHITE);
        label(c,12,154,296,32,"RESTART REQUIRED",24,WHITE);
    }
    else if(page=="restore_ready"){
        c.rect(0,44,320,152,YELLOW);
        label(c,12,68,296,48,"SAFE TO REMOVE",28,NAVY);
        label(c,12,130,296,48,"RESTART TO APPLY",24,NAVY);
    }
    else if(page=="reset_warn")message(c,"ERASE EVERYTHING?",RED);
    else if(page=="reset_confirm")message(c,"FACTORY RESET?",RED);
    else if(page=="remove_confirm"){auto x=selected_contact(s);line(c,12,70,296,80,contact_name(x),40,RED);}
    else if(page=="support"){line(c,12,55,296,64,support_code(s),40,BLUE);label(c,12,132,296,54,failure_reason(s),28,NAVY);}
    else if(page=="operation"||page=="result"){
        std::string key=s.operation_message;bool ok=s.operation_state=="done"||s.operation_state=="remove";
        if(!ok&&key=="NETWORK READY")key="ACTION FAILED";
        if(!ui_strings.count(key)||key==p.title)key=page=="operation"?"PLEASE WAIT":(ok?"DONE":"ACTION FAILED");
        message(c,key,page=="operation"?YELLOW:(ok?GREEN:RED));
        if(page=="operation"&&!s.operation_detail.empty()&&std::all_of(s.operation_detail.begin(),s.operation_detail.end(),[](unsigned char ch){return std::isdigit(ch);}))line(c,12,164,296,30,s.operation_detail+"%",24,NAVY);
    }
    buttons(c,p);
}

static void save_page(const std::string&p){write1(C.ui_page_file,p);}
static void result(const std::string&message){write_fields("/run/voider/operation.status",{{"STATE","failed"},{"MESSAGE",message}});save_page("result");}
static std::string scan_error(const std::string&log){
    std::istringstream input(log);std::string line,x;
    while(std::getline(input,line))if(!trim(line).empty())x=upper(trim(line));
    if(x.find("AMBIGUOUS")!=std::string::npos)return "ONE USB KEY ONLY";
    if(x.find("MOUNTED")!=std::string::npos)return "USB IS MOUNTED";
    if(x.find("SYSTEM DISK")!=std::string::npos)return "SYSTEM DISK";
    if(x.find("USB_NONE")!=std::string::npos)return "INSERT VOIDER KEY";
    if(x.find("DISCONNECTED")!=std::string::npos)return "USB DISCONNECTED";
    if(x.find("READ FAILED")!=std::string::npos)return "USB READ FAILED";
    if(x.find("VERIFY FAILED")!=std::string::npos)return "USB VERIFY FAILED";
    if(x.find("INVALID")!=std::string::npos)return "INVALID BUNDLE";
    if(x.find("BUNDLE MISSING")!=std::string::npos)return "NO BUNDLE";
    if(x.find("NOT READY")!=std::string::npos)return "USB NOT READY";
    if(x.find("UNMOUNT")!=std::string::npos)return "USB UNMOUNT FAILED";
    if(x.find("CHANGED")!=std::string::npos)return "USB CHANGED";
    if(x.find("BUSY")!=std::string::npos)return "USB BUSY";
    if(x.find("NOT SAFE")!=std::string::npos)return "USB NOT SAFE";
    return "USB CHECK FAILED";
}
static int command_status(const std::string&command){return std::system(command.c_str())==0?0:1;}
static bool display_page_now(const std::string&page,const State&s){
    std::string dev=display_device();if(dev.empty())return false;
    Framebuffer fb;if(!fb.open_panel(dev))return false;
    Canvas canvas;render(canvas,page,s);fb.unblank();fb.show(canvas);return true;
}
static int blank_display(){
    write1("/run/voider/display-blank","1");
    std::string dev=display_device();if(dev.empty())return 1;
    Framebuffer fb;if(!fb.open_panel(dev))return 1;
    Canvas black;black.clear(OFF);fb.show(black);fb.blank();return 0;
}
static int shell_action(const std::string&cmd,const std::string&success){
    write_fields("/run/voider/operation.status",{{"STATE","working"},{"MESSAGE","PLEASE WAIT"}});
    save_page("operation");
    int rc=command_status(cmd+" >/run/voider/last-ui-action 2>&1");
    auto op=fields("/run/voider/operation.status");
    if(op["STATE"]=="working"&&op["MESSAGE"]=="PLEASE WAIT")
        write_fields("/run/voider/operation.status",{{"STATE",rc?"failed":"done"},{"MESSAGE",rc?"ACTION FAILED":"COMPLETE"}});
    std::string next=success;
    if(!rc&&op["STATE"]=="remove"&&success!="restore_ready"){
        write1("/run/voider/usb.return",success);next="usb_remove";
    }
    if(!rc&&fs::exists("/run/voider/state-updated.status")){write1("/run/voider/state-updated.return",next);save_page("state_updated");}
    else save_page(rc?"result":next);
    return rc;
}
static std::string selected_device(){return fields("/run/voider/usb.selection")["DEVICE"];}
static std::string selected_token(){return fields("/run/voider/usb.selection")["TOKEN"];}

static int scan_pairing_usb(Action action){
    bool share=action==Action::PairStart||action==Action::PairScan;
    State checking=snapshot();checking.operation_state="working";checking.operation_message="CHECKING USB";
    display_page_now("operation",checking);
    int rc=command_status(std::string("/usr/local/sbin/voider-usb select ")+
                          (share?"erase":"read")+" >/run/voider/last-usb-scan 2>&1");
    if(rc){
        std::string error=scan_error(vu::read_file("/run/voider/last-usb-scan"));
        if(error=="INSERT VOIDER KEY")save_page(share?"pair_insert":"add_insert");
        else result(error);
        return rc;
    }
    if(!share){
        rc=command_status("/usr/local/sbin/voider-usb fingerprint "+shq(selected_device())+" >/run/voider/add-checked 2>/run/voider/last-usb-scan");
        if(rc){result(scan_error(vu::read_file("/run/voider/last-usb-scan")));return rc;}
    }
    save_page(share?"pair_erase":"add_confirm");
    return 0;
}

static int execute(Action a,const State&s,const std::string&page){
    switch(a){
    case Action::UsbDone:{
        std::string next=read1("/run/voider/usb.return");fs::remove("/run/voider/usb.return");
        if(next!="pair_wait"&&next!="contacts"&&next!="admin"&&next!="system")next="home";
        save_page(next);return 0;
    }
    case Action::None:return 0;case Action::Home:save_page("home");return 0;case Action::Contacts:save_page("contacts");return 0;
    case Action::ContactOpen:save_page(s.contacts.empty()?"contacts":"contact");return 0;
    case Action::Previous:case Action::Next:{
        if(s.contacts.empty())return 0;
        int i=selected_index(s)+(a==Action::Next?1:-1);
        if(i<0)i=(int)s.contacts.size()-1;
        if(i>=(int)s.contacts.size())i=0;
        write1("/run/voider/ui.contact",std::to_string(i));save_page("contact");return 0;}
    case Action::PairStart:case Action::AddStart:case Action::PairScan:case Action::AddScan:
        return scan_pairing_usb(a);
    case Action::Check:save_page("check");return 0;case Action::Network:save_page("network");return 0;case Action::System:save_page("system");return 0;
    case Action::Language:write1("/run/voider/ui.language.return",page=="integrity_verify"?page:"system");write1("/run/voider/ui.language.choice",lang_code(language));save_page("language");return 0;
    case Action::LanguageBack:save_page(read1("/run/voider/ui.language.return")=="integrity_verify"?"integrity_verify":"system");return 0;
    case Action::LanguageNext:{int n=(lang_index(read1("/run/voider/ui.language.choice"))+1)%3;write1("/run/voider/ui.language.choice",lang_code(n));return 0;}
    case Action::LanguageTry:write1("/run/voider/ui.language",lang_code(lang_index(read1("/run/voider/ui.language.choice"))));return 0;
    case Action::LanguageSave:return shell_action("/usr/local/sbin/voider-main language-save "+lang_code(lang_index(read1("/run/voider/ui.language.choice"))),"language");
    case Action::SystemMore:save_page("system_more");return 0;
    case Action::Admin:save_page("admin");return 0;
    case Action::AdminEnableConfirm:save_page("admin_enable");return 0;
    case Action::AdminDisableConfirm:save_page("admin_disable");return 0;
    case Action::AdminNewStart:save_page("admin_new_confirm");return 0;
    case Action::AdminNewConfirm:save_page("admin_new_insert");return 0;
    case Action::AdminRevokeConfirm:save_page("admin_revoke");return 0;
    case Action::PathsOpen:
        write1(C.ui_paths_stage,vta::canonical(cfg().transports_available));
        write1(C.ui_paths_cursor,"0");save_page("paths");return 0;
    case Action::PathsUp:case Action::PathsDown:{
        int count=(int)vta::TOKENS.size();int index=s.path_index+(a==Action::PathsDown?1:-1);
        if(index<0)index=count-1;
        if(index>=count)index=0;
        write1(C.ui_paths_cursor,std::to_string(index));return 0;}
    case Action::PathsToggle:{
        auto selected=vta::parse(s.paths_available);std::string token=vta::TOKENS[(size_t)s.path_index];
        if(selected.count(token)&&selected.size()==1)return 0;
        if(selected.count(token))selected.erase(token);else selected.insert(token);
        std::string value;for(const char* item:vta::TOKENS)if(selected.count(item)){if(!value.empty())value+=',';value+=item;}
        write1(C.ui_paths_stage,value);return 0;}
    case Action::PathsBack:
        if(s.paths_dirty)save_page("paths_apply");
        else {fs::remove(C.ui_paths_stage);fs::remove(C.ui_paths_cursor);save_page("network");}
        return 0;
    case Action::PathsCancel:save_page("paths");return 0;
    case Action::Integrity:save_page("integrity_verify");return 0;
    case Action::IntegrityBoot:save_page("integrity_boot");return 0;
    case Action::IntegritySystem:save_page("integrity_system");return 0;
    case Action::IntegrityCombined:save_page("integrity_combined");return 0;
    case Action::IntegrityState:save_page("integrity_state");return 0;
    case Action::FullBoot:save_page("full_boot");return 0;case Action::FullSystem:save_page("full_system");return 0;
    case Action::FullCombined:save_page("full_combined");return 0;
    case Action::FullState:write1("/run/voider/ui.full-state.return",page=="state_updated"?"state_updated":"integrity_state");save_page("full_state");return 0;
    case Action::FullStateBack:{std::string p=read1("/run/voider/ui.full-state.return");fs::remove("/run/voider/ui.full-state.return");save_page(p=="state_updated"?p:"integrity_state");return 0;}
    case Action::UserMatch:case Action::RecordCode:{
        bool recording=a==Action::RecordCode;
        if(recording?(!s.boot||!s.state_update_pending):s.state_update_pending){result("STATE CHANGED");return 2;}
        bool valid=s.integrity_state=="match"&&s.external_sha.size()==64&&
            std::all_of(s.external_sha.begin(),s.external_sha.end(),[](unsigned char c){return std::isxdigit(c);});
        int rc=valid?command_status("/usr/local/sbin/voider-integrity stateprint >/run/voider/last-ui-stateprint 2>&1"):1;
        if(rc||fields("/run/voider/last-ui-stateprint")["EXTERNAL_STATE_SHA256"]!=s.external_sha){
            fs::remove("/run/voider/user-integrity.status");result("STATE CHANGED");return 2;
        }
        write1("/run/voider/user-integrity.status","STATE=match\nDECISION="+std::string(recording?"recorded":"compared")+"\nEXTERNAL_STATE_SHA256="+s.external_sha);
        if(!recording){save_page("integrity_user_ok");return 0;}
        std::string p=read1("/run/voider/state-updated.return");
        fs::remove("/run/voider/state-updated.status");fs::remove("/run/voider/state-updated.return");
        if(p!="pair_wait"&&p!="contacts"&&p!="network"&&p!="result"&&p!="admin"&&p!="language"&&p!="restore_ready"&&p!="usb_remove")p="home";
        save_page(p);return 0;}
    case Action::UserMismatch:write1("/run/voider/user-integrity.status","STATE=mismatch\nEXTERNAL_STATE_SHA256="+s.external_sha);save_page("integrity_user_fail");return 0;
    case Action::UpdatedReview:save_page("state_updated");return 0;
    case Action::Support:save_page("support");return 0;case Action::PowerConfirm:save_page("power_confirm");return 0;
    case Action::NetworkConfirm:save_page("network_confirm");return 0;case Action::BackupStart:save_page("backup_insert");return 0;
    case Action::RestoreStart:save_page("restore_insert");return 0;case Action::ResetWarn:save_page("reset_warn");return 0;
    case Action::ResetConfirm:save_page("reset_confirm");return 0;case Action::Manage:save_page("manage");return 0;
    case Action::RemoveConfirm:save_page("remove_confirm");return 0;case Action::Operation:save_page("operation");return 0;
    case Action::BackupScan:case Action::AdminNewScan:case Action::RestoreScan:{
        bool read=a==Action::RestoreScan;
        int rc=command_status(std::string("/usr/local/sbin/voider-usb select ")+
                              (read?"read":"erase")+" >/run/voider/last-usb-scan 2>&1");
        if(rc){result(scan_error(vu::read_file("/run/voider/last-usb-scan")));return rc;}
        if(read)return shell_action("/usr/local/sbin/voider-main restore-check "+shq(selected_device())+" "+shq(selected_token()),"restore_confirm");
        save_page(a==Action::BackupScan?"backup_erase":"admin_new_erase");return 0;}
    case Action::AdminNewRun:return shell_action("/usr/local/sbin/voider-main admin-key-new","admin");
    case Action::AdminRevokeRun:return shell_action("/usr/local/sbin/voider-main admin-key-revoke","admin");
    case Action::AdminEnableRun:return shell_action("/usr/local/sbin/voider-main admin-ssh-enable","admin");
    case Action::AdminDisableRun:return shell_action("/usr/local/sbin/voider-main admin-ssh-disable","admin");
    case Action::PathsApply:{
        int rc=shell_action("/usr/local/sbin/voider-main paths-apply "+s.paths_available,"network");
        if(!rc){fs::remove(C.ui_paths_stage);fs::remove(C.ui_paths_cursor);}
        return rc;}
    case Action::PairRun:return shell_action("/usr/local/sbin/voider-main pair-export","pair_wait");
    case Action::AddRun:return shell_action("/usr/local/sbin/voider-main import-device "+shq(selected_device()),"contacts");
    case Action::NetworkRun:return shell_action("/usr/local/sbin/voider-main network-recover","result");
    case Action::CheckRun:return shell_action("/usr/local/sbin/voider-integrity verify","result");
    case Action::ConnectionResetConfirm:{auto x=selected_contact(s);
        write1("/run/voider/ui.reset-target",x.role+" "+std::to_string(x.slot)+" "+x.fingerprint);
        save_page("connection_reset_confirm");return 0;}
    case Action::ConnectionResetRun:{auto x=selected_contact(s);
        if(x.role.empty()||read1("/run/voider/ui.reset-target")!=x.role+" "+std::to_string(x.slot)+" "+x.fingerprint){result("CONNECTION RESET FAILED");return 11;}
        fs::remove("/run/voider/ui.reset-target");return shell_action("/usr/local/sbin/voider-main reset-connection "+x.role+" "+std::to_string(x.slot),"contact");}
    case Action::RebootConfirm:save_page("reboot_confirm");return 0;
    case Action::RebootRun:case Action::PowerRun:{
        bool reboot=a==Action::RebootRun;
        save_page(reboot?"rebooting":"powering_off");
        display_page_now(reboot?"rebooting":"powering_off",s);
        std::this_thread::sleep_for(std::chrono::milliseconds(800));
        int rc=0;
        if(!s.boot||s.integrity_state=="failure"||s.user_integrity=="mismatch"){
            blank_display();
            rc=command_status(reboot?"/sbin/reboot":"/sbin/poweroff");
        }else rc=command_status(std::string("/usr/local/sbin/voider-main ")+(reboot?"reboot":"poweroff")+" >/run/voider/last-ui-action 2>&1");
        if(rc){fs::remove("/run/voider/display-blank");result(reboot?"RESTART FAILED":"POWER OFF FAILED");display_page_now("result",snapshot());}
        return rc;}
    case Action::BackupRun:return shell_action("/usr/local/sbin/voider-main backup "+shq(selected_device())+" "+shq(selected_token()),"system");
    case Action::RestoreRun:return shell_action("/usr/local/sbin/voider-main restore "+shq(selected_device())+" "+shq(selected_token()),"restore_ready");
    case Action::RestoreReboot:return shell_action("/usr/local/sbin/voider-main restore-reboot","restore_ready");
    case Action::ResetRun:return shell_action("/usr/local/sbin/voider-main factory-reset","result");
    case Action::RemoveRun:{auto x=selected_contact(s);return shell_action("/usr/local/sbin/voider-main remove "+x.role+" "+std::to_string(x.slot),"contacts");}
    }
    return 0;
}
static std::string visible_page(const State&s,const std::string&requested){
    if(requested=="power_confirm"||requested=="powering_off"||requested=="reboot_confirm"||requested=="rebooting")return requested;
    if(s.integrity_state=="failure")return "integrity_verify";
    if(s.user_integrity=="mismatch")return "integrity_user_fail";
    if(!s.boot){
        if(requested=="language")return requested;
        if(s.integrity_state=="match"&&(requested=="integrity_state"||requested=="full_state"||requested=="integrity_user_ok"))return requested;
        return "integrity_verify";
    }
    if(s.state_update_pending&&requested!="state_updated"&&requested!="full_state"&&requested!="result")return "state_updated";
    if(s.restore_pending&&!s.state_update_pending)return "restore_ready";
    return requested.empty()?"home":requested;
}
static int button_event(int number,const std::string&kind){
    if(number<1||number>4||(kind!="short"&&kind!="long"))return 2;
    ButtonLock lock;if(!lock.held())return 2;
    State s=snapshot();std::string page=read1(C.ui_page_file);page=visible_page(s,page);
    PageSpec p=spec(page,s);const Button&x=p.buttons[number-1];
    fs::create_directories(fs::path(C.ui_event_log).parent_path());
    std::ofstream(C.ui_event_log,std::ios::app)<<std::time(nullptr)<<" "<<page<<" B"<<number<<" "<<kind<<" "<<x.label<<"\n";
    return execute(kind=="short"?x.short_action:x.long_action,s,page);
}

static void render_factory(Canvas&,const std::map<std::string,std::string>&);
enum class FactoryIntent{None,Poweroff,Install,Reboot};
static FactoryIntent factory_intent(const std::string&state,int number,const std::string&kind){
    if(state=="COMPLETE")return number==4&&kind=="short"?FactoryIntent::Reboot:FactoryIntent::None;
    if(state=="INSTALLING"||state=="RESTARTING"||state=="REBOOTING"||state=="POWERING_OFF")return FactoryIntent::None;
    if(number==1&&kind=="long")return FactoryIntent::Poweroff;
    if(number==2&&kind=="long")return FactoryIntent::Install;
    return FactoryIntent::None;
}

static std::vector<std::string> page_ids(){return {"home","language","contacts","contact","manage","pair_insert","pair_erase","add_insert","add_confirm","usb_remove","pair_wait","check","integrity_verify","integrity_boot","integrity_system","integrity_combined","integrity_state","integrity_user_ok","integrity_user_fail","full_boot","full_system","full_combined","full_state","state_updated","network","network_confirm","paths","paths_apply","system","system_more","admin","admin_enable","admin_disable","admin_new_confirm","admin_new_insert","admin_new_erase","admin_revoke","power_confirm","powering_off","reboot_confirm","rebooting","connection_reset_confirm","backup_insert","backup_erase","restore_insert","restore_confirm","restore_ready","reset_warn","reset_confirm","remove_confirm","support","operation","result"};}
static State demo_state(){
    State s;s.boot=s.os_ok=s.wan_carrier=s.wan=s.net=s.phone_carrier=s.phone=s.ipv6=s.admin_key=s.admin_ssh=true;s.peers=1;
    s.contacts={{"client",2,"CLIENT 1",std::string(64,'a'),"10.1.2.1"},{"server",254,"SERVER 253",std::string(64,'b'),"10.254.1.1"}};
    s.usb_model="SanDisk Ultra USB 3.0";s.integrity_state="match";s.paths_available=s.paths_committed=vta::all();
    s.boot_sha="06a73e1ed278123287f3e1c09fe0ae26bc7abdcbb1deac1234567890aa123456";
    s.system_sha=s.combined_sha=s.external_sha=s.boot_sha;
    s.boot_code=s.system_code=s.combined_code=s.external_code="YZ23-4567-89AB-CDEF-GHJK";
    s.peer_modes["client_2"]="tor";s.peer_modes["server_254"]="down";s.peer_modes["server_254_state"]="connecting";s.cursor=0;return s;
}
static int selftest(){
    int fails=0,cases=0;State demo=demo_state(),empty=demo,max=demo,failed=demo,working=demo;
    empty.contacts.clear();empty.admin_key=empty.admin_ssh=false;max.contacts.clear();
    for(const auto&role:{"client","server"})for(int n=2;n<=254;n++){max.contacts.push_back({role,n,vc::connection_name(role,n),std::string(64,'f'),vc::dial_ip(role,n)});max.peer_modes[std::string(role)+"_"+std::to_string(n)]="hp6";}
    max.usb_model=std::string(128,'W');max.cursor=505;failed.integrity_state="failure";failed.operation_state="failed";failed.operation_message="STATE SAVE FAILED";failed.wan=failed.phone=failed.admin_ssh=false;
    working.integrity_state="calculating";working.os_progress=99;working.operation_state="working";working.operation_message="SAVING CONNECTION";working.operation_detail="100";
    auto check=[&](Canvas&c,const std::string&id){cases++;if(c.clipped||!c.errors.empty()){fails++;std::cerr<<"UI_TEST "<<lang_code(language)<<" "<<id<<" clipped="<<c.clipped;for(auto&e:c.errors)std::cerr<<" ["<<e<<"]";std::cerr<<"\n";}};
    for(language=0;language<3;language++){
        for(const auto&page:page_ids())for(const State*state:{&empty,&demo,&max,&failed,&working}){
            auto p=spec(page,*state);for(auto&b:p.buttons){cases++;if(b.label.empty()&&(b.short_action!=Action::None||b.long_action!=Action::None))fails++;}
            Canvas c;render(c,page,*state);check(c,page);
        }
        for(auto state:{"READY","INSTALLING","FAILED","COMPLETE","RESTARTING","REBOOTING","LANGUAGE","POWERING_OFF"}){Canvas c;render_factory(c,{{"STATE",state},{"PROGRESS","100"}});check(c,std::string("factory-")+state);}
        for(const auto&entry:ui_factory_states){const auto&state=entry.first;const auto&key=entry.second;
            Canvas c;render_factory(c,{{"STATE",state},{"PHASE",key},{"DETAIL",key},{"PROGRESS","100"}});check(c,"factory-"+key);
        }
        for(int i=0;i<7;i++)for(bool on:{false,true}){
            State v=demo;v.path_index=i;v.paths_available=on?vta::all():(i==6?"lan4":"tor");Canvas c;render(c,"paths",v);check(c,"path-"+std::to_string(i));
        }
        for(const auto&m:{"lan4","lan6","direct4","direct6","holepunch4","holepunch6","tor"}){
            State v=demo;v.peer_modes["client_2"]=m;Canvas c;render(c,"contact",v);check(c,std::string("method-")+m);
            cases++;if(!contact_connected(v,v.contacts[0]))fails++;
            if(std::string(m)=="lan4"&&contact_method(v,v.contacts[0])!="LAN4")fails++;
            if(std::string(m)=="lan6"&&contact_method(v,v.contacts[0])!="LAN6")fails++;
            if(std::string(m)=="direct4"&&contact_method(v,v.contacts[0])!="DIRECT4")fails++;
            if(std::string(m)=="direct6"&&contact_method(v,v.contacts[0])!="DIRECT6")fails++;
        }
        // Every operation message is checked at maximum progress, independently of live backends.
        for(auto&entry:ui_operation_keys){State op=demo;op.operation_state="working";op.operation_message=entry;op.operation_detail="100";Canvas c;render(c,"operation",op);check(c,"operation-"+entry);}
        for(int issue=0;issue<6;issue++){Canvas c;render(c,"support",diagnostic_fixture(demo,issue));check(c,"diagnostic-"+std::to_string(issue));}
        Canvas first,last;max.cursor=0;render(first,"home",max);max.cursor=505;render(last,"home",max);cases++;
        if(first.p.size()!=last.p.size()||std::memcmp(first.p.data(),last.p.data(),first.p.size()*sizeof(RGB)))fails++;
    }
    language=0;
    cases+=5;
    if(spec("contacts",demo).buttons[1].short_action!=Action::PairStart||spec("contacts",demo).buttons[2].short_action!=Action::AddStart)fails++;
    if(spec("integrity_verify",demo).buttons[3].short_action!=Action::IntegrityState)fails++;
    if(spec("language",demo).buttons[2].short_action!=Action::LanguageTry||spec("language",demo).buttons[3].long_action!=Action::LanguageSave)fails++;
    if(factory_intent("READY",2,"short")!=FactoryIntent::None||factory_intent("READY",2,"long")!=FactoryIntent::Install)fails++;
    Canvas black;render_factory(black,{{"STATE","REBOOTING"}});if(!std::all_of(black.p.begin(),black.p.end(),[](RGB p){return !p.r&&!p.g&&!p.b;}))fails++;
    std::cout<<"UI_TEST cases="<<cases<<" pages="<<page_ids().size()<<" languages=3 min-font-px=16 fails="<<fails<<"\n";return fails?1:0;
}
static int render_dir(const std::string&dir){
    int fails=0,files=0;State s=demo_state();
    for(language=0;language<3;language++){
        std::string root=dir+"/"+lang_code(language);fs::create_directories(root);
        auto save=[&](Canvas&c,const std::string&raw){std::string name=raw;for(char&ch:name)if(!std::isalnum((unsigned char)ch)&&ch!='-'&&ch!='_')ch='-';files++;if(c.clipped||!c.errors.empty()||!c.ppm(root+"/"+name+".ppm"))fails++;
            std::ofstream f(root+"/"+name+".txt");for(auto&t:c.ink)f<<t.x<<","<<t.y<<","<<t.w<<","<<t.h<<" "<<t.value<<"\n";};
        for(auto&page:page_ids()){
            Canvas c;render(c,page,s);save(c,page);
            State maximum=s;maximum.contacts.clear();maximum.usb_model=std::string(128,'W');maximum.operation_detail="100";maximum.operation_message="SAVING CONNECTION";
            for(const auto&role:{"client","server"})for(int n=2;n<=254;n++){maximum.contacts.push_back({role,n,vc::connection_name(role,n),std::string(64,'f'),vc::dial_ip(role,n)});maximum.peer_modes[std::string(role)+"_"+std::to_string(n)]="holepunch6";}
            maximum.cursor=505;if(page=="result"){maximum.operation_state="failed";maximum.operation_message="STATE SAVE FAILED";}Canvas m;render(m,page,maximum);save(m,page+"-max");
        }
        for(auto state:{"READY","INSTALLING","FAILED","COMPLETE","RESTARTING","REBOOTING","LANGUAGE","POWERING_OFF"}){Canvas c;render_factory(c,{{"STATE",state},{"PROGRESS","91"},{"EXTERNAL_STATE_SHA256",s.external_sha},{"EXTERNAL_STATE_CODE",s.external_code}});save(c,std::string("factory-")+state);}
        for(const auto&entry:ui_operation_states){State v=s;v.operation_state=entry.first;v.operation_message=entry.second;v.operation_detail="100";Canvas c;render(c,entry.first=="working"?"operation":"result",v);save(c,"operation-"+entry.first+"-"+entry.second);}
        for(int issue=0;issue<6;issue++){Canvas c;render(c,"support",diagnostic_fixture(s,issue));save(c,"support-"+std::to_string(issue));}
        for(const auto&entry:ui_factory_states){const auto&state=entry.first;const auto&key=entry.second;Canvas c;render_factory(c,{{"STATE",state},{"PHASE",key},{"DETAIL",key},{"PROGRESS","100"}});save(c,std::string("factory-")+state+"-"+key);}
        for(int i=0;i<7;i++)for(bool on:{false,true}){State v=s;v.path_index=i;v.paths_available=on?vta::all():(i==6?"lan4":"tor");Canvas c;render(c,"paths",v);save(c,"path-"+std::to_string(i)+(on?"-on":"-off"));}
        for(const auto&m:{"lan4","lan6","direct4","direct6","holepunch4","holepunch6","tor"}){State v=s;v.peer_modes["client_2"]=m;Canvas c;render(c,"contact",v);save(c,std::string("contact-")+m);}
        for(int variant=0;variant<7;variant++){
            State v=s;std::string page="contact",name;
            if(variant==0){page="contacts";v.contacts.clear();name="empty";}
            if(variant==1){v.cursor=1;name="connecting";}
            if(variant==2){v.wan=false;v.cursor=1;name="offline";}
            if(variant==3){page="integrity_verify";v.integrity_state="calculating";v.os_progress=47;name="progress";}
            if(variant==4){page="integrity_verify";v.integrity_state="failure";name="failure";}
            if(variant==5){page="result";v.operation_state="failed";v.operation_message="STATE SAVE FAILED";name="save-failure";}
            if(variant==6){page="admin";v.admin_key=v.admin_ssh=false;name="no-key";}
            Canvas c;render(c,page,v);save(c,page+"-"+name);
        }
    }
    std::cout<<"UI_RENDER dir="<<dir<<" files="<<files<<" fails="<<fails<<"\n";return fails?1:0;
}
// Hardware verification mode: renders only, never dispatches product actions.
static int panel_test(){
    auto dev=display_device();if(dev.empty())return 1;
    ConsoleGuard console;console.acquire();Framebuffer fb;if(!fb.open_panel(dev))return 1;
    fb.unblank();State s=demo_state();int frames=0,fails=0;
    for(language=0;language<3;language++){
        for(auto&page:page_ids()){Canvas c;render(c,page,s);fb.show(c);frames++;if(!fb.matches(c)||c.clipped||!c.errors.empty())fails++;std::this_thread::sleep_for(std::chrono::milliseconds(100));}
        for(auto state:{"READY","INSTALLING","FAILED","COMPLETE","RESTARTING","REBOOTING","LANGUAGE","POWERING_OFF"}){Canvas c;render_factory(c,{{"STATE",state},{"PROGRESS","91"},{"EXTERNAL_STATE_SHA256",s.external_sha},{"EXTERNAL_STATE_CODE",s.external_code}});fb.show(c);frames++;if(!fb.matches(c)||c.clipped||!c.errors.empty())fails++;}
    }
    for(language=0;language<3;language++)for(auto page:{"home","contact"}){
        Canvas c;render(c,page,s);fb.show(c);std::cout<<"PANEL_SAMPLE "<<lang_code(language)<<" "<<page<<std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(12));
    }
    std::cout<<"PANEL_TEST device="<<dev<<" size="<<fb.width()<<"x"<<fb.height()<<" bpp="<<fb.bpp()<<" frames="<<frames<<" fails="<<fails<<std::endl;return fails?1:0;
}
static void render_ssh(const std::string&page,const State&s){
    PageSpec p=spec(page,s);std::cout<<tr(p.title)<<"\n"<<tr(failure_reason(s))<<"\n";
    if(page=="admin_new_confirm"){
        std::cout<<tr(s.admin_key?"REPLACE LOGIN KEY?":"CREATE LOGIN KEY?")<<"\n";
        if(s.admin_key)std::cout<<tr("OLD KEY WILL")<<" "<<tr("STOP WORKING")<<"\n";
    }
    if(page=="restore_confirm")std::cout<<tr("RESTORE BACKUP?")<<"\n"<<tr("REPLACES SETTINGS")<<"\n"<<tr("RESTART REQUIRED")<<"\n";
    if(page=="restore_ready")std::cout<<tr("RESTART TO APPLY")<<"\n";
    if(page=="state_updated")std::cout<<tr("WRITE THIS DOWN")<<"\n";
    if(page=="contact"&&!s.contacts.empty()){auto x=selected_contact(s);std::cout<<x.name<<"  DIAL "<<x.dial_ip<<"\n";}
    if(page=="paths")for(size_t i=0;i<vta::TOKENS.size();i++)
        std::cout<<(i==(size_t)s.path_index?"> ":"  ")<<vta::LABELS[i]<<"  "
                 <<(vta::available(s.paths_available,vta::TOKENS[i])?"ON":"OFF")<<"\n";
    for(int i=0;i<4;i++)if(!p.buttons[i].label.empty())std::cout<<"B"<<i+1<<" "<<p.buttons[i].label<<"  ";
    std::cout<<"\nSYS "<<(s.integrity_state=="match"?"MATCH":upper(s.integrity_state))<<"  USER "<<(s.user_integrity.empty()?"AWAITING DECISION":upper(s.user_integrity))<<"\n";
    std::cout<<"BOOT "<<s.boot_code<<"\nSYSTEM "<<s.system_code<<"\nCOMBINED "<<s.combined_code<<"\nSTATE "<<s.external_code<<"\n";
}

static PageSpec factory_spec(const std::string&state){
    if(state=="LANGUAGE")return {"factory","LANGUAGE",{b("BACK",Action::None),b("NEXT",Action::None),b("TRY",Action::None),blank()}};
    if(state=="POWERING_OFF")return {"factory","POWERING OFF",{blank(),blank(),blank(),blank()}};
    if(state=="RESTARTING"||state=="REBOOTING")return {"factory","RESTARTING",{blank(),blank(),blank(),blank()}};
    if(state=="COMPLETE")return {"factory","INSTALL COMPLETE",{blank(),blank(),blank(),b("REBOOT",Action::None,Action::None,GREEN)}};
    if(state=="FAILED")return {"factory","INSTALL FAILED",{hold("POWER",Action::None,RED),hold("RETRY",Action::None,ORANGE),b("LANGUAGE",Action::None),blank()}};
    if(state=="INSTALLING")return {"factory","INSTALLING",{blank(),blank(),blank(),blank()}};
    return {"factory","INSTALL VOIDER",{hold("POWER",Action::None,RED),hold("INSTALL",Action::None,GREEN),b("LANGUAGE",Action::None),blank()}};
}
static void render_factory(Canvas&c,const std::map<std::string,std::string>&f){
    std::string state=f.count("STATE")?f.at("STATE"):"READY";
    if(state=="REBOOTING"){c.clear(OFF);return;}
    State none;auto p=factory_spec(state);c.clear(CREAM);header(c,p.title,none);
    if(state=="LANGUAGE"){
        static const std::array<std::string,3> names={"English","Deutsch","Български"};
        line(c,12,70,296,80,names[read1("/run/voider/ui.language.choice").empty()?language:lang_index(read1("/run/voider/ui.language.choice"))],40,BLUE);buttons(c,p);return;
    }
    if(state=="POWERING_OFF"){message(c,"PLEASE WAIT",NAVY);return;}
    if(state=="INSTALLING"){
        std::string phase=f.count("PHASE")?f.at("PHASE"):"PLEASE WAIT";
        message(c,ui_strings.count(phase)&&phase!=p.title?phase:"PLEASE WAIT",YELLOW);int progress=f.count("PROGRESS")?std::clamp(atoi(f.at("PROGRESS").c_str()),0,100):0;
        line(c,12,165,296,30,std::to_string(progress)+"%",24,NAVY);
    }else if(state=="FAILED"){std::string detail=f.count("DETAIL")?f.at("DETAIL"):"FAILED";message(c,ui_strings.count(detail)?detail:"FAILED",RED);}
    else if(state=="COMPLETE"){
        if(f.count("DETAIL")&&f.at("DETAIL")=="REBOOT FAILED")message(c,"REBOOT FAILED",RED);
        else{auto u=fields("/run/voider/state-updated.status");if(f.count("EXTERNAL_STATE_CODE"))u=f;digest_seal(c,u["EXTERNAL_STATE_SHA256"],u["EXTERNAL_STATE_CODE"]);}
    }else if(state=="RESTARTING")message(c,"PLEASE WAIT",NAVY);
    else message(c,"OFFLINE SETUP",BLUE);
    buttons(c,p);
}
static void show_factory_transition(const std::string&state){
    std::string dev=display_device();if(dev.empty())return;
    Framebuffer fb;if(!fb.open_panel(dev))return;
    if(state!="REBOOTING")fb.unblank();
    auto status=fields("/run/voider/factory-install.status");status["STATE"]=state;
    Canvas c;render_factory(c,status);fb.show(c);
    if(state=="REBOOTING")fb.blank();
}
static int factory_button_event(int number,const std::string&kind){
    if(number<1||number>4||(kind!="short"&&kind!="long"))return 2;
    ButtonLock lock;if(!lock.held())return 2;
    auto f=fields("/run/voider/factory-install.status");std::string state=f["STATE"];
    if(fs::exists("/run/voider/factory-language")){
        if(kind!="short")return 0;
        if(number==1)fs::remove("/run/voider/factory-language");
        if(number==2)write1("/run/voider/ui.language.choice",lang_code((lang_index(read1("/run/voider/ui.language.choice"))+1)%3));
        if(number==3)write1("/run/voider/ui.language",lang_code(lang_index(read1("/run/voider/ui.language.choice"))));
        return 0;
    }
    if(number==3&&kind=="short"&&(state=="READY"||state=="FAILED")){
        write1("/run/voider/ui.language.choice",lang_code(language));write1("/run/voider/factory-language","1");return 0;
    }
    FactoryIntent intent=factory_intent(state,number,kind);
    if(intent==FactoryIntent::Reboot){
        write_fields("/run/voider/factory-install.status",{{"STATE","RESTARTING"},{"PHASE","RESTARTING"}});
        show_factory_transition("RESTARTING");
        std::this_thread::sleep_for(std::chrono::milliseconds(900));
        write_fields("/run/voider/factory-install.status",{{"STATE","REBOOTING"},{"PHASE","REBOOTING"}});
        show_factory_transition("REBOOTING");
        std::this_thread::sleep_for(std::chrono::milliseconds(600));
        int rc=command_status("/sbin/reboot");
        if(rc){f["DETAIL"]="REBOOT FAILED";write_fields("/run/voider/factory-install.status",f);show_factory_transition("COMPLETE");}
        return rc;
    }
    if(intent==FactoryIntent::Poweroff){
        write_fields("/run/voider/factory-install.status",{{"STATE","POWERING_OFF"}});show_factory_transition("POWERING_OFF");
        std::this_thread::sleep_for(std::chrono::milliseconds(900));blank_display();int rc=command_status("/sbin/poweroff");
        if(rc){fs::remove("/run/voider/display-blank");write_fields("/run/voider/factory-install.status",f);}return rc;
    }
    if(intent==FactoryIntent::Install){
        write_fields("/run/voider/factory-install.status",{{"STATE","INSTALLING"},{"PHASE","STARTING"},{"PROGRESS","0"}});
        const char*cmd=fs::exists("/usr/local/bin/install")?"/usr/local/bin/install --display":"/usr/local/sbin/voider-install --display";
        int rc=command_status(std::string(cmd)+" >/run/voider/factory-install.log 2>&1");
        if(rc&&fields("/run/voider/factory-install.status")["STATE"]!="FAILED")write_fields("/run/voider/factory-install.status",{{"STATE","FAILED"},{"DETAIL","SEE INSTALL LOG"}});
        return rc;
    }
    return 0;
}
static int factory_display(bool loop){
    std::string dev=display_device();if(dev.empty())return 1;ConsoleGuard console;console.acquire();Framebuffer fb;if(!fb.open_panel(dev))return 1;
    do{load_language();Canvas c;auto f=fields("/run/voider/factory-install.status");if(fs::exists("/run/voider/factory-language"))f["STATE"]="LANGUAGE";
        if(fs::exists("/run/voider/display-blank")){c.clear(OFF);fb.show(c);fb.blank();}else{render_factory(c,f);fb.unblank();fb.show(c);}if(loop)std::this_thread::sleep_for(std::chrono::seconds(1));}while(loop);return 0;
}

int main(int ac,char**av){
    C=cfg();load_language();std::string mode="ssh",page,render_path;bool loop=false,probe=false,console_probe=false,test=false,factory=false,blank=false;
    for(int i=1;i<ac;i++){
        std::string a=av[i];if(a=="--display")mode="display";else if(a=="--ssh")mode="ssh";else if(a=="--loop")loop=true;
        else if(a=="--factory-display")factory=true;else if(a=="--factory-button"&&i+2<ac){int n=atoi(av[++i]);return factory_button_event(n,av[++i]);}
        else if(a=="--panel-test")return panel_test();else if(a=="--display-probe")probe=true;else if(a=="--console-probe")console_probe=true;else if(a=="--blank")blank=true;else if(a=="--selftest")test=true;else if(a=="--page"&&i+1<ac)page=av[++i];
        else if(a=="--render-dir"&&i+1<ac)render_path=av[++i];else if(a=="--button"&&i+2<ac){int n=atoi(av[++i]);return button_event(n,av[++i]);}
        else if(a=="--buttons"){State s=snapshot();std::string p=read1(C.ui_page_file);if(p.empty())p="home";auto x=spec(p,s);for(int n=0;n<4;n++)std::cout<<"B"<<n+1<<" "<<(x.buttons[n].label.empty()?"unused":x.buttons[n].label)<<"\n";return 0;}
    }
    if(test)return selftest();
    if(blank)return blank_display();
    if(!render_path.empty())return render_dir(render_path);
    std::string dev=display_device();if(probe){if(dev.empty()){std::cout<<"DISPLAY_NONE\n";return 1;}Framebuffer fb;if(!fb.open_panel(dev)){std::cout<<"DISPLAY_UNUSABLE "<<dev<<"\n";return 1;}std::cout<<"DISPLAY_FOUND "<<dev<<" "<<fb.width()<<"x"<<fb.height()<<" "<<fb.bpp()<<"bpp\n";return 0;}
    if(console_probe){
        if(dev.empty()){std::cout<<"CONSOLE_NO_DISPLAY\n";return 1;}
        ConsoleGuard console;console.acquire();
        if(console.count()<2||!console.graphics()){std::cout<<"CONSOLE_GRAPHICS_FAILED count="<<console.count()<<"\n";return 1;}
        std::cout<<"CONSOLE_GRAPHICS count="<<console.count()<<"\n";return 0;
    }
    if(factory)return factory_display(loop);
    State s=snapshot();if(page.empty())page=read1(C.ui_page_file);page=visible_page(s,page);
    if(mode!="display"){render_ssh(page,s);return 0;}if(dev.empty()){std::cerr<<"DISPLAY_ERROR no supported physical panel\n";return 1;}
    ConsoleGuard console;console.acquire();
    Framebuffer fb;if(!fb.open_panel(dev)){std::cerr<<"DISPLAY_ERROR cannot open "<<dev<<"\n";return 1;}
    do{load_language();State now=snapshot();std::string current=read1(C.ui_page_file);current=visible_page(now,current.empty()?page:current);Canvas canvas;if(fs::exists("/run/voider/display-blank")){canvas.clear(OFF);fb.show(canvas);fb.blank();}else{render(canvas,current,now);fb.unblank();fb.show(canvas);}if(loop)std::this_thread::sleep_for(std::chrono::seconds(std::max(1,C.ui_refresh)));}while(loop);
    return 0;
}
