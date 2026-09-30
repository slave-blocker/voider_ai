// voider-nfqd: SIP packet normalizer on NFQUEUE.
//
// This daemon is intentionally narrow: it only touches SIP control packets.
// RTP/media packets are routed/NATed by kernel rules and should not pass
// through userspace. Incoming peer SIP packets are rewritten so the phone sees
// the per-boot fake peer IP. Outgoing phone SIP packets addressed to a fake IP
// are routed back to the real per-slot WireGuard/tundup peer address.
//
// Imported-server netns mode is also SIP-only and stateless: it replaces the
// old conntrack NAT dependency for SIP inside netnsX. RTP still follows the
// existing kernel forwarding/NAT path.
//
// fix17: checksum helpers return host-order values; store IPv4/UDP checksums in network byte order.
// fix10: SIP rewrite may change payload length. We therefore rebuild the IPv4
// packet, fix Content-Length, IPv4 total length, UDP length, IPv4 checksum, and
// UDP checksum before returning the modified packet to NFQUEUE.
//
// fix11: default-namespace incoming SIP normalization now also rewrites every
// SIP payload occurrence of the real incoming call-plane source address
// (for example 172.29.X.1) to the per-boot fake phone-visible peer IP. Without
// this, some phones display the real 172.29.X.1 identity from Contact/Via/SDP
// even though the IPv4 header source was already normalized.

//
// fix19: default-namespace phone_out now handles SIP responses as well as
// requests. Phone responses use source port 5060 and destination ephemeral
// caller ports, so queue 12 and route_phone_out() must accept sport 5060.
// For clients-of-us, route_phone_out() also rewrites matching SIP payload
// addresses before rebuilding the packet.
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <regex>
#include <string>
#include <vector>

#include "voider_config.hpp"

static Cfg C;
static int NS_X = 0;
static int NS_S = 0;

struct RewriteResult {
    bool changed = false;
    std::vector<uint8_t> packet;
};

static bool is_sip(const std::string& s) {
    return s.find("SIP/2.0") != std::string::npos ||
           s.rfind("INVITE ", 0) == 0 ||
           s.rfind("ACK ", 0) == 0 ||
           s.rfind("BYE ", 0) == 0 ||
           s.rfind("CANCEL ", 0) == 0 ||
           s.rfind("OPTIONS ", 0) == 0 ||
           s.rfind("REGISTER ", 0) == 0;
}

static uint16_t csum(const void* d, size_t n) {
    uint64_t s = 0;
    const uint8_t* p = static_cast<const uint8_t*>(d);

    while (n > 1) {
        s += (uint16_t(p[0]) << 8) | uint16_t(p[1]);
        p += 2;
        n -= 2;
    }

    if (n) {
        s += uint16_t(p[0]) << 8;
    }

    while (s >> 16) {
        s = (s & 0xffff) + (s >> 16);
    }

    return uint16_t(~s);
}

static uint32_t sum16_add(uint32_t s, const uint8_t* p, size_t n) {
    while (n > 1) {
        s += (uint16_t(p[0]) << 8) | uint16_t(p[1]);
        p += 2;
        n -= 2;
    }

    if (n) {
        s += uint16_t(p[0]) << 8;
    }

    return s;
}

static uint16_t udp4_checksum(const iphdr* ip, const udphdr* udp,
                              const uint8_t* payload, size_t payload_len) {
    uint32_t s = 0;
    uint32_t src = ntohl(ip->saddr);
    uint32_t dst = ntohl(ip->daddr);
    uint16_t udp_len = ntohs(udp->len);

    s += (src >> 16) & 0xffff;
    s += src & 0xffff;
    s += (dst >> 16) & 0xffff;
    s += dst & 0xffff;
    s += IPPROTO_UDP;
    s += udp_len;

    s = sum16_add(s, reinterpret_cast<const uint8_t*>(udp), sizeof(udphdr));
    s = sum16_add(s, payload, payload_len);

    while (s >> 16) {
        s = (s & 0xffff) + (s >> 16);
    }

    uint16_t r = uint16_t(~s);
    return r ? r : 0xffff;
}

static std::string repl(std::string s, const std::string& a, const std::string& b) {
    for (size_t p = 0; !a.empty() && (p = s.find(a, p)) != std::string::npos; p += b.size()) {
        s.replace(p, a.size(), b);
    }
    return s;
}

static std::string clen(std::string s) {
    size_t p = s.find("\r\n\r\n");
    size_t sep_len = 4;

    if (p == std::string::npos) {
        p = s.find("\n\n");
        sep_len = 2;
    }

    if (p == std::string::npos) {
        return s;
    }

    size_t body_len = s.size() - p - sep_len;
    std::regex r("Content-Length:\\s*[0-9]+", std::regex_constants::icase);
    return std::regex_replace(
        s,
        r,
        "Content-Length: " + std::to_string(body_len),
        std::regex_constants::format_first_only);
}

static bool parse_udp4(uint8_t* p, int len, iphdr*& ip, udphdr*& udp,
                       uint8_t*& pay, int& ihl, int& plen) {
    if (len < static_cast<int>(sizeof(iphdr))) {
        return false;
    }

    ip = reinterpret_cast<iphdr*>(p);
    if (ip->version != 4 || ip->protocol != IPPROTO_UDP) {
        return false;
    }

    ihl = ip->ihl * 4;
    if (ihl < static_cast<int>(sizeof(iphdr)) || len < ihl + static_cast<int>(sizeof(udphdr))) {
        return false;
    }

    udp = reinterpret_cast<udphdr*>(p + ihl);
    int udp_len = ntohs(udp->len);
    if (udp_len < static_cast<int>(sizeof(udphdr)) || ihl + udp_len > len) {
        return false;
    }

    pay = p + ihl + sizeof(udphdr);
    plen = udp_len - sizeof(udphdr);
    return plen > 0;
}

static RewriteResult build_udp4(uint8_t* oldp, int old_len,
                                const std::string& new_payload,
                                const std::string& new_src,
                                const std::string& new_dst) {
    RewriteResult rr;

    iphdr* old_ip = nullptr;
    udphdr* old_udp = nullptr;
    uint8_t* old_pay = nullptr;
    int ihl = 0;
    int old_plen = 0;

    if (!parse_udp4(oldp, old_len, old_ip, old_udp, old_pay, ihl, old_plen)) {
        return rr;
    }

    size_t new_udp_len = sizeof(udphdr) + new_payload.size();
    size_t new_total = size_t(ihl) + new_udp_len;
    if (new_total > 65535) {
        return rr;
    }

    rr.packet.assign(new_total, 0);
    std::memcpy(rr.packet.data(), oldp, ihl + sizeof(udphdr));

    iphdr* ip = reinterpret_cast<iphdr*>(rr.packet.data());
    udphdr* udp = reinterpret_cast<udphdr*>(rr.packet.data() + ihl);
    uint8_t* pay = rr.packet.data() + ihl + sizeof(udphdr);

    std::memcpy(pay, new_payload.data(), new_payload.size());

    if (inet_pton(AF_INET, new_src.c_str(), &ip->saddr) != 1) {
        return RewriteResult{};
    }
    if (inet_pton(AF_INET, new_dst.c_str(), &ip->daddr) != 1) {
        return RewriteResult{};
    }

    ip->tot_len = htons(static_cast<uint16_t>(new_total));
    udp->len = htons(static_cast<uint16_t>(new_udp_len));

    ip->check = 0;
    ip->check = htons(csum(ip, ihl));

    udp->check = 0;
    udp->check = htons(udp4_checksum(ip, udp, pay, new_payload.size()));

    rr.changed = true;
    return rr;
}

static std::string ip_to_string(uint32_t addr) {
    char out[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &addr, out, sizeof(out));
    return out;
}

static std::string fake_for_src(const char* src) {
    unsigned a, b, c, d;
    if (sscanf(src, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
        return "";
    }
    if (a == 10 && c == 1 && d == 1) {
        return fake_ip(C, "server", static_cast<int>(b));
    }
    if (a == 172 && b == 29 && d == 1) {
        return fake_ip(C, "client", static_cast<int>(c));
    }
    return "";
}

// Peer -> phone direction: expose only the fake per-boot identity to the phone.
static RewriteResult normalize_in(uint8_t* p, int len) {
    RewriteResult rr;

    iphdr* ip = nullptr;
    udphdr* udp = nullptr;
    uint8_t* pay = nullptr;
    int ihl = 0;
    int plen = 0;
    if (!parse_udp4(p, len, ip, udp, pay, ihl, plen)) {
        return rr;
    }

    std::string sip(reinterpret_cast<char*>(pay), plen);
    if (!is_sip(sip)) {
        return rr;
    }

    std::string src = ip_to_string(ip->saddr);
    std::string fake = fake_for_src(src.c_str());
    if (fake.empty()) {
        return rr;
    }

    // Header source is rewritten to the fake phone-visible peer IP below.
    // The SIP payload must be normalized the same way, otherwise phones can
    // still display the real call-plane identity from headers such as Via,
    // Contact, Record-Route, or SDP connection/origin lines. This was observed
    // with server-side incoming SIP from 172.29.X.1 where the phone displayed
    // 172.29.2.1 as the caller even though the packet IP header was rewritten.
    std::string out = sip;
    out = repl(out, src, fake);
    out = repl(out, C.phone_ip, fake);
    out = clen(out);
    return build_udp4(p, len, out, fake, C.phone_ip);
}

// Phone -> peer direction: convert the dialed fake IP back to the real slot path.
static RewriteResult route_phone_out(uint8_t* p, int len) {
    RewriteResult rr;

    iphdr* ip = nullptr;
    udphdr* udp = nullptr;
    uint8_t* pay = nullptr;
    int ihl = 0;
    int plen = 0;
    if (!parse_udp4(p, len, ip, udp, pay, ihl, plen)) {
        return rr;
    }

    // Phone-originated SIP requests usually have dport 5060:
    //   phone:ephemeral -> fake-peer:5060
    // Phone-originated SIP responses have sport 5060:
    //   phone:5060 -> fake-caller:ephemeral
    // Both are phone_out and both must be rewritten toward the tunnel.
    bool sip_request_shape = ntohs(udp->dest) == C.sip;
    bool sip_response_shape = ntohs(udp->source) == C.sip;
    if (!sip_request_shape && !sip_response_shape) {
        return rr;
    }

    std::string sip(reinterpret_cast<char*>(pay), plen);
    if (!is_sip(sip)) {
        return rr;
    }

    std::string dst = ip_to_string(ip->daddr);
    unsigned a, b, c, d;
    if (sscanf(dst.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
        return rr;
    }

    std::string nd;
    std::string ns;
    int sc = slot_from_fake_ip(C, "client", dst);
    int ss = slot_from_fake_ip(C, "server", dst);
    bool rewrite_payload_here = false;

    if (a == 10 && b == 1 && d == 1) {
        nd = "172.29." + std::to_string(c) + ".1";
        ns = "172.29.1.1";
        rewrite_payload_here = true;
    } else if (a == 10 && c == 1 && d == 1) {
        // Direct dialing 10.X.1.1 is already the local server-slot handoff.
        // Keep it unchanged: this is intentionally a no-op in the default namespace.
        return rr;
    } else if (sc >= 2) {
        // Server-side clients-of-us path. There is no per-client netns rewrite
        // after this point, so both IP headers and SIP payload must be changed
        // here. This covers responses such as 200 OK/BYE from phone:5060 to
        // fake-client:ephemeral as well as request-shaped packets.
        nd = "172.29." + std::to_string(sc) + ".1";
        ns = "172.29.1.1";
        rewrite_payload_here = true;
    } else if (ss >= 2) {
        // Imported-server path. Map IP headers to the local netns handoff;
        // the netns worker performs the final SIP payload rewrite using the
        // imported server-assigned index s. Do not collapse X and s here.
        nd = "10." + std::to_string(ss) + ".1.1";
        ns = C.phone_ip;
        rewrite_payload_here = false;
    }

    if (nd.empty() || ns.empty()) {
        return rr;
    }

    std::string out = sip;
    if (rewrite_payload_here) {
        out = repl(out, C.phone_ip, ns);
        out = repl(out, dst, nd);
        out = clen(out);
    }
    return build_udp4(p, len, out, ns, nd);
}

// Imported-server netnsX SIP translator.
//
// This is intentionally not iptables NAT. The packet is already NOTRACK in the
// netns raw table. We rewrite IP headers and SIP body deterministically before
// the netns routing decision:
//
// outbound: phone -> 10.X.1.1 becomes 172.29.s.1 -> 172.29.1.1
// inbound: 172.29.1.1 -> 172.29.s.1 becomes fake-server-IP -> phone
static RewriteResult netns_server_rewrite(uint8_t* p, int len) {
    RewriteResult rr;

    if (NS_X < 2 || NS_X > 254 || NS_S < 2 || NS_S > 254) {
        return rr;
    }

    iphdr* ip = nullptr;
    udphdr* udp = nullptr;
    uint8_t* pay = nullptr;
    int ihl = 0;
    int plen = 0;
    if (!parse_udp4(p, len, ip, udp, pay, ihl, plen)) {
        return rr;
    }

    std::string sip(reinterpret_cast<char*>(pay), plen);
    if (!is_sip(sip)) {
        return rr;
    }

    std::string src = ip_to_string(ip->saddr);
    std::string dst = ip_to_string(ip->daddr);
    std::string x = std::to_string(NS_X);
    std::string sidx = std::to_string(NS_S);

    std::string handoff = "10." + x + ".1.1";
    std::string remote = "172.29.1.1";
    std::string natid = "172.29." + sidx + ".1";
    std::string fake = fake_ip(C, "server", NS_X);

    std::string nsrc;
    std::string ndst;
    std::string out = sip;

    bool outbound = src == C.phone_ip && dst == handoff;
    bool inbound = src == remote && dst == natid;

    if (outbound) {
        nsrc = natid;
        ndst = remote;
        out = repl(out, C.phone_ip, natid);
        out = repl(out, fake, remote);
        out = repl(out, handoff, remote);
    } else if (inbound) {
        nsrc = fake.empty() ? handoff : fake;
        ndst = C.phone_ip;
        // Inbound imported-server SIP is delivered to the real phone IP in the
        // IPv4 header, but the SIP called identity must remain the logical
        // client/cert identity 172.29.s.1. Rewriting Request-URI/To from
        // 172.29.s.1 to 172.16.19.85 makes the phone see a self/local target
        // and can cause direct-IP phones to ignore the INVITE. Only the remote
        // caller identity is hidden behind the per-boot fake server IP.
        out = repl(out, remote, nsrc);
        out = repl(out, handoff, nsrc);
    } else {
        return rr;
    }

    out = clen(out);
    return build_udp4(p, len, out, nsrc, ndst);
}

static int cb(nfq_q_handle* qh, nfgenmsg*, nfq_data* nfa, void* d) {
    int kind = *static_cast<int*>(d);
    auto* h = nfq_get_msg_packet_hdr(nfa);
    uint32_t id = h ? ntohl(h->packet_id) : 0;

    unsigned char* p = nullptr;
    int l = nfq_get_payload(nfa, &p);

    if (l >= 0) {
        RewriteResult rr;
        if (kind == 4) {
            rr = netns_server_rewrite(p, l);
        } else if (kind == 3) {
            rr = route_phone_out(p, l);
        } else {
            rr = normalize_in(p, l);
        }

        if (rr.changed) {
            return nfq_set_verdict(
                qh,
                id,
                NF_ACCEPT,
                static_cast<uint32_t>(rr.packet.size()),
                rr.packet.data());
        }
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
}

int main(int ac, char** av) {
    C = cfg();

    if (ac > 1 && !strcmp(av[1], "--self-test")) {
        puts("OK");
        return 0;
    }

    bool netns_server = false;
    int netns_queue = 0;

    if (ac > 3 && !strcmp(av[1], "--netns-server")) {
        NS_X = atoi(av[2]);
        NS_S = atoi(av[3]);
        netns_queue = 1000 + NS_X;
        netns_server = true;
    }

    auto* h = nfq_open();
    if (!h) {
        return 1;
    }

    nfq_unbind_pf(h, AF_INET);
    if (nfq_bind_pf(h, AF_INET) < 0) {
        return 1;
    }

    int client = 1;
    int phone = 3;
    int netns = 4;

    nfq_q_handle* q1 = nullptr;
    nfq_q_handle* q3 = nullptr;
    nfq_q_handle* qn = nullptr;

    if (netns_server) {
        qn = nfq_create_queue(h, netns_queue, cb, &netns);
        if (!qn) {
            return 2;
        }
        nfq_set_mode(qn, NFQNL_COPY_PACKET, 0xffff);
    } else {
        // Imported-server SIP belongs to its netns worker. Only client-in and
        // phone-out rules feed the default-namespace daemon.
        q1 = nfq_create_queue(h, C.qc, cb, &client);
        q3 = nfq_create_queue(h, C.qp, cb, &phone);
        if (!q1 || !q3) {
            return 2;
        }
        nfq_set_mode(q1, NFQNL_COPY_PACKET, 0xffff);
        nfq_set_mode(q3, NFQNL_COPY_PACKET, 0xffff);
    }

    int fd = nfq_fd(h);
    std::vector<char> buf(65536);

    while (true) {
        int r = recv(fd, buf.data(), buf.size(), 0);
        if (r >= 0) {
            nfq_handle_packet(h, buf.data(), r);
        }
    }
}
