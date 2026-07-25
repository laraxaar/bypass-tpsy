#include "dns_proxy.h"
#include "logger.h"
#include "stats.h"
#include <winhttp.h>
#include <ws2tcpip.h>
#include <sstream>

#pragma comment(lib, "winhttp.lib")

DnsProxy::DnsProxy(const Config& cfg) : cfg_(cfg) {
    std::string doh_url = cfg.GetString("dns", "upstream", "https://cloudflare-dns.com/dns-query");
    ParseDoHUrl(doh_url);
}

DnsProxy::~DnsProxy() {}

void DnsProxy::ParseDoHUrl(const std::string& url) {
    std::string prefix = "https://";
    if (url.compare(0, prefix.size(), prefix) != 0) {
        throw std::runtime_error("Invalid DNS DoH upstream URL: must be HTTPS");
    }

    std::string remaining = url.substr(prefix.size());
    size_t slash = remaining.find('/');
    if (slash == std::string::npos) {
        doh_host_ = remaining;
        doh_path_ = "/";
    } else {
        doh_host_ = remaining.substr(0, slash);
        doh_path_ = remaining.substr(slash);
    }
    LOG_INFO2("DNS proxy configured DoH", "Host=" + doh_host_ + ", Path=" + doh_path_);
}

std::optional<std::string> DnsProxy::ParseDnsQuestion(const uint8_t* dns_payload, uint32_t len, uint16_t& out_tx_id) {
    if (len < 12) {
        LOG_TRACE2("[DNS-PARSE] Payload too short for DNS header. Size", std::to_string(len));
        return std::nullopt;
    }

    out_tx_id = (dns_payload[0] << 8) | dns_payload[1];
    uint16_t flags = (dns_payload[2] << 8) | dns_payload[3];
    bool is_query = (flags & 0x8000) == 0;
    uint16_t qdcount = (dns_payload[4] << 8) | dns_payload[5];

    LOG_TRACE2("[DNS-PARSE] Parsing query packet header", 
        "TxID=0x" + std::to_string(out_tx_id) + ", Flags=0x" + std::to_string(flags) + 
        ", IsQuery=" + std::to_string(is_query) + ", QDCount=" + std::to_string(qdcount));

    if (!is_query || qdcount == 0) return std::nullopt;

    std::string domain = "";
    uint32_t pos = 12;
    while (pos < len) {
        uint8_t label_len = dns_payload[pos];
        if (label_len == 0) {
            pos += 1;
            break;
        }

        if ((label_len & 0xC0) == 0xC0) {
            LOG_TRACE("[DNS-PARSE] Compression pointer encountered in question (invalid format).");
            return std::nullopt; 
        }

        if (pos + 1 + label_len > len) {
            LOG_TRACE("[DNS-PARSE] Label length exceeds packet boundary.");
            return std::nullopt;
        }

        if (!domain.empty()) domain += ".";
        domain.append(reinterpret_cast<const char*>(dns_payload + pos + 1), label_len);
        pos += 1 + label_len;
    }

    if (pos + 4 > len) {
        LOG_TRACE("[DNS-PARSE] QTYPE/QCLASS fields missing.");
        return std::nullopt;
    }

    uint16_t qtype = (dns_payload[pos] << 8) | dns_payload[pos + 1];
    uint16_t qclass = (dns_payload[pos + 2] << 8) | dns_payload[pos + 3];
    
    LOG_TRACE2("[DNS-PARSE] Extracted target domain", 
        domain + " (QType=" + std::to_string(qtype) + ", QClass=" + std::to_string(qclass) + ")");

    if (qtype != 1) { 
        LOG_DEBUG2("[DNS-PARSE] Ignoring non-IPv4 (A) record request type", std::to_string(qtype));
        return std::nullopt;
    }

    return domain;
}

std::vector<uint8_t> DnsProxy::BuildDnsResponse(uint16_t tx_id, const std::string& name, const std::vector<uint32_t>& ips, uint32_t ttl) {
    std::vector<uint8_t> buf;
    buf.reserve(512);

    buf.push_back(static_cast<uint8_t>(tx_id >> 8));
    buf.push_back(static_cast<uint8_t>(tx_id & 0xFF));
    
    buf.push_back(0x81);
    buf.push_back(0x80);

    buf.push_back(0x00); buf.push_back(0x01);
    uint16_t ancount = static_cast<uint16_t>(ips.size());
    buf.push_back(static_cast<uint8_t>(ancount >> 8));
    buf.push_back(static_cast<uint8_t>(ancount & 0xFF));
    buf.push_back(0x00); buf.push_back(0x00);
    buf.push_back(0x00); buf.push_back(0x00);

    std::stringstream ss(name);
    std::string label;
    while (std::getline(ss, label, '.')) {
        buf.push_back(static_cast<uint8_t>(label.size()));
        buf.insert(buf.end(), label.begin(), label.end());
    }
    buf.push_back(0x00); 

    buf.push_back(0x00); buf.push_back(0x01);
    buf.push_back(0x00); buf.push_back(0x01);

    for (uint32_t ip : ips) {
        buf.push_back(0xC0); buf.push_back(0x0C);
        buf.push_back(0x00); buf.push_back(0x01);
        buf.push_back(0x00); buf.push_back(0x01);
        
        buf.push_back(static_cast<uint8_t>((ttl >> 24) & 0xFF));
        buf.push_back(static_cast<uint8_t>((ttl >> 16) & 0xFF));
        buf.push_back(static_cast<uint8_t>((ttl >> 8) & 0xFF));
        buf.push_back(static_cast<uint8_t>(ttl & 0xFF));

        buf.push_back(0x00); buf.push_back(0x04);

        buf.push_back(static_cast<uint8_t>((ip >> 24) & 0xFF));
        buf.push_back(static_cast<uint8_t>((ip >> 16) & 0xFF));
        buf.push_back(static_cast<uint8_t>((ip >> 8) & 0xFF));
        buf.push_back(static_cast<uint8_t>(ip & 0xFF));
    }

    return buf;
}

std::vector<uint8_t> DnsProxy::QueryDoH(const std::vector<uint8_t>& dns_wire_query) {
    std::vector<uint8_t> result;

    LOG_TRACE2("[DoH-HTTP] Open HTTP Session connection to upstream server", doh_host_);
    HINTERNET hSession = WinHttpOpen(L"bypass_tpsy/2.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return result;

    std::wstring host_w(doh_host_.begin(), doh_host_.end());
    HINTERNET hConnect = WinHttpConnect(hSession, host_w.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return result;
    }

    std::wstring path_w(doh_path_.begin(), doh_path_.end());
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path_w.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return result;
    }

    std::wstring headers = L"Content-Type: application/dns-message\r\nAccept: application/dns-message\r\n";
    WinHttpAddRequestHeaders(hRequest, headers.c_str(), static_cast<DWORD>(-1), WINHTTP_ADDREQ_FLAG_ADD);

    LOG_TRACE2("[DoH-HTTP-SEND] Sending secure HTTP query payload. Size", std::to_string(dns_wire_query.size()) + " bytes");
    
    BOOL sent = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, (LPVOID)dns_wire_query.data(), (DWORD)dns_wire_query.size(), (DWORD)dns_wire_query.size(), 0);
    if (sent && WinHttpReceiveResponse(hRequest, nullptr)) {
        DWORD size = 0;
        do {
            if (!WinHttpQueryDataAvailable(hRequest, &size)) break;
            if (size == 0) break;

            std::vector<char> buffer(size);
            DWORD read = 0;
            if (WinHttpReadData(hRequest, buffer.data(), size, &read)) {
                result.insert(result.end(), buffer.begin(), buffer.begin() + read);
            }
        } while (size > 0);
        LOG_TRACE2("[DoH-HTTP-RECV] DoH Response received from upstream server. Size", std::to_string(result.size()) + " bytes");
    } else {
        DWORD err = GetLastError();
        LOG_ERROR2("[DoH-HTTP-ERROR] WinHTTP DoH Request Failed", "Code " + std::to_string(err));
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return result;
}

std::vector<uint32_t> DnsProxy::ResolveNow(const std::string& hostname) {
    LOG_INFO2("[DNS-RESOLVE] Querying target domain via DoH", hostname);
    BypassStats::Get().dns_doh_queries++;

    std::vector<uint8_t> query_buf;
    query_buf.push_back(0x12); query_buf.push_back(0x34); // TxID
    query_buf.push_back(0x01); query_buf.push_back(0x00); // Standard recursion query
    query_buf.push_back(0x00); query_buf.push_back(0x01); // QDCOUNT = 1
    query_buf.push_back(0x00); query_buf.push_back(0x00);
    query_buf.push_back(0x00); query_buf.push_back(0x00);
    query_buf.push_back(0x00); query_buf.push_back(0x00);

    std::stringstream ss(hostname);
    std::string label;
    while (std::getline(ss, label, '.')) {
        query_buf.push_back(static_cast<uint8_t>(label.size()));
        query_buf.insert(query_buf.end(), label.begin(), label.end());
    }
    query_buf.push_back(0x00);

    query_buf.push_back(0x00); query_buf.push_back(0x01); // QTYPE A
    query_buf.push_back(0x00); query_buf.push_back(0x01); // QCLASS IN

    if (Logger::Get().GetLevel() <= LogLevel::Trace) {
        LOG_TRACE(Logger::HexDump(query_buf.data(), query_buf.size()));
    }

    std::vector<uint8_t> resp = QueryDoH(query_buf);
    if (resp.size() < 12) {
        LOG_WARN2("[DNS-RESOLVE] DoH upstream returned empty or truncated payload for domain", hostname);
        return {};
    }

    if (Logger::Get().GetLevel() <= LogLevel::Trace) {
        LOG_TRACE(Logger::HexDump(resp.data(), resp.size()));
    }

    uint16_t reply_code = resp[3] & 0x0F;
    if (reply_code != 0) {
        LOG_WARN2("[DNS-RESOLVE] DoH server returned error status code", std::to_string(reply_code) + " for " + hostname);
        return {};
    }

    uint16_t qdcount = (resp[4] << 8) | resp[5];
    uint16_t ancount = (resp[6] << 8) | resp[7];

    if (ancount == 0) {
        LOG_WARN2("[DNS-RESOLVE] DoH server returned 0 answers for domain", hostname);
        return {};
    }

    uint32_t pos = 12;
    for (int i = 0; i < qdcount; ++i) {
        while (pos < resp.size()) {
            uint8_t len = resp[pos];
            if (len == 0) {
                pos += 1;
                break;
            }
            if ((len & 0xC0) == 0xC0) {
                pos += 2;
                break;
            }
            pos += 1 + len;
        }
        pos += 4;
    }

    std::vector<uint32_t> resolved_ips;
    uint32_t min_ttl = 300;

    for (int i = 0; i < ancount && pos < resp.size(); ++i) {
        if ((resp[pos] & 0xC0) == 0xC0) {
            pos += 2;
        } else {
            while (pos < resp.size()) {
                uint8_t len = resp[pos];
                if (len == 0) {
                    pos += 1;
                    break;
                }
                pos += 1 + len;
            }
        }

        if (pos + 10 > resp.size()) break;

        uint16_t type = (resp[pos] << 8) | resp[pos + 1];
        uint32_t ttl = (resp[pos + 4] << 24) | (resp[pos + 5] << 16) | (resp[pos + 6] << 8) | resp[pos + 7];
        uint16_t rdlen = (resp[pos + 8] << 8) | resp[pos + 9];
        pos += 10;

        if (pos + rdlen > resp.size()) break;

        if (type == 1 && rdlen == 4) { 
            uint32_t ip = (resp[pos] << 24) | (resp[pos + 1] << 16) | (resp[pos + 2] << 8) | resp[pos + 3];
            resolved_ips.push_back(ip);
            if (ttl < min_ttl) min_ttl = ttl;
        }
        pos += rdlen;
    }

    if (!resolved_ips.empty()) {
        std::lock_guard lock(cache_mutex_);
        CacheEntry entry;
        entry.ips = resolved_ips;
        
        uint32_t refresh_interval = static_cast<uint32_t>(cfg_.GetInt("dns", "refresh_interval", 300));
        uint32_t actual_ttl = (refresh_interval > 0) ? refresh_interval : min_ttl;

        entry.expires = std::chrono::steady_clock::now() + std::chrono::seconds(actual_ttl);
        cache_[hostname] = entry;

        std::string ip_list = "";
        for (uint32_t ip : resolved_ips) {
            IN_ADDR in;
            in.S_un.S_addr = htonl(ip);
            char buf[16];
            inet_ntop(AF_INET, &in, buf, sizeof(buf));
            if (!ip_list.empty()) ip_list += ", ";
            ip_list += buf;
        }
        LOG_INFO2("[DNS-CACHE-ADD] Resolved target domain", hostname + " -> [" + ip_list + "], actual TTL=" + std::to_string(actual_ttl) + "s");
    }

    return resolved_ips;
}

std::vector<uint32_t> DnsProxy::GetCachedIPs(const std::string& hostname) const {
    std::lock_guard lock(cache_mutex_);
    auto it = cache_.find(hostname);
    if (it != cache_.end() && it->second.expires > std::chrono::steady_clock::now()) {
        LOG_TRACE2("[DNS-CACHE-HIT] Found active IP cache entry for domain", hostname);
        return it->second.ips;
    }
    return {};
}

std::vector<std::string> DnsProxy::GetCachedHosts() const {
    std::lock_guard lock(cache_mutex_);
    std::vector<std::string> hosts;
    for (const auto& [host, entry] : cache_) {
        hosts.push_back(host);
    }
    return hosts;
}

std::optional<std::vector<uint8_t>> DnsProxy::ProcessDnsPacket(const uint8_t* raw_packet, uint32_t len) {
    auto* ip = ParseIPv4(raw_packet, len);
    if (!ip) return std::nullopt;

    auto* udp = ParseUDP(ip, len);
    if (!udp || ntohs(udp->dst_port) != 53) return std::nullopt;

    auto payload = GetUDPPayload(ip, udp, len);
    if (payload.empty()) return std::nullopt;

    BypassStats::Get().dns_queries++;

    uint16_t tx_id = 0;
    auto opt_domain = ParseDnsQuestion(payload.data(), (uint32_t)payload.size(), tx_id);
    if (!opt_domain) return std::nullopt;

    std::string domain = *opt_domain;
    std::vector<uint32_t> ips;

    bool match = cfg_.MatchesHostFilter(domain);
    if (match) {
        LOG_DEBUG2("[DNS-MATCH] Intercepted DNS Query matches evasion filter list", domain);
        ips = GetCachedIPs(domain);
        if (ips.empty()) {
            ips = ResolveNow(domain);
        } else {
            BypassStats::Get().dns_cache_hits++;
        }
    } else {
        LOG_TRACE2("[DNS-PASSTHROUGH] DNS query does not match filter. Standard local resolution", domain);
        ips = GetCachedIPs(domain);
        if (ips.empty()) {
            ADDRINFOA hints{};
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_DGRAM;

            PADDRINFOA res = nullptr;
            if (getaddrinfo(domain.c_str(), nullptr, &hints, &res) == 0) {
                PADDRINFOA curr = res;
                while (curr) {
                    sockaddr_in* sin = reinterpret_cast<sockaddr_in*>(curr->ai_addr);
                    ips.push_back(ntohl(sin->sin_addr.S_un.S_addr));
                    curr = curr->ai_next;
                }
                freeaddrinfo(res);
                
                std::lock_guard lock(cache_mutex_);
                CacheEntry entry;
                entry.ips = ips;
                entry.expires = std::chrono::steady_clock::now() + std::chrono::seconds(60); 
                cache_[domain] = entry;
            }
        } else {
            BypassStats::Get().dns_cache_hits++;
        }
    }

    if (ips.empty()) {
        LOG_WARN2("[DNS-PROXY-ERROR] Unable to resolve IP addresses for query domain", domain);
        return std::nullopt;
    }

    std::vector<uint8_t> dns_resp_payload = BuildDnsResponse(tx_id, domain, ips, 300);

    uint32_t ip_hdr_len = 20;
    uint32_t udp_hdr_len = 8;
    uint32_t total_packet_len = ip_hdr_len + udp_hdr_len + (uint32_t)dns_resp_payload.size();

    std::vector<uint8_t> response_packet(total_packet_len, 0);

    IPv4Header* resp_ip = reinterpret_cast<IPv4Header*>(response_packet.data());
    resp_ip->version = 4;
    resp_ip->ihl = 5;
    resp_ip->tos = 0;
    resp_ip->total_length = htons(static_cast<uint16_t>(total_packet_len));
    resp_ip->identification = ip->identification; 
    resp_ip->flags_fragment = 0;
    resp_ip->ttl = 64;
    resp_ip->protocol = 17; 
    
    resp_ip->src_addr = ip->dst_addr;
    resp_ip->dst_addr = ip->src_addr;

    UDPHeader* resp_udp = reinterpret_cast<UDPHeader*>(response_packet.data() + ip_hdr_len);
    resp_udp->src_port = udp->dst_port; 
    resp_udp->dst_port = udp->src_port;
    resp_udp->length = htons(static_cast<uint16_t>(udp_hdr_len + dns_resp_payload.size()));
    resp_udp->checksum = 0; 

    std::memcpy(response_packet.data() + ip_hdr_len + udp_hdr_len, dns_resp_payload.data(), dns_resp_payload.size());

    RecalcIPChecksum(resp_ip);

    uint32_t pseudo_len = 12 + udp_hdr_len + (uint32_t)dns_resp_payload.size();
    std::vector<uint8_t> pseudo_buf(pseudo_len, 0);
    std::memcpy(&pseudo_buf[0], &resp_ip->src_addr, 4);
    std::memcpy(&pseudo_buf[4], &resp_ip->dst_addr, 4);
    pseudo_buf[8] = 0;
    pseudo_buf[9] = 17; 
    uint16_t udp_len_net = resp_udp->length;
    std::memcpy(&pseudo_buf[10], &udp_len_net, 2);
    std::memcpy(&pseudo_buf[12], resp_udp, udp_hdr_len);
    std::memcpy(&pseudo_buf[12 + udp_hdr_len], dns_resp_payload.data(), dns_resp_payload.size());

    uint32_t sum = 0;
    uint32_t temp_len = pseudo_len;
    uint8_t* temp_ptr = pseudo_buf.data();
    while (temp_len > 1) {
        uint16_t word;
        std::memcpy(&word, temp_ptr, 2);
        sum += word;
        temp_ptr += 2;
        temp_len -= 2;
    }
    if (temp_len == 1) {
        uint16_t word = 0;
        std::memcpy(&word, temp_ptr, 1);
        sum += word;
    }
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    resp_udp->checksum = static_cast<uint16_t>(~sum);
    if (resp_udp->checksum == 0) resp_udp->checksum = 0xFFFF; 

    LOG_TRACE2("[DNS-REPLY-GEN] Built DNS response packet successfully", "Total=" + std::to_string(total_packet_len) + " bytes");
    return response_packet;
}
