#include "../include/network_util.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <thread>
#include <vector>
#include <random>

#pragma comment(lib, "ws2_32.lib")

class AdvancedBypass {
private:
    static inline std::vector<std::string> junk_pool = {"google.com", "microsoft.com", "apple.com"};

public:
    static void SetJunkPool(const std::vector<std::string>& pool) {
        if (!pool.empty()) junk_pool = pool;
    }

    static void SetDynamicMSS(SOCKET sock, int mss_size) {
        setsockopt(sock, IPPROTO_TCP, TCP_MAXSEG, (const char*)&mss_size, sizeof(mss_size));
    }

    static void SetPacketTTL(SOCKET sock, int ttl) {
        setsockopt(sock, IPPROTO_IP, IP_TTL, (const char*)&ttl, sizeof(ttl));
    }

    // Sends Part 2 before Part 1 to confuse reassembly
    static void SendOutOfOrder(SOCKET sock, const uint8_t* data, uint32_t size) {
        if (size < 100) {
            send(sock, (char*)data, size, 0);
            return;
        }

        uint32_t split = size / 2;
        send(sock, (char*)(data + split), size - split, 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        send(sock, (char*)data, split, 0);
    }

    // Injects a fake SNI with low TTL
    static void InjectJunk(SOCKET sock) {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, (int)junk_pool.size() - 1);
        
        std::string fake_domain = junk_pool[dis(gen)];
        int original_ttl = 64; 
        int low_ttl = 2; 

        SetPacketTTL(sock, low_ttl);
        
        // Mock TLS Client Hello with fake SNI
        std::string junk = "\x16\x03\x01\x00\x40" + fake_domain; 
        send(sock, junk.c_str(), (int)junk.length(), 0);
        
        std::this_thread::sleep_for(std::chrono::milliseconds(3));
        SetPacketTTL(sock, original_ttl);
    }
};
