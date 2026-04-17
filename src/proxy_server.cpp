#include <iostream>
#include <thread>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "network_util.h"
#include "bypass_engine.cpp" 
#include "dns_resolver.cpp"

#pragma comment(lib, "ws2_32.lib")

#define TCP_PROXY_PORT 8888
#define UDP_PROXY_PORT 8889
#define BUFFER_SIZE 65536

class ProxyServer {
public:
    void Start() {
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);

        std::thread([this]() { StartTCPProxy(); }).detach();
        StartUDPProxy();
    }

private:
    void StartTCPProxy() {
        SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(TCP_PROXY_PORT);

        bind(listen_sock, (sockaddr*)&addr, sizeof(addr));
        listen(listen_sock, SOMAXCONN);
        
        while (true) {
            SOCKET client_sock = accept(listen_sock, NULL, NULL);
            if (client_sock != INVALID_SOCKET) {
                std::thread(&ProxyServer::HandleTCPClient, this, client_sock).detach();
            }
        }
    }

    void StartUDPProxy() {
        SOCKET udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(UDP_PROXY_PORT);

        bind(udp_sock, (sockaddr*)&addr, sizeof(addr));

        char buffer[BUFFER_SIZE];
        sockaddr_in from;
        int from_len = sizeof(from);

        while (true) {
            int bytes = recvfrom(udp_sock, buffer, BUFFER_SIZE, 0, (sockaddr*)&from, &from_len);
            if (bytes > 0) {
                // TODO: Implement stateless UDP relay for QUIC/DNS
            }
        }
    }

    void HandleTCPClient(SOCKET client_sock) {
        char target_host[] = "1.1.1.1"; 
        int target_port = 443;

        SOCKET remote_sock = socket(AF_INET, SOCK_STREAM, 0);
        AdvancedBypass::SetDynamicMSS(remote_sock, 500);

        sockaddr_in remote_addr;
        remote_addr.sin_family = AF_INET;
        inet_pton(AF_INET, target_host, &remote_addr.sin_addr);
        remote_addr.sin_port = htons(target_port);

        if (connect(remote_sock, (sockaddr*)&remote_addr, sizeof(remote_addr)) != SOCKET_ERROR) {
            std::thread([this, client_sock, remote_sock]() { RelayTCP(client_sock, remote_sock, true); }).detach();
            RelayTCP(remote_sock, client_sock, false);
        }
        closesocket(client_sock);
        closesocket(remote_sock);
    }

    void RelayTCP(SOCKET src, SOCKET dst, bool is_outbound) {
        char buffer[BUFFER_SIZE];
        int bytes;
        while ((bytes = recv(src, buffer, BUFFER_SIZE, 0)) > 0) {
            if (is_outbound && bytes > 5 && (uint8_t)buffer[0] == 0x16) {
                AdvancedBypass::InjectJunk(dst); // Uses dynamic pool
                AdvancedBypass::SendOutOfOrder(dst, (uint8_t*)buffer, bytes);
            } else {
                send(dst, buffer, bytes, 0);
            }
        }
    }
};
