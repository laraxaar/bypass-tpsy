#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <thread>
#include "network_util.h"

class BypassEngine {
public:
    // Фрагментация и отправка данных
    static void SendFragmented(SOCKET target_sock, const uint8_t* data, uint32_t size) {
        if (size < 100) { // Слишком мелкие пакеты не трогаем
            send(target_sock, (char*)data, size, 0);
            return;
        }

        // Стратегия: рвем пакет на втором байте SNI или просто в районе 40-60 байта
        // Большинство ТСПУ ищут SNI в первом же пакете. Если он неполный - они его пропускают.
        uint32_t split_pos = 50; 
        
        std::cout << "[*] Фрагментация: Отправка первой части (" << split_pos << " байт)" << std::endl;
        send(target_sock, (char*)data, split_pos, 0);
        
        // Маленькая задержка для того, чтобы пакеты ушли разными сегментами
        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        std::cout << "[*] Фрагментация: Отправка второй части (" << size - split_pos << " байт)" << std::endl;
        send(target_sock, (char*)(data + split_pos), size - split_pos, 0);
    }

    // Здесь можно добавить логику "Junk" пакетов (мусора)
    static void SendWithJunk(SOCKET target_sock, const uint8_t* data, uint32_t size) {
        // Отправляем 1 байт мусора с неправильным TCP Checksum или маленьким TTL
        // Но так как мы в юзермоде, проще всего отправить 1 байт реальных данных, 
        // а потом "дослать" остальное.
        send(target_sock, (char*)data, 1, 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        send(target_sock, (char*)(data + 1), size - 1, 0);
    }
};
