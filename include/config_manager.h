#pragma once
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <windows.h>
#include <tlhelp32.h>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

struct AppConfig {
    std::vector<std::wstring> whitelist;
    std::vector<std::string> junk_pool;
    struct {
        bool doh_enabled;
        std::string primary_dns;
        std::string doh_url;
    } dns;
    struct {
        bool tcp_fragmentation;
        bool udp_obfuscation;
        int ttl_value;
    } strategies;
};

class ConfigManager {
public:
    static AppConfig LoadConfig(const std::string& filename) {
        AppConfig config;
        std::ifstream file(filename);
        if (!file.is_open()) return config;

        std::stringstream ss;
        ss << file.rdbuf();
        std::string content = ss.str();

        ExtractWhitelist(content, config);
        ExtractJunkPool(content, config);

        config.strategies.tcp_fragmentation = (content.find("\"tcp_fragmentation\": true") != std::string::npos);
        config.strategies.ttl_value = 2;

        return config;
    }

private:
    static void ExtractWhitelist(const std::string& content, AppConfig& config) {
        size_t pos = content.find("\"whitelist_apps\": [");
        if (pos == std::string::npos) return;
        
        size_t end = content.find("]", pos);
        std::string list = content.substr(pos, end - pos);
        size_t start_q = 0;
        while ((start_q = list.find("\"", start_q)) != std::string::npos) {
            size_t end_q = list.find("\"", start_q + 1);
            if (end_q == std::string::npos) break;
            std::string app_name = list.substr(start_q + 1, end_q - start_q - 1);
            std::wstring resolved = ResolveProcessPath(app_name);
            if (!resolved.empty()) config.whitelist.push_back(resolved);
            start_q = end_q + 1;
        }
    }

    static void ExtractJunkPool(const std::string& content, AppConfig& config) {
        size_t pos = content.find("\"junk_pool\": [");
        if (pos == std::string::npos) return;
        
        size_t end = content.find("]", pos);
        std::string list = content.substr(pos, end - pos);
        size_t start_q = 0;
        while ((start_q = list.find("\"", start_q)) != std::string::npos) {
            size_t end_q = list.find("\"", start_q + 1);
            if (end_q == std::string::npos) break;
            config.junk_pool.push_back(list.substr(start_q + 1, end_q - start_q - 1));
            start_q = end_q + 1;
        }
    }

    static std::wstring ResolveProcessPath(const std::string& name) {
        std::wstring wname(name.begin(), name.end());
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return L"";

        PROCESSENTRY32W entry = { sizeof(entry) };
        if (Process32FirstW(snapshot, &entry)) {
            do {
                if (_wcsicmp(wname.c_str(), entry.szExeFile) == 0) {
                    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID);
                    if (hProc) {
                        wchar_t path[MAX_PATH];
                        DWORD size = MAX_PATH;
                        if (QueryFullProcessImageNameW(hProc, 0, path, &size)) {
                            CloseHandle(hProc);
                            CloseHandle(snapshot);
                            return std::wstring(path);
                        }
                        CloseHandle(hProc);
                    }
                }
            } while (Process32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
        return L"";
    }
};
