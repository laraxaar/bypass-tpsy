#include "config.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <ws2tcpip.h>

Config::Config(const std::string& filepath) : filepath_(filepath) {
    Load();
}

void Config::Trim(std::string& str) const {
    str.erase(str.begin(), std::find_if(str.begin(), str.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
    str.erase(std::find_if(str.rbegin(), str.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), str.end());
}

bool Config::Load() {
    std::lock_guard lock(mutex_);
    std::ifstream file(filepath_);
    if (!file.is_open()) {
        LOG_ERROR2("Failed to open configuration file", filepath_);
        return false;
    }

    data_.clear();
    std::string line;
    std::string current_section = "";

    while (std::getline(file, line)) {
        Trim(line);
        if (line.empty() || line[0] == ';' || line[0] == '#') {
            continue; // Skip comments and empty lines
        }

        if (line[0] == '[' && line[line.size() - 1] == ']') {
            current_section = line.substr(1, line.size() - 2);
            Trim(current_section);
        } else {
            size_t pos = line.find('=');
            if (pos != std::string::npos) {
                std::string key = line.substr(0, pos);
                std::string val = line.substr(pos + 1);
                Trim(key);
                Trim(val);
                if (!current_section.empty()) {
                    data_[current_section][key] = val;
                }
            }
        }
    }
    LOG_INFO2("Loaded config from file", filepath_);
    return true;
}

std::string Config::GetString(const std::string& section, const std::string& key, const std::string& default_val) const {
    std::lock_guard lock(mutex_);
    auto s_it = data_.find(section);
    if (s_it != data_.end()) {
        auto k_it = s_it->second.find(key);
        if (k_it != s_it->second.end()) {
            return k_it->second;
        }
    }
    return default_val;
}

int Config::GetInt(const std::string& section, const std::string& key, int default_val) const {
    std::string val = GetString(section, key);
    if (val.empty()) return default_val;
    try {
        return std::stoi(val);
    } catch (...) {
        return default_val;
    }
}

bool Config::GetBool(const std::string& section, const std::string& key, bool default_val) const {
    std::string val = GetString(section, key);
    if (val.empty()) return default_val;
    for (char& c : val) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return (val == "true" || val == "yes" || val == "1");
}

std::vector<std::string> Config::GetStringList(const std::string& section, const std::string& key) const {
    std::string val = GetString(section, key);
    std::vector<std::string> result;
    if (val.empty()) return result;

    std::stringstream ss(val);
    std::string item;
    while (std::getline(ss, item, ',')) {
        Trim(item);
        if (!item.empty()) {
            result.push_back(item);
        }
    }
    return result;
}

std::vector<std::pair<uint32_t, uint32_t>> Config::GetSubnets() const {
    std::vector<std::string> list = GetStringList("routes", "subnets");
    std::vector<std::pair<uint32_t, uint32_t>> subnets;

    for (const auto& subnet_str : list) {
        size_t slash = subnet_str.find('/');
        if (slash == std::string::npos) continue;

        std::string ip_str = subnet_str.substr(0, slash);
        std::string mask_str = subnet_str.substr(slash + 1);

        IN_ADDR addr;
        if (inet_pton(AF_INET, ip_str.c_str(), &addr) != 1) continue;

        uint32_t ip = ntohl(addr.S_un.S_addr);
        int bits = std::stoi(mask_str);
        if (bits < 0 || bits > 32) continue;

        uint32_t mask = (bits == 0) ? 0 : (~0u << (32 - bits));
        subnets.push_back({ip & mask, mask});
    }

    return subnets;
}

std::vector<std::string> Config::GetHosts() const {
    return GetStringList("routes", "hosts");
}

bool Config::WildcardMatch(const std::string& pattern, const std::string& host) const {
    if (pattern == "*") return true;

    // Direct match
    if (pattern == host) return true;

    // Simple wildcard support (*.domain.com)
    if (pattern.size() > 2 && pattern.substr(0, 2) == "*.") {
        std::string suffix = pattern.substr(1); // ".domain.com"
        if (host.size() >= suffix.size()) {
            return host.compare(host.size() - suffix.size(), suffix.size(), suffix) == 0;
        }
    }

    return false;
}

bool Config::MatchesHostFilter(const std::string& hostname) const {
    std::string mode = GetString("host_filter", "mode", "whitelist");
    std::vector<std::string> patterns = GetStringList("host_filter", "patterns");

    bool matched = false;
    for (const auto& pattern : patterns) {
        if (WildcardMatch(pattern, hostname)) {
            matched = true;
            break;
        }
    }

    if (mode == "blacklist") {
        return !matched;
    }
    return matched;
}
