/**
 * config.h — Config parser for INI format.
 *
 * WHY THIS EXISTS:
 * The original config_manager.h relied on a manual string-search "JSON parser"
 * that was extremely fragile. It enumerated active processes to find paths,
 * which is slow and error-prone. This new module uses a clean, section-aware
 * INI parser. It stores configurations typed and structured.
 * It also supports wildcard matching for host filters (e.g., "*.google.com").
 */
#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include "logger.h"

class Config {
public:
    explicit Config(const std::string& filepath);

    bool Load();

    // Accessors
    std::string GetString(const std::string& section, const std::string& key, const std::string& default_val = "") const;
    int GetInt(const std::string& section, const std::string& key, int default_val = 0) const;
    bool GetBool(const std::string& section, const std::string& key, bool default_val = false) const;
    std::vector<std::string> GetStringList(const std::string& section, const std::string& key) const;

    // Custom structural parsers
    std::vector<std::pair<uint32_t, uint32_t>> GetSubnets() const; // Parsed CIDR subnets (IP, Mask)
    std::vector<std::string> GetHosts() const;                    // Target hostnames for bypass
    bool MatchesHostFilter(const std::string& hostname) const;

private:
    std::string filepath_;
    // Nested map for section -> key -> value
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> data_;
    mutable std::mutex mutex_;

    void Trim(std::string& str) const;
    bool WildcardMatch(const std::string& pattern, const std::string& host) const;
};
