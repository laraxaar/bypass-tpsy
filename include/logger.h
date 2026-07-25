/**
 * logger.h — Upgraded Thread-safe Network Logger with byte-level hex dumping.
 *
 * WHY THIS EXISTS:
 * For deep DPI analysis and network correlation audits (matching code logs vs tcpdump),
 * standard logging is insufficient. We need to trace exact hex bytes of TLS ClientHellos,
 * injected junk, DNS wire messages, and raw packet checksums.
 * This upgraded logger introduces:
 *   1. LogLevel::Trace for high-frequency packet flow details.
 *   2. HexDump helper function to print byte arrays cleanly in hex/ASCII columns.
 *   3. Synchronized write locks preventing multi-threaded stdout corruption.
 */
#pragma once

#include <string>
#include <string_view>
#include <mutex>
#include <fstream>
#include <cstdint>

enum class LogLevel : uint8_t {
    Trace = 0,
    Debug = 1,
    Info  = 2,
    Warn  = 3,
    Error = 4
};

class Logger {
public:
    static Logger& Get();

    // Initialize from config values. Call once at startup.
    void Init(LogLevel level, const std::string& file_path = "");

    void Log(LogLevel level, std::string_view msg);
    void Log(LogLevel level, std::string_view msg, std::string_view detail);

    LogLevel GetLevel() const { return level_; }

    // Generates a standard Wireshark-like 16-byte aligned Hex/ASCII dump of a packet payload
    static std::string HexDump(const uint8_t* data, size_t size);

    // Non-copyable, non-movable
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

private:
    Logger() = default;

    std::mutex mutex_;
    LogLevel level_ = LogLevel::Info;
    std::ofstream file_;
    bool file_enabled_ = false;

    const char* LevelStr(LogLevel level) const;
    std::string Timestamp() const;
};

// Convenience macros for compile-time level checking
#define LOG_TRACE(msg)       do { if (Logger::Get().GetLevel() <= LogLevel::Trace) Logger::Get().Log(LogLevel::Trace, msg); } while(0)
#define LOG_DEBUG(msg)       do { if (Logger::Get().GetLevel() <= LogLevel::Debug) Logger::Get().Log(LogLevel::Debug, msg); } while(0)
#define LOG_INFO(msg)        do { if (Logger::Get().GetLevel() <= LogLevel::Info)  Logger::Get().Log(LogLevel::Info,  msg); } while(0)
#define LOG_WARN(msg)        do { if (Logger::Get().GetLevel() <= LogLevel::Warn)  Logger::Get().Log(LogLevel::Warn,  msg); } while(0)
#define LOG_ERROR(msg)       do { if (Logger::Get().GetLevel() <= LogLevel::Error) Logger::Get().Log(LogLevel::Error, msg); } while(0)

#define LOG_TRACE2(msg, det) do { if (Logger::Get().GetLevel() <= LogLevel::Trace) Logger::Get().Log(LogLevel::Trace, msg, det); } while(0)
#define LOG_DEBUG2(msg, det) do { if (Logger::Get().GetLevel() <= LogLevel::Debug) Logger::Get().Log(LogLevel::Debug, msg, det); } while(0)
#define LOG_INFO2(msg, det)  do { if (Logger::Get().GetLevel() <= LogLevel::Info)  Logger::Get().Log(LogLevel::Info,  msg, det); } while(0)
#define LOG_WARN2(msg, det)  do { if (Logger::Get().GetLevel() <= LogLevel::Warn)  Logger::Get().Log(LogLevel::Warn,  msg, det); } while(0)
#define LOG_ERROR2(msg, det) do { if (Logger::Get().GetLevel() <= LogLevel::Error) Logger::Get().Log(LogLevel::Error, msg, det); } while(0)
