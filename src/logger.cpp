#include "logger.h"
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>

Logger& Logger::Get() {
    static Logger instance;
    return instance;
}

void Logger::Init(LogLevel level, const std::string& file_path) {
    std::lock_guard lock(mutex_);
    level_ = level;
    if (!file_path.empty()) {
        file_.open(file_path, std::ios::app);
        file_enabled_ = file_.is_open();
    }
}

void Logger::Log(LogLevel level, std::string_view msg) {
    if (level < level_) return;
    std::lock_guard lock(mutex_);

    auto ts = Timestamp();
    auto lvl = LevelStr(level);

    std::cerr << ts << " [" << lvl << "] " << msg << std::endl;
    if (file_enabled_) {
        file_ << ts << " [" << lvl << "] " << msg << std::endl;
    }
}

void Logger::Log(LogLevel level, std::string_view msg, std::string_view detail) {
    if (level < level_) return;
    std::lock_guard lock(mutex_);

    auto ts = Timestamp();
    auto lvl = LevelStr(level);

    std::cerr << ts << " [" << lvl << "] " << msg << ": " << detail << std::endl;
    if (file_enabled_) {
        file_ << ts << " [" << lvl << "] " << msg << ": " << detail << std::endl;
    }
}

const char* Logger::LevelStr(LogLevel level) const {
    switch (level) {
        case LogLevel::Trace: return "TRACE";
        case LogLevel::Debug: return "DEBUG";
        case LogLevel::Info:  return "INFO ";
        case LogLevel::Warn:  return "WARN ";
        case LogLevel::Error: return "ERROR";
    }
    return "?????";
}

std::string Logger::Timestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

    std::tm tm_buf{};
    localtime_s(&tm_buf, &time);

    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%S")
        << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return oss.str();
}

std::string Logger::HexDump(const uint8_t* data, size_t size) {
    if (!data || size == 0) return "[empty]";
    
    std::ostringstream oss;
    oss << "\n--- HEX DUMP (" << size << " bytes) ---\n";
    
    for (size_t i = 0; i < size; i += 16) {
        // Offset
        oss << std::setw(4) << std::setfill('0') << std::hex << i << ":  ";
        
        // Hex values
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < size) {
                oss << std::setw(2) << std::setfill('0') << std::hex << (int)data[i + j] << " ";
            } else {
                oss << "   ";
            }
            if (j == 7) oss << " "; // Split column
        }
        
        oss << "  |";
        
        // ASCII values
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < size) {
                char c = (char)data[i + j];
                if (std::isprint((unsigned char)c)) {
                    oss << c;
                } else {
                    oss << ".";
                }
            }
        }
        oss << "|\n";
    }
    
    return oss.str();
}
