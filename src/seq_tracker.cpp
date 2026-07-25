#include "seq_tracker.h"
#include "packet.h"

void SeqTracker::Update(const TcpSessionKey& key, uint32_t seq, uint32_t ack, uint8_t flags) {
    std::lock_guard lock(mutex_);

    // If RST or FIN is set, terminate tracked state
    if ((flags & TcpFlags::RST) || (flags & TcpFlags::FIN)) {
        sessions_.erase(key);
        return;
    }

    auto& state = sessions_[key];
    state.last_seq = seq;
    state.last_ack = ack;
    state.last_seen = std::chrono::steady_clock::now();
}

bool SeqTracker::IsBypassApplied(const TcpSessionKey& key) const {
    std::lock_guard lock(mutex_);
    auto it = sessions_.find(key);
    if (it != sessions_.end()) {
        return it->second.bypass_applied;
    }
    return false;
}

void SeqTracker::MarkBypassed(const TcpSessionKey& key) {
    std::lock_guard lock(mutex_);
    sessions_[key].bypass_applied = true;
}

std::optional<uint32_t> SeqTracker::GetClientSeq(const TcpSessionKey& key) const {
    std::lock_guard lock(mutex_);
    auto it = sessions_.find(key);
    if (it != sessions_.end()) {
        return it->second.last_seq;
    }
    return std::nullopt;
}

void SeqTracker::ExpireStale(std::chrono::seconds max_age) {
    std::lock_guard lock(mutex_);
    auto now = std::chrono::steady_clock::now();

    for (auto it = sessions_.begin(); it != sessions_.end(); ) {
        if (now - it->second.last_seen > max_age) {
            it = sessions_.erase(it);
        } else {
            ++it;
        }
    }
}
