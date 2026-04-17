#include <vector>
#include <string>

#pragma comment(lib, "fwpuclnt.lib")

class WFPManager {
public:
    WFPManager();
    ~WFPManager();

    bool Initialize();
    bool SetupRedirection(uint16_t local_proxy_port, const std::vector<std::wstring>& app_whitelist);
    void Cleanup();

private:
    HANDLE engine_handle;
    GUID sublayer_guid;
    std::vector<uint64_t> filter_ids;
};
