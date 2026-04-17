#include "../include/wfp_manager.h"
#include <fwpmu.h>
#include <iostream>

// Unique sublayer GUID
static const GUID BYPASS_SUBLAYER_GUID = { 0x12345678, 0x1234, 0x1234, { 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56 } };

WFPManager::WFPManager() : engine_handle(NULL) {}

WFPManager::~WFPManager() {
    Cleanup();
}

bool WFPManager::Initialize() {
    FWPM_SESSION0 session = {0};
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    if (FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &engine_handle) != ERROR_SUCCESS) {
        return false;
    }

    FWPM_SUBLAYER0 sublayer = {0};
    sublayer.displayData.name = L"Bypass TSPU Sublayer";
    sublayer.subLayerKey = BYPASS_SUBLAYER_GUID;
    sublayer.weight = 0x100;

    FwpmSubLayerAdd0(engine_handle, &sublayer, NULL);
    return true;
}

void WFPManager::AddFilter(FWP_BYTE_BLOB* app_id, uint8_t protocol, uint16_t port) {
    FWPM_FILTER0 filter = {0};
    FWPM_FILTER_CONDITION0 conditions[3] = {0};

    filter.displayData.name = L"Bypass App Redirect";
    filter.subLayerKey = BYPASS_SUBLAYER_GUID;
    filter.layerKey = FWPM_LAYER_ALE_CONNECT_REDIRECT_V4;
    filter.action.type = FWP_ACTION_REDIRECT;
    filter.action.calloutKey = FWPM_CALLOUT_CONNECTION_REDIRECT_V4;

    // Condition 1: Match Application Path
    conditions[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
    conditions[0].matchType = FWP_MATCH_EQUAL;
    conditions[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;
    conditions[0].conditionValue.byteBlob = app_id;

    // Condition 2: Protocol (TCP/UDP)
    conditions[1].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    conditions[1].matchType = FWP_MATCH_EQUAL;
    conditions[1].conditionValue.type = FWP_UINT8;
    conditions[1].conditionValue.uint8 = protocol;

    // Condition 3: Destination Port
    conditions[2].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    conditions[2].matchType = FWP_MATCH_EQUAL;
    conditions[2].conditionValue.type = FWP_UINT16;
    conditions[2].conditionValue.uint16 = port;

    filter.filterCondition = conditions;
    filter.numFilterConditions = 3;

    UINT64 filter_id = 0;
    if (FwpmFilterAdd0(engine_handle, &filter, NULL, &filter_id) == ERROR_SUCCESS) {
        filter_ids.push_back(filter_id);
    }
}

bool WFPManager::SetupRedirection(uint16_t local_proxy_port, const std::vector<std::wstring>& app_whitelist) {
    if (!engine_handle) return false;

    for (const auto& app_path : app_whitelist) {
        FWP_BYTE_BLOB* app_id = NULL;
        if (FwpmGetAppIdFromFileName0(app_path.c_str(), &app_id) == ERROR_SUCCESS) {
            AddFilter(app_id, IPPROTO_TCP, 443);
            AddFilter(app_id, IPPROTO_UDP, 443);
            AddFilter(app_id, IPPROTO_UDP, 53);
            FwpmFreeMemory0((void**)&app_id);
        }
    }
    return true;
}

void WFPManager::Cleanup() {
    if (!engine_handle) return;
    for (UINT64 id : filter_ids) FwpmFilterDeleteById0(engine_handle, id);
    filter_ids.clear();
    FwpmEngineClose0(engine_handle);
    engine_handle = NULL;
}
