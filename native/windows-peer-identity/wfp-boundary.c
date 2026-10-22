#include "wfp-boundary.h"
#include <initguid.h>
#include <fwpmu.h>
#include <objbase.h>
#include <rpc.h>
#include <string.h>

#ifdef __MINGW32__
// Zig's bundled MinGW headers omit WFP GUID declarations; native MSVC uses the Windows SDK.
#define FWPM_SESSION_FLAG_DYNAMIC 0x00000001
#define FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT 0x00000008
#define FWPM_FILTER_FLAG_DISABLED 0x00000020
EXTERN_C const GUID FWPM_LAYER_ALE_AUTH_CONNECT_V4;
EXTERN_C const GUID FWPM_LAYER_ALE_AUTH_CONNECT_V6;
EXTERN_C const GUID FWPM_LAYER_ALE_AUTH_LISTEN_V4;
EXTERN_C const GUID FWPM_LAYER_ALE_AUTH_LISTEN_V6;
EXTERN_C const GUID FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
EXTERN_C const GUID FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;
EXTERN_C const GUID FWPM_CONDITION_ALE_PACKAGE_ID;
#endif

static const GUID *const denied_layers[SGW_WFP_FILTER_COUNT] = {
    &FWPM_LAYER_ALE_AUTH_CONNECT_V4, &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    &FWPM_LAYER_ALE_AUTH_LISTEN_V4, &FWPM_LAYER_ALE_AUTH_LISTEN_V6,
    &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6
};

DWORD sgw_wfp_start(PSID package_sid, SGW_WFP_BOUNDARY *boundary) {
    if (!boundary || !package_sid || !IsValidSid(package_sid)) return ERROR_INVALID_PARAMETER;
    memset(boundary, 0, sizeof(*boundary));
    boundary->sid_length = GetLengthSid(package_sid);
    if (boundary->sid_length > (DWORD)sizeof(boundary->package_sid) ||
        !CopySid((DWORD)sizeof(boundary->package_sid), boundary->package_sid, package_sid)) {
        return ERROR_INVALID_SID;
    }

    FWPM_SESSION0 session = { 0 };
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    session.displayData.name = L"s-gw agent egress boundary";
    DWORD result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &boundary->engine);
    if (result != ERROR_SUCCESS) goto fail;
    if (CoCreateGuid(&boundary->sublayer) != S_OK) {
        result = ERROR_GEN_FAILURE;
        goto fail;
    }
    result = FwpmTransactionBegin0(boundary->engine, 0);
    if (result != ERROR_SUCCESS) goto fail;

    FWPM_SUBLAYER0 sublayer = { 0 };
    sublayer.subLayerKey = boundary->sublayer;
    sublayer.displayData.name = L"s-gw agent package deny";
    sublayer.weight = 0xffff;
    result = FwpmSubLayerAdd0(boundary->engine, &sublayer, NULL);
    if (result != ERROR_SUCCESS) goto abort;

    FWPM_FILTER_CONDITION0 condition = { 0 };
    condition.fieldKey = FWPM_CONDITION_ALE_PACKAGE_ID;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.type = FWP_SID;
    condition.conditionValue.sid = (SID *)boundary->package_sid;

    for (int i = 0; i < SGW_WFP_FILTER_COUNT; i++) {
        FWPM_FILTER0 filter = { 0 };
        filter.displayData.name = L"s-gw agent package network deny";
        filter.layerKey = *denied_layers[i];
        filter.subLayerKey = boundary->sublayer;
        filter.weight.type = FWP_UINT8;
        filter.weight.uint8 = 15;
        filter.numFilterConditions = 1;
        filter.filterCondition = &condition;
        filter.action.type = FWP_ACTION_BLOCK;
        result = FwpmFilterAdd0(boundary->engine, &filter, NULL, &boundary->filters[i]);
        if (result != ERROR_SUCCESS) goto abort;
    }

    result = FwpmTransactionCommit0(boundary->engine);
    if (result != ERROR_SUCCESS) goto fail;
    if (sgw_wfp_healthy(boundary)) return ERROR_SUCCESS;
    result = ERROR_INVALID_DATA;
    goto fail;

abort:
    FwpmTransactionAbort0(boundary->engine);
fail:
    sgw_wfp_stop(boundary);
    return result;
}

BOOL sgw_wfp_healthy(const SGW_WFP_BOUNDARY *boundary) {
    if (!boundary || !boundary->engine || !boundary->sid_length) return FALSE;
    for (int i = 0; i < SGW_WFP_FILTER_COUNT; i++) {
        FWPM_FILTER0 *filter = NULL;
        DWORD result = FwpmFilterGetById0(boundary->engine, boundary->filters[i], &filter);
        BOOL matches = result == ERROR_SUCCESS && filter &&
            IsEqualGUID(&filter->layerKey, denied_layers[i]) &&
            IsEqualGUID(&filter->subLayerKey, &boundary->sublayer) &&
            filter->action.type == FWP_ACTION_BLOCK &&
            !(filter->flags & (FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT | FWPM_FILTER_FLAG_DISABLED)) &&
            filter->numFilterConditions == 1 && filter->filterCondition &&
            IsEqualGUID(&filter->filterCondition[0].fieldKey, &FWPM_CONDITION_ALE_PACKAGE_ID) &&
            filter->filterCondition[0].matchType == FWP_MATCH_EQUAL &&
            filter->filterCondition[0].conditionValue.type == FWP_SID &&
            filter->filterCondition[0].conditionValue.sid &&
            EqualSid(filter->filterCondition[0].conditionValue.sid, (PSID)boundary->package_sid);
        if (filter) FwpmFreeMemory0((void **)&filter);
        if (!matches) return FALSE;
    }
    return TRUE;
}

void sgw_wfp_stop(SGW_WFP_BOUNDARY *boundary) {
    if (!boundary) return;
    if (boundary->engine) FwpmEngineClose0(boundary->engine);
    memset(boundary, 0, sizeof(*boundary));
}
