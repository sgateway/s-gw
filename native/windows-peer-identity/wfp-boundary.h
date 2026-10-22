#ifndef SGW_WFP_BOUNDARY_H
#define SGW_WFP_BOUNDARY_H

#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <windows.h>

#define SGW_WFP_FILTER_COUNT 6

typedef struct {
    HANDLE engine;
    GUID sublayer;
    UINT64 filters[SGW_WFP_FILTER_COUNT];
    BYTE package_sid[SECURITY_MAX_SID_SIZE];
    DWORD sid_length;
} SGW_WFP_BOUNDARY;

DWORD sgw_wfp_start(PSID package_sid, SGW_WFP_BOUNDARY *boundary);
BOOL sgw_wfp_healthy(const SGW_WFP_BOUNDARY *boundary);
void sgw_wfp_stop(SGW_WFP_BOUNDARY *boundary);

#endif
