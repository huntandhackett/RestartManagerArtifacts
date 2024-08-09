/*
 * Copyright (c) 2024 Hunt & Hackett.
 *
 * This project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#ifndef _ARTIFACT_COLLECTOR_H
#define _ARTIFACT_COLLECTOR_H

#include <phnt_windows.h>
#include <phnt.h>
#include <RestartManager.h>
#include "helpers.h"

NTSTATUS
NTAPI
H2DetermineUserSid(
	_In_opt_ PCWSTR UserNameOrSid,
	_Outptr_ PSID *Sid // RtlFreeSid
);

NTSTATUS
NTAPI
H2OpenRestartManagerRoot(
	_Out_ PHANDLE RootKeyHandle,
	_In_ PSID UserSid
);

NTSTATUS
NTAPI
H2QueryRestartManagerRootLastWriteTime(
	_In_ HANDLE RootKeyHandle,
	_Out_ PLARGE_INTEGER LastWriteTime
);

NTSTATUS
NTAPI
H2EnumerateRestartManagerSessions(
	_In_ HANDLE RootKey,
	_In_ ULONG Index,
	_Out_ PUNICODE_STRING SessionName, // RtlFreeUnicodeString
	_Out_ PLARGE_INTEGER LastWriteTime
);

NTSTATUS
NTAPI
H2OpenRestartManagerSession(
	_In_ HANDLE RootKey,
	_In_ PUNICODE_STRING SessionName,
	_Out_ PHANDLE SessionKey
);

typedef struct _H2_RM_SESSION_INFO
{
	BOOLEAN OwnerValid;
	BOOLEAN SequenceValid;
	RM_UNIQUE_PROCESS Owner;
	ULONG Sequence;
	LIST_ENTRY Files;        // H2_STRINGS_GROUP
	LIST_ENTRY Applications; // H2_STRINGS_GROUP
	LIST_ENTRY Services;     // H2_STRINGS_GROUP
} H2_RM_SESSION_INFO, *PH2_RM_SESSION_INFO;

NTSTATUS
NTAPI
H2QueryRestartManagerSessionInfo(
	_In_ HANDLE SessionKey,
	_Out_ PH2_RM_SESSION_INFO Info
);

NTSTATUS
NTAPI
H2QueryRestartManagerSessionInfoByName(
	_In_ HANDLE RootKey,
	_In_ PUNICODE_STRING SessionName,
	_Out_ PH2_RM_SESSION_INFO Info
);

VOID
NTAPI
H2FreeRestartManagerSessionInfo(
	_Inout_ PH2_RM_SESSION_INFO Info
);

NTSTATUS
NTAPI
H2QuerySystemName(
	_Out_ PUNICODE_STRING SystemName // H2FreeSystemName
);

VOID
NTAPI
H2FreeSystemName(
	_Inout_ PUNICODE_STRING SystemName
);

NTSTATUS
NTAPI
H2InitProcessLookupCache(
	VOID
);

VOID
NTAPI
H2FreeProcessLookupCache(
	VOID
);

typedef enum _H2_PROCESS_STATE
{
	ProcessStateUnknown,
	ProcessStateActive,
	ProcessStateTerminated
} H2_PROCESS_STATE, *PH2_PROCESS_STATE;

H2_PROCESS_STATE
NTAPI
H2LookupProcessState(
	_In_ PRM_UNIQUE_PROCESS Process
);

NTSTATUS
NTAPI
H2QueryProcessImageName(
	_In_ PRM_UNIQUE_PROCESS Process,
	_Out_ PUNICODE_STRING ImageName // RtlFreeUnicodeString
);

#endif
