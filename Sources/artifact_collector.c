/*
 * Copyright (c) 2024 Hunt & Hackett.
 *
 * This project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#include "artifact_collector.h"
#include <wchar.h>
#include <sddl.h>
#include <UserEnv.h>

#define RM_ROOT_FORMAT L"\\Registry\\User\\%wZ\\SOFTWARE\\Microsoft\\RestartManager"
#define RM_SESSION_NAME L"Session0000"

NTSTATUS
NTAPI
H2CopySid(
	_In_ PSID SourceSid,
	_Outptr_ PSID *Sid
)
{
	NTSTATUS status;
	ULONG bufferSize;
	PSID buffer;

	bufferSize = RtlLengthRequiredSid(*RtlSubAuthorityCountSid(SourceSid));
	buffer = RtlAllocateHeap(RtlProcessHeap(), 0, bufferSize);

	if (buffer)
	{
		status = RtlCopySid(bufferSize, buffer, SourceSid);

		if (NT_SUCCESS(status))
			*Sid = buffer;
		else
			RtlFreeHeap(RtlProcessHeap(), 0, buffer);
	}
	else
		status = STATUS_NO_MEMORY;

	return status;
}

NTSTATUS
NTAPI
H2DetermineUserSid(
	_In_opt_ PCWSTR UserNameOrSid,
	_Outptr_ PSID *Sid
)
{
	NTSTATUS status;

	if (UserNameOrSid)
	{
		PSID buffer;

		// Try converting SDDL S-1-* strings first
		if (ConvertStringSidToSidW(UserNameOrSid, &buffer))
		{
			status = H2CopySid(buffer, Sid);
			LocalFree(buffer);
			return status;
		}

		// Connect to LSA for name lookup
		LSA_HANDLE hLsaPolicy;
		LSA_OBJECT_ATTRIBUTES objAttr;

		InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

		status = LsaOpenPolicy(NULL, &objAttr, POLICY_LOOKUP_NAMES, &hLsaPolicy);

		if (!NT_SUCCESS(status))
			return status;

		// Perform the lookup
		LSA_UNICODE_STRING name;
		PLSA_REFERENCED_DOMAIN_LIST domainList;
		PLSA_TRANSLATED_SID2 translatedSids;

		RtlInitUnicodeString(&name, UserNameOrSid);

		status = LsaLookupNames2(
			hLsaPolicy,
			0,
			1,
			&name,
			&domainList,
			&translatedSids
		);

		LsaClose(hLsaPolicy);

		// Copy and cleanup
		if (NT_SUCCESS(status) || (status == STATUS_NONE_MAPPED))
		{
			if (NT_SUCCESS(status))
				status = H2CopySid(translatedSids->Sid, Sid);

			LsaFreeMemory(domainList);
			LsaFreeMemory(translatedSids);
		}

		return status;
	}
	else
	{
		// Use the user from the the current process token
		HANDLE hToken;

		if (RtlGetCurrentPeb()->OSMajorVersion > 6 ||
			((RtlGetCurrentPeb()->OSMajorVersion == 6) && (RtlGetCurrentPeb()->OSMinorVersion > 1)))
		{
			// Use the pseudo-handle on Windows 8+
			hToken = NULL;
		}
		else
		{
			// Open the token on Windows 7
			status = NtOpenProcessToken(
				NtCurrentProcess(),
				TOKEN_QUERY,
				&hToken
			);

			if (!NT_SUCCESS(status))
				return status;
		}

		// Retrieve the user SID
		SE_TOKEN_USER userBuffer;
		ULONG returnLength;

		status = NtQueryInformationToken(
			hToken ? hToken : NtCurrentProcessToken(),
			TokenUser,
			&userBuffer,
			sizeof(userBuffer),
			&returnLength
		);

		if (hToken)
			NtClose(hToken);

		if (!NT_SUCCESS(status))
			return status;

		// Make a copy
		status = H2CopySid(userBuffer.User.Sid, Sid);

		return status;
	}
}

NTSTATUS
NTAPI
H2OpenRestartManagerRoot(
	_Out_ PHANDLE RootKeyHandle,
	_In_ PSID UserSid
)
{
	NTSTATUS status;

	// Convert the user SID into a string representation
	UNICODE_STRING sddl;
	WCHAR sddlBuffer[SECURITY_MAX_SID_STRING_CHARACTERS];

	sddl.Buffer = sddlBuffer;
	sddl.Length = 0;
	sddl.MaximumLength = sizeof(sddlBuffer);

	status = RtlConvertSidToUnicodeString(&sddl, UserSid, FALSE);

	if (!NT_SUCCESS(status))
		return status;

	// Prepare the registry key name
	UNICODE_STRING keyName;
	WCHAR keyNameBuffer[SECURITY_MAX_SID_STRING_CHARACTERS + sizeof(RM_ROOT_FORMAT)];

	keyName.Buffer = keyNameBuffer;
	keyName.MaximumLength = sizeof(keyNameBuffer);

	keyName.Length = (USHORT)swprintf(
		keyName.Buffer,
		keyName.MaximumLength / sizeof(WCHAR),
		RM_ROOT_FORMAT,
		&sddl
	) * sizeof(WCHAR);

	if (!keyName.Length)
		return STATUS_BUFFER_TOO_SMALL;

	// Open the key
	OBJECT_ATTRIBUTES objAttr;
	InitializeObjectAttributes(&objAttr, &keyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = NtOpenKeyEx(RootKeyHandle, KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, &objAttr, 0);

	if (status == STATUS_ACCESS_DENIED)
	{
		// Retry using the backup privilege
		status = NtOpenKeyEx(RootKeyHandle, KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, &objAttr, REG_OPTION_BACKUP_RESTORE);
	}

	return status;
}

NTSTATUS
NTAPI
H2QueryRestartManagerRootLastWriteTime(
	_In_ HANDLE RootKeyHandle,
	_Out_ PLARGE_INTEGER LastWriteTime
)
{
	NTSTATUS status;
	KEY_CACHED_INFORMATION buffer;
	ULONG returnLength;

	status = NtQueryKey(RootKeyHandle, KeyCachedInformation, &buffer, sizeof(buffer), &returnLength);

	if (NT_SUCCESS(status))
		*LastWriteTime = buffer.LastWriteTime;

	return status;
}

NTSTATUS
NTAPI
H2EnumerateRestartManagerSessions(
	_In_ HANDLE RootKey,
	_In_ ULONG Index,
	_Out_ PUNICODE_STRING SessionName,
	_Out_ PLARGE_INTEGER LastWriteTime
)
{
	NTSTATUS status;
	ULONG bufferSize, requiredSize;
	PKEY_BASIC_INFORMATION buffer;

	bufferSize = sizeof(KEY_BASIC_INFORMATION);

	do
	{
		buffer = RtlAllocateHeap(RtlProcessHeap(), 0, bufferSize);

		if (!buffer)
			return STATUS_NO_MEMORY;

		// Retrieve the sub-key (session) information by index
		status = NtEnumerateKey(
			RootKey,
			Index,
			KeyBasicInformation,
			buffer,
			bufferSize,
			&requiredSize
			);

		if (status == STATUS_BUFFER_OVERFLOW)
		{
			RtlFreeHeap(RtlProcessHeap(), 0, buffer);
			buffer = NULL;

			if (requiredSize <= bufferSize)
				return status;

			bufferSize = requiredSize;
		}
	}
	while (status == STATUS_BUFFER_OVERFLOW);

	if (!NT_SUCCESS(status))
		return status;

	// Copy the session name
	UNICODE_STRING sessionName;

	sessionName.Length = (USHORT)buffer->NameLength;
	sessionName.MaximumLength = (USHORT)buffer->NameLength;
	sessionName.Buffer = buffer->Name;

	status = RtlDuplicateUnicodeString(
		RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE,
		&sessionName,
		SessionName
	);

	// Copy the timestamp
	*LastWriteTime = buffer->LastWriteTime;

	// Clean-up
	RtlFreeHeap(RtlProcessHeap(), 0, buffer);
	return status;
}

NTSTATUS
NTAPI
H2OpenRestartManagerSession(
	_In_ HANDLE RootKey,
	_In_ PUNICODE_STRING SessionName,
	_Out_ PHANDLE SessionKeyHandle
)
{
	NTSTATUS status;
	OBJECT_ATTRIBUTES objAttr;

	InitializeObjectAttributes(&objAttr, SessionName, OBJ_CASE_INSENSITIVE, RootKey, NULL);

	status = NtOpenKeyEx(SessionKeyHandle, KEY_QUERY_VALUE, &objAttr, 0);

	if (status == STATUS_ACCESS_DENIED)
	{
		// Retry using the backup privilege
		status = NtOpenKeyEx(SessionKeyHandle, KEY_QUERY_VALUE, &objAttr, REG_OPTION_BACKUP_RESTORE);
	}

	return status;
}

NTSTATUS
NTAPI
H2EnumerateFullValueKey(
	_In_ HANDLE KeyHandle,
	_In_ ULONG Index,
	_Outptr_ PKEY_VALUE_FULL_INFORMATION *Buffer // RtlFreeHeap
)
{
	NTSTATUS status;
	ULONG bufferSize, returnedLength;
	PKEY_VALUE_FULL_INFORMATION buffer;

	bufferSize = sizeof(KEY_VALUE_FULL_INFORMATION);

	do
	{
		buffer = RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, bufferSize);

		if (!buffer)
			return STATUS_NO_MEMORY;

		status = NtEnumerateValueKey(
			KeyHandle,
			Index,
			KeyValueFullInformation,
			buffer,
			bufferSize,
			&returnedLength
		);

		if (!NT_SUCCESS(status))
		{
			RtlFreeHeap(RtlProcessHeap(), 0, buffer);
			buffer = NULL;

			// Retry with a new size
			if (status == STATUS_BUFFER_OVERFLOW)
			{
				if (returnedLength <= bufferSize)
					status = STATUS_INVALID_BUFFER_SIZE;

				bufferSize = returnedLength;
			}
		}

	} while (status == STATUS_BUFFER_OVERFLOW);

	if (NT_SUCCESS(status))
		*Buffer = buffer;

	return status;
}

NTSTATUS
NTAPI
H2QueryRestartManagerSessionInfo(
	_In_ HANDLE SessionKey,
	_Out_ PH2_RM_SESSION_INFO Info
)
{
	NTSTATUS status;
	ULONG index = 0;

	static UNICODE_STRING ownerName = RTL_CONSTANT_STRING(L"Owner");
	static UNICODE_STRING sequenceName = RTL_CONSTANT_STRING(L"Sequence");
	static UNICODE_STRING filesNamePrefix = RTL_CONSTANT_STRING(L"RegFiles");
	static UNICODE_STRING processesNamePrefix = RTL_CONSTANT_STRING(L"RegProcs");
	static UNICODE_STRING servicesNamePrefix = RTL_CONSTANT_STRING(L"RegSvcs");

	memset(Info, 0, sizeof(H2_RM_SESSION_INFO));
	InitializeListHead(&Info->Files);
	InitializeListHead(&Info->Applications);
	InitializeListHead(&Info->Services);

	do
	{
		PKEY_VALUE_FULL_INFORMATION buffer;

		// Retrieve a value by index
		status = H2EnumerateFullValueKey(SessionKey, index, &buffer);

		if (!NT_SUCCESS(status))
			break;

		UNICODE_STRING name;
		name.Buffer = buffer->Name;
		name.Length = (USHORT)buffer->NameLength;
		name.MaximumLength = name.Length;

		PVOID data;
		data = RtlOffsetToPointer(buffer, buffer->DataOffset);

		if (RtlEqualUnicodeString(&name, &ownerName, TRUE))
		{
			// Save the owner
			Info->OwnerValid = (buffer->Type == REG_BINARY) && (buffer->DataLength == sizeof(RM_UNIQUE_PROCESS));

			if (Info->OwnerValid)
			{
				Info->Owner = *((PRM_UNIQUE_PROCESS)data);
			}
		}
		else if (RtlEqualUnicodeString(&name, &sequenceName, TRUE))
		{
			// Save the sequence
			Info->SequenceValid = (buffer->Type == REG_DWORD) && (buffer->DataLength == sizeof(ULONG));

			if (Info->SequenceValid)
			{
				Info->Sequence = *((PULONG)data);
			}
		}
		else if (H2MatchPrefixSuffixDigtsString(&name, &filesNamePrefix, 4))
		{
			// Parse and save a multi-string of files
			H2AppendStringsGroup(&name, data, buffer->DataLength / sizeof(WCHAR), &Info->Files);
		}
		else if (H2MatchPrefixSuffixDigtsString(&name, &processesNamePrefix, 4))
		{
			// Parse and save a multi-string of processes
			H2AppendStringsGroup(&name, data, buffer->DataLength / sizeof(WCHAR), &Info->Applications);

		}
		else if (H2MatchPrefixSuffixDigtsString(&name, &servicesNamePrefix, 4))
		{
			// Parse and save a multi-string of services
			H2AppendStringsGroup(&name, data, buffer->DataLength / sizeof(WCHAR), &Info->Services);
		}

		RtlFreeHeap(RtlProcessHeap(), 0, buffer);
		index++;
	} while (TRUE);

	if (status == STATUS_NO_MORE_ENTRIES)
		status = STATUS_SUCCESS;

	return status;
}

NTSTATUS
NTAPI
H2QueryRestartManagerSessionInfoByName(
	_In_ HANDLE RootKey,
	_In_ PUNICODE_STRING SessionName,
	_Out_ PH2_RM_SESSION_INFO Info
)
{
	NTSTATUS status;
	HANDLE hSessionKey;

	status = H2OpenRestartManagerSession(RootKey, SessionName, &hSessionKey);

	if (!NT_SUCCESS(status))
		return status;

	status = H2QueryRestartManagerSessionInfo(hSessionKey, Info);

	NtClose(hSessionKey);
	return status;
}

VOID
NTAPI
H2FreeRestartManagerSessionInfo(
	_Inout_ PH2_RM_SESSION_INFO Info
)
{
	H2FreeStringsGroup(&Info->Files);
	H2FreeStringsGroup(&Info->Applications);
	H2FreeStringsGroup(&Info->Services);
}

NTSTATUS
NTAPI
H2QuerySystemName(
	_Out_ PUNICODE_STRING SystemName
)
{
	NTSTATUS status;
	PVOID environment = NULL;

	if (!CreateEnvironmentBlock(&environment, NULL, FALSE))
		return ERROR_SEVERITY_ERROR | (FACILITY_NTWIN32 << 16) | (RtlGetLastWin32Error() & 0xFFFF);

	UNICODE_STRING name = RTL_CONSTANT_STRING(L"COMPUTERNAME");
	UNICODE_STRING value;

	value.Length = 0;
	value.MaximumLength = 10;

	do
	{
		value.Buffer = RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, value.MaximumLength);

		if (!value.Buffer)
		{
			status = STATUS_NO_MEMORY;
			break;
		}

		status = RtlQueryEnvironmentVariable_U(environment, &name, &value);

		if (!NT_SUCCESS(status))
		{
			RtlFreeHeap(RtlProcessHeap(), 0, value.Buffer);
			value.Buffer = NULL;

			if (status == STATUS_BUFFER_TOO_SMALL)
			{
				if (value.MaximumLength > 0xFFFC)
					break;

				// Include terminating zero
				value.MaximumLength += sizeof(WCHAR);
			}
		}
	} while (status == STATUS_BUFFER_TOO_SMALL);

	if (NT_SUCCESS(status))
		*SystemName = value;

	DestroyEnvironmentBlock(environment);
	return status;
}

VOID
NTAPI
H2FreeSystemName(
	_Inout_ PUNICODE_STRING SystemName
)
{
	RtlFreeHeap(RtlProcessHeap(), 0, SystemName->Buffer);
	SystemName->Length = 0;
	SystemName->MaximumLength = 0;
	SystemName->Buffer = NULL;
}

PSYSTEM_PROCESS_INFORMATION ProcessCache;

NTSTATUS
NTAPI
H2InitProcessLookupCache(
	VOID
)
{
	if (ProcessCache)
		return STATUS_SUCCESS;

	NTSTATUS status;
	ULONG bufferSize, returnLength;
	PSYSTEM_PROCESS_INFORMATION buffer;

	bufferSize = 0x100000;

	do
	{
		buffer = RtlAllocateHeap(RtlProcessHeap(), 0, bufferSize);

		if (!buffer)
			return STATUS_NO_MEMORY;

		status = NtQuerySystemInformation(
			SystemProcessInformation,
			buffer,
			bufferSize,
			&returnLength
		);

		if (!NT_SUCCESS(status))
		{
			RtlFreeHeap(RtlProcessHeap(), 0, buffer);
			buffer = NULL;

			if (status == STATUS_BUFFER_TOO_SMALL)
			{
				if (returnLength <= bufferSize)
					return status;

				bufferSize = returnLength;
			}
		}

	} while (status == STATUS_BUFFER_TOO_SMALL);

	if (NT_SUCCESS(status))
		ProcessCache = buffer;

	return status;
}

VOID
NTAPI
H2FreeProcessLookupCache(
	VOID
)
{
	if (ProcessCache)
	{
		RtlFreeHeap(RtlProcessHeap(), 0, ProcessCache);
		ProcessCache = NULL;
	}
}

H2_PROCESS_STATE
NTAPI
H2LookupProcessState(
	_In_ PRM_UNIQUE_PROCESS Process
)
{
	if (!NT_SUCCESS(H2InitProcessLookupCache()) || !ProcessCache)
		return ProcessStateUnknown; // Snapshot not available

	PSYSTEM_PROCESS_INFORMATION cursor = ProcessCache;

	do
	{
		if (cursor->UniqueProcessId == (HANDLE)(ULONG_PTR)Process->dwProcessId)
		{
			if (cursor->CreateTime.LowPart == Process->ProcessStartTime.dwLowDateTime &&
				cursor->CreateTime.HighPart == Process->ProcessStartTime.dwHighDateTime)
				return ProcessStateActive; // Found
			else
				return ProcessStateTerminated; // PID reused
		}

		if (cursor->NextEntryOffset)
			cursor = (PVOID)RtlOffsetToPointer(cursor, cursor->NextEntryOffset);
		else
			return ProcessStateTerminated; // PID not found

	} while (TRUE);
}

NTSTATUS
NTAPI
H2QueryProcessImageName(
	_In_ PRM_UNIQUE_PROCESS Process,
	_Out_ PUNICODE_STRING ImageName
)
{
	NTSTATUS status;
	ULONG returnLength;
	SYSTEM_PROCESS_ID_INFORMATION request;

	request.ProcessId = (HANDLE)(ULONG_PTR)Process->dwProcessId;
	request.ImageName.Length = 0;
	request.ImageName.MaximumLength = 0xFFFE;
	request.ImageName.Buffer = RtlAllocateHeap(RtlProcessHeap(), 0, request.ImageName.MaximumLength);

	if (!request.ImageName.Buffer)
		return STATUS_NO_MEMORY;

	status = NtQuerySystemInformation(
		SystemProcessIdInformation,
		&request,
		sizeof(request),
		&returnLength
	);

	if (NT_SUCCESS(status))
	{
		status = RtlDuplicateUnicodeString(
			RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE,
			&request.ImageName,
			ImageName
		);
	}

	RtlFreeHeap(RtlProcessHeap(), 0, request.ImageName.Buffer);
	return status;
}
