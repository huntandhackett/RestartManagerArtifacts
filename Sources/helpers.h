/*
 * Copyright (c) 2024 Hunt & Hackett.
 *
 * This project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#ifndef _HELPERS_H
#define _HELPERS_H

#include <phnt_windows.h>
#include <phnt.h>
#include <RestartManager.h>

// Arguments

NTSTATUS
NTAPI
H2ParseArguments(
	_In_ LONG argc,
	_In_ PCWSTR argv[],
	_Out_ _Post_maybenull_ PCWSTR *UserName,
	_Out_ _Post_maybenull_ PCWSTR *OutputFile
);

// Timestamps

#define TIMESTAMP_STRING_LENGTH 20

_Success_(return)
BOOLEAN
NTAPI
H2FormatTimestamp(
	_Out_writes_(TIMESTAMP_STRING_LENGTH) PWSTR Buffer,
	_In_ PLARGE_INTEGER NativeTime
);

VOID
NTAPI
H2PrintTimestamp(
	_In_ PLARGE_INTEGER NativeTime
);

// Multi-string capture

typedef struct _H2_STRINGS {
	ULONG Count;
	_Field_size_(Count) PUNICODE_STRING Strings;
} H2_STRINGS, *PH2_STRINGS;

NTSTATUS
NTAPI
H2CaptureMultiStrings(
	_In_reads_(BufferLength) PWCHAR Buffer,
	_In_ ULONG BufferLength,
	_Out_ PH2_STRINGS Strings
);

VOID
NTAPI
H2FreeMultiStrings(
	_Inout_ PH2_STRINGS Strings
);

// Multi-string groups

typedef struct _H2_STRINGS_GROUP {
	LIST_ENTRY Link;
	UNICODE_STRING GroupName;
	H2_STRINGS Strings;
} H2_STRINGS_GROUP, * PH2_STRINGS_GROUP;

NTSTATUS
NTAPI
H2AppendStringsGroup(
	_In_ PUNICODE_STRING GroupName,
	_In_reads_(BufferLength) PWCHAR Buffer,
	_In_ ULONG BufferLength,
	_Inout_ PLIST_ENTRY ListHead
);

VOID
NTAPI
H2FreeStringsGroup(
	_Inout_ PLIST_ENTRY ListHead
);

// String matching

BOOLEAN
NTAPI
H2MatchPrefixSuffixDigtsString(
	_In_ PUNICODE_STRING String,
	_In_ PUNICODE_STRING Prefix,
	_In_ USHORT NumberOfSuffixDigits
);

// Parsing

_Success_(return)
BOOLEAN
NTAPI
H2ParseRmUniqueProcess(
	_In_ PUNICODE_STRING String,
	_Out_ PRM_UNIQUE_PROCESS Process
);

#endif
