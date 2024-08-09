/*
 * Copyright (c) 2024 Hunt & Hackett.
 *
 * This project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#include "helpers.h"
#include <time.h>
#include <wchar.h>

// Arguments

NTSTATUS
NTAPI
H2ParseArguments(
	_In_ LONG argc,
	_In_ PCWSTR argv[],
	_Out_ _Post_maybenull_ PCWSTR *UserName,
	_Out_ _Post_maybenull_ PCWSTR *OutputFile
)
{
	*UserName = NULL;
	*OutputFile = NULL;

	if (argc <= 1)
	{
		// No extra parameters - print usage and use defaults
		return STATUS_SUCCESS;
	}

	if (argc % 2 == 0)
	{
		// Currently only accepting extra parameters in pairs
		return STATUS_INVALID_PARAMETER;
	}

	for (LONG i = 1; i < argc - 1; i++)
	{
		if (wcscmp(argv[i], L"-u") == 0)
		{
			*UserName = argv[i + 1];
			i++;
		}
		else if (wcscmp(argv[i], L"-o") == 0)
		{
			*OutputFile = argv[i + 1];
			i++;
		}
		else
		{
			// An unrecognized parameter
			return STATUS_INVALID_PARAMETER;
		}
	}

	return STATUS_SUCCESS;
}

// Timestamps

#define NATIVE_SECOND 10000000
#define SecondsToStartOf1970 11644473600

_Success_(return)
BOOLEAN
NTAPI
H2FormatTimestamp(
	_Out_writes_(TIMESTAMP_STRING_LENGTH) PWSTR Buffer,
	_In_ PLARGE_INTEGER NativeTime
)
{
	time_t timeStamp = (NativeTime->QuadPart -
		((PLARGE_INTEGER)(&USER_SHARED_DATA->TimeZoneBias))->QuadPart)
		/ NATIVE_SECOND - SecondsToStartOf1970;

	// Convert to calendar tim
	struct tm calendarTime;

	if (gmtime_s(&calendarTime, &timeStamp))
		return FALSE;

	// Construct the string
	memset(Buffer, 0, TIMESTAMP_STRING_LENGTH * sizeof(WCHAR));
	return !!wcsftime(Buffer, TIMESTAMP_STRING_LENGTH, L"%F %T", &calendarTime);
}

VOID
NTAPI
H2PrintTimestamp(
	_In_ PLARGE_INTEGER NativeTime
)
{
	WCHAR timeStamp[TIMESTAMP_STRING_LENGTH];

	if (H2FormatTimestamp(timeStamp, NativeTime))
		wprintf(L"%s", timeStamp);
}

// Multi-strings

NTSTATUS
NTAPI
H2CaptureMultiStrings(
	_In_reads_(BufferLength) PWCHAR Buffer,
	_In_ ULONG BufferLength,
	_Out_ PH2_STRINGS Strings
)
{
	NTSTATUS status;
	ULONG count;
	PWCHAR cursor, bufferEnd;
	PUNICODE_STRING strings;

	count = 0;
	cursor = Buffer;
	bufferEnd = Buffer + BufferLength;

	while (cursor < bufferEnd && *cursor != L'\0')
	{
		while (cursor < bufferEnd && *cursor != L'\0')
			cursor++;

		count++;
		cursor++;
	}

	if (!count)
	{
		Strings->Count = 0;
		Strings->Strings = NULL;
		return STATUS_SUCCESS;
	}

	strings = RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, count * sizeof(UNICODE_STRING));

	if (!strings)
		return STATUS_NO_MEMORY;

	count = 0;
	cursor = Buffer;
	status = STATUS_UNSUCCESSFUL;
	UNICODE_STRING item;

	while (cursor < bufferEnd && *cursor != L'\0')
	{
		item.Length = 0;
		item.MaximumLength = 0;
		item.Buffer = cursor;

		while (cursor < bufferEnd && *cursor != L'\0')
		{
			cursor++;
			item.Length += sizeof(WCHAR);
			item.MaximumLength += sizeof(WCHAR);
		}

		status = RtlDuplicateUnicodeString(
			RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE,
			&item,
			&strings[count]
		);

		if (!NT_SUCCESS(status))
			break;

		count++;
		cursor++;
	}

	if (NT_SUCCESS(status))
	{
		Strings->Strings = strings;
		Strings->Count = count;
	}
	else
	{
		RtlFreeHeap(RtlProcessHeap(), 0, strings);
		Strings->Strings = NULL;
		Strings->Count = 0;
	}

	return status;
}

VOID
NTAPI
H2FreeMultiStrings(
	_Inout_ PH2_STRINGS Strings
)
{
	if (Strings->Strings)
	{
		for (ULONG i = 0; i < Strings->Count; i++)
			RtlFreeUnicodeString(&Strings->Strings[i]);

		RtlFreeHeap(RtlProcessHeap(), 0, Strings->Strings);
	}

	Strings->Count = 0;
	Strings->Strings = NULL;
}

// Multi-string groups

NTSTATUS
NTAPI
H2AppendStringsGroup(
	_In_ PUNICODE_STRING GroupName,
	_In_reads_(BufferLength) PWCHAR Buffer,
	_In_ ULONG BufferLength,
	_Inout_ PLIST_ENTRY ListHead
)
{
	NTSTATUS status;
	PH2_STRINGS_GROUP entry = RtlAllocateHeap(RtlProcessHeap(), 0, sizeof(H2_STRINGS_GROUP));

	if (!entry)
		return STATUS_NO_MEMORY;

	status = RtlDuplicateUnicodeString(
		RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE,
		GroupName,
		&entry->GroupName
	);

	if (!NT_SUCCESS(status))
		return status;

	status = H2CaptureMultiStrings(Buffer, BufferLength, &entry->Strings);

	if (NT_SUCCESS(status))
		InsertTailList(ListHead, &entry->Link);
	else
		RtlFreeHeap(RtlProcessHeap(), 0, entry);

	return status;
}

VOID
NTAPI
H2FreeStringsGroup(
	_Inout_ PLIST_ENTRY ListHead
)
{
	PLIST_ENTRY entry;
	PH2_STRINGS_GROUP group;

	while (!IsListEmpty(ListHead))
	{
		entry = RemoveTailList(ListHead);
		group = CONTAINING_RECORD(entry, H2_STRINGS_GROUP, Link);

		H2FreeMultiStrings(&group->Strings);
		RtlFreeUnicodeString(&group->GroupName);
		RtlFreeHeap(RtlProcessHeap(), 0, group);
	}
}

// String matching

BOOLEAN
NTAPI
H2MatchPrefixSuffixDigtsString(
	_In_ PUNICODE_STRING String,
	_In_ PUNICODE_STRING Prefix,
	_In_ USHORT NumberOfSuffixDigits
)
{
	if (String->Length != Prefix->Length + NumberOfSuffixDigits * sizeof(WCHAR))
		return FALSE;

	if (!RtlPrefixUnicodeString(Prefix, String, TRUE))
		return FALSE;

	for (USHORT i = Prefix->Length / sizeof(WCHAR); i < String->Length / sizeof(WCHAR); i++)
	{
		WCHAR c = String->Buffer[i];

		if (c < L'0' || c > L'9')
			return FALSE;
	}

	return TRUE;
}

// Parsing

_Success_(return)
BOOLEAN
NTAPI
H2ParseRmUniqueProcess(
	_In_ PUNICODE_STRING String,
	_Out_ PRM_UNIQUE_PROCESS Process
)
{
	//                dwPID     dwHi    dwLow
	//               ________ ________ _______
	// The format is xxxxxxxx:xxxxxxxx:xxxxxxxx
	//               |        |        |
	// Index:        0        9        18

	if (String->Length != 52)
		return FALSE;

	if ((String->Buffer[8] != L':') || (String->Buffer[17] != L':'))
		return FALSE;

	UNICODE_STRING part;
	part.Length = 16;
	part.MaximumLength = 16;

	// ProcessId
	part.Buffer = String->Buffer;

	if (!NT_SUCCESS(RtlUnicodeStringToInteger(&part, 16, &Process->dwProcessId)))
		return FALSE;

	// High date time
	part.Buffer = &String->Buffer[9];

	if (!NT_SUCCESS(RtlUnicodeStringToInteger(&part, 16, &Process->ProcessStartTime.dwHighDateTime)))
		return FALSE;

	// Low date time
	part.Buffer = &String->Buffer[18];

	if (!NT_SUCCESS(RtlUnicodeStringToInteger(&part, 16, &Process->ProcessStartTime.dwLowDateTime)))
		return FALSE;

	return TRUE;
}
