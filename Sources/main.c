/*
 * Copyright (c) 2024 Hunt & Hackett.
 *
 * This project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#include <phnt_windows.h>
#include <phnt.h>
#include <stdio.h>
#include <wchar.h>
#include "helpers.h"
#include "artifact_collector.h"
#include "xml_export.h"

int wmain(int argc, wchar_t* argv[])
{
	NTSTATUS status;
	PCWSTR userName;
	PCWSTR outputFile;
	PSID userSid = NULL;
	HANDLE hRootKey = NULL;
	IXmlWriter* xmlWriter = NULL;

	wprintf_s(L"A tool for collecting Restart Manager artifacts by Hunt & Hackett.\r\n");
	wprintf_s(L"Usage: RmArtifacts.exe [[-u <User name or SID>]] [[-o <Output XML file>]] \r\n\r\n");

	status = H2ParseArguments(argc, argv, &userName, &outputFile);

	if (!NT_SUCCESS(status))
		return status;

	// Determine which HKU hive to use
	status = H2DetermineUserSid(userName, &userSid);

	if (!NT_SUCCESS(status))
	{
		wprintf_s(L"Unable to determine user SID: 0x%0.8X\r\n", status);
		goto CLEANUP;
	}
	else if (!userName)
	{
		wprintf_s(L"Using the current user SID...\r\n\r\n");
	}

	if (outputFile)
	{
		// Prepare the output file
		status = H2XmlInitialize(outputFile, &xmlWriter);

		if (!SUCCEEDED(status))
		{
			wprintf_s(L"Unable to create the output file: 0x%0.8X\r\n", status);
			goto CLEANUP;
		}

		H2XmlWriteSystemInfoElement(xmlWriter);
		H2XmlBeginDatabaseElement(xmlWriter, userSid);
	}

	// Enable the backup privilege to help with accessing hives of other users
	BOOLEAN wasEnabled;
	RtlAdjustPrivilege(SE_BACKUP_PRIVILEGE, TRUE, FALSE, &wasEnabled);

	// Open RestartManager's database root
	status = H2OpenRestartManagerRoot(&hRootKey, userSid);

	if (status == STATUS_OBJECT_NAME_NOT_FOUND)
	{
		wprintf_s(L"Restart Manager database is not initialized for the user.\r\n");
		goto CLEANUP;
	}
	else if (!NT_SUCCESS(status))
	{
		wprintf_s(L"Unable to open Restart Manager database: 0x%0.8X\r\n", status);
		H2XmlReportQueryFailure(xmlWriter, status);
		goto CLEANUP;
	}

	// Capture database last write time
	H2XmlCaptureDatabaseLastWriteTime(xmlWriter, hRootKey);

	// Enumerate Restart Manager sessions
	ULONG index;
	index = 0;

	do
	{
		UNICODE_STRING sessionName;
		LARGE_INTEGER lastWriteTime;

		// Retrieve session name by index
		status = H2EnumerateRestartManagerSessions(hRootKey, index, &sessionName, &lastWriteTime);

		if (status == STATUS_NO_MORE_ENTRIES)
		{
			wprintf_s(L"Found %d sessions.\r\n", index);
			status = STATUS_SUCCESS;
			break;
		}
		else if (!NT_SUCCESS(status))
		{
			wprintf_s(L"Unable to enumerate Restart Manager sessions: 0x%0.8X\r\n", status);
			goto CLEANUP;
		}

		// Print generic info
		wprintf(L"[*] %wZ\r\n", &sessionName);
		wprintf(L"  Modified: ");
		H2PrintTimestamp(&lastWriteTime);
		wprintf(L"\r\n");

		H2XmlBeginSessionElement(xmlWriter, sessionName.Buffer, &lastWriteTime);

		// Collect detailed info about the session
		H2_RM_SESSION_INFO info;
		PH2_STRINGS_GROUP entry;

		status = H2QueryRestartManagerSessionInfoByName(hRootKey, &sessionName, &info);

		if (!NT_SUCCESS(status))
		{
			wprintf(L"  <Unable to query>: 0x%0.8X\r\n", status);
			H2XmlReportQueryFailure(xmlWriter, status);
			status = STATUS_MORE_ENTRIES;
		}
		else
		{
			// Print the sequence
			if (info.SequenceValid)
			{
				H2XmlWriteSequenceElement(xmlWriter, info.Sequence);
			}

			// Print the owner
			if (info.OwnerValid)
			{
				wprintf(L"  Owner: (PID %d; started ", info.Owner.dwProcessId);
				H2PrintTimestamp((PLARGE_INTEGER)&info.Owner.ProcessStartTime);
				wprintf(L")\r\n");

				H2XmlWriteOwnerElement(xmlWriter, &info.Owner);
			}

			// Print resources
			wprintf(L"  [Resources]\r\n");
			H2XmlBeginResourcesElement(xmlWriter);

			// Files
			entry = CONTAINING_RECORD(info.Files.Flink, H2_STRINGS_GROUP, Link);
			while (&entry->Link != &info.Files)
			{
				H2XmlBeginResourceGroupElement(xmlWriter, RmResourceFile, entry->GroupName.Buffer);

				for (ULONG i = 0; i < entry->Strings.Count; i++)
				{
					wprintf(L"    File: %wZ\r\n", &entry->Strings.Strings[i]);
					H2XmlWriteFileElement(xmlWriter, entry->Strings.Strings[i].Buffer);
				}

				H2XmlEndResourceGroupElement(xmlWriter);
				entry = CONTAINING_RECORD(entry->Link.Flink, H2_STRINGS_GROUP, Link);
			}

			// Applications
			entry = CONTAINING_RECORD(info.Applications.Flink, H2_STRINGS_GROUP, Link);

			while (&entry->Link != &info.Applications)
			{
				H2XmlBeginResourceGroupElement(xmlWriter, RmResourceApplication, entry->GroupName.Buffer);

				for (ULONG i = 0; i < entry->Strings.Count; i++)
				{
					RM_UNIQUE_PROCESS process;

					if (H2ParseRmUniqueProcess(&entry->Strings.Strings[i], &process))
					{
						wprintf(L"    Application: (PID %d; started ", process.dwProcessId);
						H2PrintTimestamp((PLARGE_INTEGER)&process.ProcessStartTime);
						wprintf(L")\r\n");

						H2XmlWriteApplicationElement(xmlWriter, &process);
					}
					else
					{
						wprintf(L"    Application (invalid): %wZ\r\n", &entry->Strings.Strings[i]);
						H2XmlWriteApplicationElementRaw(xmlWriter, entry->Strings.Strings[i].Buffer);
					}
				}

				H2XmlEndResourceGroupElement(xmlWriter);
				entry = CONTAINING_RECORD(entry->Link.Flink, H2_STRINGS_GROUP, Link);
			}

			// Services
			entry = CONTAINING_RECORD(info.Services.Flink, H2_STRINGS_GROUP, Link);

			while (&entry->Link != &info.Services)
			{
				H2XmlBeginResourceGroupElement(xmlWriter, RmResourceService, entry->GroupName.Buffer);

				for (ULONG i = 0; i < entry->Strings.Count; i++)
				{
					wprintf(L"    Service: %wZ\r\n", &entry->Strings.Strings[i]);
					H2XmlWriteServiceElement(xmlWriter, entry->Strings.Strings[i].Buffer);
				}

				H2XmlEndResourceGroupElement(xmlWriter);
				entry = CONTAINING_RECORD(entry->Link.Flink, H2_STRINGS_GROUP, Link);
			}

			H2XmlEndResourcesElement(xmlWriter);
		}

		wprintf(L"\r\n");
		H2XmlEndSessionElement(xmlWriter);
		RtlFreeUnicodeString(&sessionName);
		index++;
	} while (TRUE);

CLEANUP:
	if (userSid)
		RtlFreeSid(userSid);

	if (xmlWriter)
	{
		H2XmlFinalize(xmlWriter);
		IXmlWriter_Release(xmlWriter);
	}

	H2FreeProcessLookupCache();
}