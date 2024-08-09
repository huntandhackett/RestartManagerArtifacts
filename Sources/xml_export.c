/*
 * Copyright (c) 2024 Hunt & Hackett.
 *
 * This project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#include "xml_export.h"
#include "helpers.h"
#include "artifact_collector.h"
#include <Shlwapi.h>
#include <wchar.h>

// Conversion helpers

_Success_(return)
BOOLEAN
STDAPICALLTYPE
H2XmlWriteUlongAttribute(
	_In_ IXmlWriter *XmlWriter,
	_In_ PCWSTR Name,
	_In_ ULONG Value
)
{
	WCHAR buffer[12] = { 0 };
	UNICODE_STRING str = { sizeof(buffer), sizeof(buffer), buffer };

	if (!NT_SUCCESS(RtlIntegerToUnicodeString(Value, 10, &str)))
		return FALSE;

	return SUCCEEDED(IXmlWriter_WriteAttributeString(XmlWriter, NULL, Name, NULL, buffer));
}

_Success_(return)
BOOLEAN
STDAPICALLTYPE
H2XmlWriteUlong64Attribute(
	_In_ IXmlWriter *XmlWriter,
	_In_ PCWSTR Name,
	_In_ ULONG64 Value
)
{
	WCHAR buffer[22] = { 0 };
	UNICODE_STRING str = { sizeof(buffer), sizeof(buffer), buffer };

	if (!NT_SUCCESS(RtlInt64ToUnicodeString(Value, 10, &str)))
		return FALSE;

	return SUCCEEDED(IXmlWriter_WriteAttributeString(XmlWriter, NULL, Name, NULL, buffer));
}

VOID
STDAPICALLTYPE
H2XmlWriteTimeAttributes(
	_In_ IXmlWriter *XmlWriter,
	_In_ PLARGE_INTEGER Time,
	_In_ PCWSTR AttributeName,
	_In_ PCWSTR AttributeNameRaw
)
{
	WCHAR timeStamp[TIMESTAMP_STRING_LENGTH];

	if (H2FormatTimestamp(timeStamp, Time))
		IXmlWriter_WriteAttributeString(XmlWriter, NULL, AttributeName, NULL, timeStamp);

	H2XmlWriteUlong64Attribute(XmlWriter, AttributeNameRaw, Time->QuadPart);
}

VOID
STDAPICALLTYPE
H2XmlWriteProcessElement(
	_In_ IXmlWriter *XmlWriter,
	_In_ PRM_UNIQUE_PROCESS Process,
	_In_ PCWSTR ElementName
)
{
	IXmlWriter_WriteStartElement(XmlWriter, NULL, ElementName, NULL);

	WCHAR pidBuffer[15] = { 0 };
	UNICODE_STRING pidStr = { sizeof(pidBuffer), sizeof(pidBuffer), pidBuffer };

	if (NT_SUCCESS(RtlIntegerToUnicodeString(Process->dwProcessId, 10, &pidStr)))
		IXmlWriter_WriteAttributeString(XmlWriter, NULL, L"PID", NULL, pidBuffer);

	H2XmlWriteTimeAttributes(XmlWriter, (PLARGE_INTEGER)&Process->ProcessStartTime, L"StartedAt", L"StartedAtRaw");

	switch (H2LookupProcessState(Process))
	{
		case ProcessStateActive:
			{
				IXmlWriter_WriteAttributeString(XmlWriter, NULL, L"CurrentState", NULL, L"Active");

				UNICODE_STRING imageName;

				if (NT_SUCCESS(H2QueryProcessImageName(Process, &imageName)))
				{
					IXmlWriter_WriteAttributeString(XmlWriter, NULL, L"ImageName", NULL, imageName.Buffer);
					RtlFreeUnicodeString(&imageName);
				}
			}
			break;
		case ProcessStateTerminated:
			IXmlWriter_WriteAttributeString(XmlWriter, NULL, L"CurrentState", NULL, L"Terminated");
			break;
	}

	IXmlWriter_WriteEndElement(XmlWriter);
}

// Initialization

HRESULT
STDAPICALLTYPE
H2XmlInitialize(
	_In_ PCWSTR FileName,
	_Out_ IXmlWriter **XmlWriter
)
{
	HRESULT hresult;
	IStream* stream = NULL;
	IXmlWriter* xmlWriter = NULL;

	// Create a writer stream on the file
	hresult = SHCreateStreamOnFileEx(
		FileName,
		STGM_WRITE | STGM_SHARE_DENY_WRITE | STGM_CREATE,
		FILE_ATTRIBUTE_NORMAL,
		TRUE,
		NULL,
		&stream
	);

	if (!SUCCEEDED(hresult))
		goto CLEANUP;

	// Create an XmlLite writer
	hresult = CreateXmlWriter(
		&IID_IXmlWriter,
		&xmlWriter,
		NULL
	);

	if (!SUCCEEDED(hresult))
		goto CLEANUP;

	// Associate it with the file stream
	hresult = IXmlWriter_SetOutput(xmlWriter, (IUnknown*)stream);

	if (!SUCCEEDED(hresult))
		goto CLEANUP;

	// Write the header
	IXmlWriter_SetProperty(xmlWriter, XmlWriterProperty_Indent, TRUE);
	IXmlWriter_WriteStartDocument(xmlWriter, TRUE);
	IXmlWriter_WriteStartElement(xmlWriter, NULL, L"Artifacts", NULL);

	// Attach the timestamp
	LARGE_INTEGER currentTime;
	currentTime.QuadPart = ((PLARGE_INTEGER)&USER_SHARED_DATA->SystemTime)->QuadPart;
	H2XmlWriteTimeAttributes(xmlWriter, &currentTime, L"CaptureTime", L"CaptureTimeRaw");

	*XmlWriter = xmlWriter;
	xmlWriter = NULL;

CLEANUP:
	if (stream)
		IStream_Release(stream);

	if (xmlWriter)
		IXmlWriter_Release(xmlWriter);

	return hresult;
}

HRESULT
STDAPICALLTYPE
H2XmlFinalize(
	_In_ IXmlWriter *XmlWriter
)
{
	IXmlWriter_WriteEndElement(XmlWriter);
	IXmlWriter_WriteEndDocument(XmlWriter);
	return IXmlWriter_Flush(XmlWriter);
}

// System info

VOID
STDAPICALLTYPE
H2XmlWriteSystemInfoElement(
	_In_ IXmlWriter *XmlWriter
)
{
	IXmlWriter_WriteStartElement(XmlWriter, NULL, L"SystemInfo", NULL);
	IXmlWriter_WriteStartElement(XmlWriter, NULL, L"System", NULL);
	{
		UNICODE_STRING systemName;

		if (NT_SUCCESS(H2QuerySystemName(&systemName)))
		{
			IXmlWriter_WriteAttributeString(XmlWriter, NULL, L"Name", NULL, systemName.Buffer);
			H2FreeSystemName(&systemName);
		}
	}
	IXmlWriter_WriteEndElement(XmlWriter);
	IXmlWriter_WriteStartElement(XmlWriter, NULL, L"Boot", NULL);
	{
		if (RtlGetCurrentPeb()->OSMajorVersion >= 10)
			H2XmlWriteUlongAttribute(XmlWriter, L"BootId", USER_SHARED_DATA->BootId);

		LARGE_INTEGER bootTime;
		bootTime.QuadPart = ((PLARGE_INTEGER)&USER_SHARED_DATA->SystemTime)->QuadPart -
			((PLARGE_INTEGER)&USER_SHARED_DATA->InterruptTime)->QuadPart;

		H2XmlWriteTimeAttributes(XmlWriter, &bootTime, L"BootTime", L"BootTimeRaw");
	}
	IXmlWriter_WriteEndElement(XmlWriter);
	IXmlWriter_WriteEndElement(XmlWriter);
}

// Restart Manager database

VOID
STDAPICALLTYPE
H2XmlBeginDatabaseElement(
	_In_ IXmlWriter *XmlWriter,
	_In_ PSID UserSid
)
{
	IXmlWriter_WriteStartElement(XmlWriter, NULL, L"RestartManagerDatabase", NULL);

	WCHAR sddlBuffer[SECURITY_MAX_SID_STRING_CHARACTERS] = { 0 };
	UNICODE_STRING sddl = { 0, sizeof(sddlBuffer), sddlBuffer };

	if (NT_SUCCESS(RtlConvertSidToUnicodeString(&sddl, UserSid, FALSE)))
		IXmlWriter_WriteAttributeString(XmlWriter, NULL, L"UserSid", NULL, sddl.Buffer);
}

VOID
STDAPICALLTYPE
H2XmlReportQueryFailure(
	_In_opt_ IXmlWriter *XmlWriter,
	_In_ NTSTATUS Status
)
{
	if (!XmlWriter)
		return;

	WCHAR buffer[12] = { 0 };

	if (swprintf_s(buffer, (sizeof(buffer) - sizeof(UNICODE_NULL)) / sizeof(WCHAR), L"0x%0.8X", Status) > 0)
		IXmlWriter_WriteAttributeString(XmlWriter, NULL, L"QueryFailureStatus", NULL, buffer);
}

VOID
STDAPICALLTYPE
H2XmlCaptureDatabaseLastWriteTime(
	_In_opt_ IXmlWriter *XmlWriter,
	_In_ HANDLE RootKeyHndle
)
{
	if (!XmlWriter)
		return;

	LARGE_INTEGER lastWriteTime;

	if (NT_SUCCESS(H2QueryRestartManagerRootLastWriteTime(RootKeyHndle, &lastWriteTime)))
		H2XmlWriteTimeAttributes(XmlWriter, &lastWriteTime, L"LastWriteTime", L"LastWriteTimeRaw");
}

// Sessions

VOID
STDAPICALLTYPE
H2XmlBeginSessionElement(
	_In_opt_ IXmlWriter *XmlWriter,
	_In_ PCWSTR SessionName,
	_In_ PLARGE_INTEGER LastWriteTime
)
{
	if (!XmlWriter)
		return;

	IXmlWriter_WriteStartElement(XmlWriter, NULL, L"Session", NULL);
	IXmlWriter_WriteAttributeString(XmlWriter, NULL, L"Name", NULL, SessionName);
	H2XmlWriteTimeAttributes(XmlWriter, LastWriteTime, L"LastWriteTime", L"LastWriteTimeRaw");
}

VOID
STDAPICALLTYPE
H2XmlEndSessionElement(
	_In_opt_ IXmlWriter *XmlWriter
)
{
	if (XmlWriter)
		IXmlWriter_WriteEndElement(XmlWriter);
}

VOID
STDAPICALLTYPE
H2XmlWriteSequenceElement(
	_In_opt_ IXmlWriter *XmlWriter,
	_In_ ULONG Sequence
)
{
	if (!XmlWriter)
		return;

	IXmlWriter_WriteStartElement(XmlWriter, NULL, L"Sequence", NULL);

	WCHAR sequenceBuffer[15] = { 0 };
	UNICODE_STRING sequenceStr = { sizeof(sequenceBuffer), sizeof(sequenceBuffer), sequenceBuffer };

	if (NT_SUCCESS(RtlIntegerToUnicodeString(Sequence, 10, &sequenceStr)))
		IXmlWriter_WriteAttributeString(XmlWriter, NULL, L"Value", NULL, sequenceBuffer);

	IXmlWriter_WriteEndElement(XmlWriter);
}

VOID
STDAPICALLTYPE
H2XmlWriteOwnerElement(
	_In_opt_ IXmlWriter *XmlWriter,
	_In_ PRM_UNIQUE_PROCESS Process
)
{
	if (XmlWriter)
		H2XmlWriteProcessElement(XmlWriter, Process, L"Owner");
}

VOID
STDAPICALLTYPE
H2XmlBeginResourcesElement(
	_In_opt_ IXmlWriter *XmlWriter
)
{
	if (XmlWriter)
		IXmlWriter_WriteStartElement(XmlWriter, NULL, L"RegisteredResources", NULL);
}

VOID
STDAPICALLTYPE
H2XmlEndResourcesElement(
	_In_opt_ IXmlWriter *XmlWriter
)
{
	if (XmlWriter)
		IXmlWriter_WriteEndElement(XmlWriter);
}

VOID
STDAPICALLTYPE
H2XmlBeginResourceGroupElement(
	_In_opt_ IXmlWriter *XmlWriter,
	_In_ H2_RM_RESOURCE_TYPE ResourceType,
	_In_ PCWSTR Name
)
{
	if (!XmlWriter)
		return;

	PCWSTR typeString = NULL;

	switch (ResourceType)
	{
		case RmResourceFile:
			typeString = L"File";
			break;
		case RmResourceApplication:
			typeString = L"Application";
			break;
		case RmResourceService:
			typeString = L"Service";
			break;
	}

	IXmlWriter_WriteStartElement(XmlWriter, NULL, L"Group", NULL);

	if (typeString)
		IXmlWriter_WriteAttributeString(XmlWriter, NULL, L"Type", NULL, typeString);

	IXmlWriter_WriteAttributeString(XmlWriter, NULL, L"Name", NULL, Name);
}

VOID
STDAPICALLTYPE
H2XmlEndResourceGroupElement(
	_In_opt_ IXmlWriter *XmlWriter
)
{
	if (XmlWriter)
		IXmlWriter_WriteEndElement(XmlWriter);
}

VOID
STDAPICALLTYPE
H2XmlWriteFileElement(
	_In_opt_ IXmlWriter *XmlWriter,
	_In_ PCWSTR Path
)
{
	if (!XmlWriter)
		return;

	IXmlWriter_WriteStartElement(XmlWriter, NULL, L"File", NULL);
	IXmlWriter_WriteAttributeString(XmlWriter, NULL, L"Path", NULL, Path);
	IXmlWriter_WriteEndElement(XmlWriter);
}

VOID
STDAPICALLTYPE
H2XmlWriteApplicationElement(
	_In_opt_ IXmlWriter *XmlWriter,
	_In_ PRM_UNIQUE_PROCESS Process
)
{
	if (XmlWriter)
		H2XmlWriteProcessElement(XmlWriter, Process, L"Application");
}

VOID
STDAPICALLTYPE
H2XmlWriteApplicationElementRaw(
	_In_opt_ IXmlWriter *XmlWriter,
	_In_ PCWSTR RawValue
)
{
	if (!XmlWriter)
		return;

	IXmlWriter_WriteStartElement(XmlWriter, NULL, L"Application", NULL);
	IXmlWriter_WriteAttributeString(XmlWriter, NULL, L"ValueRaw", NULL, RawValue);
	IXmlWriter_WriteEndElement(XmlWriter);
}

VOID
STDAPICALLTYPE
H2XmlWriteServiceElement(
	_In_opt_ IXmlWriter *XmlWriter,
	_In_ PCWSTR SvcName
)
{
	if (!XmlWriter)
		return;

	IXmlWriter_WriteStartElement(XmlWriter, NULL, L"Service", NULL);
	IXmlWriter_WriteAttributeString(XmlWriter, NULL, L"Name", NULL, SvcName);
	IXmlWriter_WriteEndElement(XmlWriter);
}
