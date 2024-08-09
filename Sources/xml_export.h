/*
 * Copyright (c) 2024 Hunt & Hackett.
 *
 * This project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#ifndef _XML_EXPORT_H
#define _XML_EXPORT_H

#include <phnt_windows.h>
#include <phnt.h>
#include <objbase.h>
#include <xmllite.h>
#include <RestartManager.h>

// Initialization

HRESULT
STDAPICALLTYPE
H2XmlInitialize(
	_In_ PCWSTR FileName,
	_Out_ IXmlWriter **XmlWriter
);

HRESULT
STDAPICALLTYPE
H2XmlFinalize(
	_In_ IXmlWriter *XmlWriter
);

// System info

VOID
STDAPICALLTYPE
H2XmlWriteSystemInfoElement(
	_In_ IXmlWriter *XmlWriter
);

// Restart Manager database

VOID
STDAPICALLTYPE
H2XmlBeginDatabaseElement(
	_In_ IXmlWriter *XmlWriter,
	_In_ PSID UserSid
);

VOID
STDAPICALLTYPE
H2XmlReportQueryFailure(
	_In_opt_ IXmlWriter *XmlWriter,
	_In_ NTSTATUS Status
);

VOID
STDAPICALLTYPE
H2XmlCaptureDatabaseLastWriteTime(
	_In_opt_ IXmlWriter *XmlWriter,
	_In_ HANDLE RootKeyHndle
);

// Sessions

VOID
STDAPICALLTYPE
H2XmlBeginSessionElement(
	_In_opt_ IXmlWriter *XmlWriter,
	_In_ PCWSTR SessionName,
	_In_ PLARGE_INTEGER LastWriteTime
);

VOID
STDAPICALLTYPE
H2XmlEndSessionElement(
	_In_opt_ IXmlWriter *XmlWriter
);

VOID
STDAPICALLTYPE
H2XmlWriteSequenceElement(
	_In_opt_ IXmlWriter *XmlWriter,
	_In_ ULONG Sequence
);

VOID
STDAPICALLTYPE
H2XmlWriteOwnerElement(
	_In_opt_ IXmlWriter *XmlWriter,
	_In_ PRM_UNIQUE_PROCESS Process
);

VOID
STDAPICALLTYPE
H2XmlBeginResourcesElement(
	_In_opt_ IXmlWriter *XmlWriter
);

VOID
STDAPICALLTYPE
H2XmlEndResourcesElement(
	_In_opt_ IXmlWriter *XmlWriter
);

typedef enum _H2_RM_RESOURCE_TYPE
{
	RmResourceInvalid = 0,
	RmResourceFile,
	RmResourceApplication,
	RmResourceService
} H2_RM_RESOURCE_TYPE, *PH2_RM_RESOURCE_TYPE;

VOID
STDAPICALLTYPE
H2XmlBeginResourceGroupElement(
	_In_opt_ IXmlWriter *XmlWriter,
	_In_ H2_RM_RESOURCE_TYPE ResourceType,
	_In_ PCWSTR Name
);

VOID
STDAPICALLTYPE
H2XmlEndResourceGroupElement(
	_In_opt_ IXmlWriter *XmlWriter
);

VOID
STDAPICALLTYPE
H2XmlWriteFileElement(
	_In_opt_ IXmlWriter *XmlWriter,
	_In_ PCWSTR Path
);

VOID
STDAPICALLTYPE
H2XmlWriteApplicationElement(
	_In_opt_ IXmlWriter *XmlWriter,
	_In_ PRM_UNIQUE_PROCESS Process
);

VOID
STDAPICALLTYPE
H2XmlWriteApplicationElementRaw(
	_In_opt_ IXmlWriter *XmlWriter,
	_In_ PCWSTR RawValue
);

VOID
STDAPICALLTYPE
H2XmlWriteServiceElement(
	_In_opt_ IXmlWriter *XmlWriter,
	_In_ PCWSTR SvcName
);

#endif
