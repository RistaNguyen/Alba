#include "pch.h"
#include "CMCFilter.h"
#include "Alba.h"

UNICODE_STRING kernelVol;
UNICODE_STRING MyDir = RTL_CONSTANT_STRING(L"\\Test");



NTSTATUS InitFilter(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	HANDLE hKey = nullptr, hSubkey = nullptr;
	NTSTATUS status;

	//Set necessary registry
	do {
		OBJECT_ATTRIBUTES keyAttr = RTL_CONSTANT_OBJECT_ATTRIBUTES(RegistryPath, OBJ_KERNEL_HANDLE);
		status = ZwOpenKey(&hKey, KEY_WRITE, &keyAttr);
		if (!NT_SUCCESS(status)) {
			break;
		}

		UNICODE_STRING subKey = RTL_CONSTANT_STRING(L"Instances");
		OBJECT_ATTRIBUTES subKeyAttr;
		InitializeObjectAttributes(&subKeyAttr, &subKey, OBJ_KERNEL_HANDLE, hKey, nullptr);
		status = ZwCreateKey(&hSubkey, KEY_WRITE, &subKeyAttr, 0, nullptr, 0, nullptr);
		if (!NT_SUCCESS(status)) {
			break;
		}

		UNICODE_STRING valueName = RTL_CONSTANT_STRING(L"DefaultInstance");
		WCHAR name[] = L"CMCProtectDefaultInstance";
		status = ZwSetValueKey(hSubkey, &valueName, 0, REG_SZ, name, sizeof(name));
		if (!NT_SUCCESS(status))
			break;

		UNICODE_STRING instKeyName;
		RtlInitUnicodeString(&instKeyName, name);
		HANDLE hInstKey;
		InitializeObjectAttributes(&subKeyAttr, &instKeyName, OBJ_KERNEL_HANDLE, hSubkey, nullptr);
		status = ZwCreateKey(&hInstKey, KEY_WRITE, &subKeyAttr, 0, nullptr, 0, nullptr);
		if (!NT_SUCCESS(status))
			break;

		WCHAR altitude[] = L"367891.676564";
		UNICODE_STRING altitudeName = RTL_CONSTANT_STRING(L"Altitude");
		status = ZwSetValueKey(hInstKey, &altitudeName, 0, REG_SZ, altitude, sizeof(altitude));
		if (!NT_SUCCESS(status))
			break;

		UNICODE_STRING flagsName = RTL_CONSTANT_STRING(L"Flags");
		ULONG flags = 0;
		status = ZwSetValueKey(hInstKey, &flagsName, 0, REG_DWORD, &flags, sizeof(flags));
		if (!NT_SUCCESS(status))
			break;

		ZwClose(hInstKey);

		if (hSubkey) {
			if (!NT_SUCCESS(status))
				ZwDeleteKey(hSubkey);
			ZwClose(hSubkey);
		}

		if (hKey)
			ZwClose(hKey);

		//setup minifilter
		FLT_OPERATION_REGISTRATION const callbacks[] = {
			{IRP_MJ_CREATE,0,CMCProtectPreCreate,nullptr},
			{IRP_MJ_SET_INFORMATION,0,CMCProtectPreSetInformation,nullptr},
			{IRP_MJ_WRITE,0,CMCProtectWrite,nullptr},
			{IRP_MJ_OPERATION_END}
		};

		FLT_REGISTRATION const reg = {
			sizeof(FLT_REGISTRATION),
			FLT_REGISTRATION_VERSION,
			0,
			nullptr,
			callbacks,
			CMCProtectUnload,
			CMCProtectInstanceSetup,
			CMCProtectInstanceQueryTeardown,
			CMCProtectInstanceTeardownStart,
			CMCProtectInstanceTeardownComplete,
		};
		status = FltRegisterFilter(DriverObject, &reg, &CMCFilter);

		if (!NT_SUCCESS(status)) {
			break;
		}

		PFLT_VOLUME vol;
		UNICODE_STRING userVol = RTL_CONSTANT_STRING(L"C:");
		status = FltGetVolumeFromName(CMCFilter, &userVol, &vol);
		if (!NT_SUCCESS(status)) {
			FltUnregisterFilter(CMCFilter);
			break;
		}

		ULONG BufferSize = 0;
		FltGetVolumeName(vol, NULL, &BufferSize);

		BufferSize += sizeof(WCHAR) * 5;
		PWSTR Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, BufferSize, DriverTag);
		if (Buffer == nullptr) {
			FltUnregisterFilter(CMCFilter);
			FltObjectDereference(vol);
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		kernelVol.Buffer = Buffer;
		kernelVol.MaximumLength = (USHORT)BufferSize;
		status = FltGetVolumeName(vol, &kernelVol, NULL);

		if (!NT_SUCCESS(status)) {
			FltUnregisterFilter(CMCFilter);
			FltObjectDereference(vol);
			ExFreePool(Buffer);
			break;
		}
		//KdPrint((Prefix "Kernel vol: %wZ\n",&kernelVol));
		status = RtlAppendUnicodeStringToString(&kernelVol, &MyDir);
		if (!NT_SUCCESS(status)) {
			ExFreePool(Buffer);
			FltUnregisterFilter(CMCFilter);
		}
		//KdPrint((Prefix "Kernel vol: %wZ\n", &kernelVol));

		FltObjectDereference(vol);
	} while (false);


	return status;
}

//IRP_MJ_CREATE
FLT_PREOP_CALLBACK_STATUS CMCProtectPreCreate(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID* CompletionContext
) {
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	
	if (Data->RequestorMode == KernelMode)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	
	auto& params = Data->Iopb->Parameters.Create;
	auto status = FLT_PREOP_SUCCESS_NO_CALLBACK;
	auto dispos = params.Options >> 24;

	if (params.Options & FILE_DELETE_ON_CLOSE 
		||dispos== FILE_SUPERSEDE 
		|| dispos== FILE_CREATE 
		||dispos == FILE_OPEN_IF
		|| dispos==  FILE_OVERWRITE 
		|| dispos == FILE_OVERWRITE_IF) {
	
		KdPrint(("IrpCreate: \n"));
		PFLT_FILE_NAME_INFORMATION name;
		
		if (!NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &name))) {
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}

		KdPrint((Prefix "FltGetFileNameInformation %wZ\n", &name->Name));
		KdPrint((Prefix "aaaaaaaaaaaaaFltGetVolumeName %wZ\n", &kernelVol));
		KdPrint((Prefix "aaaaaaaaaaaaaFile Vol: %wZ, File Dir: %wZ\n", &name->Volume, &name->ParentDir));
		
		if (!IsDeleteAllowed(name)) {
			if (!(params.Options & FILE_DELETE_ON_CLOSE) && dispos == FILE_OPEN_IF) {
				params.Options = (params.Options & 0x00FFFFFFu) | (FILE_OPEN<<24);
				FltSetCallbackDataDirty(Data);
				FltReleaseFileNameInformation(name);
				return FLT_PREOP_SUCCESS_NO_CALLBACK;
			}
			Data->IoStatus.Status = STATUS_ACCESS_DENIED;
			status = FLT_PREOP_COMPLETE;
		}
		FltReleaseFileNameInformation(name);
	}
	return status;
}

//IRP_MJ_SETFILEINFORMATION
FLT_PREOP_CALLBACK_STATUS CMCProtectPreSetInformation(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID* CompletionContext
) {
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(FltObjects);
	KdPrint((Prefix "IRP_MJ_SETINFORMATION: start \n"));

	if (Data->RequestorMode == KernelMode )
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	auto status = FLT_PREOP_SUCCESS_NO_CALLBACK;
	PFLT_FILE_NAME_INFORMATION name;

	if (!NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &name))) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	//if (!NT_SUCCESS(FltParseFileNameInformation(name))) {
	//	return FLT_PREOP_SUCCESS_NO_CALLBACK;
	//}

	//KdPrint((Prefix "IRP_MJ_SETINFORMATION: Checking Source file dir: %wZ, finalcomponent: %wZ, fullName: %wZ \n", &name->ParentDir,&name->FinalComponent, &name->Name));
	PFLT_FILE_NAME_INFORMATION destName = nullptr;

	auto infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
	if (infoClass == FileRenameInformation ||
		infoClass == FileRenameInformationEx ||
		infoClass == FileLinkInformation ||
		infoClass == FileLinkInformationEx){

		KdPrint((Prefix "IRP_MJ_SETINFORMATION: suspicious inforClass \n"));

		auto renameInfo = (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
		if (renameInfo != nullptr) {
			if (NT_SUCCESS(FltGetDestinationFileNameInformation(
				FltObjects->Instance,
				FltObjects->FileObject,
				renameInfo->RootDirectory,
				renameInfo->FileName,
				renameInfo->FileNameLength,
				FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
				&destName
			))) {
				//if (!NT_SUCCESS(FltParseFileNameInformation(destName))) {
				//	return FLT_PREOP_SUCCESS_NO_CALLBACK;
				//}
				//KdPrint((Prefix "IRP_MJ_SETINFORMATION: Checking Dest file dir: %wZ, finalcomponent: %wZ, fullName: %wZ \n", &destName->ParentDir, &destName->FinalComponent, &destName->Name));				
			}
		}
	}
	if (!IsDeleteAllowed(name) || (destName!=nullptr && !IsDeleteAllowed(destName))) {
		Data->IoStatus.Status = STATUS_ACCESS_DENIED;
		status = FLT_PREOP_COMPLETE;
	}
	
	KdPrint((Prefix "IRP_MJ_SETINFORMATION: end \n"));
	if(destName!=nullptr){
		FltReleaseFileNameInformation(destName);
	}
	FltReleaseFileNameInformation(name);

	return status;
}

FLT_PREOP_CALLBACK_STATUS CMCProtectWrite(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID* CompletionContext
) {
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	if (Data->RequestorMode == KernelMode)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	auto status = FLT_PREOP_SUCCESS_NO_CALLBACK;
	PFLT_FILE_NAME_INFORMATION name;

	if (!NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &name))) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (!IsDeleteAllowed(name)) {
		Data->IoStatus.Status = STATUS_ACCESS_DENIED;
		status = FLT_PREOP_COMPLETE;
	}
	
	FltReleaseFileNameInformation(name);

	return status;
}

bool IsDeleteAllowed( PFLT_FILE_NAME_INFORMATION FileName) {
	if (!NT_SUCCESS(FltParseFileNameInformation(FileName))) {
		return true;
	}
	
	if (!RtlPrefixUnicodeString(&kernelVol, &FileName->Name, TRUE)) {
		return true;
	}

	if (FileName->Name.Length > kernelVol.Length) {
		WCHAR exptectSlash = FileName->Name.Buffer[kernelVol.Length / sizeof(WCHAR)];
		if (exptectSlash != L'\\') {
			return true;
		}
	}

	return false;
}

NTSTATUS CMCProtectUnload(FLT_FILTER_UNLOAD_FLAGS Flags) {
	UNREFERENCED_PARAMETER(Flags);
	
	FltUnregisterFilter(CMCFilter);
	CmUnRegisterCallback(RegistryCookie);
	ObUnRegisterCallbacks(RegHandle);
	FwpmFilterDeleteById0(hEngine, FilterId);
	FwpmEngineClose0(hEngine);
	ExFreePool(kernelVol.Buffer);

	return STATUS_SUCCESS;
}

NTSTATUS CMCProtectInstanceSetup(
	PCFLT_RELATED_OBJECTS FltObject,
	FLT_INSTANCE_SETUP_FLAGS Flags,
	DEVICE_TYPE VolumeDeviceType,
	FLT_FILESYSTEM_TYPE VolumeFilesystemType
) {
	UNREFERENCED_PARAMETER(FltObject);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeDeviceType);
	return VolumeFilesystemType == FLT_FSTYPE_NTFS ? STATUS_SUCCESS : STATUS_FLT_DO_NOT_ATTACH;
}
NTSTATUS CMCProtectInstanceQueryTeardown(
	PCFLT_RELATED_OBJECTS FltObjects,
	FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
) {
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	return STATUS_SUCCESS;
}
VOID CMCProtectInstanceTeardownStart(
	PCFLT_RELATED_OBJECTS FltObjects,
	FLT_INSTANCE_TEARDOWN_FLAGS Reason
) {
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Reason);
}
VOID CMCProtectInstanceTeardownComplete(
	PCFLT_RELATED_OBJECTS FltObjects,
	FLT_INSTANCE_TEARDOWN_FLAGS Reason
) {
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Reason);
}
