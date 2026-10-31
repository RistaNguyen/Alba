#include "pch.h"
#include "Alba.h"
#include "CMCFilter.h"
//RegistryProtect
NTSTATUS CancelCMCRegMod(PVOID CallbackContext, PVOID Arg1, PVOID Arg2);
NTSTATUS GeneralCaseHandle(PVOID RegistryObject);
NTSTATUS Compare(PWSTR a, size_t sizea, size_t sizeb);

//ProcessProtect
OB_PREOP_CALLBACK_STATUS CMCProcessProtect(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation);

//Driver Operation
//VOID AlbaUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS AlbaCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);

//default value
static const WCHAR machine[] = L"\\REGISTRY\\MACHINE\\SOFTWARE\\CMC";
UNICODE_STRING CMCProcess = RTL_CONSTANT_STRING(L"\\CMC.exe");

// Value Init for Filter to unload
LARGE_INTEGER RegistryCookie;
PVOID RegHandle;
PFLT_FILTER CMCFilter;
UINT64 FilterId;
HANDLE hEngine = nullptr;

//Entry
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);

	UNICODE_STRING Altitude = RTL_CONSTANT_STRING(L"367890.676564");
	NTSTATUS status = STATUS_SUCCESS;
	bool Registry = false, Process = false, File = false,HandleEngine = false;

	do {
		//Registry callback register
		status = CmRegisterCallbackEx(CancelCMCRegMod, &Altitude, DriverObject, NULL, &RegistryCookie, NULL);
		if (!NT_SUCCESS(status)) {
			break;
		}
		Registry = true;
		
		//Process callback register
		OB_OPERATION_REGISTRATION ObReg = { PsProcessType,OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,CMCProcessProtect,nullptr };
		OB_CALLBACK_REGISTRATION reg = {
			OB_FLT_REGISTRATION_VERSION,
			1,
			RTL_CONSTANT_STRING(L"367899.676564"),
			nullptr,
			&ObReg
		};
		status = ObRegisterCallbacks(&reg, &RegHandle);
		if (!NT_SUCCESS(status)) {
			break;
		}
		Process = true;

		//File callback register
		KdPrint((Prefix "Start register filter"));
		status = InitFilter(DriverObject, RegistryPath);
		if (!NT_SUCCESS(status)) {
			break;
		}
		File = true;

		status = FltStartFiltering(CMCFilter);
		if (!NT_SUCCESS(status)) {
			break;
		}

		//Internet callback register
		status = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_DEFAULT, nullptr, nullptr, &hEngine);
		if (!NT_SUCCESS(status)) {
			break;
		}
		HandleEngine = true;

		FWPM_FILTER0 filter{};
		WCHAR filterName[] = L"No Google DNS";
		filter.displayData.name = filterName;
		filter.layerKey = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;
		filter.action.type = FWP_ACTION_BLOCK;
		FWPM_FILTER_CONDITION0 Conditions[2] = {};

		Conditions[0].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
		Conditions[0].matchType = FWP_MATCH_EQUAL;
		Conditions[0].conditionValue.type = FWP_UINT16;
		Conditions[0].conditionValue.uint16 = 53;
		Conditions[1].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
		Conditions[1].matchType = FWP_MATCH_EQUAL;
		Conditions[1].conditionValue.type = FWP_UINT32;
		Conditions[1].conditionValue.uint32 = 0x08080808;

		filter.filterCondition = Conditions;
		filter.numFilterConditions = 2;

		status = FwpmFilterAdd0(hEngine, &filter, nullptr, &FilterId);
		if (!NT_SUCCESS(status)) {
			break;
		}
	} while (false);

	if(!NT_SUCCESS(status)){
		if (Registry) {
			CmUnRegisterCallback(RegistryCookie);
		}
		if (Process) {
			ObUnRegisterCallbacks(RegHandle);
		}
		if (File) {
			FltUnregisterFilter(CMCFilter);
		}
		if (HandleEngine) {
			FwpmEngineClose0(hEngine);
		}
	}
	//ObRegisterCallbacks();

	KdPrint((Prefix "Done createFilter"));
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = AlbaCreateClose;
	//DriverObject->DriverUnload = AlbaUnload;
	return status;
}

//Registry Protect
NTSTATUS CancelCMCRegMod(PVOID CallbackContext, PVOID Arg1, PVOID Arg2) {
	UNREFERENCED_PARAMETER(CallbackContext);

	NTSTATUS status = STATUS_SUCCESS;

	switch ((REG_NOTIFY_CLASS)(ULONG_PTR)Arg1) {
	case RegNtPreDeleteKey:
	{
		PREG_DELETE_KEY_INFORMATION Args = (PREG_DELETE_KEY_INFORMATION)Arg2;
		status = GeneralCaseHandle(Args->Object);
		break;
	}
	case RegNtPreSetValueKey:
	{
		PREG_SET_VALUE_KEY_INFORMATION Args = (PREG_SET_VALUE_KEY_INFORMATION)Arg2;
		status = GeneralCaseHandle(Args->Object);
		break;
	}
	case RegNtPreDeleteValueKey:
	{
		PREG_DELETE_VALUE_KEY_INFORMATION Args = (PREG_DELETE_VALUE_KEY_INFORMATION)Arg2;
		status = GeneralCaseHandle(Args->Object);
		break;
	}
	case RegNtPreRenameKey:
	{
		PREG_RENAME_KEY_INFORMATION Args = (PREG_RENAME_KEY_INFORMATION)Arg2;
		status = GeneralCaseHandle(Args->Object);
		break;
	}
	case RegNtPreCreateKeyEx:
	{
		PREG_CREATE_KEY_INFORMATION_V1 Args = (PREG_CREATE_KEY_INFORMATION_V1)Arg2;
		PUNICODE_STRING CreatePath = Args->CompleteName;

		if (CreatePath->Length < 1) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		if (wcsncmp(CreatePath->Buffer, L"\\", 1) == 0) {
			UNICODE_STRING UpperRegPath;
			NTSTATUS result =RtlUpcaseUnicodeString(&UpperRegPath, CreatePath, TRUE);

			if (!NT_SUCCESS(result)) {
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}

			status = Compare(UpperRegPath.Buffer, UpperRegPath.Length / sizeof(WCHAR), ARRAYSIZE(machine) - 1);
			RtlFreeUnicodeString(&UpperRegPath);
		}
		else {
			PCUNICODE_STRING RegistryRoot;
		
			if (NT_SUCCESS(CmCallbackGetKeyObjectIDEx(&RegistryCookie, Args->RootObject, nullptr, &RegistryRoot, 0))) {
				USHORT BufferLen = RegistryRoot->Length + CreatePath->Length + sizeof(WCHAR);
				UNICODE_STRING FullPath;
				PWSTR Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, BufferLen, DriverTag);
			
				if (Buffer == nullptr) {
					status = STATUS_INSUFFICIENT_RESOURCES;
					CmCallbackReleaseKeyObjectIDEx(RegistryRoot);
					break;
				}
				
				FullPath.Buffer = Buffer;
				FullPath.Length = 0;
				FullPath.MaximumLength = BufferLen;
				NTSTATUS result = RtlAppendUnicodeStringToString(&FullPath, RegistryRoot);
				
				if (!NT_SUCCESS(result)) {
					ExFreePool(Buffer);
					CmCallbackReleaseKeyObjectIDEx(RegistryRoot);
					break;
				}
				
				WCHAR SlashCheck = RegistryRoot->Buffer[RegistryRoot->Length / sizeof(WCHAR) - 1];
				KdPrint((Prefix "Registry createPath: %wZ\n", CreatePath));
				KdPrint((Prefix "Registry Root: %wZ\n", RegistryRoot));
				KdPrint((Prefix "Checking if root have the '\\' character\n"));
				
				if (SlashCheck != L'\\') {
					result = RtlAppendUnicodeToString(&FullPath, L"\\");
					if (!NT_SUCCESS(result)) {
						ExFreePool(Buffer);
						CmCallbackReleaseKeyObjectIDEx(RegistryRoot);
						break;
					}
				}
				result = RtlAppendUnicodeStringToString(&FullPath, CreatePath);
				
				if (!NT_SUCCESS(result)) {
					ExFreePool(Buffer);
					CmCallbackReleaseKeyObjectIDEx(RegistryRoot);
					break;
				}
				
				UNICODE_STRING UpperRegPath;
				result = RtlUpcaseUnicodeString(&UpperRegPath, &FullPath, TRUE);
				
				if (!NT_SUCCESS(result)) {
					status = STATUS_INSUFFICIENT_RESOURCES;
					ExFreePool(Buffer);
					CmCallbackReleaseKeyObjectIDEx(RegistryRoot);
					break;
				}
				
				status = Compare(UpperRegPath.Buffer, UpperRegPath.Length / sizeof(WCHAR), ARRAYSIZE(machine) - 1) ;
				RtlFreeUnicodeString(&UpperRegPath);
				ExFreePool(Buffer);
				CmCallbackReleaseKeyObjectIDEx(RegistryRoot);
			}
		}
	}
	}
	return status;
}

NTSTATUS GeneralCaseHandle(PVOID RegistryObject) {
	PCUNICODE_STRING RegistryPath;
	NTSTATUS status = STATUS_SUCCESS;

	if (NT_SUCCESS(CmCallbackGetKeyObjectIDEx(&RegistryCookie, RegistryObject, nullptr, &RegistryPath, 0))) {
		KdPrint((Prefix "Registry path: %wZ\n",RegistryPath));
		UNICODE_STRING UpperRegPath;
		NTSTATUS result = RtlUpcaseUnicodeString(&UpperRegPath, RegistryPath, TRUE);
		
		if (!NT_SUCCESS(result)) {
			CmCallbackReleaseKeyObjectIDEx(RegistryPath);
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		
		status = Compare(UpperRegPath.Buffer, UpperRegPath.Length/sizeof(WCHAR), ARRAYSIZE(machine) - 1) ;
		RtlFreeUnicodeString(&UpperRegPath);
		CmCallbackReleaseKeyObjectIDEx(RegistryPath);
	}
	
	return status;
}

NTSTATUS AlbaCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

//VOID AlbaUnload(PDRIVER_OBJECT DriverObject) {
//	UNREFERENCED_PARAMETER(DriverObject);
//
//}

NTSTATUS Compare(PWSTR a, size_t sizea, size_t sizeb) {
	if (sizea < sizeb) {
		return STATUS_SUCCESS;
	}
	if (sizea > sizeb && a[sizeb] != '\\') {
		return STATUS_SUCCESS;
	}

	return wcsncmp(a, machine, sizeb) == 0 ? STATUS_ACCESS_DENIED : STATUS_SUCCESS;
}

//Process Protect
OB_PREOP_CALLBACK_STATUS CMCProcessProtect(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation) {
	UNREFERENCED_PARAMETER(RegistrationContext);
	
	if (OperationInformation->KernelHandle)
	{
		KdPrint((Prefix "Kernel call"));
		return OB_PREOP_SUCCESS;
	}
	
	PEPROCESS Process = (PEPROCESS)OperationInformation->Object;
	PUNICODE_STRING ProcessName;
	
	NTSTATUS status = SeLocateProcessImageName(Process, &ProcessName);
	if (!NT_SUCCESS(status)) {
		return OB_PREOP_SUCCESS;
	}

	//debug
	KdPrint((Prefix "Processname: %wZ\n", ProcessName));
	//USHORT ProcessNameLen = ProcessName->Length;
	//USHORT CMCProcessLen = CMCProcess.Length;
	//KdPrint((Prefix "Processname len: %d, CMCProcess len: %d", ProcessNameLen, CMCProcessLen));
	//BOOLEAN test1 = RtlSuffixUnicodeString(&CMCProcess, ProcessName, TRUE);
	//BOOLEAN test2 = RtlSuffixUnicodeString(ProcessName, &CMCProcess,  TRUE);
	//KdPrint((Prefix "test1: %d, test2: %d", test1,test2));

	if (RtlSuffixUnicodeString(&CMCProcess, ProcessName,   TRUE)) {
		KdPrint((Prefix "Done"));
		if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
			OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
		}
		else {
			OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
		}
	}

	ExFreePool(ProcessName);
	return OB_PREOP_SUCCESS;
}
