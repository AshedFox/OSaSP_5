#include <ntddk.h>
#include <stdio.h>


#define PROCESS_DRIVER_DEVICE 0x8000

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT  DriverObject, _In_ PUNICODE_STRING RegistryPath);
void RegistryDriverUnload(_In_ PDRIVER_OBJECT DriverObject);
NTSTATUS RegisterDriverCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS RegisterDriverDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS status, ULONG_PTR info);
NTSTATUS OnRegistryNotify(PVOID context, PVOID arg1, PVOID arg2);

bool isLoggingActive;
unsigned long targetProcessId;
LARGE_INTEGER cookie;


extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT  DriverObject, _In_ PUNICODE_STRING RegistryPath) 
{
	UNREFERENCED_PARAMETER(RegistryPath);

	UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\RegistryDriver");
	UNICODE_STRING symbolicLinkName = RTL_CONSTANT_STRING(L"\\??\\RegistryDriver");
	PDEVICE_OBJECT DeviceObject;
	NTSTATUS status;

	status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, false, &DeviceObject);

	if (!NT_SUCCESS(status)) 
	{
		KdPrint(("Error on device creation"));
		return status;
	}

	status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);

	if (!NT_SUCCESS(status)) 
	{
		KdPrint(("Error on link creation"));
		IoDeleteDevice(DeviceObject);
		return status;
	}

	UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"16092");

	status = CmRegisterCallbackEx(OnRegistryNotify, &altitude, DriverObject, nullptr, &cookie, nullptr);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed to register callback"));
		IoDeleteSymbolicLink(&symbolicLinkName);
		IoDeleteDevice(DeviceObject);
		return status;
	}

	DriverObject->DriverUnload = RegistryDriverUnload;

	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = RegisterDriverCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = RegisterDriverDeviceControl;

	KdPrint(("Driver init"));

	return STATUS_SUCCESS;
}

void RegistryDriverUnload(_In_ PDRIVER_OBJECT DriverObject) 
{
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\RLogger");

	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(DriverObject->DeviceObject);
	CmUnRegisterCallback(cookie);

	KdPrint(("Driver unload"));
}

NTSTATUS RegisterDriverCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) 
{
	UNREFERENCED_PARAMETER(DeviceObject);

	return CompleteIrp(Irp, STATUS_SUCCESS, 0);
}

NTSTATUS RegisterDriverDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) 
{
	UNREFERENCED_PARAMETER(DeviceObject);

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS status = STATUS_SUCCESS;

	switch (stack->Parameters.DeviceIoControl.IoControlCode) 
	{
		case CTL_CODE(PROCESS_DRIVER_DEVICE, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS): {

			if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(unsigned long)) 
			{
				status = STATUS_BUFFER_TOO_SMALL;
				break;
			}

			targetProcessId = *(unsigned long*)stack->Parameters.DeviceIoControl.Type3InputBuffer;
			isLoggingActive = true;
			KdPrint(("Target process id changed"));
		}
		break;

		case CTL_CODE(PROCESS_DRIVER_DEVICE, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS): {
			isLoggingActive = false;
			KdPrint(("Logging stoped"));
		}
		break;

		default: {
			status = STATUS_INVALID_DEVICE_REQUEST;
		}
		break;
	}

	return CompleteIrp(Irp, status, 0);
}

NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS status, ULONG_PTR info) 
{
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS OnRegistryNotify(PVOID context, PVOID arg1, PVOID arg2)
{
	UNREFERENCED_PARAMETER(context);
	UNREFERENCED_PARAMETER(arg2);

	if ((REG_NOTIFY_CLASS)(ULONG_PTR)arg1 != RegNtPostSetValueKey)
	{
		return STATUS_SUCCESS;
	}

	if (!isLoggingActive)
	{
		KdPrint(("Logging disabled"));

		return STATUS_SUCCESS;
	}

	ULONG processId = HandleToULong(PsGetCurrentProcessId());

	if ((processId != targetProcessId)) {
		KdPrint(("Uninteresting process, id: %u", processId));

		return STATUS_SUCCESS;
	}

	REG_POST_OPERATION_INFORMATION* info = (REG_POST_OPERATION_INFORMATION*)arg2;
	if (!NT_SUCCESS(info->Status)) {
		return STATUS_SUCCESS;
	}

	UNICODE_STRING fileName = RTL_CONSTANT_STRING(L"\\SystemRoot\\Log.txt");
	OBJECT_ATTRIBUTES objectAttributes;

	InitializeObjectAttributes(&objectAttributes, &fileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);

	HANDLE hFile;
	IO_STATUS_BLOCK ioStatusBlock;

	NTSTATUS status = ZwCreateFile(&hFile, FILE_APPEND_DATA, &objectAttributes, &ioStatusBlock, 0, FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, nullptr, 0);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("Error on opening file"));

		return STATUS_SUCCESS;
	}

	REG_SET_VALUE_KEY_INFORMATION* valueKeyinfo = (REG_SET_VALUE_KEY_INFORMATION*)info->PreInformation;

	if (valueKeyinfo == nullptr)
	{
		return STATUS_SUCCESS;
	}

	CHAR buffer[512];

	LARGE_INTEGER systemTime;
	KeQuerySystemTime(&systemTime);

	PCUNICODE_STRING name;
	CmCallbackGetKeyObjectIDEx(&cookie, info->Object, nullptr, &name, 0);

	int position = sprintf_s(buffer, sizeof(buffer), "System time: %u\nProcess Id: %u\n%ws\\\n%ws\nSize: %d\nData:",
		(ULONG)systemTime.QuadPart, processId, name->Buffer, valueKeyinfo->ValueName->Buffer, valueKeyinfo->DataSize);

	CmCallbackReleaseKeyObjectIDEx(name);

	int left = sizeof(buffer) - position - ((int)strlen("\n\n") + 1);
	int limit = left < (int)valueKeyinfo->DataSize ? left : (int)valueKeyinfo->DataSize;

	for (int i = 0; i < limit; i++)
	{
		sprintf(buffer + position + i, "%02X", ((UCHAR*)valueKeyinfo->Data)[i]);
	}
	sprintf(buffer + position + limit, "\n\n");

	LARGE_INTEGER fileEnd;
	fileEnd.HighPart = 0xffffffff;
	fileEnd.LowPart = FILE_WRITE_TO_END_OF_FILE;

	status = ZwWriteFile(hFile, nullptr, nullptr, nullptr, &ioStatusBlock, (PVOID)buffer, (ULONG)strlen(buffer), &fileEnd, nullptr);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("Error on file write"));

		ZwClose(hFile);

		return STATUS_SUCCESS;
	}

	ZwClose(hFile);

	KdPrint(("Writen all changed to log"));

	return STATUS_SUCCESS;
}