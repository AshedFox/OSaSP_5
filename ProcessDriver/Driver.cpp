#include <ntddk.h>
#include <wdf.h>

#define PROCESS_X_PATH L"C:\\Windows\\System32\\cmd.exe"
#define PROCESS_Y_PATH L"C:\\Windows\\System32\\notepad.exe"
#define DRIVER_TAG 19280

enum ProcessEventType {
	None,
	Create,
	Close
};

struct ProcessEventInfo {
	unsigned long processId;
	ProcessEventType eventType;
};

struct ProcessEventItem {
	ProcessEventInfo processEventInfo;
	LIST_ENTRY readListEntry;
	LIST_ENTRY searchListEntry;
	int linksCount;
};

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT  DriverObject, _In_ PUNICODE_STRING RegistryPath);
void ProcessDriverUnload(_In_ PDRIVER_OBJECT DriverObject);
NTSTATUS ProcessDriverCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS ProcessDriverRead(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
void OnProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);
NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS status = STATUS_SUCCESS, ULONG_PTR info = 0);


LIST_ENTRY readListHead;
LIST_ENTRY searchListHead;
FAST_MUTEX mutex;

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT  DriverObject, _In_ PUNICODE_STRING RegistryPath) 
{
	UNREFERENCED_PARAMETER(RegistryPath);

	UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\ProcessDriver");
	UNICODE_STRING symbolicLinkName = RTL_CONSTANT_STRING(L"\\??\\ProcessDriver");
	PDEVICE_OBJECT deviceObject;
	NTSTATUS status;

	status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, false, &deviceObject);

	if (!NT_SUCCESS(status)) 
	{
		KdPrint(("Error on device creation"));
		return status;
	}

	deviceObject->Flags = deviceObject->Flags | DO_BUFFERED_IO;

	status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("Error on link creation"));
		IoDeleteDevice(deviceObject);
		return status;
	}

	status = PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, false);

	if (!NT_SUCCESS(status)) 
	{
		KdPrint(("Error on callback creation"));
		IoDeleteSymbolicLink(&symbolicLinkName);
		IoDeleteDevice(deviceObject);
		return status;
	}

	InitializeListHead(&searchListHead);
	InitializeListHead(&readListHead);
	ExInitializeFastMutex(&mutex);

	DriverObject->DriverUnload = ProcessDriverUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = ProcessDriverCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = ProcessDriverCreateClose;
	DriverObject->MajorFunction[IRP_MJ_READ] = ProcessDriverRead;

	KdPrint(("Driver initialized"));

	return STATUS_SUCCESS;
}

void ProcessDriverUnload(_In_ PDRIVER_OBJECT DriverObject) 
{
	UNICODE_STRING symbolicLinkName = RTL_CONSTANT_STRING(L"\\??\\ProcessDriver");

	PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, true);
	IoDeleteSymbolicLink(&symbolicLinkName);
	IoDeleteDevice(DriverObject->DeviceObject);

	KdPrint(("Driver unloaded"));
}

NTSTATUS ProcessDriverCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) 
{
	UNREFERENCED_PARAMETER(DeviceObject);

	return CompleteIrp(Irp, STATUS_SUCCESS, 0);
}

void OnProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) 
{
	UNREFERENCED_PARAMETER(Process);
	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(CreateInfo);

	if (CreateInfo != nullptr) 
	{
		UNICODE_STRING targetImage = RTL_CONSTANT_STRING(PROCESS_X_PATH);

		if ((CreateInfo->ImageFileName == nullptr) || (RtlCompareUnicodeString(&targetImage, CreateInfo->ImageFileName, true) != 0)) 
		{
			return;
		}

		KdPrint(("X process created"));

		ProcessEventItem* processEventItem = (ProcessEventItem*)ExAllocatePoolWithTag(PagedPool, sizeof(ProcessEventItem), DRIVER_TAG);

		if (processEventItem == nullptr) 
		{
			KdPrint(("Failed to allocate pool"));
			return;
		}

		processEventItem->processEventInfo.eventType = Create;
		processEventItem->processEventInfo.processId = HandleToULong(ProcessId);
		processEventItem->linksCount = 2;

		ExAcquireFastMutex(&mutex);

		InsertTailList(&searchListHead, &processEventItem->searchListEntry);
		InsertTailList(&readListHead, &processEventItem->readListEntry);

		ExReleaseFastMutex(&mutex);

		KdPrint(("Start event enqueued"));
	}
	else 
	{
		ULONG processId = HandleToULong(ProcessId);
		ProcessEventItem* killedProcess = nullptr;

		bool needRelise = false;
		ExAcquireFastMutex(&mutex);

		PLIST_ENTRY next = searchListHead.Flink;
		while (next != &searchListHead) 
		{
			ProcessEventItem* currentEventItem = CONTAINING_RECORD(next, ProcessEventItem, searchListEntry);

			if (currentEventItem->processEventInfo.processId == processId)
			{
				killedProcess = currentEventItem;

				RemoveEntryList(&killedProcess->searchListEntry);
				killedProcess->linksCount--;
				needRelise = killedProcess->linksCount == 0;

				break;
			}

			next = next->Flink;
		}

		ExReleaseFastMutex(&mutex);

		if (killedProcess == nullptr) 
		{
			return;
		}

		if (needRelise) 
		{
			ExFreePool(killedProcess);
			KdPrint(("Event dequeued"));
		}

		ProcessEventItem* processEventItem = (ProcessEventItem*)ExAllocatePoolWithTag(PagedPool, sizeof(ProcessEventItem), DRIVER_TAG);

		if (processEventItem == nullptr) 
		{
			KdPrint(("Failed to allocate pool"));
			return;
		}

		processEventItem->processEventInfo.eventType = Close;
		processEventItem->processEventInfo.processId = processId;
		processEventItem->linksCount = 1;


		ExAcquireFastMutex(&mutex);

		InsertTailList(&readListHead, &processEventItem->readListEntry);

		ExReleaseFastMutex(&mutex);
		KdPrint(("Exit event enqueued"));
	}
}

NTSTATUS ProcessDriverRead(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) 
{
	UNREFERENCED_PARAMETER(DeviceObject);

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	ULONG length = stack->Parameters.Read.Length;

	if (length < sizeof(ProcessEventInfo)) 
	{
		return CompleteIrp(Irp, STATUS_BUFFER_TOO_SMALL, 0);
	}

	ProcessEventInfo* systemBuffer = (ProcessEventInfo*)Irp->AssociatedIrp.SystemBuffer;
	ProcessEventItem* itemToRead = nullptr;

	bool isNeedRelease = false;
	ExAcquireFastMutex(&mutex);

	if (readListHead.Flink != &readListHead) 
	{
		itemToRead = CONTAINING_RECORD(readListHead.Flink, ProcessEventItem, readListEntry);
		RemoveEntryList(&itemToRead->readListEntry);
		itemToRead->linksCount--;
		isNeedRelease = itemToRead->linksCount == 0;
	}

	ExReleaseFastMutex(&mutex);

	if (itemToRead != nullptr) 
	{
		systemBuffer->eventType = itemToRead->processEventInfo.eventType;
		systemBuffer->processId = itemToRead->processEventInfo.processId;

		if (isNeedRelease) 
		{
			ExFreePool(itemToRead);
			KdPrint(("Event dequeued"));
		}

		return CompleteIrp(Irp, STATUS_SUCCESS, sizeof(ProcessEventInfo));
	}

	return CompleteIrp(Irp, STATUS_SUCCESS, 0);
}

NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS status, ULONG_PTR info) 
{
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}