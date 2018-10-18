#pragma once
#include <iostream>

#include "LdrDefs.h"
#include "ShellcodeMacros.h"

void preselectionStub();
void preselectionFunc();
void preselectionFunc_end();

bool prepareStub(void* entryOffset, void* &stub, size_t &len, std::ostream &infoStream, std::ostream &errorStream)
{
	if (&preselectionStub > &preselectionFunc)
	{
		errorStream << "\t\tprepareStub: preselectionStub() must come before preselectionFunc()" << std::endl;
		return false;
	}

	if (&preselectionFunc > &preselectionFunc_end)
	{
		errorStream << "\t\tprepareStub: preselectionFunc() must come before preselectionFunc_end()" << std::endl;
		return false;
	}

	stub = &preselectionStub;
	len = (size_t)&preselectionFunc_end - (size_t)&preselectionStub;

	infoStream << "\t\tprepareStub: preparing stub at 0x" << std::hex << stub << " (len " << std::dec << len << ")" << std::endl;

	DWORD oldprotect;
	VirtualProtect(&preselectionStub, len, PAGE_EXECUTE_READWRITE, &oldprotect);

	const uint32_t entryOffsetMarker = 0xDEADB33F;
	for (auto ptr = (size_t)&preselectionStub; ptr < (size_t)&preselectionFunc_end; ptr++)
	{
		if (memcmp((void*)ptr, &entryOffsetMarker, 4) == 0)
		{
			memcpy((void*)ptr, &entryOffset, sizeof(void*));
			infoStream << "\t\tprepareStub: configured entry point at 0x" << std::hex << ptr << std::endl;
		}
	}

	VirtualProtect(&preselectionStub, len, oldprotect, &oldprotect);

	return true;
}


// this code absolutely needs to be compiled with all of these options,
// which sometimes don't take effect. so if you're having issues, make sure they
// are off in the project settings.
#pragma runtime_checks("scu", off)
#pragma optimize("", off)
#pragma strict_gs_check(push, off)
#pragma check_stack(off)

__declspec(naked) void preselectionStub()
{
	/*
		This function, along with preselectionFunc, get injected into the PE.
		The responsibility of this function is to preserve everything and call into preselectionFunc.
		That function will carry out the ASLR preselection attack. The assumption is that,
		if it fails, it will end our life with ExitProcess(). However, if the failing is during function resolution,
		it will int3 breakpoint.

		If it does not breakpoint and successfully returns, the assumption is the preselection was successfull.
		This means our base address is 0x00010000, and we will assume that when jumping to the original entry point.

		Marker in both funcs:
			0xDEADB33F   offset for original entry point
			0xBADB33F5   not a marker, but a magic value used as an exit code to communicate between processes
			0x00010000   if we ever want to preselect a different base, we much change all occurances of this (and make many changes to the pe recompiler)
	*/

	__asm
	{
		//PUSHAD
		//PUSHFD

		CALL preselectionFunc

		//POPFD
		//POPAD

		MOV EAX, 0x00010000
		ADD EAX, 0xDEADB33F
		JMP EAX

	}
}


void preselectionFunc()
{
	// grab loader list
	PPEB_LDR_DATA LoaderData;
	__asm
	{
		MOV EAX, DWORD PTR FS : [30h]
		MOV EAX, DWORD PTR DS : [EAX + 12]
		MOV LoaderData, EAX
	}

	// get modules
	LDR_GET_MODULE(kernel32Handle, 12, 'k', '2');

	// get functions
	// TODO could actually really simplify this by first locating GetModuleHandle and GetProcAddress
	// and using them to locate the rest of the functions.. but I got carried away working macro magic
	//
	// but hey guess what this actually makes reversing much harder so let's call it a feature!
	LDR_GET_PROC(f_GetModuleHandle,      kernel32Handle, HMODULE(__stdcall *)(PUCHAR), LDR_STR_SIG('G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 'A'));
	LDR_GET_PROC(f_CreateMutexA,         kernel32Handle, HANDLE(__stdcall *)(PVOID, BOOL, LPCSTR), LDR_STR_SIG('C', 'r', 'e', 'a', 't', 'e', 'M', 'u', 't', 'e', 'x', 'A'));
	LDR_GET_PROC(f_GetLastError,         kernel32Handle, DWORD(__stdcall *)(), LDR_STR_SIG('G', 'e', 't', 'L', 'a', 's', 't', 'E', 'r', 'r', 'o', 'r'));
	LDR_GET_PROC(f_CloseHandle,          kernel32Handle, BOOL(__stdcall *)(HANDLE), LDR_STR_SIG('C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e'));
	LDR_GET_PROC(f_GetCurrentProcessId,  kernel32Handle, DWORD(__stdcall *)(), LDR_STR_SIG('G', 'e', 't', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', 'I', 'd'));
	LDR_GET_PROC(f_GetModuleFileNameW,   kernel32Handle, DWORD(__stdcall *)(HMODULE, LPWSTR, DWORD), LDR_STR_SIG('G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'F', 'i', 'l', 'e', 'N', 'a', 'm', 'e', 'W'));
	LDR_GET_PROC(f_CreateProcessW,       kernel32Handle, BOOL(__stdcall *)(LPCWSTR, LPWSTR, PVOID, PVOID, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION), LDR_STR_SIG('C', 'r', 'e', 'a', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'W'));
	LDR_GET_PROC(f_WaitForSingleObject,  kernel32Handle, DWORD(__stdcall *)(HANDLE, DWORD), LDR_STR_SIG('W', 'a', 'i', 't', 'F', 'o', 'r', 'S', 'i', 'n', 'g', 'l', 'e', 'O', 'b', 'j', 'e', 'c', 't'));
	LDR_GET_PROC(f_GetExitCodeProcess,   kernel32Handle, BOOL(__stdcall *)(HANDLE, LPDWORD), LDR_STR_SIG('G', 'e', 't', 'E', 'x', 'i', 't', 'C', 'o', 'd', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's'));
	LDR_GET_PROC(f_CreateFileW,          kernel32Handle, HANDLE(__stdcall *)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE), LDR_STR_SIG('C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'l', 'e', 'W'));
	LDR_GET_PROC(f_CreateFileMappingW,   kernel32Handle, HANDLE(__stdcall *)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR), LDR_STR_SIG('C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'l', 'e', 'M', 'a', 'p', 'p', 'i', 'n', 'g', 'W'));
	LDR_GET_PROC(f_MapViewOfFileEx,      kernel32Handle, LPVOID(__stdcall *)(HANDLE, DWORD, DWORD, DWORD, SIZE_T, LPVOID), LDR_STR_SIG('M', 'a', 'p', 'V', 'i', 'e', 'w', 'O', 'f', 'F', 'i', 'l', 'e', 'E', 'x'));
	LDR_GET_PROC(f_UnmapViewOfFile,      kernel32Handle, BOOL(__stdcall *)(LPCVOID), LDR_STR_SIG('U', 'n', 'm', 'a', 'p', 'V', 'i', 'e', 'w', 'O', 'f', 'F', 'i', 'l', 'e'));
	LDR_GET_PROC(f_CopyFileW,            kernel32Handle, BOOL(__stdcall *)(LPCWSTR, LPCWSTR, BOOL), LDR_STR_SIG('C', 'o', 'p', 'y', 'F', 'i', 'l', 'e', 'W'));
	LDR_GET_PROC(f_DeleteFileW,          kernel32Handle, BOOL(__stdcall *)(LPCWSTR), LDR_STR_SIG('D', 'e', 'l', 'e', 't', 'e', 'F', 'i', 'l', 'e', 'W'));
	LDR_GET_PROC(f_lstrcatW,             kernel32Handle, LPWSTR(__stdcall *)(LPWSTR, LPCWSTR), LDR_STR_SIG('l', 's', 't', 'r', 'c', 'a', 't', 'W'));
	LDR_GET_PROC(f_ExitProcess,          kernel32Handle, VOID(__stdcall *)(DWORD), LDR_STR_SIG('E', 'x', 'i', 't', 'P', 'r', 'o', 'c', 'e', 's', 's'));

	// define strings
	DEFINE_STR(const char*, mutexName, 'r', 'e', 'l', 'o', 'c', '_', 'p', 'a', 'c', 'k', '_', 'm', 'u', 't');
	DEFINE_STR(const wchar_t*, copySuffix, '2', 0x00, '.', 0x00, 'e', 0x00, 'x', 0x00, 'e', 0x00);


	// do preselection
	auto base = f_GetModuleHandle(NULL);
	auto mutex = f_CreateMutexA(NULL, FALSE, mutexName);
	auto mutexErr = f_GetLastError();
	//printf("%06d: 0x%0p - ASLR Preselection ", f_GetCurrentProcessId(), base);
	if (base == (HMODULE)0x00010000)
	{
		// we have the correct base and it doesn't matter who we are, we're done
		//printf("SUCCESS\n");
		f_CloseHandle(mutex);
		return;
	}
	else if (mutexErr == ERROR_ALREADY_EXISTS)
	{
		// we don't have the correct base and we're not the original process, return
		//printf("FAILURE\n");
		f_CloseHandle(mutex);
		f_ExitProcess(0xBADB33F5);
	}
	else
	{
		// we don't have the correct base and we're the original process, begin ASLR Preselection
		//printf("STARTING\n");
		wchar_t filePath[MAX_PATH * 2];
		wchar_t destFilePath[MAX_PATH * 2];
		f_GetModuleFileNameW(NULL, filePath, sizeof(filePath));
		f_GetModuleFileNameW(NULL, destFilePath, sizeof(destFilePath));
		f_lstrcatW(destFilePath, copySuffix);
		if (f_CopyFileW(filePath, destFilePath, FALSE) == TRUE)
		{
			for (size_t i = 0; true; i++)
			{
				// launch the process
				STARTUPINFOW info;
				ZERO_MEM(&info, sizeof(info));
				info.cb = sizeof(info);

				PROCESS_INFORMATION processInfo;
				if (f_CreateProcessW(destFilePath, NULL, NULL, NULL, TRUE, 0, NULL, NULL, &info, &processInfo))
				{
					DWORD code;
					f_WaitForSingleObject(processInfo.hProcess, INFINITE);
					f_GetExitCodeProcess(processInfo.hProcess, &code);
					f_CloseHandle(processInfo.hProcess);
					f_CloseHandle(processInfo.hThread);

					if (code != 0xBADB33F5) // if we haven't thrown this code, it was a successfull execution
					{
						//printf("ASLR Preselection completed in %d tries", i);
						f_DeleteFileW(destFilePath);
						break;
					}
				}

				// trigger flush of the previous base
				auto fileHandle = f_CreateFileW(destFilePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
				if (fileHandle == INVALID_HANDLE_VALUE)
					continue;
				auto mapping = f_CreateFileMappingW(fileHandle, NULL, PAGE_READONLY, 0, 0, NULL);
				if (!mapping)
				{
					f_CloseHandle(fileHandle);
					continue;
				}
				auto mapView = f_MapViewOfFileEx(mapping, FILE_MAP_READ, 0, 0, 0, (LPVOID)0x00010000);
				if (mapView)
					f_UnmapViewOfFile(mapView);
				f_CloseHandle(mapping);
				f_CloseHandle(fileHandle);
			}
		}

		f_CloseHandle(mutex);
	}

	f_ExitProcess(0);
}

void preselectionFunc_end() {}

#pragma check_stack()
#pragma strict_gs_check(pop)
#pragma optimize("", on)
#pragma runtime_checks("scu", restore)