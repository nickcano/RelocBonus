#pragma once

// HELPERS FOR VARIADIC MACROS
#define EXPAND( x ) x
#define __ARG_N( \
      _1, _2, _3, _4, _5, _6, _7, _8, _9,_10, \
     _11,_12,_13,_14,_15,_16,_17,_18,_19,_20, \
     _21,_22,_23,_24,_25,_26,_27,_28,_29,_30, \
     _31,_32,_33,_34,_35,_36,_37,_38,_39,_40, \
     _41,_42,_43,_44,_45,_46,_47,_48,_49,_50, \
     _51,_52,_53,_54,_55,_56,_57,_58,_59,_60, \
     _61,_62,_63,N,...) N
#define __RSEQ_N() \
     63,62,61,60,                   \
     59,58,57,56,55,54,53,52,51,50, \
     49,48,47,46,45,44,43,42,41,40, \
     39,38,37,36,35,34,33,32,31,30, \
     29,28,27,26,25,24,23,22,21,20, \
     19,18,17,16,15,14,13,12,11,10, \
     9,8,7,6,5,4,3,2,1,0
#define __NARG_I_(...) EXPAND(__ARG_N(__VA_ARGS__))
#define __NARG__(...) __NARG_I_(__VA_ARGS__,__RSEQ_N())
#define __NARG_PLUS_TWO__(...) __NARG__(0, 0, __VA_ARGS__)

#define _VFUNC_(name, n) name##n
#define _VFUNC(name, n) _VFUNC_(name, n)
#define VFUNC(func, ...) EXPAND(_VFUNC(func, __NARG__(__VA_ARGS__)) (__VA_ARGS__))

// GetModuleHandle as a macro
#define LOWER(c) ((((char)c) <= 0x5A && ((char)c) >= 0x41) ? ((char)c) + 0x20 : ((char)c))
#define LDR_GET_MODULE(varName, len, firstChar, lastCharBeforeExt) \
	PVOID varName = NULL; \
	auto module##varName = (PLDR_MODULE)LoaderData->InLoadOrderModuleList.Flink; \
	do { \
		auto checkLen = module##varName->FullDllName.Length / 2; \
		/*wprintf(L"Mod (len %d): %s\n", checkLen, module##varName->FullDllName.Buffer);*/ \
		if (checkLen > len) { \
			if (LOWER(module##varName->FullDllName.Buffer[checkLen - len - 1]) == '\\' && \
				LOWER(module##varName->FullDllName.Buffer[checkLen - len]) == firstChar && \
				LOWER(module##varName->FullDllName.Buffer[checkLen - 5]) == lastCharBeforeExt) { \
					varName = module##varName->BaseAddress; \
					break; \
			} \
		} \
		module##varName = (PLDR_MODULE)module##varName->InLoadOrderModuleList.Flink; \
	} while ((PVOID)module##varName != &LoaderData->InLoadOrderModuleList && module##varName->BaseAddress); \
	if (varName == NULL) /*return 0xBADB33F5;*/ {__asm int 3} \
	//printf("%s at 0x%p\n", #varName, varName);

// GetProcAddress as a macro
#define LDR_STR_SIG1(c1) ((int)c1 * (1 << (1 % 16)))
#define LDR_STR_SIG2(c1, c2) (LDR_STR_SIG1(c1) + (int)c2 * (1 << (2 % 16)))
#define LDR_STR_SIG3(c1, c2, c3) (LDR_STR_SIG2(c1, c2) + (int)c3 * (1 << (3 % 16)))
#define LDR_STR_SIG4(c1, c2, c3, c4) (LDR_STR_SIG3(c1, c2, c3) + (int)c4 * (1 << (4 % 16)))
#define LDR_STR_SIG5(c1, c2, c3, c4, c5) (LDR_STR_SIG4(c1, c2, c3, c4) + (int)c5 * (1 << (5 % 16)))
#define LDR_STR_SIG6(c1, c2, c3, c4, c5, c6) (LDR_STR_SIG5(c1, c2, c3, c4, c5) + (int)c6 * (1 << (6 % 16)))
#define LDR_STR_SIG7(c1, c2, c3, c4, c5, c6, c7) (LDR_STR_SIG6(c1, c2, c3, c4, c5, c6) + (int)c7 * (1 << (7 % 16)))
#define LDR_STR_SIG8(c1, c2, c3, c4, c5, c6, c7, c8) (LDR_STR_SIG7(c1, c2, c3, c4, c5, c6, c7) + (int)c8 * (1 << (8 % 16)))
#define LDR_STR_SIG9(c1, c2, c3, c4, c5, c6, c7, c8, c9) (LDR_STR_SIG8(c1, c2, c3, c4, c5, c6, c7, c8) + (int)c9 * (1 << (9 % 16)))
#define LDR_STR_SIG10(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10) (LDR_STR_SIG9(c1, c2, c3, c4, c5, c6, c7, c8, c9) + (int)c10 * (1 << (10 % 16)))
#define LDR_STR_SIG11(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11) (LDR_STR_SIG10(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10) + (int)c11 * (1 << (11 % 16)))
#define LDR_STR_SIG12(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12) (LDR_STR_SIG11(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11) + (int)c12 * (1 << (12 % 16)))
#define LDR_STR_SIG13(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13) (LDR_STR_SIG12(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12) + (int)c13 * (1 << (13 % 16)))
#define LDR_STR_SIG14(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14) (LDR_STR_SIG13(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13) + (int)c14 * (1 << (14 % 16)))
#define LDR_STR_SIG15(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15) (LDR_STR_SIG14(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14) + (int)c15 * (1 << (15 % 16)))
#define LDR_STR_SIG16(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16) (LDR_STR_SIG15(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15) + (int)c16 * (1 << (16 % 16)))
#define LDR_STR_SIG17(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17) (LDR_STR_SIG16(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16) + (int)c17 * (1 << (17 % 16)))
#define LDR_STR_SIG18(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18) (LDR_STR_SIG17(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17) + (int)c18 * (1 << (18 % 16)))
#define LDR_STR_SIG19(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19) (LDR_STR_SIG18(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18) + (int)c19 * (1 << (19 % 16)))
#define LDR_STR_SIG20(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19, c20) (LDR_STR_SIG19(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19) + (int)c20 * (1 << (20 % 16)))
#define LDR_STR_SIG21(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19, c20, c21) (LDR_STR_SIG20(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19, c20) + (int)c21 * (1 << (21 % 16)))
#define LDR_STR_SIG22(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19, c20, c21, c22) (LDR_STR_SIG21(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19, c20, c21) + (int)c22 * (1 << (22 % 16)))
#define LDR_STR_SIG23(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19, c20, c21, c22, c23) (LDR_STR_SIG22(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19, c20, c21, c22) + (int)c23 * (1 << (23 % 16)))
#define LDR_STR_SIG24(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19, c20, c21, c22, c23, c24) (LDR_STR_SIG23(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19, c20, c21, c22, c23) + (int)c24 * (1 << (24 % 16)))
#define LDR_STR_SIG25(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19, c20, c21, c22, c23, c24, c25) (LDR_STR_SIG24(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19, c20, c21, c22, c23, c24) + (int)c25 * (1 << (25 % 16)))
#define LDR_STR_SIG26(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19, c20, c21, c22, c23, c24, c25, c26) (LDR_STR_SIG25(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19, c20, c21, c22, c23, c24, c25) + (int)c26 * (1 << (26 % 16)))
#define LDR_STR_SIG27(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19, c20, c21, c22, c23, c24, c25, c26, c27) (LDR_STR_SIG26(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19, c20, c21, c22, c23, c24, c25, c26) + (int)c27 * (1 << (27 % 16)))
#define LDR_STR_SIG28(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19, c20, c21, c22, c23, c24, c25, c26, c27, c28) (LDR_STR_SIG27(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19, c20, c21, c22, c23, c24, c25, c26, c27) + (int)c28 * (1 << (28 % 16)))
#define LDR_STR_SIG29(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19, c20, c21, c22, c23, c24, c25, c26, c27, c28, c29) (LDR_STR_SIG28(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19, c20, c21, c22, c23, c24, c25, c26, c27, c28) + (int)c29 * (1 << (29 % 16)))
#define LDR_STR_SIG(...) __NARG__(__VA_ARGS__), VFUNC(LDR_STR_SIG, __VA_ARGS__)

#define LDR_GET_PROC_INTERNAL(varName, module, typeCast, len, sig) \
	auto varName = (typeCast)NULL; \
	auto base##varName = (HINSTANCE)module; \
	auto dosHeader##varName = (PIMAGE_DOS_HEADER)base##varName; \
	auto ntHeader##varName = (PIMAGE_NT_HEADERS)((LONG)dosHeader##varName + dosHeader##varName->e_lfanew); \
	auto exportOffset##varName = ntHeader##varName->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress; \
	auto exportSize##varName = ntHeader##varName->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size; \
	auto exportDir##varName = (PIMAGE_EXPORT_DIRECTORY)((DWORD)base##varName + exportOffset##varName); \
	auto functionArray##varName = (PDWORD)((LPBYTE)base##varName + exportDir##varName->AddressOfFunctions); \
	auto functionNameArray##varName = (PDWORD)((LPBYTE)base##varName + exportDir##varName->AddressOfNames); \
	auto ordinal##varName = (PWORD)((LPBYTE)base##varName + exportDir##varName->AddressOfNameOrdinals); \
	for (DWORD i = 0; i < exportDir##varName->NumberOfFunctions; i++) { \
		if (functionNameArray##varName[i] == NULL) continue; \
		auto funcName = (char*)base##varName+functionNameArray##varName[i]; \
		int nameLen = 0; \
		int nameSig = 0; \
		for (; funcName[nameLen] != '\x00'; nameLen++) \
			nameSig += (int)funcName[nameLen] * (1 << ((nameLen + 1) % 16)); \
		/*printf("Func (len %02d, sig %08d): %s\n", nameLen, nameSig, funcName);*/ \
		if (nameLen == len && nameSig == sig) { \
			varName = (typeCast)((LPBYTE)base##varName+functionArray##varName[ordinal##varName[i]]); \
			/*printf("%s %08d - %s %08d\n", #varName, sig, funcName, nameSig);*/ \
			break; \
		} \
	} \
	if (varName == NULL) /*return 0xBADB33F5;*/ {__asm int 3} \
	//printf("%s at 0x%p\n", #varName, varName);

#define LDR_GET_PROC(...) EXPAND(LDR_GET_PROC_INTERNAL(__VA_ARGS__))

// String definitions in inline assembly as a macro
#define EMIT1(c1) __asm _emit c1
#define EMIT2(c1, c2) EMIT1(c1)  __asm _emit c2
#define EMIT3(c1, c2, c3) EMIT2(c1, c2)  __asm _emit c3
#define EMIT4(c1, c2, c3, c4) EMIT3(c1, c2, c3)  __asm _emit c4
#define EMIT5(c1, c2, c3, c4, c5) EMIT4(c1, c2, c3, c4)  __asm _emit c5
#define EMIT6(c1, c2, c3, c4, c5, c6) EMIT5(c1, c2, c3, c4, c5)  __asm _emit c6
#define EMIT7(c1, c2, c3, c4, c5, c6, c7) EMIT6(c1, c2, c3, c4, c5, c6)  __asm _emit c7
#define EMIT8(c1, c2, c3, c4, c5, c6, c7, c8) EMIT7(c1, c2, c3, c4, c5, c6, c7)  __asm _emit c8
#define EMIT9(c1, c2, c3, c4, c5, c6, c7, c8, c9) EMIT8(c1, c2, c3, c4, c5, c6, c7, c8)  __asm _emit c9
#define EMIT10(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10) EMIT9(c1, c2, c3, c4, c5, c6, c7, c8, c9)  __asm _emit c10
#define EMIT11(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11) EMIT10(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10)  __asm _emit c11
#define EMIT12(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12) EMIT11(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11)  __asm _emit c12
#define EMIT13(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13) EMIT12(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12)  __asm _emit c13
#define EMIT14(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14) EMIT13(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13)  __asm _emit c14
#define EMIT15(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15) EMIT14(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14)  __asm _emit c15
#define EMIT16(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16) EMIT15(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15)  __asm _emit c16
#define EMIT17(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17) EMIT16(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16)  __asm _emit c17
#define EMIT18(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18) EMIT17(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17)  __asm _emit c18
#define EMIT19(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19) EMIT18(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18)  __asm _emit c19
#define EMIT20(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19, c20) EMIT19(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19)  __asm _emit c20
#define EMIT21(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19, c20, c21) EMIT20(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19, c20)  __asm _emit c21

#define DEFINE_STR(type, varName, ...) \
	type varName = NULL; \
	__asm _emit 0xE8 __asm _emit 00 __asm _emit 00 __asm _emit 00 __asm  _emit 00 /* CALL <next instruction> */ \
	__asm POP EAX \
	__asm ADD EAX, 0x06 \
	__asm _emit 0xEB __asm _emit __NARG_PLUS_TWO__(__VA_ARGS__)                  /* jmp over string */ \
	VFUNC(EMIT, __VA_ARGS__)                                                     /* emit string */ \
	__asm _emit '\0' __asm _emit '\0'                                            /* emit nullterm */ \
	__asm MOV varName, EAX

#define ZERO_MEM(ptr, size) \
	for (size_t zerosize = 0; zerosize < size; zerosize++) { \
		((char*)ptr)[zerosize] = 0x00; \
	}
