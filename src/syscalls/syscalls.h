#pragma once

#include <windows.h>

extern "C" {
extern DWORD NtReadId;
extern DWORD NtWriteId;
extern DWORD NtOpenId;
extern DWORD NtCloseId;
extern DWORD NtProtectId;
extern DWORD NtCreateThreadId;

NTSTATUS Luck_NtReadVirtualMemory(HANDLE h, PVOID base, PVOID buf, SIZE_T size, PSIZE_T got);
NTSTATUS Luck_NtWriteVirtualMemory(HANDLE h, PVOID base, PVOID buf, SIZE_T size, PSIZE_T wrote);
NTSTATUS Luck_NtOpenProcess(PHANDLE h, ACCESS_MASK access, PVOID oa, PVOID cid);
NTSTATUS Luck_NtClose(HANDLE h);
NTSTATUS Luck_NtProtectVirtualMemory(HANDLE h, PVOID* base, PSIZE_T size, ULONG prot, PULONG old);
NTSTATUS Luck_NtCreateThreadEx(PHANDLE h, ACCESS_MASK access, PVOID oa, HANDLE process, PVOID start, PVOID arg,
                               ULONG flags, SIZE_T zeroBits, SIZE_T stackSize, SIZE_T maxStackSize, PVOID attrList);
}

#ifndef NT_SUCCESS
#define NT_SUCCESS(status) (((NTSTATUS)(status)) >= 0)
#endif

namespace Syscalls
{
	bool Init() noexcept;
	bool Ready() noexcept;

	inline DWORD ReadId() noexcept    { return NtReadId; }
	inline DWORD WriteId() noexcept   { return NtWriteId; }
	inline DWORD OpenId() noexcept    { return NtOpenId; }
	inline DWORD CloseId() noexcept   { return NtCloseId; }
	inline DWORD ProtectId() noexcept { return NtProtectId; }
	inline DWORD ThreadId() noexcept  { return NtCreateThreadId; }
}
