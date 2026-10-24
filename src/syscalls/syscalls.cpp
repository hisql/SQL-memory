#include "syscalls.h"

#include <cstdint>
#include <cstring>

namespace
{
	constexpr int StubWindow = 40; 

	bool ValidWindow(const void* p, const size_t need) noexcept
	{
		MEMORY_BASIC_INFORMATION mbi{};
		if (!VirtualQuery(p, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_NOACCESS))
			return false;

		return (uint8_t*)mbi.BaseAddress + mbi.RegionSize >= (const uint8_t*)p + need;
	}

	
	const uint8_t* Unhooked(const uint8_t* fn) noexcept
	{
		if (fn[0] == 0xE9)
		{
			int32_t disp = 0;
			memcpy(&disp, fn + 1, 4);
			fn += 5 + disp;
		}
		else if (fn[0] == 0xFF && fn[1] == 0x25)
		{
			int32_t disp = 0;
			memcpy(&disp, fn + 2, 4);
			const uint8_t* const* slot = (const uint8_t* const*)(fn + 6 + disp);

			if (!ValidWindow(slot, sizeof(void*)))
				return nullptr;

			fn = *slot;
		}

		return fn;
	}

	DWORD ReadSsn(const uint8_t* fn) noexcept
	{
		for (int i = 0; i + 8 <= StubWindow; ++i)
		{
			if (fn[i] == 0x4C && fn[i + 1] == 0x8B && fn[i + 2] == 0xD1 && fn[i + 3] == 0xB8)
			{
				DWORD ssn = 0;
				memcpy(&ssn, fn + i + 4, 4);
				return ssn;
			}
		}

		for (int i = 0; i + 5 <= StubWindow; ++i)
		{
			if (fn[i] == 0xB8)
			{
				DWORD ssn = 0;
				memcpy(&ssn, fn + i + 1, 4);
				return ssn;
			}
		}

		return 0;
	}
}

namespace Syscalls
{
	bool Init() noexcept
	{
		const HMODULE ntdll = GetModuleHandleA("ntdll.dll");
		if (!ntdll)
			return false;

		struct Entry
		{
			const char* name;
			DWORD* out;
		};

		const Entry table[] = {
			{ "NtReadVirtualMemory",    &NtReadId },
			{ "NtWriteVirtualMemory",   &NtWriteId },
			{ "NtOpenProcess",          &NtOpenId },
			{ "NtClose",                &NtCloseId },
			{ "NtProtectVirtualMemory", &NtProtectId },
			{ "NtCreateThreadEx",       &NtCreateThreadId },
		};

		
		for (const Entry& e : table)
		{
			const uint8_t* fn = (const uint8_t*)GetProcAddress(ntdll, e.name);
			if (!fn || !ValidWindow(fn, 4))
				continue;

			fn = Unhooked(fn);
			if (!fn || !ValidWindow(fn, StubWindow))
				continue;

			if (const DWORD ssn = ReadSsn(fn))
				*e.out = ssn;
		}

		return Ready();
	}

	bool Ready() noexcept
	{
		return NtReadId && NtWriteId && NtOpenId && NtCloseId;
	}
}
