#include "memory.h"

#include <cstring>
#include <cwchar>

namespace
{
	constexpr size_t MaxName = 260;
	struct Snap
	{
		HANDLE h;

		Snap(const DWORD flags, const DWORD pid) : h(CreateToolhelp32Snapshot(flags, pid)) {}
		~Snap() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
		Snap(const Snap&) = delete;
		Snap& operator=(const Snap&) = delete;

		[[nodiscard]] bool ok() const noexcept { return h != INVALID_HANDLE_VALUE; }
	};

	bool eq(const std::string_view a, const wchar_t* b) noexcept
	{
		if (!b || a.size() >= MaxName)
			return false;

		size_t i = 0;
		for (; i < a.size() && b[i]; ++i)
		{
			if (towlower((unsigned char)a[i]) != towlower(b[i]))
				return false;
		}

		return i == a.size() && !b[i];
	}
}

Memory::~Memory()
{
	Detach();
}

Memory::Memory(Memory&& o) noexcept
	: m_pid(o.m_pid), m_base(o.m_base), m_handle(o.m_handle)
{
	o.Reset();
}

Memory& Memory::operator=(Memory&& o) noexcept
{
	if (this != &o)
	{
		Detach();
		m_pid = o.m_pid;
		m_base = o.m_base;
		m_handle = o.m_handle;
		o.Reset();
	}
	return *this;
}

void Memory::Detach() noexcept
{
	if (m_handle)
	{
		Luck_NtClose(m_handle);
		m_handle = nullptr;
	}
	Reset();
}


uint32_t Memory::FindProcessId(const std::string_view name) noexcept
{
	if (name.empty())
		return 0;

	const Snap snap(TH32CS_SNAPPROCESS, 0);
	if (!snap.ok())
		return 0;

	PROCESSENTRY32W e{};
	e.dwSize = sizeof(e);
	if (!Process32FirstW(snap.h, &e))
		return 0;

	do
	{
		if (eq(name, e.szExeFile))
			return e.th32ProcessID;
	} while (Process32NextW(snap.h, &e));

	return 0;
}

uint64_t Memory::FindModule(const std::string_view name) const noexcept
{
	if (!m_pid || name.empty())
		return 0;

	const Snap snap(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_pid);
	if (!snap.ok())
		return 0;

	MODULEENTRY32W e{};
	e.dwSize = sizeof(e);
	if (!Module32FirstW(snap.h, &e))
		return 0;

	do
	{
		if (eq(name, e.szModule))
			return (uint64_t)e.modBaseAddr;
	} while (Module32NextW(snap.h, &e));

	return 0;
}

std::vector<Module> Memory::ListModules() const
{
	std::vector<Module> out;
	if (!m_pid)
		return out;

	const Snap snap(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_pid);
	if (!snap.ok())
		return out;

	MODULEENTRY32W e{};
	e.dwSize = sizeof(e);
	if (!Module32FirstW(snap.h, &e))
		return out;

	do
	{
		Module m{};
		size_t i = 0;
		for (; i < sizeof(m.Name) - 1 && e.szModule[i]; ++i)
			m.Name[i] = (char)e.szModule[i];
		m.Name[i] = '\0';
		m.Base = (uint64_t)e.modBaseAddr;
		m.Size = e.modBaseSize;

		if (m.Base && m.Size)
			out.push_back(m);
	} while (Module32NextW(snap.h, &e));

	return out;
}

bool Memory::Attach(const std::string_view name) noexcept
{
	Detach();

	const uint32_t pid = FindProcessId(name);
	if (!pid)
		return false;

	struct Cid { HANDLE proc, thread; } cid{ (HANDLE)(uintptr_t)pid, nullptr };
	struct Oa
	{
		ULONG len; PVOID root, name; ULONG attr; PVOID sec, qos;
	} oa{ sizeof(Oa), nullptr, nullptr, 0, nullptr, nullptr };

	HANDLE h = nullptr;
	const ACCESS_MASK access = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION;
	if (!NT_SUCCESS(Luck_NtOpenProcess(&h, access, &oa, &cid)) || !h)
		return false;

	m_pid = pid;
	m_handle = h;
	m_base = FindModule(name);
	return true;
}



size_t Memory::ReadRaw(const uint64_t addr, void* dst, const size_t size) const noexcept
{
	if (!m_handle || !dst || !size)
		return 0;

	SIZE_T got = 0;
	const NTSTATUS st = Luck_NtReadVirtualMemory(m_handle, (PVOID)addr, dst, size, &got);
	return (st >= 0 || st == kPartialCopy) ? (size_t)got : 0;
}

size_t Memory::WriteRaw(const uint64_t addr, const void* src, const size_t size) const noexcept
{
	if (!m_handle || !src || !size)
		return 0;

	SIZE_T wrote = 0;
	const NTSTATUS st = Luck_NtWriteVirtualMemory(m_handle, (PVOID)addr, (PVOID)src, size, &wrote);
	return NT_SUCCESS(st) ? (size_t)wrote : 0;
}

size_t Memory::ReadChunked(const uint64_t addr, void* dst, size_t size, size_t chunk) const noexcept
{
	if (!m_handle || !dst || !size)
		return 0;

	if (!chunk)
		chunk = 65536;

	auto* out = (uint8_t*)dst;
	size_t total = 0;
	for (size_t off = 0; off < size; off += chunk)
	{
		const size_t cur = size - off < chunk ? size - off : chunk;

		SIZE_T got = 0;
		const NTSTATUS st = Luck_NtReadVirtualMemory(m_handle, (PVOID)(addr + off), out + off, cur, &got);
		if (st >= 0 || st == kPartialCopy)
		{
			total += (size_t)got;
			if ((size_t)got != cur)
				memset(out + off + got, 0, cur - (size_t)got);
		}
		else
		{
			memset(out + off, 0, cur);
		}
	}
	return total;
}



uint64_t Memory::ModuleSize(const uint64_t base) const noexcept
{
	if (!m_handle || !base)
		return 0;

	uint8_t hdr[1024];
	if (ReadRaw(base, hdr, sizeof(hdr)) == sizeof(hdr))
	{
		uint16_t mz = 0;
		uint32_t pe = 0;
		uint32_t sig = 0;
		uint16_t magic = 0;
		uint32_t image = 0;

		memcpy(&mz, hdr, 2);
		memcpy(&pe, hdr + 0x3C, 4);

		if (mz == 0x5A4D && pe < sizeof(hdr) - 88)
		{
			memcpy(&sig, hdr + pe, 4);
			memcpy(&magic, hdr + pe + 24, 2);
			memcpy(&image, hdr + pe + 80, 4);

			if (sig == 0x4550 && magic == 0x20B && image && image <= 256u * 1024 * 1024)
				return image;
		}
	}

	MEMORY_BASIC_INFORMATION mbi{};
	if (!VirtualQueryEx(m_handle, (LPCVOID)base, &mbi, sizeof(mbi)))
		return 0;

	const PVOID alloc = mbi.AllocationBase;
	const uint64_t limit = base + (256ull * 1024 * 1024);
	size_t total = 0;
	for (uint64_t cur = base; cur < limit;)
	{
		if (!VirtualQueryEx(m_handle, (LPCVOID)cur, &mbi, sizeof(mbi)))
			break;
		if (mbi.AllocationBase != alloc || mbi.State != MEM_COMMIT || mbi.Type != MEM_IMAGE)
			break;

		total += mbi.RegionSize;
		cur += mbi.RegionSize;
	}
	return total;
}

uintptr_t Memory::Alloc(const uint64_t size, const DWORD prot) const noexcept
{
	return m_handle && size ? (uintptr_t)VirtualAllocEx(m_handle, nullptr, size, MEM_COMMIT | MEM_RESERVE, prot) : 0;
}

bool Memory::Free(const uintptr_t addr) const noexcept
{
	return addr && VirtualFreeEx(m_handle, (LPVOID)addr, 0, MEM_RELEASE);
}

bool Memory::Protect(const uintptr_t addr, const uint64_t size, const DWORD prot, DWORD& old) const noexcept
{
	if (!m_handle || !addr || !size)
		return false;

	PVOID base = (PVOID)addr;
	SIZE_T len = size;
	ULONG prev = 0;
	if (!NT_SUCCESS(Luck_NtProtectVirtualMemory(m_handle, &base, &len, prot, &prev)))
		return false;

	old = prev;
	return true;
}

// helper 

std::string Mem::ReadString(const Memory& mem, const uint64_t addr, const size_t max)
{
	std::string out;
	if (!addr || !max)
		return out;

	char stack[256];
	if (max <= sizeof(stack))
	{
		const size_t got = mem.ReadRaw(addr, stack, max);
		out.assign(stack, got ? strnlen(stack, got) : 0);
		return out;
	}

	out.resize(max);
	out.resize(mem.ReadRaw(addr, out.data(), max));

	const size_t nul = out.find('\0');
	if (nul != std::string::npos)
		out.resize(nul);

	return out;
}
