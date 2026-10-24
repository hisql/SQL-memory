#pragma once

#include "../syscalls/syscalls.h"

#include <windows.h>
#include <TlHelp32.h>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

struct Module
{
	char Name[64]{};
	uint64_t Base = 0;
	uint64_t Size = 0;
};

class Memory
{
public:
	Memory() = default;
	~Memory();

	Memory(const Memory&) = delete;
	Memory& operator=(const Memory&) = delete;

	Memory(Memory&& o) noexcept;
	Memory& operator=(Memory&& o) noexcept;



	[[nodiscard]] bool Attach(std::string_view name) noexcept;
	void Detach() noexcept;

	[[nodiscard]] static uint32_t FindProcessId(std::string_view name) noexcept;
	[[nodiscard]] uint64_t FindModule(std::string_view name) const noexcept;
	[[nodiscard]] std::vector<Module> ListModules() const;


	template <typename T>
	[[nodiscard]] __forceinline T Read(const uint64_t addr, const T fallback = T{}) const noexcept
	{
		static_assert(std::is_trivially_copyable_v<T>);

		T out{};
		return ReadInto(addr, out) ? out : fallback;
	}

	template <typename T>
	__forceinline bool ReadInto(const uint64_t addr, T& out) const noexcept
	{
		static_assert(std::is_trivially_copyable_v<T>);

		SIZE_T got = 0;
		const NTSTATUS st = Luck_NtReadVirtualMemory(m_handle, (PVOID)addr, &out, sizeof(T), &got);
		return got == sizeof(T) && (st >= 0 || st == kPartialCopy);
	}

	template <typename T>
	__forceinline bool ReadArray(const uint64_t addr, T* dst, const size_t count) const noexcept
	{
		static_assert(std::is_trivially_copyable_v<T>);

		if (dst && count)
			return ReadRaw(addr, dst, sizeof(T) * count) == sizeof(T) * count;
		return false;
	}

	size_t ReadRaw(uint64_t addr, void* dst, size_t size) const noexcept;
	size_t ReadChunked(uint64_t addr, void* dst, size_t size, size_t chunk = 65536) const noexcept;

	template <typename T>
	[[nodiscard]] uint64_t Chain(const uint64_t base, const T* offsets, const size_t count) const noexcept
	{
		if (!offsets || !count || !base)
			return 0;

		uint64_t p = 0;
		if (!ReadInto(base, p) || !p)
			return 0;

		for (size_t i = 0; i + 1 < count; ++i)
		{
			if (!ReadInto(p + offsets[i], p) || !p)
				return 0;
		}

		return p + offsets[count - 1];
	}


	template <typename T>
	__forceinline bool Write(const uint64_t addr, const T& val) const noexcept
	{
		static_assert(std::is_trivially_copyable_v<T>);

		SIZE_T wrote = 0;
		const NTSTATUS st = Luck_NtWriteVirtualMemory(m_handle, (PVOID)addr, (PVOID)&val, sizeof(T), &wrote);
		return NT_SUCCESS(st) && wrote == sizeof(T);
	}

	size_t WriteRaw(uint64_t addr, const void* src, size_t size) const noexcept;


	[[nodiscard]] uint64_t ModuleSize(uint64_t base) const noexcept;
	[[nodiscard]] uintptr_t Alloc(uint64_t size, DWORD prot) const noexcept;
	bool Free(uintptr_t addr) const noexcept;
	bool Protect(uintptr_t addr, uint64_t size, DWORD prot, DWORD& old) const noexcept;

	[[nodiscard]] bool IsAttached() const noexcept { return m_handle != nullptr; }
	[[nodiscard]] uint32_t GetPid() const noexcept { return m_pid; }
	[[nodiscard]] uint64_t GetBase() const noexcept { return m_base; }
	[[nodiscard]] HANDLE GetHandle() const noexcept { return m_handle; }

private:
	static constexpr NTSTATUS kPartialCopy = (NTSTATUS)0x8000000D;

	void Reset() noexcept { m_pid = 0; m_base = 0; m_handle = nullptr; }

	uint32_t m_pid = 0;
	uint64_t m_base = 0;
	HANDLE m_handle = nullptr;
};

namespace Mem
{
	[[nodiscard]] inline bool IsValid(const uintptr_t addr) noexcept
	{
		return addr >= 0x10000 && addr < 0x7FFFFFFFFFFFULL;
	}

	template <typename T>
	class Cached
	{
	public:
		static_assert(std::is_trivially_copyable_v<T>);

		[[nodiscard]] bool Ready() const noexcept { return m_ok; }
		[[nodiscard]] const T& Value() const noexcept { return m_val; }
		void Clear() noexcept { m_ok = false; }

		bool Poll(const Memory& mem, const uint64_t addr, const uint32_t ttlMs) noexcept
		{
			const uint64_t now = GetTickCount64();
			if (m_ok && (uint32_t)(now - m_last) < ttlMs)
				return true;

			if (!mem.ReadInto(addr, m_val))
				return false;

			m_last = now;
			m_ok = true;
			return true;
		}

		T Get(const Memory& mem, const uint64_t addr, const uint32_t ttlMs, const T fallback = T{}) noexcept
		{
			return Poll(mem, addr, ttlMs) ? m_val : fallback;
		}

	private:
		T m_val{};
		uint64_t m_last = 0;
		bool m_ok = false;
	};

	[[nodiscard]] std::string ReadString(const Memory& mem, uint64_t addr, size_t max = 256);
}
