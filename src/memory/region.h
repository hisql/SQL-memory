#pragma once

#include "memory.h"

#include <cstdint>
#include <cstring>
#include <memory>
#include <new>
#include <optional>
#include <type_traits>

namespace sql
{
	class Region
	{
	public:
		static constexpr size_t kMaxSize = 256ull * 1024 * 1024;
		static constexpr size_t kChunk = 65536;

		Region() = default;
		Region(const Memory* mem, uint64_t base, size_t size) { Load(mem, base, size); }
		Region(const Region&) = delete;
		Region& operator=(const Region&) = delete;
		Region(Region&&) noexcept = default;
		Region& operator=(Region&&) noexcept = default;

		void Load(const Memory* mem, uint64_t base, size_t size)
		{
			Clear();
			if (!mem || !mem->IsAttached() || !base || !size || size > kMaxSize)
				return;

			std::unique_ptr<uint8_t[]> buf(new (std::nothrow) uint8_t[size]);
			if (!buf)
				return;

			if (mem->ReadRaw(base, buf.get(), size) != size)
				mem->ReadChunked(base, buf.get(), size, kChunk);

			m_buf = std::move(buf);
			m_base = base;
			m_size = size;
			m_ok = true;
		}

		void Clear() noexcept
		{
			m_buf.reset();
			m_base = 0;
			m_size = 0;
			m_ok = false;
		}

		[[nodiscard]] bool Valid() const noexcept { return m_ok; }
		[[nodiscard]] uint64_t Base() const noexcept { return m_base; }
		[[nodiscard]] uint64_t Size() const noexcept { return m_size; }
		[[nodiscard]] const uint8_t* Data() const noexcept { return m_buf.get(); }
		[[nodiscard]] bool Empty() const noexcept { return m_size == 0; }
		[[nodiscard]] uint8_t operator[](size_t i) const noexcept { return m_buf[i]; }

		template <typename T>
		[[nodiscard]] __forceinline bool Get(size_t off, T& out) const noexcept
		{
			static_assert(std::is_trivially_copyable_v<T>);

			if (!m_ok || off > m_size || sizeof(T) > m_size - off)
				return false;

			memcpy(&out, m_buf.get() + off, sizeof(T));
			return true;
		}

		template <typename T>
		[[nodiscard]] __forceinline T GetOr(size_t off, T fb = T{}) const noexcept
		{
			static_assert(std::is_trivially_copyable_v<T>);

			T val = fb;
			(void)Get(off, val);
			return val;
		}

		template <typename T>
		[[nodiscard]] __forceinline T Fast(size_t off) const noexcept
		{
			static_assert(std::is_trivially_copyable_v<T>);

			T val;
			memcpy(&val, m_buf.get() + off, sizeof(T));
			return val;
		}

		template <typename T>
		[[nodiscard]] std::optional<uint64_t> Find(const T& val, size_t start = 0) const
		{
			static_assert(std::is_trivially_copyable_v<T>);

			if (!m_ok || sizeof(T) > m_size || start > m_size - sizeof(T))
				return std::nullopt;

			const uint8_t* b = m_buf.get();
			const uint8_t first = ((const uint8_t*)&val)[0];
			const size_t end = m_size - sizeof(T);

			for (size_t i = start; i <= end;)
			{
				const void* hit = memchr(b + i, first, end - i + 1);
				if (!hit)
					return std::nullopt;

				i = (const uint8_t*)hit - b;
				if (memcmp(b + i, &val, sizeof(T)) == 0)
					return m_base + i;
				++i;
			}
			return std::nullopt;
		}

		[[nodiscard]] std::optional<uint64_t> FindPattern(const uint8_t* pat, const char* msk, size_t len, size_t start = 0) const
		{
			if (!m_ok || !pat || !msk || !len || len > m_size || start > m_size - len)
				return std::nullopt;

			const uint8_t* b = m_buf.get();
			const size_t end = m_size - len;

			size_t anchor = 0;
			while (anchor < len && msk[anchor] == '?')
				++anchor;
			if (anchor == len)
				return m_base + start;

			for (size_t i = start; i <= end;)
			{
				const void* hit = memchr(b + i + anchor, pat[anchor], end - i + 1);
				if (!hit)
					return std::nullopt;

				i = (const uint8_t*)hit - b - anchor;
				if (match(b, pat, msk, len, i))
					return m_base + i;
				++i;
			}
			return std::nullopt;
		}

	private:
		static bool match(const uint8_t* b, const uint8_t* p, const char* msk, size_t len, size_t i) noexcept
		{
			for (size_t j = 0; j < len; ++j)
			{
				if (msk[j] != '?' && b[i + j] != p[j])
					return false;
			}
			return true;
		}

		std::unique_ptr<uint8_t[]> m_buf;
		uint64_t m_base = 0;
		size_t m_size = 0;
		bool m_ok = false;
	};
}
