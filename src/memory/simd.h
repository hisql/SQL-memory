#pragma once

#include "region.h"

#include <intrin.h>
#include <cstdint>
#include <cstring>
#include <emmintrin.h>
#include <optional>
#ifdef __AVX2__
#include <immintrin.h>
#endif

namespace sql
{
	namespace detail
	{
		__forceinline bool match(const uint8_t* b, const uint8_t* p, const char* msk, size_t len, size_t i) noexcept
		{
			for (size_t j = 0; j < len; ++j)
			{
				if (msk[j] != '?' && b[i + j] != p[j])
					return false;
			}
			return true;
		}

		__forceinline unsigned long tz(uint32_t v) noexcept
		{
			unsigned long bit = 0;
			_BitScanForward(&bit, v);
			return bit;
		}

		
		inline std::optional<uint64_t> scan_sse2(const uint8_t* b, const uint8_t* p, const char* msk, size_t len,
		                                         size_t anchor, uint64_t base, size_t start, size_t end)
		{
			const __m128i needle = _mm_set1_epi8((char)p[anchor]);
			const size_t tail = end + 1 >= 16 ? end + 1 - 16 : 0;

			size_t i = start + anchor;
			while (tail && i <= tail)
			{
				uint32_t hits = (uint32_t)_mm_movemask_epi8(_mm_cmpeq_epi8(_mm_loadu_si128((const __m128i*)(b + i)), needle));
				while (hits)
				{
					size_t at = i + tz(hits) - anchor;
					if (match(b, p, msk, len, at))
						return base + at;
					hits &= hits - 1;
				}
				i += 16;
			}

			for (; i <= end; ++i)
			{
				if (b[i] != p[anchor])
					continue;
				size_t at = i - anchor;
				if (match(b, p, msk, len, at))
					return base + at;
			}
			return std::nullopt;
		}

#ifdef __AVX2__
		inline std::optional<uint64_t> scan_avx2(const uint8_t* b, const uint8_t* p, const char* msk, size_t len,
		                                         size_t anchor, uint64_t base, size_t start, size_t end)
		{
			const __m256i needle = _mm256_set1_epi8((char)p[anchor]);
			const size_t tail = end + 1 >= 32 ? end + 1 - 32 : 0;

			size_t i = start + anchor;
			while (tail && i <= tail)
			{
				uint32_t hits = (uint32_t)_mm256_movemask_epi8(_mm256_cmpeq_epi8(_mm256_loadu_si256((const __m256i*)(b + i)), needle));
				while (hits)
				{
					size_t at = i + tz(hits) - anchor;
					if (match(b, p, msk, len, at))
						return base + at;
					hits &= hits - 1;
				}
				i += 32;
			}

			for (; i <= end; ++i)
			{
				if (b[i] != p[anchor])
					continue;
				size_t at = i - anchor;
				if (match(b, p, msk, len, at))
					return base + at;
			}
			return std::nullopt;
		}
#endif
	}

	inline std::optional<uint64_t> FindPatternSimd(const Region& region, const uint8_t* pat, const char* msk,
	                                               size_t len, size_t start = 0)
	{
		if (!region.Valid() || !pat || !msk || !len || len > region.Size() || start > region.Size() - len)
			return std::nullopt;

		const uint8_t* b = region.Data();
		const size_t end = region.Size() - len;

		size_t anchor = 0;
		while (anchor < len && msk[anchor] == '?')
			++anchor;
		if (anchor == len)
			return region.Base() + start;

		if (len < 16)
			return region.FindPattern(pat, msk, len, start);
#ifdef __AVX2__
		if (len >= 32)
			return detail::scan_avx2(b, pat, msk, len, anchor, region.Base(), start, end);
#endif
		return detail::scan_sse2(b, pat, msk, len, anchor, region.Base(), start, end);
	}
}
