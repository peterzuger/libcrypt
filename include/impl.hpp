/**
 * @file   libcrypt/include/impl.hpp
 * @author Brad Conte (brad AT bradconte.com)
 * @author Peter Züger
 * @date   27.02.2019
 * @brief  libcrypt implementation details
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2019 Peter Züger
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef LIBCRYPT_IMPL_HPP
#define LIBCRYPT_IMPL_HPP

#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace libcrypt{
    namespace impl{
        template<typename T>
        constexpr T ROTLEFT(T a, std::size_t b){
            static_assert(std::is_integral_v<T>, "type must be integral");
            return ((a << b) | (a >> ((sizeof(T)*8) - b)));
        }

        template<typename T>
        constexpr T ROTRIGHT(T a, std::size_t b){
            static_assert(std::is_integral_v<T>, "type must be integral");
            return (((a) >> (b)) | ((a) << ((sizeof(T)*8)-(b))));
        }

        constexpr std::uint32_t CH(std::uint32_t x, std::uint32_t y, std::uint32_t z){
            return (((x) & (y)) ^ (~(x) & (z)));
        }

        constexpr std::uint32_t MAJ(std::uint32_t x, std::uint32_t y, std::uint32_t z){
            return (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)));
        }

        constexpr std::uint32_t EP0(std::uint32_t x){
            return (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22));
        }

        constexpr std::uint32_t EP1(std::uint32_t x){
            return (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25));
        }

        constexpr std::uint32_t SIG0(std::uint32_t x){
            return (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3));
        }

        constexpr std::uint32_t SIG1(std::uint32_t x){
            return (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10));
        }
    }
}

#endif /* LIBCRYPT_IMPL_HPP */
