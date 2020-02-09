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

        template<typename T>
        constexpr T CH(T x, T y, T z){
            static_assert(std::is_integral_v<T>, "type must be integral");
            return (((x) & (y)) ^ (~(x) & (z)));
        }

        template<typename T>
        constexpr T MAJ(T x, T y, T z){
            static_assert(std::is_integral_v<T>, "type must be integral");
            return (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)));
        }

        template<typename T>
        constexpr T EP0(T x){
            static_assert(std::is_integral_v<T>, "type must be integral");
            return (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22));
        }

        template<typename T>
        constexpr T EP1(T x){
            static_assert(std::is_integral_v<T>, "type must be integral");
            return (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25));
        }

        template<typename T>
        constexpr T SIG0(T x){
            static_assert(std::is_integral_v<T>, "type must be integral");
            return (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3));
        }

        template<typename T>
        constexpr T SIG1(T x){
            static_assert(std::is_integral_v<T>, "type must be integral");
            return (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10));
        }
    }
}

#endif /* LIBCRYPT_IMPL_HPP */
