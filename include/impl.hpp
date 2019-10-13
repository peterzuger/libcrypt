/**
 * @file   libcrypt/include/impl.hpp
 * @author Brad Conte (brad AT bradconte.com)
 * @author Peter Züger
 * @date   27.02.2019
 * @brief  libcrypt implementation details
 *
 * This file is part of libcrypt (https://gitlab.com/peterzuger/libcrypt).
 * Copyright (c) 2019 Peter Züger.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
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
