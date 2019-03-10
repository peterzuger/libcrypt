/**
 * @file   libcrypt/include/impl.hpp
 * @author Brad Conte (brad AT bradconte.com)
 * @author Peter Zueger
 * @date   27.02.2019
 * @brief  libcrypt implementation details
 */
#ifndef LIBCRYPT_IMPL_HPP
#define LIBCRYPT_IMPL_HPP

#include <cstdint>
#include <cstddef>

namespace libcrypt{
    namespace impl{
        template<typename T>
        constexpr T ROTLEFT(T a, std::size_t b){
            return ((a << b) | (a >> (32 - b)));
        }

        template<typename T>
        constexpr T ROTRIGHT(T a, std::size_t b){
            return (((a) >> (b)) | ((a) << (32-(b))));
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
