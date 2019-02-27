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

namespace libcrypt{
    namespace impl{
        template<typename T>
        constexpr T ROTLEFT(T a, std::size_t b){
            return ((a << b) | (a >> (32 - b)));
        }
    }
}

#endif /* LIBCRYPT_IMPL_HPP */
