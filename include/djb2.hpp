/**
 * @file   libcrypt/include/djb2.hpp
 * @author Peter Züger
 * @date   20.03.2020
 * @brief  Bernstein djb2 Hash implementation
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2020 Peter Züger
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
#ifndef LIBCRYPT_DJB2_HPP
#define LIBCRYPT_DJB2_HPP

#include <cstdint>
#include <iterator>

namespace crypt{
    class djb2{
        std::uint32_t hash;

    public:
        djb2(): hash{5381}{}

        template<typename T>
        void update(const T& byte){
            static_assert((sizeof(T) == 1),
                          "crypt::djb2::update: T must be byte");
            hash = ((hash << 5) + hash) + byte; /* hash * 33 + c */
        }

        template<typename Iterator>
        void update(Iterator first, Iterator last){
            static_assert((sizeof(typename std::iterator_traits<Iterator>::value_type) == 1),
                          "crypt::djb::update: T::value_type must be byte");
            for(; first != last; ++first){
                update(*first);
            }
        }

        std::uint32_t final(){
            return hash;
        }
    };
}

#endif /* LIBCRYPT_DJB2_HPP */
