/**
 * @file   libcrypt/include/sha1.hpp
 * @author Brad Conte (brad AT bradconte.com)
 * @author Peter Züger
 * @date   26.02.2019
 * @brief  sha1 hash implementation
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
#ifndef LIBCRYPT_SHA1_HPP
#define LIBCRYPT_SHA1_HPP

#include <array>
#include <cstdint>
#include <iterator>

#include "impl.hpp"

namespace libcrypt{
    class sha1{
        std::array<std::uint8_t, 64> data;
        std::uint32_t datalen;
        std::uint64_t bitlen;
        std::array<std::uint32_t, 5> state;
        inline constexpr static std::array<std::uint32_t, 4> k{
            0x5a827999,
            0x6ed9eba1,
            0x8f1bbcdc,
            0xca62c1d6
        };

        void transform(){
            std::array<std::uint32_t, 80> m;
            std::uint32_t a, b, c, d, e, i, j, t;

            for(i = 0, j = 0; i < 16; ++i, j += 4)
                m[i] = static_cast<std::uint32_t>((data[j]     << 24) +
                                                  (data[j + 1] << 16) +
                                                  (data[j + 2] <<  8) +
                                                  (data[j + 3]      )   );
            for(; i < 80; ++i){
                m[i] = (m[i - 3] ^ m[i - 8] ^ m[i - 14] ^ m[i - 16]);
                m[i] = (m[i] << 1) | (m[i] >> 31);
            }

            a = state[0];
            b = state[1];
            c = state[2];
            d = state[3];
            e = state[4];

            {
                using impl::ROTLEFT;
                for(i = 0; i < 20; ++i){
                    t = ROTLEFT(a, 5) + ((b & c) ^ (~b & d)) + e + k[0] + m[i];
                    e = d;
                    d = c;
                    c = ROTLEFT(b, 30);
                    b = a;
                    a = t;
                }
                for(; i < 40; ++i){
                    t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + k[1] + m[i];
                    e = d;
                    d = c;
                    c = ROTLEFT(b, 30);
                    b = a;
                    a = t;
                }
                for(; i < 60; ++i){
                    t = ROTLEFT(a, 5) + ((b & c) ^ (b & d) ^ (c & d))  + e + k[2] + m[i];
                    e = d;
                    d = c;
                    c = ROTLEFT(b, 30);
                    b = a;
                    a = t;
                }
                for(; i < 80; ++i){
                    t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + k[3] + m[i];
                    e = d;
                    d = c;
                    c = ROTLEFT(b, 30);
                    b = a;
                    a = t;
                }
            }

            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
            state[4] += e;
        }

    public:
        sha1(){
            datalen = 0;
            bitlen = 0;
            state[0] = 0x67452301;
            state[1] = 0xEFCDAB89;
            state[2] = 0x98BADCFE;
            state[3] = 0x10325476;
            state[4] = 0xc3d2e1f0;
        }

        template<typename T>
        void update(const T& byte){
            static_assert((sizeof(T) == 1),
                          "libcrypt::sha1::update: T must be byte");
            data[datalen] = static_cast<std::uint8_t>(byte);
            datalen++;
            if(datalen == data.size()){
                transform();
                bitlen += 512;
                datalen = 0;
            }
        }

        template<typename Iterator>
        void update(Iterator first, Iterator last){
            static_assert((sizeof(typename std::iterator_traits<Iterator>::value_type) == 1),
                          "libcrypt::sha1::update: T::value_type must be byte");
            for(; first != last; ++first){
                update(*first);
            }
        }

        std::array<std::uint8_t, 20> final(){
            std::array<std::uint8_t, 20> hash;
            std::uint32_t i = datalen;

            // Pad whatever data is left in the buffer.
            if(datalen < 56){
                data[i++] = 0x80;
                while (i < 56)
                    data[i++] = 0x00;
            }else {
                data[i++] = 0x80;
                while(i < 64)
                    data[i++] = 0x00;
                transform();
                for(std::size_t j = 0; j < 56; j++)
                    data[j] = 0;
            }

            // Append to the padding the total message's length in bits and transform.
            bitlen += datalen * 8;
            data[63] = static_cast<std::uint8_t>(bitlen);
            data[62] = static_cast<std::uint8_t>(bitlen >> 8);
            data[61] = static_cast<std::uint8_t>(bitlen >> 16);
            data[60] = static_cast<std::uint8_t>(bitlen >> 24);
            data[59] = static_cast<std::uint8_t>(bitlen >> 32);
            data[58] = static_cast<std::uint8_t>(bitlen >> 40);
            data[57] = static_cast<std::uint8_t>(bitlen >> 48);
            data[56] = static_cast<std::uint8_t>(bitlen >> 56);
            transform();

            // Since this implementation uses little endian byte ordering and MD uses big endian,
            // reverse all the bytes when copying the final state to the output hash.
            for(i = 0; i < 4; ++i){
                hash[i]      = (state[0] >> (24 - i * 8)) & 0x000000ff;
                hash[i + 4]  = (state[1] >> (24 - i * 8)) & 0x000000ff;
                hash[i + 8]  = (state[2] >> (24 - i * 8)) & 0x000000ff;
                hash[i + 12] = (state[3] >> (24 - i * 8)) & 0x000000ff;
                hash[i + 16] = (state[4] >> (24 - i * 8)) & 0x000000ff;
            }
            return hash;
        }
    };
}

#endif /* LIBCRYPT_SHA1_HPP */
