/**
 * @file   libcrypt/include/sha224.hpp
 * @author Brad Conte (brad AT bradconte.com)
 * @author Peter Züger
 * @date   28.02.2019
 * @brief  sha224 hash implementation
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
#ifndef LIBCRYPT_SHA224_HPP
#define LIBCRYPT_SHA224_HPP

#include <array>
#include <cstdint>
#include <iterator>

#include "impl.hpp"

namespace crypt{
    class sha224{
        std::array<std::uint8_t, 64> data;
        std::uint32_t datalen;
        std::uint64_t bitlen;
        std::array<std::uint32_t, 8> state;
        inline constexpr static std::array<std::uint32_t, 64> k{
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
        };

        void transform(){
            using namespace impl;
            std::array<std::uint32_t, 64> m;
            std::uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2;

            for(i = 0, j = 0; i < 16; ++i, j += 4)
                m[i] = static_cast<std::uint32_t>((data[j]     << 24) |
                                                  (data[j + 1] << 16) |
                                                  (data[j + 2] <<  8) |
                                                  (data[j + 3]      )   );
            for(; i < 64; ++i)
                m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

            a = state[0];
            b = state[1];
            c = state[2];
            d = state[3];
            e = state[4];
            f = state[5];
            g = state[6];
            h = state[7];

            for(i = 0; i < 64; ++i){
                t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
                t2 = EP0(a) + MAJ(a,b,c);
                h = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b;
                b = a;
                a = t1 + t2;
            }

            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
            state[4] += e;
            state[5] += f;
            state[6] += g;
            state[7] += h;
        }

    public:
        sha224(){
            datalen = 0;
            bitlen = 0;
            state[0] = 0xc1059ed8;
            state[1] = 0x367cd507;
            state[2] = 0x3070dd17;
            state[3] = 0xf70e5939;
            state[4] = 0xffc00b31;
            state[5] = 0x68581511;
            state[6] = 0x64f98fa7;
            state[7] = 0xbefa4fa4;
        }

        template<typename T>
        void update(const T& byte){
            static_assert((sizeof(T) == 1),
                          "crypt::sha224::update: T must be byte");
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
                          "crypt::sha224::update: T::value_type must be byte");
            for(; first != last; ++first){
                update(*first);
            }
        }

        std::array<std::uint8_t, 28> final(){
            std::array<std::uint8_t, 28> hash;
            std::uint32_t i = datalen;

            // Pad whatever data is left in the buffer.
            if(datalen < 56){
                data[i++] = 0x80;
                while(i < 56)
                    data[i++] = 0x00;
            }else{
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

            // Since this implementation uses little endian byte ordering and SHA uses big endian,
            // reverse all the bytes when copying the final state to the output hash.
            for(i = 0; i < 4; ++i){
                hash[i]      = (state[0] >> (24 - i * 8)) & 0x000000ff;
                hash[i + 4]  = (state[1] >> (24 - i * 8)) & 0x000000ff;
                hash[i + 8]  = (state[2] >> (24 - i * 8)) & 0x000000ff;
                hash[i + 12] = (state[3] >> (24 - i * 8)) & 0x000000ff;
                hash[i + 16] = (state[4] >> (24 - i * 8)) & 0x000000ff;
                hash[i + 20] = (state[5] >> (24 - i * 8)) & 0x000000ff;
                hash[i + 24] = (state[6] >> (24 - i * 8)) & 0x000000ff;
            }

            return hash;
        }
    };
}

#endif /* LIBCRYPT_SHA224_HPP */
