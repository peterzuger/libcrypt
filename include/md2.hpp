/**
 * @file   libcrypt/include/md2.hpp
 * @author Brad Conte (brad AT bradconte.com)
 * @author Peter Züger
 * @date   02.02.2020
 * @brief  md2 hash implementation
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
#ifndef LIBCRYPT_MD2_HPP
#define LIBCRYPT_MD2_HPP

#include <array>
#include <cstdint>
#include <cstring>
#include <iterator>

#include "impl.hpp"

namespace crypt{
    class md2{
        std::array<std::uint8_t, 16> data;
        std::array<std::uint8_t, 48> state;
        std::array<std::uint8_t, 16> checksum;
        std::uint32_t len;

        inline constexpr static std::array<std::uint8_t, 256> s{
            41,  46,  67,  201, 162, 216, 124, 1,   61,  54,  84,  161, 236, 240, 6,   19,
            98,  167, 5,   243, 192, 199, 115, 140, 152, 147, 43,  217, 188, 76,  130, 202,
            30,  155, 87,  60,  253, 212, 224, 22,  103, 66,  111, 24,  138, 23,  229, 18,
            190, 78,  196, 214, 218, 158, 222, 73,  160, 251, 245, 142, 187, 47,  238, 122,
            169, 104, 121, 145, 21,  178, 7,   63,  148, 194, 16,  137, 11,  34,  95,  33,
            128, 127, 93,  154, 90,  144, 50,  39,  53,  62,  204, 231, 191, 247, 151, 3,
            255, 25,  48,  179, 72,  165, 181, 209, 215, 94,  146, 42,  172, 86,  170, 198,
            79,  184, 56,  210, 150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4,   241,
            69,  157, 112, 89,  100, 113, 135, 32,  134, 91,  207, 101, 230, 45,  168, 2,
            27,  96,  37,  173, 174, 176, 185, 246, 28,  70,  97,  105, 52,  64,  126, 15,
            85,  71,  163, 35,  221, 81,  175, 58,  195, 92,  249, 206, 186, 197, 234, 38,
            44,  83,  13,  110, 133, 40,  132, 9,   211, 223, 205, 244, 65,  129, 77,  82,
            106, 220, 55,  200, 108, 193, 171, 250, 36,  225, 123, 8,   12,  189, 177, 74,
            120, 136, 149, 139, 227, 99,  232, 109, 233, 203, 213, 254, 59,  0,   29,  57,
            242, 239, 183, 14,  102, 88,  208, 228, 166, 119, 114, 248, 235, 117, 75,  10,
            49,  68,  80,  180, 143, 237, 31,  26,  219, 153, 141, 51,  159, 17,  131, 20
        };

        void transform(){
            for(std::uint8_t j = 0; j < 16; ++j){
                state[j + 16] = data[j];
                state[j + 32] = (state[j+16] ^ state[j]);
            }

            std::uint32_t t = 0;
            for(std::uint8_t j = 0; j < 18; ++j){
                for(std::uint8_t k = 0; k < 48; ++k){
                    state[k] = static_cast<std::uint8_t>(state[k]^ s[t]);
                    t = state[k];
                }
                t = (t+j) & 0xFF;
            }

            t = checksum[15];
            for(std::uint8_t j = 0; j < 16; ++j){
                checksum[j] = static_cast<std::uint8_t>(checksum[j] ^ s[data[j] ^ t]);
                t = checksum[j];
            }
        }

    public:
        md2(){
            state.fill(0);
            checksum.fill(0);
            len = 0;
        }

        template<typename T>
        void update(const T& byte){
            static_assert((sizeof(T) == 1),
                          "crypt::md2::update: T must be byte");
            data[len] = static_cast<std::uint8_t>(byte);
            len++;
            if(len == data.size()){
                transform();
                len = 0;
            }
        }

        template<typename Iterator>
        void update(Iterator first, Iterator last){
            static_assert((sizeof(typename std::iterator_traits<Iterator>::value_type) == 1),
                          "crypt::md2::update: T::value_type must be byte");
            for(; first != last; ++first){
                update(*first);
            }
        }

        std::array<std::uint8_t, 16> final(){
            std::uint8_t to_pad = static_cast<std::uint8_t>(data.size() - len);

            while(len < data.size())
                data[len++] = to_pad;

            transform();

            for(std::uint8_t j = 0; j < 16; ++j){
                state[j + 16] = checksum[j];
                state[j + 32] = (state[j+16] ^ state[j]);
            }

            std::uint32_t t = 0;
            for(std::uint8_t j = 0; j < 18; ++j){
                for(std::uint8_t k = 0; k < 48; ++k){
                    state[k] = static_cast<std::uint8_t>(state[k] ^ s[t]);
                    t = state[k];
                }
                t = (t+j) & 0xFF;
            }

            t = checksum[15];
            for(std::uint8_t j = 0; j < 16; ++j){
                checksum[j] = static_cast<std::uint8_t>(checksum[j] ^ s[checksum[j] ^ t]);
                t = checksum[j];
            }

            std::array<std::uint8_t, 16> hash;
            std::memcpy(hash.data(), state.data(), hash.size());

            return hash;
        }
    };
}

#endif /* LIBCRYPT_MD2_HPP */
