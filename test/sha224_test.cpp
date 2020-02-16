/**
 * @file   libcrypt/test/sha224_test.cpp
 * @author Brad Conte (brad AT bradconte.com)
 * @author Peter Züger
 * @date   26.02.2019
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
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#include <sha224.hpp>

int main(){
    {
        crypt::sha224 algo;
        std::string txt{"abc"};
        std::string output{"0x23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"};

        algo.update(txt.begin(), txt.end());
        auto res = algo.final();
        std::stringstream str;
        str << "0x";
        for(const auto& i : res)
            str << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(i);
        std::cout << str.str() << "\n" << output << "\n";
        if(str.str() != output){
            std::cerr << "failed\n";
            return 1;
        }
    }
    {
        crypt::sha224 algo;
        //std::string txt{""};
        std::string output{"0xd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"};

        //algo.update(txt.begin(), txt.end());
        auto res = algo.final();
        std::stringstream str;
        str << "0x";
        for(const auto& i : res)
            str << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(i);
        std::cout << str.str() << "\n" << output << "\n";
        if(str.str() != output){
            std::cerr << "failed\n";
            return 1;
        }
    }
    {
        crypt::sha224 algo;
        std::string txt{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"};
        std::string output{"0x75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"};

        algo.update(txt.begin(), txt.end());
        auto res = algo.final();
        std::stringstream str;
        str << "0x";
        for(const auto& i : res)
            str << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(i);
        std::cout << str.str() << "\n" << output << "\n";
        if(str.str() != output){
            std::cerr << "failed\n";
            return 1;
        }
    }
    {
        crypt::sha224 algo;
        std::string txt{"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
                        "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"};
        std::string output{"0xc97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3"};

        algo.update(txt.begin(), txt.end());
        auto res = algo.final();
        std::stringstream str;
        str << "0x";
        for(const auto& i : res)
            str << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(i);
        std::cout << str.str() << "\n" << output << "\n";
        if(str.str() != output){
            std::cerr << "failed\n";
            return 1;
        }
    }
    {
        crypt::sha224 algo;
        std::string txt{"a"};
        std::string output{"0x20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67"};

        for(std::size_t i = 0; i < 1000000; i++)
            algo.update(txt.begin(), txt.end());
        auto res = algo.final();
        std::stringstream str;
        str << "0x";
        for(const auto& i : res)
            str << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(i);
        std::cout << str.str() << "\n" << output << "\n";
        if(str.str() != output){
            std::cerr << "failed\n";
            return 1;
        }
    }
    {
        crypt::sha224 algo;
        std::string txt{"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"};
        std::string output{"0xb5989713ca4fe47a009f8621980b34e6d63ed3063b2a0a2c867d8a85"};

        for(std::size_t i = 0; i < 16777216; i++)
            algo.update(txt.begin(), txt.end());
        auto res = algo.final();
        std::stringstream str;
        str << "0x";
        for(const auto& i : res)
            str << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(i);
        std::cout << str.str() << "\n" << output << "\n";
        if(str.str() != output){
            std::cerr << "failed\n";
            return 1;
        }
    }
}
