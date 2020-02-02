/**
 * @file   libcrypt/test/md2_test.cpp
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
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#include <md2.hpp>

int main(){
    {
        libcrypt::md2 algo;
        std::string txt{"abc"};
        std::string output{"0xda853b0d3f88d99b30283a69e6ded6bb"};

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
        libcrypt::md2 algo;
        std::string txt{"abcdefghijklmnopqrstuvwxyz"};
        std::string output{"0x4e8ddff3650292ab5a4108c3aa47940b"};

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
        libcrypt::md2 algo;
        std::string txt1{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcde"};
        std::string txt2{"fghijklmnopqrstuvwxyz0123456789"};
        std::string output{"0xda33def2a42df13975352846c30338cd"};

        algo.update(txt1.begin(), txt1.end());
        algo.update(txt2.begin(), txt2.end());
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
