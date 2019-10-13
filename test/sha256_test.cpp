/**
 * @file   libcrypt/test/sha256_test.cpp
 * @author Brad Conte (brad AT bradconte.com)
 * @author Peter Züger
 * @date   26.02.2019
 * @brief  sha256 hash implementation
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
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#include <sha256.hpp>

int main(){
    {
        libcrypt::sha256 algo;
        std::string txt{"abc"};
        std::string output{"0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"};

        algo.update(txt);
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
        libcrypt::sha256 algo;
        //std::string txt{""};
        std::string output{"0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"};

        //algo.update(txt);
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
        libcrypt::sha256 algo;
        std::string txt{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"};
        std::string output{"0x248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"};

        algo.update(txt);
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
        libcrypt::sha256 algo;
        std::string txt{"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
                        "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"};
        std::string output{"0xcf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"};

        algo.update(txt);
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
        libcrypt::sha256 algo;
        std::string txt{"a"};
        std::string output{"0xcdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"};

        for(std::size_t i = 0; i < 1000000; i++)
            algo.update(txt);
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
        libcrypt::sha256 algo;
        std::string txt{"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"};
        std::string output{"0x50e72a0e26442fe2552dc3938ac58658228c0cbfb1d2ca872ae435266fcd055e"};

        for(std::size_t i = 0; i < 16777216; i++)
            algo.update(txt);
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
