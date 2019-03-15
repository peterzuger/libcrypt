/**
 * @file   libcrypt/test/sha1_test.cpp
 * @author Brad Conte (brad AT bradconte.com)
 * @author Peter Zueger
 * @date   26.02.2019
 * @brief  sha1 hash implementation
 */
#include <sha1.hpp>
#include <iomanip>
#include <iostream>
#include <string>
#include <sstream>

int main(){
    {
        libcrypt::sha1 algo;
        std::string txt{"abc"};
        std::string output{"0xa9993e364706816aba3e25717850c26c9cd0d89d"};

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
        libcrypt::sha1 algo;
        //std::string txt{""};
        std::string output{"0xda39a3ee5e6b4b0d3255bfef95601890afd80709"};

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
        libcrypt::sha1 algo;
        std::string txt{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"};
        std::string output{"0x84983e441c3bd26ebaae4aa1f95129e5e54670f1"};

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
        libcrypt::sha1 algo;
        std::string txt{"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
                        "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"};
        std::string output{"0xa49b2446a02c645bf419f995b67091253a04a259"};

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
        libcrypt::sha1 algo;
        std::string txt{"a"};
        std::string output{"0x34aa973cd4c4daa4f61eeb2bdbad27316534016f"};

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
        libcrypt::sha1 algo;
        std::string txt{"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"};
        std::string output{"0x7789f0c9ef7bfc40d93311143dfbe69e2017f592"};

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
