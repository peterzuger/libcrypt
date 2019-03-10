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

int main(){
    {
        libcrypt::sha1 algo;
        std::string txt{"abc"};
        std::string output{"a9993e364706816aba3e25717850c26c9cd0d89d"};

        algo.update(txt);
        auto res = algo.final();
        std::cout << "0x";
        for(const auto& i : res)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(i);
        std::cout << "\n0x" << output << "\n";
    }
    {
        libcrypt::sha1 algo;
        //std::string txt{""};
        std::string output{"da39a3ee5e6b4b0d3255bfef95601890afd80709"};

        //algo.update(txt);
        auto res = algo.final();
        std::cout << "0x";
        for(const auto& i : res)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(i);
        std::cout << "\n0x" << output << "\n";
    }
    {
        libcrypt::sha1 algo;
        std::string txt{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"};
        std::string output{"84983e441c3bd26ebaae4aa1f95129e5e54670f1"};

        algo.update(txt);
        auto res = algo.final();
        std::cout << "0x";
        for(const auto& i : res)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(i);
        std::cout << "\n0x" << output << "\n";
    }
    {
        libcrypt::sha1 algo;
        std::string txt{"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
                        "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"};
        std::string output{"a49b2446a02c645bf419f995b67091253a04a259"};

        algo.update(txt);
        auto res = algo.final();
        std::cout << "0x";
        for(const auto& i : res)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(i);
        std::cout << "\n0x" << output << "\n";
    }
    {
        libcrypt::sha1 algo;
        std::string txt{"a"};
        std::string output{"34aa973cd4c4daa4f61eeb2bdbad27316534016f"};

        for(std::size_t i = 0; i < 1000000; i++)
            algo.update(txt);
        auto res = algo.final();
        std::cout << "0x";
        for(const auto& i : res)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(i);
        std::cout << "\n0x" << output << "\n";
    }
    {
        libcrypt::sha1 algo;
        std::string txt{"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"};
        std::string output{"7789f0c9ef7bfc40d93311143dfbe69e2017f592"};

        for(std::size_t i = 0; i < 16777216; i++)
            algo.update(txt);
        auto res = algo.final();
        std::cout << "0x";
        for(const auto& i : res)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(i);
        std::cout << "\n0x" << output << "\n";
    }
}
