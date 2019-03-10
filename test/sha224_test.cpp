/**
 * @file   libcrypt/test/sha224_test.cpp
 * @author Brad Conte (brad AT bradconte.com)
 * @author Peter Zueger
 * @date   26.02.2019
 * @brief  sha224 hash implementation
 */
#include <sha224.hpp>
#include <iomanip>
#include <iostream>
#include <string>

int main(){
    {
        libcrypt::sha224 algo;
        std::string txt{"abc"};
        std::string output{"23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"};

        algo.update(txt);
        auto res = algo.final();
        std::cout << "0x";
        for(const auto& i : res)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(i);
        std::cout << "\n0x" << output << "\n";
    }
    {
        libcrypt::sha224 algo;
        //std::string txt{""};
        std::string output{"d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"};

        //algo.update(txt);
        auto res = algo.final();
        std::cout << "0x";
        for(const auto& i : res)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(i);
        std::cout << "\n0x" << output << "\n";
    }
    {
        libcrypt::sha224 algo;
        std::string txt{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"};
        std::string output{"75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"};

        algo.update(txt);
        auto res = algo.final();
        std::cout << "0x";
        for(const auto& i : res)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(i);
        std::cout << "\n0x" << output << "\n";
    }
    {
        libcrypt::sha224 algo;
        std::string txt{"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
                        "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"};
        std::string output{"c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3"};

        algo.update(txt);
        auto res = algo.final();
        std::cout << "0x";
        for(const auto& i : res)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(i);
        std::cout << "\n0x" << output << "\n";
    }
    {
        libcrypt::sha224 algo;
        std::string txt{"a"};
        std::string output{"20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67"};

        for(std::size_t i = 0; i < 1000000; i++)
            algo.update(txt);
        auto res = algo.final();
        std::cout << "0x";
        for(const auto& i : res)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(i);
        std::cout << "\n0x" << output << "\n";
    }
    {
        libcrypt::sha224 algo;
        std::string txt{"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"};
        std::string output{"b5989713ca4fe47a009f8621980b34e6d63ed3063b2a0a2c867d8a85"};

        for(std::size_t i = 0; i < 16777216; i++)
            algo.update(txt);
        auto res = algo.final();
        std::cout << "0x";
        for(const auto& i : res)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(i);
        std::cout << "\n0x" << output << "\n";
    }
}
