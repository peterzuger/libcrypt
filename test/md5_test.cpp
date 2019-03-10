/**
 * @file   libcrypt/test/md5_test.cpp
 * @author Brad Conte (brad AT bradconte.com)
 * @author Peter Zueger
 * @date   26.02.2019
 * @brief  md5 hash implementation
 */
#include <md5.hpp>
#include <iomanip>
#include <iostream>
#include <string>

int main(){
    {
        libcrypt::md5 algo;
        std::string txt{"abc"};
        std::string output{"900150983cd24fb0d6963f7d28e17f72"};

        algo.update(txt);
        auto res = algo.final();
        std::cout << "0x";
        for(const auto& i : res)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(i);
        std::cout << "\n0x" << output << "\n";
    }
    {
        libcrypt::md5 algo;
        //std::string txt{""};
        std::string output{"d41d8cd98f00b204e9800998ecf8427e"};

        //algo.update(txt);
        auto res = algo.final();
        std::cout << "0x";
        for(const auto& i : res)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(i);
        std::cout << "\n0x" << output << "\n";
    }
    {
        libcrypt::md5 algo;
        std::string txt{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"};
        std::string output{"8215ef0796a20bcaaae116d3876c664a"};

        algo.update(txt);
        auto res = algo.final();
        std::cout << "0x";
        for(const auto& i : res)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(i);
        std::cout << "\n0x" << output << "\n";
    }
    {
        libcrypt::md5 algo;
        std::string txt{"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
                        "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"};
        std::string output{"03dd8807a93175fb062dfb55dc7d359c"};

        algo.update(txt);
        auto res = algo.final();
        std::cout << "0x";
        for(const auto& i : res)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(i);
        std::cout << "\n0x" << output << "\n";
    }
    {
        libcrypt::md5 algo;
        std::string txt{"a"};
        std::string output{"7707d6ae4e027c70eea2a935c2296f21"};

        for(std::size_t i = 0; i < 1000000; i++)
            algo.update(txt);
        auto res = algo.final();
        std::cout << "0x";
        for(const auto& i : res)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(i);
        std::cout << "\n0x" << output << "\n";
    }
    {
        libcrypt::md5 algo;
        std::string txt{"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"};
        std::string output{"d338139169d50f55526194c790ec0448"};

        for(std::size_t i = 0; i < 16777216; i++)
            algo.update(txt);
        auto res = algo.final();
        std::cout << "0x";
        for(const auto& i : res)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(i);
        std::cout << "\n0x" << output << "\n";
    }
}
