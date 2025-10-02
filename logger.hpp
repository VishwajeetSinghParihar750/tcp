#pragma once
#include <string>
#include <iostream>
#include <ostream>

class logger // just took from my code at : https://github.com/VishwajeetSinghParihar750/httpserver/blob/master/logger.hpp
{            // logger singleton

    bool on = true;

    logger() = default;
    ~logger() = default;

public:
    logger(const logger &) = delete;
    logger &operator=(const logger &) = delete;
    logger(logger &&) = delete;
    logger &operator=(logger &&) = delete;

    static logger &getInstance() // this is thread safe in modern c++
    {
        static logger instance;
        return instance;
    }
    template <typename... Args>
    void logInfo(Args &&...args) // msgs would be interleaved without lockign
    {
        if (on)
        {
            size_t n = 0;
            ((std::cout << args << (n++ + 1 == sizeof...(Args) ? '\n' : ' ')), ...);
        }
    }
    template <typename... Args>
    void logError(Args &&...args) // msgs would be interleaved without lockign
    {
        if (on)
        {
            size_t n = 0;
            ((std::cerr << args << (n++ + 1 == sizeof...(Args) ? '\n' : ' ')), ...);
        }
    }

    template <typename... Args>
    void logTest(Args &&...args) // msgs would be interleaved without lockign
    {
        size_t n = 0;
        ((std::cerr << args << (n++ + 1 == sizeof...(Args) ? '\n' : ' ')), ...);
    }
};
