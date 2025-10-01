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

    void logInfo(const std::string &msg) // msgs would be interleaved without lockign
    {
        if (on)
            std::cout << msg << '\n';
    }
    void logError(const std::string &msg)
    {
        if (on)
            std::cerr << msg << '\n';
    }
    void logTest(const std::string &msg)
    {
        std::cout << msg << '\n';
    }
};
