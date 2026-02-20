#pragma once
// Minimal test harness: no external deps. ASSERT fails with message and exit(1).
// RUN_TEST(name, body) runs body; on assert failure exits 1; otherwise continues.

#include <cstdlib>
#include <iostream>

#define ASSERT(cond) \
    do { \
        if (!(cond)) { \
            std::cerr << "FAIL [" << __FILE__ << ":" << __LINE__ << "] " << #cond << std::endl; \
            std::exit(1); \
        } \
    } while (0)

#define ASSERT_MSG(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "FAIL [" << __FILE__ << ":" << __LINE__ << "] " << (msg) << std::endl; \
            std::exit(1); \
        } \
    } while (0)

#define RUN_TEST(name, body) \
    do { \
        std::cout << "  " << (name) << " ... " << std::flush; \
        body; \
        std::cout << "ok" << std::endl; \
    } while (0)
