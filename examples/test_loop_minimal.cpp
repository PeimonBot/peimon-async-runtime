#include "peimon/event_loop.hpp"
#include <cstdlib>
#include <iostream>

int main() {
    peimon::EventLoop loop;
    bool callback_ran = false;
    loop.run_in_loop([&]() {
        callback_ran = true;
        loop.stop();
    });
    loop.run();
    if (!callback_ran) {
        std::cerr << "FAIL: run_in_loop callback did not run\n";
        return 1;
    }
    return 0;
}
