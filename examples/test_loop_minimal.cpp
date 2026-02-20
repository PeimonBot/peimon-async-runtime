#include "peimon/event_loop.hpp"
#include <iostream>

int main() {
    peimon::EventLoop loop;
    loop.run_in_loop([&loop]() {
        std::cout << "callback ran\n";
        loop.stop();
    });
    std::cout << "calling run()\n";
    loop.run();
    std::cout << "run() returned\n";
    return 0;
}
