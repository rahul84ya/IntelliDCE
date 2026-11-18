#include <iostream>

int main() {
    int val = 0;
    if (std::cin >> val) {
        int dead_computation = val * 99;
        std::cout << "Echo: " << (val + 10) << std::endl;
    } else {
        std::cout << "No Input Provided" << std::endl;
    }
    return 0;
}

