#include <iostream>

int main() {
    int val = 0;
    if (std::cin >> val) {
        // [IDCE VERIFIED PRUNED] dead_computation
        std::cout << "Echo: " << (val + 10) << std::endl;
    } else {
        std::cout << "No Input Provided" << std::endl;
    }
    return 0;
}

