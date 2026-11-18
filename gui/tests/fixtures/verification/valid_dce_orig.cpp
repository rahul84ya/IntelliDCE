#include <iostream>

int main() {
    int dead_store = 42;
    int x = 10;
    std::cout << "Original Value: " << x << std::endl;
    return 0;
}

