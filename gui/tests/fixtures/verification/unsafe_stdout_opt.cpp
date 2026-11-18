#include <iostream>

int main() {
    int base = 100;
    // Unsafe DCE mistake: bonus erroneously pruned to 0
    int total = base;
    std::cout << "Computed total: " << total << std::endl;
    return 0;
}

