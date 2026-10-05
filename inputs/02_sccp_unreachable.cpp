#include <iostream>

int main() {
    int x = 1;
    int y = 2;
    
    if (x == 0) {
        // Dead block
        std::cout << "This will be removed" << std::endl;
        y = 500;
    } else {
        y = 100;
    }
    
    return y;
}
