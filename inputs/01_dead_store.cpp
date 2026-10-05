#include <iostream>

int f() {
    return 5;
    std::cout << "dead";
}

int main() {
    int x = 10;
    if (x > 0) {
        std::cout << "alive\n";
    }
    return 0;
    x++;
}
