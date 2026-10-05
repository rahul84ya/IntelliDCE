#include <iostream>
#include <vector>

// 1. Unused function
void unused_helper() {
    std::cout << "Unused function" << std::endl;
}

int f() {
    int x = 10;
    return x;
    // 2. Unreachable after return
    x = 20; 
}

int main() {
    // 3. Redundant pure call
    f();
    
    // 4. Dead store chain
    int a = 100;
    int b = a + 1;
    
    // 5. Constant condition
    if (0) {
        std::cout << "Dead block" << std::endl;
    }
    
    // 6. Same branch behavior (Redundant branch)
    int cond = 0;
    if (cond == 0) {
        std::cout << "Same" << std::endl;
    } else {
        std::cout << "Same" << std::endl;
    }
    
    // 7. No-op (Self assignment)
    int z = 5;
    z = z;
    
    // 8. Algebraic identity
    int w = z + 0;
    
    // 9. Pure expression statement
    10 + 20;

    return 0;
}
