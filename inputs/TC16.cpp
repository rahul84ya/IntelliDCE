#include <iostream>
using namespace std;

int f(int n) {
    if (n == 0) return 0;
    return f(n - 1);
}

int main() {
    f(3);
    return 0;
}