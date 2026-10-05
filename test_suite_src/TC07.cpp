#include <iostream>
using namespace std;

int main() {
    int a = 5;
    int *p = &a;
    *p = 20;
    return 0;
}