#include <iostream>
using namespace std;

int main() {
    int sum = 0;
    for (int i = 0; i < 5; i++) {
        int x = i * 2;
        sum += i;
        int y = i + 10;
    }
    cout << sum;
    return 0;
}