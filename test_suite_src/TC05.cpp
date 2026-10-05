#include <iostream>
using namespace std;

int main() {
    int sum = 0;
    for (int i = 0; i < 5; i++) {
        int temp = i * 3;
        sum += i;
    }
    cout << sum;
    return 0;
}