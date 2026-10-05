int math_identities(int x) {
    int a = x + 0;      // Identity
    int b = a * 1;      // Identity
    int c = b / 1;      // Identity
    int d = c << 0;     // Identity
    int result = d * d; 
    return result;
}

int main() {
    return math_identities(5);
}
