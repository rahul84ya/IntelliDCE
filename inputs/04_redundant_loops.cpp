int test_loops() {
    int sum = 0;
    int redundant_counter = 0;
    for (int i = 0; i < 100; i++) {
        sum += i;
        redundant_counter++; // This increment is never used
    }
    return sum;
}

int main() {
    return test_loops();
}
