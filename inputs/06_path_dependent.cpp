int path_pruning(int x) {
    if (x > 10) {
        if (x < 5) {
            // This block is unreachable
            return -1;
        }
    }
    
    int flag = 0;
    if (flag) {
        // Also unreachable because flag is constant 0
        return 42;
    }
    
    return x * 2;
}

int main() {
    return path_pruning(20);
}