#include <iostream>
#include <cstring>
#include <cstdlib>

void vulnerable_copy(const char* input) {
    char buffer[16];
    strcpy(buffer, input);          // CWE-120: no bounds check, classic buffer overflow
    std::cout << "Copied: " << buffer << std::endl;
}

void run_shell_command(const std::string& user_input) {
    std::string cmd = "echo " + user_input;
    system(cmd.c_str());            // CWE-78: unsanitized input passed to shell
}

int format_string_bug(const char* user_input) {
    printf(user_input);             // CWE-134: format string vulnerability (should be printf("%s", user_input))
    return 0;
}

char* use_after_free_demo() {
    char* data = (char*)malloc(32);
    strcpy(data, "sensitive");
    free(data);
    return data;                    // CWE-416: returning a pointer after free
}

int main() {
    char password[8] = "admin123";  // CWE-798: hardcoded credential
    vulnerable_copy("this string is way longer than sixteen bytes on purpose");
    format_string_bug("%s%s%s%s");  // will likely crash or leak stack memory
    use_after_free_demo();
    return 0;
}

