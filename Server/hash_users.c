#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

#define MAX_LINE 512
#define MAX_EMAIL 128
#define MAX_PASS 128

void sha256_string(const char *input, char *output_hex) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)input, strlen(input), hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output_hex + (i * 2), "%02x", hash[i]);
    }
    output_hex[SHA256_DIGEST_LENGTH * 2] = '\0';
}

int main() {
    FILE *input = fopen("user.txt", "r");
    FILE *output = fopen("user_hashed.txt", "w");

    if (!input || !output) {
        perror("Error opening files");
        return 1;
    }

    char email[MAX_EMAIL], password[MAX_PASS];
    char hash_hex[SHA256_DIGEST_LENGTH * 2 + 1];

    while (fscanf(input, "%s %s", email, password) == 2) {
        sha256_string(password, hash_hex);
        fprintf(output, "%s %s\n", email, hash_hex);
    }

    fclose(input);
    fclose(output);

    printf("Done! Hashed user list saved to user_hashed.txt\n");
    return 0;
}
