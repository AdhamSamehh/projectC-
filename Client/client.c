#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sys/stat.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define AES_KEYLEN 16
#define AES_IVLEN 16

unsigned char aes_key[AES_KEYLEN];
unsigned char aes_iv[AES_IVLEN];

int aes_encrypt(const unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, aes_key, aes_iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len += len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int file_exists(const char *filename) {
    struct stat buffer;
    return (stat(filename, &buffer) == 0);
}

void send_encrypted_file(int sock) {
    char filename[BUFFER_SIZE];
    unsigned char file_data[BUFFER_SIZE], encrypted_data[BUFFER_SIZE];

    while (1) {
        printf("Enter filename to send (or type 'exit' to go back): ");
        scanf("%s", filename);

        if (strcmp(filename, "exit") == 0)
            return;

        if (!file_exists(filename)) {
            printf("No such file. Try again or type 'exit'.\n");
            continue;
        }

        FILE *file = fopen(filename, "rb");
        if (!file) {
            perror("Error opening file");
            continue;
        }

        size_t bytes_read = fread(file_data, 1, BUFFER_SIZE, file);
        fclose(file);

        int encrypted_len = aes_encrypt(file_data, bytes_read, encrypted_data);

        // Send file header
        send(sock, "[FILE]", 6, 0);
        usleep(100000);

        // Encrypt and send filename
        unsigned char enc_filename[BUFFER_SIZE];
        int enc_name_len = aes_encrypt((unsigned char *)filename, strlen(filename), enc_filename);
        send(sock, enc_filename, enc_name_len, 0);
        usleep(100000);

        // Send encrypted content
        send(sock, encrypted_data, encrypted_len, 0);
        printf("Encrypted file '%s' sent to server.\n", filename);
        break;
    }
}

int main() {
    int sock;
    struct sockaddr_in server_address;
    unsigned char buffer[BUFFER_SIZE] = {0};
    unsigned char email[BUFFER_SIZE], password[BUFFER_SIZE], message[BUFFER_SIZE];

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    server_address.sin_addr.s_addr = INADDR_ANY;

    if (connect(sock, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        perror("Connection failed!");
        exit(EXIT_FAILURE);
    }

    // Generate AES key/IV and send to server
    RAND_bytes(aes_key, AES_KEYLEN);
    RAND_bytes(aes_iv, AES_IVLEN);
    send(sock, aes_key, AES_KEYLEN, 0);
    send(sock, aes_iv, AES_IVLEN, 0);

    // Email
    printf("Email Required: ");
    scanf("%s", email);

    unsigned char enc_email[BUFFER_SIZE];
    int enc_email_len = aes_encrypt(email, strlen((char *)email), enc_email);
    send(sock, enc_email, enc_email_len, 0);

    // Password and authentication loop
    int authenticated = 0;
    for (int attempt = 1; attempt <= 3; attempt++) {
        printf("Password Required: ");
        scanf("%s", password);

        unsigned char enc_pass[BUFFER_SIZE];
        int enc_pass_len = aes_encrypt(password, strlen((char *)password), enc_pass);
        send(sock, enc_pass, enc_pass_len, 0);

        memset(buffer, 0, BUFFER_SIZE);
        int bytes_received = read(sock, buffer, BUFFER_SIZE - 1);
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';
            printf("Server: %s\n", buffer);

            if (strncmp((char *)buffer, "Login successful", 16) == 0) {
                authenticated = 1;
                break;
            } else if (strcmp((char *)buffer, "Failed Login!") == 0) {
                close(sock);
                return 0;
            }
        }
    }

    if (!authenticated) {
        printf("Authentication failed. Exiting...\n");
        close(sock);
        return 0;
    }

    // Menu after successful login
    while (1) {
        int choice;
        printf("\nChoose an option:\n");
        printf("1. Send a message\n");
        printf("2. Send a file\n");
        printf("3. Exit\n");
        printf("Enter choice: ");
        scanf("%d", &choice);
        getchar(); // consume newline

        if (choice == 1) {
            printf("Enter your message: ");
            fgets((char *)message, BUFFER_SIZE, stdin);
            message[strcspn((char *)message, "\n")] = '\0';

            unsigned char enc_msg[BUFFER_SIZE];
            int enc_msg_len = aes_encrypt(message, strlen((char *)message), enc_msg);
            send(sock, enc_msg, enc_msg_len, 0);

            memset(buffer, 0, BUFFER_SIZE);
            int bytes_received = read(sock, buffer, BUFFER_SIZE - 1);
            if (bytes_received > 0) {
                buffer[bytes_received] = '\0';
                printf("Message echoed from server: %s\n", buffer);
            }
        } else if (choice == 2) {
            send_encrypted_file(sock);
        } else if (choice == 3) {
            printf("Exiting client.\n");
            close(sock);
            break;
        } else {
            printf("Invalid option. Please try again.\n");
        }
    }

    return 0;
}
