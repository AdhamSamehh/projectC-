#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define MAX_ATTEMPTS 3
#define AES_KEYLEN 16
#define AES_IVLEN 16

void *handle_client(void *socket_desc);
void sha256_string(const char *input, char *output_hex);
int authentication(const char *email, const char *plain_password);

int main() {
    int server_fd, *new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        perror("Socket failed!");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Bind failed!");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 10) < 0) {
        perror("Listen failed!");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", PORT);

    while (1) {
        new_socket = malloc(sizeof(int));
        *new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
        if (*new_socket < 0) {
            perror("Accept failed!");
            free(new_socket);
            continue;
        }

        pthread_t tid;
        if (pthread_create(&tid, NULL, handle_client, new_socket) != 0) {
            perror("Thread creation failed");
            free(new_socket);
        }

        pthread_detach(tid);
    }

    close(server_fd);
    return 0;
}

void *handle_client(void *socket_desc) {
    int sock = *(int *)socket_desc;
    free(socket_desc);

    unsigned char aes_key[AES_KEYLEN], aes_iv[AES_IVLEN];
    recv(sock, aes_key, AES_KEYLEN, 0);
    recv(sock, aes_iv, AES_IVLEN, 0);

    unsigned char buffer[BUFFER_SIZE], decrypted[BUFFER_SIZE];
    unsigned char email[BUFFER_SIZE], password[BUFFER_SIZE];
    int bytes_received, decrypted_len;

    // Receive and decrypt email
    EVP_CIPHER_CTX *ctx_email = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx_email, EVP_aes_128_ctr(), NULL, aes_key, aes_iv);
    bytes_received = recv(sock, buffer, BUFFER_SIZE, 0);
    EVP_DecryptUpdate(ctx_email, email, &decrypted_len, buffer, bytes_received);
    email[decrypted_len] = '\0';
    EVP_CIPHER_CTX_free(ctx_email);

    int authenticated = 0;

    for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        EVP_CIPHER_CTX *ctx_pass = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx_pass, EVP_aes_128_ctr(), NULL, aes_key, aes_iv);

        bytes_received = recv(sock, buffer, BUFFER_SIZE, 0);
        EVP_DecryptUpdate(ctx_pass, password, &decrypted_len, buffer, bytes_received);
        password[decrypted_len] = '\0';
        EVP_CIPHER_CTX_free(ctx_pass);

        printf("Attempt %d\nEmail: %s\nPassword: %s\n", attempt, email, password);

        if (authentication((char *)email, (char *)password)) {
            char *at = strchr((char *)email, '@');
            int name_len = at ? (at - (char *)email) : 0;
            char name[50] = {0};
            strncpy(name, (char *)email, name_len);
            if (name_len > 0) name[0] = toupper(name[0]);

            char welcome_msg[BUFFER_SIZE];
            snprintf(welcome_msg, BUFFER_SIZE, "Login successful\nWelcome to AS for penetration testing %s!", name);
            send(sock, welcome_msg, strlen(welcome_msg), 0);
            authenticated = 1;
            break;
        } else {
            const char *fail_msg = (attempt < MAX_ATTEMPTS) ? "Wrong password. Try again." : "Failed Login!";
            send(sock, fail_msg, strlen(fail_msg), 0);
            if (attempt == MAX_ATTEMPTS) {
                close(sock);
                pthread_exit(NULL);
            }
        }
    }

    while (authenticated) {
        memset(buffer, 0, BUFFER_SIZE);
        bytes_received = recv(sock, buffer, BUFFER_SIZE, 0);
        if (bytes_received <= 0) break;

        if (strncmp((char *)buffer, "[FILE]", 6) == 0) {
            // Receive file name
            unsigned char enc_name[BUFFER_SIZE] = {0}, filename[BUFFER_SIZE] = {0};
            bytes_received = recv(sock, enc_name, BUFFER_SIZE, 0);
            EVP_CIPHER_CTX *ctx_name = EVP_CIPHER_CTX_new();
            EVP_DecryptInit_ex(ctx_name, EVP_aes_128_ctr(), NULL, aes_key, aes_iv);
            EVP_DecryptUpdate(ctx_name, filename, &decrypted_len, enc_name, bytes_received);
            filename[decrypted_len] = '\0';
            EVP_CIPHER_CTX_free(ctx_name);

            // Receive file data
            unsigned char enc_data[BUFFER_SIZE] = {0}, file_data[BUFFER_SIZE] = {0};
            bytes_received = recv(sock, enc_data, BUFFER_SIZE, 0);
            EVP_CIPHER_CTX *ctx_file = EVP_CIPHER_CTX_new();
            EVP_DecryptInit_ex(ctx_file, EVP_aes_128_ctr(), NULL, aes_key, aes_iv);
            EVP_DecryptUpdate(ctx_file, file_data, &decrypted_len, enc_data, bytes_received);
            EVP_CIPHER_CTX_free(ctx_file);

            FILE *fp = fopen((char *)filename, "wb");
            if (fp) {
                fwrite(file_data, 1, decrypted_len, fp);
                fclose(fp);
                printf("Saved file: %s\n", filename);
            }
        } else {
            // Decrypt and print message
            unsigned char message[BUFFER_SIZE] = {0};
            EVP_CIPHER_CTX *ctx_msg = EVP_CIPHER_CTX_new();
            EVP_DecryptInit_ex(ctx_msg, EVP_aes_128_ctr(), NULL, aes_key, aes_iv);
            EVP_DecryptUpdate(ctx_msg, message, &decrypted_len, buffer, bytes_received);
            message[decrypted_len] = '\0';
            EVP_CIPHER_CTX_free(ctx_msg);

            printf("Client message: %s\n", message);

            FILE *log = fopen("message.txt", "a");
            if (log) {
                fprintf(log, "%s message: %s\n", email, message);
                fclose(log);
            }

            send(sock, (char *)message, strlen((char *)message), 0);
        }
    }

    close(sock);
    pthread_exit(NULL);
}

void sha256_string(const char *input, char *output_hex) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)input, strlen(input), hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(output_hex + (i * 2), "%02x", hash[i]);
    output_hex[SHA256_DIGEST_LENGTH * 2] = '\0';
}

int authentication(const char *email, const char *plain_password) {
    FILE *file = fopen("user.txt", "r");
    if (!file) {
        perror("user.txt");
        return 0;
    }

    char file_email[BUFFER_SIZE], file_hash[BUFFER_SIZE];
    char input_hash[SHA256_DIGEST_LENGTH * 2 + 1];
    sha256_string(plain_password, input_hash);

    while (fscanf(file, "%s %s", file_email, file_hash) == 2) {
        if (strcmp(email, file_email) == 0 && strcmp(file_hash, input_hash) == 0) {
            fclose(file);
            return 1;
        }
    }

    fclose(file);
    return 0;
}