#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define MAX_ATTEMPTS 3  // Allow 3 authentication attempts

int main() {
    int sock;
    struct sockaddr_in server_address;
    char buffer[BUFFER_SIZE] = {0};
    char phone_number[12], password[50], message[BUFFER_SIZE];

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Define server address
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    server_address.sin_addr.s_addr = INADDR_ANY; // Connect to localhost

    // Connect to server
    if (connect(sock, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        perror("Connection failed!");
        exit(EXIT_FAILURE);
    }

    // Get phone number
    printf("Phone Number Required: ");
    scanf("%s", phone_number);

    // Send phone number
    send(sock, phone_number, strlen(phone_number), 0);

    int authenticated = 0; // Flag to check authentication success

    for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        // Get password
        printf("Password Required: ");
        scanf("%s", password);

        // Send password
        send(sock, password, strlen(password), 0);

        // Receive response from server
        memset(buffer, 0, BUFFER_SIZE);
        int bytes_received = read(sock, buffer, BUFFER_SIZE - 1);
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0'; // Null-terminate
            printf("Server: %s\n", buffer);
        } else {
            printf("No response from server.\n");
            close(sock);
            return 0;
        }

        // Check server response
        if (strcmp(buffer, "Login successful") == 0) {
            authenticated = 1; // Mark authentication success
            break;  
        } else if (strcmp(buffer, "Failed Login!") == 0) {
            close(sock);
            return 0;  
        }
    }

    // If authentication failed, exit before message prompt
    if (!authenticated) {
        printf("Authentication failed. Exiting...\n");
        close(sock);
        return 0;
    }

    // If authentication was successful, send a message to the server
    getchar(); // Consume leftover newline from previous input
    printf("Communicate with the server: ");
    fgets(message, BUFFER_SIZE, stdin);
    message[strcspn(message, "\n")] = '\0'; // Remove newline character

    send(sock, message, strlen(message), 0);

    // Receive acknowledgment from server
    memset(buffer, 0, BUFFER_SIZE);
    int bytes_received = read(sock, buffer, BUFFER_SIZE - 1);
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        printf("Message sent server: %s\n", buffer);
    }

    // Close socket
    close(sock);
    return 0;
}
