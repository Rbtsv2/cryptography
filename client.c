#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>

#define PORT 8080
#define BUFFER_SIZE 1024

void *receive_messages(void *sock) {
    int client_sock = *(int *)sock;
    char buffer[BUFFER_SIZE];
    int read_size;

    // Lire les messages du serveur
    while ((read_size = recv(client_sock, buffer, sizeof(buffer), 0)) > 0) {
        buffer[read_size] = '\0';
        printf("%s\n", buffer);
    }

    return NULL;
}

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char message[BUFFER_SIZE];
    char pseudo[50]; // Nouveau champ pour le pseudo
    pthread_t tid;

    // Créer un socket pour le client
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("Erreur lors de la création du socket\n");
        return -1;
    }

    // Configuration de l'adresse du serveur
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convertir l'adresse IP du serveur en format réseau
    if (inet_pton(AF_INET, "192.168.1.12", &serv_addr.sin_addr) <= 0) {
        printf("Adresse IP non valide\n");
        return -1;
    }

    // Connexion au serveur
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("Connexion échouée\n");
        return -1;
    }

    // Demander le pseudo
    printf("Entrez votre pseudo : ");
    fgets(pseudo, 50, stdin);
    pseudo[strcspn(pseudo, "\n")] = '\0';  // Retirer le saut de ligne

    // Envoyer le pseudo au serveur
    send(sock, pseudo, strlen(pseudo), 0);

    // Créer un thread pour recevoir les messages du serveur
    pthread_create(&tid, NULL, receive_messages, (void *)&sock);

    // Envoyer des messages au serveur
    while (1) {
        fgets(message, BUFFER_SIZE, stdin);
        send(sock, message, strlen(message), 0);
    }

    // Fermer le socket du client
    close(sock);
    return 0;
}
