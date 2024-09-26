#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sodium.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define PSEUDO_SIZE 100  // Taille maximale du pseudo
#define MAX_CLIENTS 10   // Nombre maximum de clients

// Variables globales
char pseudos[MAX_CLIENTS][PSEUDO_SIZE];  // Stocker les pseudos des clients
int client_sockets[MAX_CLIENTS];         // Stocker les descripteurs de socket des clients
int client_count = 0;                    // Compteur de clients connectés
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;  // Mutex pour la gestion des clients
unsigned char shared_secrets[MAX_CLIENTS][crypto_kx_SESSIONKEYBYTES];  // Clés partagées pour chaque client

// Fonction pour générer la paire de clés ECC du serveur
void generate_ecc_keys(unsigned char *public_key, unsigned char *private_key) {
    crypto_kx_keypair(public_key, private_key);
}

// Fonction pour calculer la clé partagée du serveur
void calculate_shared_secret_server(int client_index, unsigned char *client_public_key, unsigned char *server_public_key, unsigned char *server_private_key) {
    if (crypto_kx_server_session_keys(shared_secrets[client_index], NULL, server_public_key, server_private_key, client_public_key) != 0) {
        printf("Erreur lors du calcul de la clé partagée pour le client %d\n", client_index);
        exit(1);
    }
    printf("Clé partagée avec le client %d générée avec succès\n", client_index);
}

// Fonction pour chiffrer un message avec la clé partagée
int encrypt_message(int client_index, const char *message, unsigned char *ciphertext, unsigned long long *ciphertext_len) {
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));  // Générer un nonce aléatoire

    if (crypto_secretbox_easy(ciphertext + crypto_secretbox_NONCEBYTES, (unsigned char *)message, strlen(message), nonce, shared_secrets[client_index]) != 0) {
        printf("Erreur lors du chiffrement du message\n");
        return -1;
    }

    memcpy(ciphertext, nonce, crypto_secretbox_NONCEBYTES);  // Préfixer le nonce au message chiffré
    *ciphertext_len = crypto_secretbox_MACBYTES + strlen(message) + crypto_secretbox_NONCEBYTES;
    return 0;
}

// Fonction pour déchiffrer un message avec la clé partagée
int decrypt_message(int client_index, unsigned char *ciphertext, unsigned long long ciphertext_len, unsigned char *decrypted) {
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    memcpy(nonce, ciphertext, crypto_secretbox_NONCEBYTES);  // Extraire le nonce

    if (crypto_secretbox_open_easy(decrypted, ciphertext + crypto_secretbox_NONCEBYTES, ciphertext_len - crypto_secretbox_NONCEBYTES, nonce, shared_secrets[client_index]) != 0) {
        printf("Erreur lors du déchiffrement du message pour le client %d\n", client_index);
        return -1;
    }
    return 0;
}

// Fonction pour envoyer un message à tous les clients sauf l'expéditeur
void send_to_all_clients(char *message, int sender_sock) {
    pthread_mutex_lock(&clients_mutex);

    for (int i = 0; i < client_count; ++i) {
        if (client_sockets[i] != sender_sock) {
            if (send(client_sockets[i], message, strlen(message), 0) < 0) {
                perror("Erreur lors de l'envoi du message aux autres clients");
            }
        }
    }

    pthread_mutex_unlock(&clients_mutex);
}

// Fonction pour gérer chaque client
void *handle_client(void *socket_desc) {
    int client_sock = *(int *)socket_desc;
    free(socket_desc);
    char buffer[BUFFER_SIZE];
    unsigned char encrypted[BUFFER_SIZE + crypto_secretbox_MACBYTES + crypto_secretbox_NONCEBYTES];
    unsigned char decrypted[BUFFER_SIZE];
    char message_with_pseudo[BUFFER_SIZE + PSEUDO_SIZE];
    int read_size;

    // Index du client dans la liste
    int client_index = -1;
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < client_count; ++i) {
        if (client_sockets[i] == client_sock) {
            client_index = i;
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);

    // Recevoir le pseudo du client
    if ((read_size = recv(client_sock, buffer, sizeof(buffer), 0)) > 0) {
        buffer[read_size] = '\0';  // Terminer la chaîne reçue
        snprintf(pseudos[client_sock], PSEUDO_SIZE, "%.99s", buffer);
        char join_message[BUFFER_SIZE];
        snprintf(join_message, sizeof(join_message), "%.99s a rejoint le chat !\n", pseudos[client_sock]);
        send_to_all_clients(join_message, client_sock);
        printf("%s", join_message);
    }

    // Lire et transmettre les messages des clients
    while ((read_size = recv(client_sock, encrypted, sizeof(encrypted), 0)) > 0) {
        // Déchiffrer le message
        if (decrypt_message(client_index, encrypted, read_size, decrypted) == 0) {
            decrypted[read_size - crypto_secretbox_MACBYTES - crypto_secretbox_NONCEBYTES] = '\0';  // Terminer la chaîne déchiffrée

            snprintf(message_with_pseudo, sizeof(message_with_pseudo), "%.49s: %s", pseudos[client_sock], decrypted);
            send_to_all_clients(message_with_pseudo, client_sock);
            printf("%s", message_with_pseudo);  // Afficher le message sur le serveur
        }
    }

    // Gestion de la déconnexion du client
    if (read_size == 0) {
        printf("Client %s s'est déconnecté\n", pseudos[client_sock]);
        char leave_message[BUFFER_SIZE];
        snprintf(leave_message, sizeof(leave_message), "%s a quitté le chat.\n", pseudos[client_sock]);
        send_to_all_clients(leave_message, client_sock);

        pthread_mutex_lock(&clients_mutex);
        for (int i = 0; i < client_count; ++i) {
            if (client_sockets[i] == client_sock) {
                client_sockets[i] = client_sockets[client_count - 1];
                client_count--;
                break;
            }
        }
        pthread_mutex_unlock(&clients_mutex);
    } else if (read_size == -1) {
        perror("Erreur lors de la réception");
    }

    close(client_sock);
    return NULL;
}

int main() {
    int server_sock, client_sock, c;
    struct sockaddr_in server, client;
    pthread_t client_thread;

    // Clés ECC du serveur
    unsigned char server_public_key[crypto_kx_PUBLICKEYBYTES];
    unsigned char server_private_key[crypto_kx_SECRETKEYBYTES];
    generate_ecc_keys(server_public_key, server_private_key);

    // Créer le socket pour le serveur
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock == -1) {
        printf("Erreur lors de la création du socket\n");
        return -1;
    }
    printf("Socket du serveur créé avec succès\n");

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(PORT);

    // Associer le socket à l'adresse IP et au port
    if (bind(server_sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("Erreur lors de l'association du socket");
        return -1;
    }
    printf("Socket lié avec succès\n");

    listen(server_sock, MAX_CLIENTS);
    printf("En attente de connexions...\n");

    c = sizeof(struct sockaddr_in);

    // Accepter les connexions
    while ((client_sock = accept(server_sock, (struct sockaddr *)&client, (socklen_t *)&c))) {
        printf("Connexion acceptée\n");

        pthread_mutex_lock(&clients_mutex);
        if (client_count < MAX_CLIENTS) {
            client_sockets[client_count++] = client_sock;
        } else {
            printf("Le serveur est plein.\n");
            close(client_sock);
            pthread_mutex_unlock(&clients_mutex);
            continue;
        }
        pthread_mutex_unlock(&clients_mutex);

        // Recevoir la clé publique du client et calculer la clé partagée
        unsigned char client_public_key[crypto_kx_PUBLICKEYBYTES];
        recv(client_sock, client_public_key, sizeof(client_public_key), 0);

        // Calculer la clé partagée pour ce client
        calculate_shared_secret_server(client_count - 1, client_public_key, server_public_key, server_private_key);

        // Allouer de la mémoire pour le descripteur de socket du client
        int *new_sock = malloc(sizeof(int));
        *new_sock = client_sock;

        // Créer un thread pour gérer le client
        if (pthread_create(&client_thread, NULL, handle_client, (void *)new_sock) < 0) {
            perror("Erreur lors de la création du thread");
            return 1;
        }

        printf("Gestion du client dans un thread séparé\n");
    }

    if (client_sock < 0) {
        perror("Erreur lors de l'acceptation");
        return 1;
    }

    return 0;
}
