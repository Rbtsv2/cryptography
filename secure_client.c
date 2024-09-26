#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sodium.h>

#define PORT 8080
#define BUFFER_SIZE 1024

unsigned char shared_secret[crypto_kx_SESSIONKEYBYTES];

// Fonction pour générer une paire de clés ECC (privée/publique)
void generate_ecc_keys(unsigned char *public_key, unsigned char *private_key) {
    crypto_kx_keypair(public_key, private_key);
}

// Fonction pour calculer la clé partagée du client
void calculate_shared_secret(unsigned char *public_key_peer, unsigned char *public_key, unsigned char *private_key) {
    if (crypto_kx_client_session_keys(shared_secret, NULL, public_key, private_key, public_key_peer) != 0) {
        printf("Erreur lors du calcul de la clé partagée\n");
        exit(1);
    }
    printf("Clé partagée générée avec succès\n");
}

// Fonction pour chiffrer un message
int encrypt_message(const char *message, unsigned char *ciphertext, unsigned long long *ciphertext_len) {
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));  // Générer un nonce aléatoire

    if (crypto_secretbox_easy(ciphertext + crypto_secretbox_NONCEBYTES, (unsigned char *)message, strlen(message), nonce, shared_secret) != 0) {
        printf("Erreur lors du chiffrement du message\n");
        return -1;
    }

    memcpy(ciphertext, nonce, crypto_secretbox_NONCEBYTES);  // Préfixer le nonce au message chiffré
    *ciphertext_len = crypto_secretbox_MACBYTES + strlen(message) + crypto_secretbox_NONCEBYTES;
    return 0;
}

// Fonction pour déchiffrer un message
int decrypt_message(unsigned char *ciphertext, unsigned long long ciphertext_len, unsigned char *decrypted) {
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    memcpy(nonce, ciphertext, crypto_secretbox_NONCEBYTES);  // Extraire le nonce

    if (crypto_secretbox_open_easy(decrypted, ciphertext + crypto_secretbox_NONCEBYTES, ciphertext_len - crypto_secretbox_NONCEBYTES, nonce, shared_secret) != 0) {
        printf("Erreur lors du déchiffrement du message\n");
        return -1;
    }
    return 0;
}

// Fonction pour envoyer des messages
void *send_messages(void *socket_desc) {
    int sock = *(int *)socket_desc;
    char buffer[BUFFER_SIZE];
    unsigned char encrypted[BUFFER_SIZE + crypto_secretbox_MACBYTES + crypto_secretbox_NONCEBYTES];
    unsigned long long encrypted_len;

    while (1) {
        printf("Vous: ");
        fgets(buffer, BUFFER_SIZE, stdin);
        buffer[strlen(buffer) - 1] = '\0';  // Supprimer le '\n'

        // Chiffrement du message avant de l'envoyer
        if (encrypt_message(buffer, encrypted, &encrypted_len) == 0) {
            send(sock, encrypted, encrypted_len, 0);  // Envoyer le message chiffré
        }
    }
}

// Fonction pour recevoir les messages
void *receive_messages(void *socket_desc) {
    int sock = *(int *)socket_desc;
    unsigned char buffer[BUFFER_SIZE + crypto_secretbox_MACBYTES + crypto_secretbox_NONCEBYTES];
    unsigned char decrypted[BUFFER_SIZE];

    while (1) {
        int received_len = recv(sock, buffer, BUFFER_SIZE, 0);
        if (received_len > 0) {
            // Déchiffrement du message reçu
            if (decrypt_message(buffer, received_len, decrypted) == 0) {
                decrypted[received_len - crypto_secretbox_MACBYTES - crypto_secretbox_NONCEBYTES] = '\0';  // Terminer la chaîne déchiffrée
                printf("Message reçu: %s\n", decrypted);
            }
        }
    }
}

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;

    // Générer une paire de clés ECC pour le client
    unsigned char public_key[crypto_kx_PUBLICKEYBYTES];
    unsigned char private_key[crypto_kx_SECRETKEYBYTES];
    generate_ecc_keys(public_key, private_key);

    // Créer le socket du client
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Erreur de création de socket \n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convertir l'adresse IP du serveur en format binaire
    if (inet_pton(AF_INET, "192.168.1.12", &serv_addr.sin_addr) <= 0) {
        printf("\n Adresse non valide \n");
        return -1;
    }

    // Se connecter au serveur
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\n Connexion échouée \n");
        return -1;
    }

    // Simuler l'échange de la clé publique avec le serveur
    unsigned char server_public_key[crypto_kx_PUBLICKEYBYTES];
    send(sock, public_key, sizeof(public_key), 0);  // Envoyer la clé publique du client
    recv(sock, server_public_key, sizeof(server_public_key), 0);  // Recevoir la clé publique du serveur

    // Calculer la clé de session partagée
    calculate_shared_secret(server_public_key, public_key, private_key);

    // Lancer les threads pour envoyer et recevoir les messages
    pthread_t send_thread, receive_thread;
    pthread_create(&send_thread, NULL, send_messages, (void *)&sock);
    pthread_create(&receive_thread, NULL, receive_messages, (void *)&sock);

    pthread_join(send_thread, NULL);
    pthread_join(receive_thread, NULL);

    close(sock);
    return 0;
}
