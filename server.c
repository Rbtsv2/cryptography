#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define PSEUDO_SIZE 100  // Taille maximale du pseudo (100 caractères)
#define MAX_CLIENTS 10   // Nombre maximum de clients connectés

// Variables globales
char pseudos[MAX_CLIENTS][PSEUDO_SIZE];     // Stocker les pseudos des clients
int client_sockets[MAX_CLIENTS];            // Stocker les descripteurs de socket des clients
int client_count = 0;                       // Compteur de clients connectés
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;  // Mutex pour gérer les accès concurrents

// Fonction pour envoyer un message à tous les clients sauf à l'expéditeur
void send_to_all_clients(char *message, int sender_sock) {
    pthread_mutex_lock(&clients_mutex);  // Protéger l'accès au tableau client_sockets

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
    int client_sock = *(int *)socket_desc;  // Récupérer le descripteur de socket du client
    free(socket_desc);  // Libérer la mémoire après avoir récupéré le descripteur
    char buffer[BUFFER_SIZE];
    char message_with_pseudo[BUFFER_SIZE + PSEUDO_SIZE]; // Pseudo + message
    int read_size;

    // Recevoir le pseudo du client
    if ((read_size = recv(client_sock, buffer, sizeof(buffer), 0)) > 0) {
        buffer[read_size] = '\0'; // Terminer la chaîne

        // Stocker le pseudo (on limite à PSEUDO_SIZE - 1 caractères)
        snprintf(pseudos[client_sock], PSEUDO_SIZE, "%.99s", buffer);

        // Informer tous les clients qu'un nouveau client a rejoint
        char join_message[BUFFER_SIZE];
        snprintf(join_message, sizeof(join_message), "%.99s a rejoint le chat !\n", pseudos[client_sock]);
        send_to_all_clients(join_message, client_sock);  // Envoyer le message à tous les clients sauf le nouvel arrivant
        printf("%s", join_message);  // Afficher dans le serveur
    }

    // Lire et transmettre les messages des clients
    while ((read_size = recv(client_sock, buffer, sizeof(buffer), 0)) > 0) {
        buffer[read_size] = '\0'; // Terminer la chaîne reçue

        // Créer le message à envoyer avec le pseudo
        snprintf(message_with_pseudo, sizeof(message_with_pseudo), "%.49s: %.1023s", pseudos[client_sock], buffer);
        
        // Diffuser le message à tous les clients sauf l'expéditeur
        send_to_all_clients(message_with_pseudo, client_sock);
        printf("%s", message_with_pseudo);  // Afficher dans le serveur
    }

    // Si la réception retourne 0, le client s'est déconnecté
    if (read_size == 0) {
        printf("Client %s s'est déconnecté\n", pseudos[client_sock]);
        
        // Informer les autres clients que le client s'est déconnecté
        char leave_message[BUFFER_SIZE];
        snprintf(leave_message, sizeof(leave_message), "%s a quitté le chat.\n", pseudos[client_sock]);
        send_to_all_clients(leave_message, client_sock);

        // Supprimer le client des tableaux
        pthread_mutex_lock(&clients_mutex);
        for (int i = 0; i < client_count; ++i) {
            if (client_sockets[i] == client_sock) {
                // Remplacer le client par le dernier client pour maintenir la liste compacte
                client_sockets[i] = client_sockets[client_count - 1];
                client_count--;
                break;
            }
        }
        pthread_mutex_unlock(&clients_mutex);
    } else if (read_size == -1) {
        perror("Erreur lors de la réception");
    }

    close(client_sock);  // Fermer le socket du client
    return NULL;
}

int main() {
    int server_sock, client_sock, c;
    struct sockaddr_in server, client;
    pthread_t client_thread;

    // Créer le socket pour le serveur
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock == -1) {
        printf("Erreur lors de la création du socket\n");
        return -1;
    }
    printf("Socket du serveur créé avec succès\n");

    // Configurer la structure sockaddr_in
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY; // Accepter les connexions de toutes les interfaces
    server.sin_port = htons(PORT);       // Port défini

    // Associer le socket à l'adresse IP et au port
    if (bind(server_sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("Erreur lors de l'association du socket");
        return -1;
    }
    printf("Socket lié avec succès\n");

    // Écouter les connexions entrantes (jusqu'à 10 clients en attente)
    listen(server_sock, MAX_CLIENTS);
    printf("En attente de connexions...\n");

    c = sizeof(struct sockaddr_in);

    // Boucle pour accepter plusieurs clients
    while ((client_sock = accept(server_sock, (struct sockaddr *)&client, (socklen_t *)&c))) {
        printf("Connexion acceptée\n");

        // Ajouter le client au tableau des clients connectés
        pthread_mutex_lock(&clients_mutex);
        if (client_count < MAX_CLIENTS) {
            client_sockets[client_count++] = client_sock;
        } else {
            printf("Le serveur est plein. Connexion refusée.\n");
            close(client_sock);
            pthread_mutex_unlock(&clients_mutex);
            continue;
        }
        pthread_mutex_unlock(&clients_mutex);

        // Allouer de la mémoire pour le descripteur de socket client
        int *new_sock = malloc(sizeof(int));
        if (new_sock == NULL) {
            perror("Erreur d'allocation mémoire");
            return 1;
        }
        *new_sock = client_sock;

        // Créer un thread pour gérer le nouveau client
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
