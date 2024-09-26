#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

#define BUFFER_SIZE 4096  // Taille du tampon pour les fichiers

// Fonction de décodage Base64
void base64_decode(const char *input, unsigned char *output, size_t output_len) {
    sodium_base642bin(output, output_len, input, strlen(input), NULL, NULL, NULL, sodium_base64_VARIANT_ORIGINAL);
}

// Fonction pour charger et décoder une clé privée en Base64 à partir d'un fichier PEM
void load_private_key_from_pem(const char *filename, unsigned char *private_key) {
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        perror("Erreur d'ouverture du fichier PEM pour la clé privée");
        exit(1);
    }

    char line[1024];
    char key_base64[1024] = {0};

    // Lire le fichier PEM ligne par ligne
    while (fgets(line, sizeof(line), fp)) {
        // Ignorer les délimiteurs PEM
        if (strstr(line, "-----BEGIN PRIVATE KEY-----") || strstr(line, "-----END PRIVATE KEY-----")) {
            continue;
        }
        // Concaténer les lignes pour former la clé complète en Base64
        strcat(key_base64, line);
    }

    // Supprimer les retours à la ligne dans la chaîne Base64
    key_base64[strcspn(key_base64, "\r\n")] = 0;

    // Décoder la clé base64
    base64_decode(key_base64, private_key, crypto_box_SECRETKEYBYTES);

    fclose(fp);
}

// Fonction pour charger et décoder une clé publique en Base64 à partir d'un fichier PEM
void load_public_key_from_pem(const char *filename, unsigned char *public_key) {
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        perror("Erreur d'ouverture du fichier PEM pour la clé publique");
        exit(1);
    }

    char line[1024];
    char key_base64[1024] = {0};

    // Lire le fichier PEM ligne par ligne
    while (fgets(line, sizeof(line), fp)) {
        // Ignorer les délimiteurs PEM
        if (strstr(line, "-----BEGIN PUBLIC KEY-----") || strstr(line, "-----END PUBLIC KEY-----")) {
            continue;
        }
        // Concaténer les lignes pour former la clé complète en Base64
        strcat(key_base64, line);
    }

    // Supprimer les retours à la ligne dans la chaîne Base64
    key_base64[strcspn(key_base64, "\r\n")] = 0;

    // Décoder la clé base64
    base64_decode(key_base64, public_key, crypto_box_PUBLICKEYBYTES);

    fclose(fp);
}

// Fonction pour déchiffrer un fichier
void decrypt_file(const char *input_path, const unsigned char *recipient_public_key, const unsigned char *recipient_private_key) {
    FILE *input_file = fopen(input_path, "rb");
    if (!input_file) {
        perror("Erreur lors de l'ouverture du fichier chiffré");
        exit(EXIT_FAILURE);
    }

    // Construire le nom du fichier de sortie en supprimant l'extension ".rbts"
    char output_filename[BUFFER_SIZE];
    size_t input_path_len = strlen(input_path);
    if (input_path_len > 5 && strcmp(input_path + input_path_len - 5, ".rbts") == 0) {
        strncpy(output_filename, input_path, input_path_len - 5);
        output_filename[input_path_len - 5] = '\0';
    } else {
        printf("Erreur : le fichier d'entrée n'a pas l'extension '.rbts'\n");
        fclose(input_file);
        exit(EXIT_FAILURE);
    }

    FILE *output_file = fopen(output_filename, "wb");
    if (!output_file) {
        perror("Erreur lors de la création du fichier déchiffré");
        fclose(input_file);
        exit(EXIT_FAILURE);
    }

    // Obtenir la taille du fichier chiffré
    fseek(input_file, 0, SEEK_END);
    long file_size = ftell(input_file);
    fseek(input_file, 0, SEEK_SET);

    // Allouer de la mémoire pour les données chiffrées et déchiffrées
    unsigned char *encrypted_content = malloc(file_size);
    unsigned char *decrypted_content = malloc(file_size - crypto_box_SEALBYTES);

    if (!encrypted_content || !decrypted_content) {
        perror("Erreur d'allocation de mémoire");
        fclose(input_file);
        fclose(output_file);
        exit(EXIT_FAILURE);
    }

    // Lire le contenu chiffré
    size_t read_size = fread(encrypted_content, 1, file_size, input_file);
    if (read_size != file_size) {
        perror("Erreur lors de la lecture du fichier chiffré");
        fclose(input_file);
        fclose(output_file);
        free(encrypted_content);
        free(decrypted_content);
        exit(EXIT_FAILURE);
    }

    // Déchiffrer le contenu
    if (crypto_box_seal_open(decrypted_content, encrypted_content, file_size, recipient_public_key, recipient_private_key) != 0) {
        printf("Erreur lors du déchiffrement du fichier\n");
        fclose(input_file);
        fclose(output_file);
        free(encrypted_content);
        free(decrypted_content);
        exit(EXIT_FAILURE);
    }

    // Écrire le contenu déchiffré dans le fichier de sortie
    fwrite(decrypted_content, 1, file_size - crypto_box_SEALBYTES, output_file);

    fclose(input_file);
    fclose(output_file);
    free(encrypted_content);
    free(decrypted_content);

    printf("Fichier déchiffré avec succès sous le nom '%s'\n", output_filename);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage : %s <encrypted_file>\n", argv[0]);
        return 1;
    }

    unsigned char recipient_private_key[crypto_box_SECRETKEYBYTES];
    unsigned char recipient_public_key[crypto_box_PUBLICKEYBYTES];

    // Charger la clé privée depuis private_key.pem
    load_private_key_from_pem("private_key.pem", recipient_private_key);

    // Charger la clé publique depuis public_key.pem
    load_public_key_from_pem("public_key.pem", recipient_public_key);

    // Initialiser sodium
    if (sodium_init() < 0) {
        printf("Erreur lors de l'initialisation de sodium\n");
        return 1;
    }

    // Déchiffrer le fichier en utilisant la clé privée et la clé publique
    decrypt_file(argv[1], recipient_public_key, recipient_private_key);

    return 0;
}
