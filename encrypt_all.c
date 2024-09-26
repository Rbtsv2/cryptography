#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

#define BUFFER_SIZE 4096  // Taille du tampon pour les fichiers

// Fonction de décodage Base64
void base64_decode(const char *input, unsigned char *output, size_t output_len) {
    sodium_base642bin(output, output_len, input, strlen(input), NULL, NULL, NULL, sodium_base64_VARIANT_ORIGINAL);
}

// Fonction pour charger et décoder la clé publique en Base64 à partir d'un fichier PEM
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
        if (strstr(line, "-----BEGIN PUBLIC KEY-----") || strstr(line, "-----END PUBLIC KEY-----")) {
            continue;  // Ignorer les lignes de délimitation
        }
        strcat(key_base64, line);  // Concaténer les lignes pour former la clé complète en Base64
    }

    // Supprimer les retours à la ligne dans la chaîne Base64
    key_base64[strcspn(key_base64, "\r\n")] = 0;

    // Décoder la clé base64
    base64_decode(key_base64, public_key, crypto_box_PUBLICKEYBYTES);

    fclose(fp);
}

// Fonction pour chiffrer un fichier en utilisant uniquement la clé publique du destinataire
void encrypt_file(const char *input_path, const unsigned char *recipient_public_key) {
    FILE *input_file = fopen(input_path, "rb");
    if (!input_file) {
        perror("Erreur lors de l'ouverture du fichier à chiffrer");
        exit(EXIT_FAILURE);
    }

    // Nom du fichier de sortie avec extension .rbts
    char output_filename[BUFFER_SIZE];
    snprintf(output_filename, sizeof(output_filename), "%s.rbts", input_path);

    FILE *output_file = fopen(output_filename, "wb");
    if (!output_file) {
        perror("Erreur lors de la création du fichier chiffré");
        fclose(input_file);
        exit(EXIT_FAILURE);
    }

    // Obtenir la taille du fichier
    fseek(input_file, 0, SEEK_END);
    long file_size = ftell(input_file);
    fseek(input_file, 0, SEEK_SET);

    // Allouer de la mémoire pour le contenu du fichier et les données chiffrées
    unsigned char *file_content = malloc(file_size);
    unsigned char *encrypted_content = malloc(file_size + crypto_box_SEALBYTES);

    if (!file_content || !encrypted_content) {
        perror("Erreur d'allocation de mémoire");
        fclose(input_file);
        fclose(output_file);
        exit(EXIT_FAILURE);
    }

    // Lire le contenu du fichier
    size_t read_size = fread(file_content, 1, file_size, input_file);
    if (read_size != file_size) {
        perror("Erreur lors de la lecture du fichier");
        fclose(input_file);
        fclose(output_file);
        free(file_content);
        free(encrypted_content);
        exit(EXIT_FAILURE);
    }

    // Chiffrer le contenu du fichier
    if (crypto_box_seal(encrypted_content, file_content, file_size, recipient_public_key) != 0) {
        printf("Erreur lors du chiffrement\n");
        fclose(input_file);
        fclose(output_file);
        free(file_content);
        free(encrypted_content);
        exit(EXIT_FAILURE);
    }

    // Écrire les données chiffrées dans le fichier de sortie
    fwrite(encrypted_content, 1, file_size + crypto_box_SEALBYTES, output_file);

    fclose(input_file);
    fclose(output_file);
    free(file_content);
    free(encrypted_content);

    printf("Fichier chiffré avec succès et enregistré sous le nom '%s'\n", output_filename);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage : %s <input_file>\n", argv[0]);
        return 1;
    }

    unsigned char recipient_public_key[crypto_box_PUBLICKEYBYTES];

    // Charger la clé publique depuis public_key.pem
    load_public_key_from_pem("public_key.pem", recipient_public_key);

    // Initialiser sodium
    if (sodium_init() < 0) {
        printf("Erreur lors de l'initialisation de sodium\n");
        return 1;
    }

    // Chiffrer le fichier en utilisant uniquement la clé publique
    encrypt_file(argv[1], recipient_public_key);

    return 0;
}
