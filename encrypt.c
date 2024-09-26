#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

#define BUFFER_SIZE 1024  // Taille du tampon pour les fichiers
#define MAX_KEY_SIZE 1024  // Taille maximale de la clé pour le chargement depuis PEM

// Fonction de décodage Base64
void base64_decode(const char *input, unsigned char *output, size_t output_len) {
    sodium_base642bin(output, output_len, input, strlen(input), NULL, NULL, NULL, sodium_base64_VARIANT_ORIGINAL);
}

// Fonction pour convertir les données en hexadécimal, formatées par blocs de 4 octets
void to_hex_formatted(const unsigned char *data, size_t len, FILE *output_file) {
    for (size_t i = 0; i < len; i++) {
        // Écrire chaque octet en hexadécimal
        fprintf(output_file, "%02x", data[i]);

        // Ajouter un espace toutes les 2 paires d'octets
        if ((i + 1) % 2 == 0) {
            fprintf(output_file, " ");
        }

        // Ajouter un saut de ligne toutes les 16 octets (32 caractères hex)
        if ((i + 1) % 16 == 0) {
            fprintf(output_file, "\n");
        }
    }

    // Ajouter un saut de ligne final si nécessaire
    if (len % 16 != 0) {
        fprintf(output_file, "\n");
    }
}

// Fonction pour charger et décoder la clé publique en base64 à partir d'un fichier PEM
void load_public_key_from_pem(const char *filename, unsigned char *public_key) {
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        perror("Erreur d'ouverture du fichier PEM pour la clé publique");
        exit(1);
    }

    char line[MAX_KEY_SIZE];
    char key_base64[MAX_KEY_SIZE] = {0};

    // Lire le fichier PEM ligne par ligne
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "-----BEGIN PUBLIC KEY-----") || strstr(line, "-----END PUBLIC KEY-----")) {
            continue;  // Ignorer les lignes de délimitation
        }
        strcat(key_base64, line);  // Concaténer les lignes pour former la clé complète en Base64
    }

    // Supprimer les retours à la ligne dans la chaîne Base64
    key_base64[strcspn(key_base64, "\n")] = 0;

    // Décoder la clé base64
    base64_decode(key_base64, public_key, crypto_box_PUBLICKEYBYTES);

    fclose(fp);
}

// Fonction pour crypter le nom et l'extension du fichier
void encrypt_filename(const char *filename, unsigned char *encrypted_name, unsigned long long *encrypted_name_len, const unsigned char *recipient_public_key) {
    unsigned char nonce[crypto_box_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    // Crypter le nom du fichier avec crypto_box_seal
    if (crypto_box_seal(encrypted_name, (unsigned char *)filename, strlen(filename), recipient_public_key) != 0) {
        printf("Erreur lors du chiffrement du nom du fichier\n");
        exit(EXIT_FAILURE);
    }

    *encrypted_name_len = crypto_box_SEALBYTES + strlen(filename);
}

// Fonction pour générer un nom de fichier hexadécimal court
void generate_random_hex_name(char *output, size_t len) {
    unsigned char random_bytes[len / 2];  // La moitié de la taille pour chaque octet en hex
    randombytes_buf(random_bytes, sizeof(random_bytes));

    for (size_t i = 0; i < sizeof(random_bytes); i++) {
        sprintf(output + (i * 2), "%02x", random_bytes[i]);  // Convertir en hexadécimal
    }

    output[len] = '\0';  // Terminer la chaîne
}

// Fonction pour chiffrer un fichier en utilisant uniquement la clé publique du destinataire
void encrypt_file(const char *input_path, const unsigned char *recipient_public_key) {
    FILE *input_file = fopen(input_path, "rb");
    if (!input_file) {
        perror("Erreur lors de l'ouverture du fichier à chiffrer");
        exit(EXIT_FAILURE);
    }

    // Générer un nom de fichier chiffré pour le fichier de sortie
    unsigned char encrypted_filename[BUFFER_SIZE];
    unsigned long long encrypted_filename_len;
    encrypt_filename(input_path, encrypted_filename, &encrypted_filename_len, recipient_public_key);

    // Générer un nom de fichier hexadécimal aléatoire pour le fichier chiffré
    char random_hex_filename[32];  // Nom de fichier en hexadécimal (16 octets -> 32 caractères)
    generate_random_hex_name(random_hex_filename, 32);

    // Nom du fichier de sortie chiffré
    FILE *output_file = fopen(random_hex_filename, "w");  // Ouvrir en mode texte pour écrire en hexadécimal
    if (!output_file) {
        perror("Erreur lors de la création du fichier chiffré");
        fclose(input_file);
        exit(EXIT_FAILURE);
    }

    unsigned char nonce[crypto_box_NONCEBYTES];
    unsigned char buffer[BUFFER_SIZE];
    unsigned char encrypted[BUFFER_SIZE + crypto_box_MACBYTES];
    unsigned long long encrypted_len;

    // Générer un nonce aléatoire
    randombytes_buf(nonce, sizeof(nonce));

    // Écrire le nonce en hexadécimal dans le fichier de sortie
    to_hex_formatted(nonce, crypto_box_NONCEBYTES, output_file);

    // Écrire le nom du fichier chiffré
    to_hex_formatted(encrypted_filename, encrypted_filename_len, output_file);

    size_t read_len;
    while ((read_len = fread(buffer, 1, BUFFER_SIZE, input_file)) > 0) {
        // Utiliser la clé publique du destinataire pour chiffrer le message
        if (crypto_box_seal(encrypted, buffer, read_len, recipient_public_key) != 0) {
            printf("Erreur lors du chiffrement\n");
            exit(EXIT_FAILURE);
        }

        // Écrire les données chiffrées en hexadécimal dans le fichier de sortie
        to_hex_formatted(encrypted, read_len + crypto_box_MACBYTES, output_file);
    }

    fclose(input_file);
    fclose(output_file);

    printf("Fichier chiffré avec succès et enregistré sous le nom '%s'\n", random_hex_filename);
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
