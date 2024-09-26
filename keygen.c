#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>

// Fonction d'encodage Base64
void base64_encode(const unsigned char *input, size_t input_len, char *output, size_t output_len) {
    sodium_bin2base64(output, output_len, input, input_len, sodium_base64_VARIANT_ORIGINAL);
}

// Fonction pour générer et sauvegarder les clés Curve25519 en Base64 avec des en-têtes PEM
void generate_keys() {
    unsigned char public_key[crypto_box_PUBLICKEYBYTES];
    unsigned char private_key[crypto_box_SECRETKEYBYTES];
    char public_key_base64[crypto_box_PUBLICKEYBYTES * 2];  // Espace suffisant pour l'encodage Base64
    char private_key_base64[crypto_box_SECRETKEYBYTES * 2];

    // Initialiser libsodium
    if (sodium_init() < 0) {
        printf("Erreur lors de l'initialisation de libsodium\n");
        return;
    }

    // Générer une paire de clés Curve25519
    crypto_box_keypair(public_key, private_key);

    // Encoder les clés en Base64
    base64_encode(public_key, sizeof(public_key), public_key_base64, sizeof(public_key_base64));
    base64_encode(private_key, sizeof(private_key), private_key_base64, sizeof(private_key_base64));

    // Sauvegarder les clés dans des fichiers
    FILE *private_file = fopen("private_key.pem", "w");
    FILE *public_file = fopen("public_key.pem", "w");

    if (private_file != NULL) {
        fprintf(private_file, "-----BEGIN PRIVATE KEY-----\n%s\n-----END PRIVATE KEY-----\n", private_key_base64);
        fclose(private_file);
        printf("Clé privée sauvegardée dans 'private_key.pem'.\n");
    } else {
        printf("Erreur lors de la sauvegarde de la clé privée.\n");
    }

    if (public_file != NULL) {
        fprintf(public_file, "-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n", public_key_base64);
        fclose(public_file);
        printf("Clé publique sauvegardée dans 'public_key.pem'.\n");
    } else {
        printf("Erreur lors de la sauvegarde de la clé publique.\n");
    }
}

int main() {
    generate_keys();
    return 0;
}
