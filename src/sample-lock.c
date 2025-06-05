#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <errno.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>

#define DEFAULT_POSITIONS 128
#define DEFAULT_LOCKERS 1000000
#define HASH_LENGTH 32
#define CRYPTO_KEY_LENGTH 32

const unsigned char hmac_key[] = "thisisasecretkey1234567890abcdef";

unsigned char cryptographic_key[CRYPTO_KEY_LENGTH];

void generate_crypto_key(const char *filename) {
    if (RAND_load_file("/dev/urandom", 64) != 64) {
        fprintf(stderr, "Error seeding PRNG for crypto key generation\n");
        exit(1);
    }

    if (RAND_bytes(cryptographic_key, CRYPTO_KEY_LENGTH) != 1) {
        fprintf(stderr, "Error generating cryptographic key\n");
        exit(1);
    }

    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        fprintf(stderr, "Error creating crypto key file %s: %s\n", filename, strerror(errno));
        exit(1);
    }

    if (fwrite(cryptographic_key, 1, CRYPTO_KEY_LENGTH, fp) != CRYPTO_KEY_LENGTH) {
        fprintf(stderr, "Error writing crypto key to file %s: %s\n", filename, strerror(errno));
        fclose(fp);
        exit(1);
    }

    fclose(fp);
    printf("Generated cryptographic key and saved to %s\n", filename);
}

int load_crypto_key(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        return 0;
    }

    size_t read_bytes = fread(cryptographic_key, 1, CRYPTO_KEY_LENGTH, fp);
    fclose(fp);

    if (read_bytes != CRYPTO_KEY_LENGTH) {
        fprintf(stderr, "Error: Crypto key file %s has invalid size (%zu bytes, expected %d)\n",
                filename, read_bytes, CRYPTO_KEY_LENGTH);
        return 0;
    }

    return 1;
}

void derive_locker_key(int locker_index, unsigned char *derived_key) {
    char locker_str[32];
    snprintf(locker_str, sizeof(locker_str), "locker_%d", locker_index);

    unsigned int len = HASH_LENGTH;
    HMAC(EVP_sha256(), hmac_key, sizeof(hmac_key)-1,
         (const unsigned char*)locker_str, strlen(locker_str),
         derived_key, &len);

    if (len != HASH_LENGTH) {
        fprintf(stderr, "Derived key length unexpected (%u != %d)\n", len, HASH_LENGTH);
        exit(1);
    }
}

void compute_locker_hmac(const char *input, int locker_index, unsigned char *output) {
    unsigned char locker_key[HASH_LENGTH];
    derive_locker_key(locker_index, locker_key);

    unsigned int len = HASH_LENGTH;
    HMAC(EVP_sha256(), locker_key, HASH_LENGTH,
         (const unsigned char*)input, strlen(input), output, &len);

    if (len != HASH_LENGTH) {
        fprintf(stderr, "HMAC output length unexpected (%u != %d)\n", len, HASH_LENGTH);
        exit(1);
    }

    OPENSSL_cleanse(locker_key, HASH_LENGTH);
}

void xor_with_crypto_key(unsigned char *hash) {
    for (int i = 0; i < HASH_LENGTH; i++) {
        hash[i] ^= cryptographic_key[i];
    }
}

int compare_hashes(const unsigned char *hash1, const unsigned char *hash2) {
    return CRYPTO_memcmp(hash1, hash2, HASH_LENGTH) == 0;
}

void shuffle_positions(unsigned int *positions, int count) {
    for (int i = count - 1; i > 0; i--) {
        unsigned int rand_bytes;
        if (RAND_bytes((unsigned char *)&rand_bytes, sizeof(unsigned int)) != 1) {
            fprintf(stderr, "Error generating random number for shuffle\n");
            exit(1);
        }
        int j = rand_bytes % (i + 1);

        unsigned int temp = positions[i];
        positions[i] = positions[j];
        positions[j] = temp;
    }
}

void generate_unique_positions(unsigned int *positions, int num_positions, int max_positions) {
    if (num_positions <= max_positions / 4) {
        int generated = 0;
        while (generated < num_positions) {
            unsigned int rand_bytes;
            if (RAND_bytes((unsigned char *)&rand_bytes, sizeof(unsigned int)) != 1) {
                fprintf(stderr, "Error generating random number\n");
                exit(1);
            }
            unsigned int candidate = rand_bytes % max_positions;

            int duplicate = 0;
            for (int i = 0; i < generated; i++) {
                if (positions[i] == candidate) {
                    duplicate = 1;
                    break;
                }
            }

            if (!duplicate) {
                positions[generated++] = candidate;
            }
        }
    } else {
        unsigned int *temp_positions = malloc(sizeof(unsigned int) * max_positions);
        if (!temp_positions) {
            fprintf(stderr, "Memory allocation failed for temp positions\n");
            exit(1);
        }

        for (int i = 0; i < max_positions; i++) {
            temp_positions[i] = i;
        }

        shuffle_positions(temp_positions, max_positions);
        memcpy(positions, temp_positions, sizeof(unsigned int) * num_positions);
        free(temp_positions);
    }
}

void generate_lockers(int num_positions, int num_lockers, int max_bitstring_len, const char *filename) {
    FILE *fp = fopen(filename, "wb");
    if (fp == NULL) {
        fprintf(stderr, "Error opening file %s: %s\n", filename, strerror(errno));
        exit(1);
    }

    if (RAND_load_file("/dev/urandom", 64) != 64) {
        fprintf(stderr, "Error seeding PRNG\n");
        fclose(fp);
        exit(1);
    }

    if (num_positions > max_bitstring_len) {
        fprintf(stderr, "Error: Number of positions (%d) cannot exceed max bitstring length (%d)\n",
                num_positions, max_bitstring_len);
        fclose(fp);
        exit(1);
    }

    const int batch_size = 1000;
    unsigned int *batch_buffer = malloc(sizeof(unsigned int) * num_positions * batch_size);
    if (!batch_buffer) {
        fprintf(stderr, "Memory allocation failed for batch buffer\n");
        fclose(fp);
        exit(1);
    }

    printf("Generating %d lockers with %d unique positions each (max bitstring length: %d)...\n",
           num_lockers, num_positions, max_bitstring_len);

    for (int locker = 0; locker < num_lockers; locker += batch_size) {
        int current_batch = (locker + batch_size > num_lockers) ? num_lockers - locker : batch_size;

        for (int b = 0; b < current_batch; b++) {
            generate_unique_positions(&batch_buffer[b * num_positions], num_positions, max_bitstring_len);
        }

        if (fwrite(batch_buffer, sizeof(unsigned int), current_batch * num_positions, fp) !=
            (size_t)(current_batch * num_positions)) {
            fprintf(stderr, "Error writing locker batch to file %s: %s\n", filename, strerror(errno));
            free(batch_buffer);
            fclose(fp);
            exit(1);
        }

        if (locker % 10000 == 0) {
            printf("  Generated %d lockers...\n", locker);
        }
    }

    free(batch_buffer);
    fclose(fp);
    printf("Completed generating %d lockers\n", num_lockers);
}

char *read_single_bitstring(const char *filename, int *length_out) {
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        fprintf(stderr, "Error opening bitstring file %s: %s\n", filename, strerror(errno));
        return NULL;
    }

    char *line = NULL;
    size_t len = 0;
    ssize_t read = getline(&line, &len, fp);
    fclose(fp);

    if (read == -1) {
        if (line) free(line);
        fprintf(stderr, "Error reading bitstring line from file %s or file is empty\n", filename);
        return NULL;
    }

    char *cleaned_bitstring = malloc((size_t)read + 1);
    if (!cleaned_bitstring) {
        fprintf(stderr, "Error: Memory allocation failed for processing bitstring line\n");
        free(line);
        return NULL;
    }

    int cleaned_len = 0;
    ssize_t original_len_signed = read;

    while (original_len_signed > 0 &&
           (line[original_len_signed - 1] == '\n' || line[original_len_signed - 1] == ',' ||
            line[original_len_signed - 1] == '\r' || isspace(line[original_len_signed - 1]))) {
        original_len_signed--;
    }

    for (ssize_t k = 0; k < original_len_signed; k++) {
        if (line[k] == '0' || line[k] == '1') {
            cleaned_bitstring[cleaned_len++] = line[k];
        } else if (line[k] == ',' || isspace(line[k])) {
            continue;
        } else {
            fprintf(stderr, "Invalid character '%c' at position %zd in bitstring file %s.\n",
                    line[k], k, filename);
            free(line);
            free(cleaned_bitstring);
            return NULL;
        }
    }

    cleaned_bitstring[cleaned_len] = '\0';
    free(line);

    if (cleaned_len == 0) {
        fprintf(stderr, "Error: Bitstring file '%s' resulted in empty bitstring after cleaning.\n", filename);
        free(cleaned_bitstring);
        return NULL;
    }

    *length_out = cleaned_len;
    return cleaned_bitstring;
}

void extract_bits(const char *bitstring, int bitstring_len, const unsigned int *positions,
                  int num_positions, char *extracted) {
    for (int i = 0; i < num_positions; i++) {
        if (positions[i] >= (unsigned int)bitstring_len) {
            fprintf(stderr, "Error: Position %u exceeds bitstring length %d\n", positions[i], bitstring_len);
            exit(1);
        }
        extracted[i] = bitstring[positions[i]];
    }
    extracted[num_positions] = '\0';
}

void store_bitstring(const char *locker_filename, const char *bitstring_filename,
                     const char *stored_hashes_filename, int num_positions) {
    int bitstring_len = 0;
    char *bitstring = read_single_bitstring(bitstring_filename, &bitstring_len);
    if (!bitstring) {
        exit(1);
    }
    printf("Read bitstring (length %d) from %s\n", bitstring_len, bitstring_filename);

    FILE *locker_fp = fopen(locker_filename, "rb");
    if (!locker_fp) {
        fprintf(stderr, "Error opening locker file %s: %s\n", locker_filename, strerror(errno));
        free(bitstring);
        exit(1);
    }

    fseek(locker_fp, 0, SEEK_END);
    long file_size = ftell(locker_fp);
    fseek(locker_fp, 0, SEEK_SET);

    long expected_locker_size = (long)sizeof(unsigned int) * num_positions;
    if (file_size <= 0 || file_size % expected_locker_size != 0) {
        fprintf(stderr, "Error: Locker file size (%ld) is not a multiple of expected locker size (%ld)\n",
                file_size, expected_locker_size);
        fclose(locker_fp);
        free(bitstring);
        exit(1);
    }

    int num_lockers = file_size / expected_locker_size;
    printf("Processing %d lockers from %s\n", num_lockers, locker_filename);

    FILE *hash_out_fp = fopen(stored_hashes_filename, "wb");
    if (!hash_out_fp) {
        fprintf(stderr, "Error opening output hash file %s: %s\n", stored_hashes_filename, strerror(errno));
        fclose(locker_fp);
        free(bitstring);
        exit(1);
    }

    unsigned int *current_positions = malloc(sizeof(unsigned int) * num_positions);
    char *extracted = malloc(num_positions + 1);
    unsigned char *hash_buffer = malloc(HASH_LENGTH);

    if (!current_positions || !extracted || !hash_buffer) {
        fprintf(stderr, "Memory allocation failed for store buffers\n");
        exit(1);
    }

    printf("Processing lockers...\n");

    for (int locker = 0; locker < num_lockers; locker++) {
        if (fread(current_positions, sizeof(unsigned int), num_positions, locker_fp) != (size_t)num_positions) {
            fprintf(stderr, "Error reading positions for locker %d\n", locker);
            goto cleanup;
        }

        extract_bits(bitstring, bitstring_len, current_positions, num_positions, extracted);
        compute_locker_hmac(extracted, locker, hash_buffer);

        xor_with_crypto_key(hash_buffer);

        if (fwrite(hash_buffer, HASH_LENGTH, 1, hash_out_fp) != 1) {
            fprintf(stderr, "Error writing hash for locker %d\n", locker);
            goto cleanup;
        }

        if (locker % 10000 == 0 && locker > 0) {
            printf("  Processed %d lockers...\n", locker);
        }
    }

    printf("Finished processing. Stored %d hashes in %s\n", num_lockers, stored_hashes_filename);

cleanup:
    free(current_positions);
    free(extracted);
    free(hash_buffer);
    fclose(locker_fp);
    fclose(hash_out_fp);
    free(bitstring);
}

int verify_bitstring(const char *locker_filename, const char *bitstring_filename,
                     const char *stored_hashes_filename, int num_positions) {
    int input_bitstring_len = 0;
    char *input_bitstring = read_single_bitstring(bitstring_filename, &input_bitstring_len);
    if (!input_bitstring) {
        return 0;
    }
    printf("Read input bitstring (length %d) from %s\n", input_bitstring_len, bitstring_filename);

    FILE *locker_fp = fopen(locker_filename, "rb");
    if (!locker_fp) {
        fprintf(stderr, "Error opening locker file %s: %s\n", locker_filename, strerror(errno));
        free(input_bitstring);
        return 0;
    }

    fseek(locker_fp, 0, SEEK_END);
    long file_size = ftell(locker_fp);
    fseek(locker_fp, 0, SEEK_SET);

    long expected_locker_size = (long)sizeof(unsigned int) * num_positions;
    int num_lockers = file_size / expected_locker_size;
    printf("Loaded %d lockers from %s\n", num_lockers, locker_filename);

    FILE *stored_hash_fp = fopen(stored_hashes_filename, "rb");
    if (!stored_hash_fp) {
        fprintf(stderr, "Error opening stored hash file %s: %s\n", stored_hashes_filename, strerror(errno));
        fclose(locker_fp);
        free(input_bitstring);
        return 0;
    }

    fseek(stored_hash_fp, 0, SEEK_END);
    long stored_file_size = ftell(stored_hash_fp);
    fseek(stored_hash_fp, 0, SEEK_SET);

    int num_stored_hashes = stored_file_size / HASH_LENGTH;
    printf("Found %d stored hashes in %s\n", num_stored_hashes, stored_hashes_filename);

    unsigned int *current_positions = malloc(sizeof(unsigned int) * num_positions);
    char *extracted = malloc(num_positions + 1);
    unsigned char *computed_hash = malloc(HASH_LENGTH);
    unsigned char *stored_hash = malloc(HASH_LENGTH);

    if (!current_positions || !extracted || !computed_hash || !stored_hash) {
        fprintf(stderr, "Memory allocation failed for verify buffers\n");
        goto cleanup_verify;
    }

    int max_check = (num_lockers < num_stored_hashes) ? num_lockers : num_stored_hashes;
    for (int locker = 0; locker < max_check; locker++) {
        if (fread(current_positions, sizeof(unsigned int), num_positions, locker_fp) != (size_t)num_positions) {
            fprintf(stderr, "Error reading positions for locker %d\n", locker);
            goto cleanup_verify;
        }

        extract_bits(input_bitstring, input_bitstring_len, current_positions, num_positions, extracted);
        compute_locker_hmac(extracted, locker, computed_hash);

        if (fread(stored_hash, HASH_LENGTH, 1, stored_hash_fp) != 1) {
            fprintf(stderr, "Error reading stored hash for locker %d\n", locker);
            goto cleanup_verify;
        }

        unsigned char result[HASH_LENGTH];
        for (int i = 0; i < HASH_LENGTH; i++) {
            result[i] = stored_hash[i] ^ computed_hash[i];
        }

        if (compare_hashes(result, cryptographic_key)) {
            printf("OK (Match found at locker %d)\n", locker);
            free(current_positions);
            free(extracted);
            free(computed_hash);
            free(stored_hash);
            fclose(locker_fp);
            fclose(stored_hash_fp);
            free(input_bitstring);
            return 1;
        }
    }

    printf("Verification failed - no match found\n");

cleanup_verify:
    if (current_positions) free(current_positions);
    if (extracted) free(extracted);
    if (computed_hash) free(computed_hash);
    if (stored_hash) free(stored_hash);
    fclose(locker_fp);
    fclose(stored_hash_fp);
    free(input_bitstring);
    return 0;
}

int main(int argc, char *argv[]) {
    int num_positions = DEFAULT_POSITIONS;
    int num_lockers_gen = DEFAULT_LOCKERS;
    int max_bitstring_len = 512;
    char *locker_filename = "lockers.bin";
    char *bitstring_filename = NULL;
    char *stored_hashes_filename = "stored_hashes.bin";
    char *crypto_key_filename = "crypto_key.bin";
    char *command = NULL;
    int generate_mode_lockers_set = 0;

    int opt;
    struct option long_options[] = {
        {"positions",   required_argument, 0, 'p'},
        {"lockers",     required_argument, 0, 'l'},
        {"maxbits",     required_argument, 0, 'm'},
        {"lockerfile",  required_argument, 0, 'f'},
        {"bitstring",   required_argument, 0, 'b'},
        {"storedfile",  required_argument, 0, 'o'},
        {"cryptokey",   required_argument, 0, 'k'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "p:l:m:f:b:o:k:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'p':
                num_positions = atoi(optarg);
                if (num_positions <= 0) {
                    fprintf(stderr, "Error: Number of positions must be positive.\n");
                    exit(1);
                }
                break;
            case 'l':
                num_lockers_gen = atoi(optarg);
                if (num_lockers_gen <= 0) {
                    fprintf(stderr, "Error: Number of lockers must be positive.\n");
                    exit(1);
                }
                generate_mode_lockers_set = 1;
                break;
            case 'm':
                max_bitstring_len = atoi(optarg);
                if (max_bitstring_len <= 0) {
                    fprintf(stderr, "Error: Max bitstring length must be positive.\n");
                    exit(1);
                }
                break;
            case 'f':
                locker_filename = optarg;
                break;
            case 'b':
                bitstring_filename = optarg;
                break;
            case 'o':
                stored_hashes_filename = optarg;
                break;
            case 'k':
                crypto_key_filename = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s [command] [options]\n", argv[0]);
                fprintf(stderr, "Commands: generate, store, verify\n");
                fprintf(stderr, "Options:\n");
                fprintf(stderr, "  -p, --positions    Number of unique positions per locker (default: %d)\n", DEFAULT_POSITIONS);
                fprintf(stderr, "  -l, --lockers      Number of lockers (ONLY for generate, default: %d)\n", DEFAULT_LOCKERS);
                fprintf(stderr, "  -m, --maxbits      Maximum bitstring length (default: 512)\n");
                fprintf(stderr, "  -f, --lockerfile   Filename for lockers (default: lockers.bin)\n");
                fprintf(stderr, "  -b, --bitstring    Bitstring file\n");
                fprintf(stderr, "  -o, --storedfile   Filename for storing/loading HMACs (default: stored_hashes.bin)\n");
                fprintf(stderr, "  -k, --cryptokey    Filename for cryptographic key (default: crypto_key.bin)\n");
                exit(1);
        }
    }

    if (optind < argc) {
        command = argv[optind];
    } else {
        fprintf(stderr, "Error: No command specified (generate, store, or verify)\n");
        exit(1);
    }

    if (!load_crypto_key(crypto_key_filename)) {
        printf("Cryptographic key file not found, generating new key...\n");
        generate_crypto_key(crypto_key_filename);
    } else {
        printf("Loaded cryptographic key from %s\n", crypto_key_filename);
    }

    if (strcmp(command, "generate") == 0) {
        if (!generate_mode_lockers_set) {
            num_lockers_gen = DEFAULT_LOCKERS;
        }
        generate_lockers(num_positions, num_lockers_gen, max_bitstring_len, locker_filename);
        printf("Generated %d lockers with %d unique positions each into %s\n",
               num_lockers_gen, num_positions, locker_filename);

    } else if (strcmp(command, "store") == 0) {
        if (bitstring_filename == NULL) {
            fprintf(stderr, "Error: -b <input_bitstring_file> is required for 'store'\n");
            exit(1);
        }
        if (generate_mode_lockers_set) {
            fprintf(stderr, "Warning: -l/--lockers option ignored for 'store'. Number of lockers is determined by locker file size.\n");
        }

        store_bitstring(locker_filename, bitstring_filename, stored_hashes_filename, num_positions);

    } else if (strcmp(command, "verify") == 0) {
        if (bitstring_filename == NULL) {
            fprintf(stderr, "Error: -b <input_bitstring_file> is required for 'verify'\n");
            exit(1);
        }
        if (generate_mode_lockers_set) {
            fprintf(stderr, "Warning: -l/--lockers option ignored for 'verify'. Number of lockers is determined by locker file size.\n");
        }

        if (!verify_bitstring(locker_filename, bitstring_filename, stored_hashes_filename, num_positions)) {
            return 1;
        }

    } else {
        fprintf(stderr, "Invalid command: %s. Use 'generate', 'store', or 'verify'.\n", command);
        exit(1);
    }

    return 0;
}
