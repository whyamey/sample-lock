#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define DEFAULT_POSITIONS 128
#define DEFAULT_LOCKERS 1000000
#define HASH_LENGTH 32
#define CRYPTO_KEY_LENGTH 32
#define IO_BATCH_SIZE 10000

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
    fprintf(stderr, "Error creating crypto key file %s: %s\n", filename,
            strerror(errno));
    exit(1);
  }
  if (fwrite(cryptographic_key, 1, CRYPTO_KEY_LENGTH, fp) !=
      CRYPTO_KEY_LENGTH) {
    fprintf(stderr, "Error writing crypto key to file %s: %s\n", filename,
            strerror(errno));
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
    fprintf(
        stderr,
        "Error: Crypto key file %s has invalid size (%zu bytes, expected %d)\n",
        filename, read_bytes, CRYPTO_KEY_LENGTH);
    return 0;
  }
  return 1;
}

void compute_locker_hmac(EVP_MAC_CTX *master_ctx, const char *input,
                         int locker_index, unsigned char *output) {
  char locker_str[32];
  int locker_str_len =
      snprintf(locker_str, sizeof(locker_str), "locker_%d", locker_index);
  size_t mac_len;

  EVP_MAC_CTX *ctx = EVP_MAC_CTX_dup(master_ctx);
  if (!ctx) {
    fprintf(stderr, "Error duplicating HMAC context\n");
    exit(1);
  }

  if (EVP_MAC_update(ctx, (const unsigned char *)locker_str, locker_str_len) !=
          1 ||
      EVP_MAC_update(ctx, (const unsigned char *)input, strlen(input)) != 1 ||
      EVP_MAC_final(ctx, output, &mac_len, HASH_LENGTH) != 1) {
    fprintf(stderr, "Error during HMAC computation\n");
    EVP_MAC_CTX_free(ctx);
    exit(1);
  }

  EVP_MAC_CTX_free(ctx);
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
    unsigned int rand_val;
    if (RAND_bytes((unsigned char *)&rand_val, sizeof(unsigned int)) != 1) {
      fprintf(stderr, "Error generating random number for shuffle\n");
      exit(1);
    }
    int j = rand_val % (i + 1);
    unsigned int temp = positions[i];
    positions[i] = positions[j];
    positions[j] = temp;
  }
}

void generate_unique_positions(unsigned int *positions, int num_positions,
                               int max_positions) {
  if (num_positions > max_positions) {
    fprintf(stderr,
            "Error: Cannot generate %d unique positions from a pool of %d.\n",
            num_positions, max_positions);
    exit(1);
  }

  if (num_positions <= max_positions / 4) {
    char *seen = calloc(max_positions, sizeof(char));
    if (!seen) {
      fprintf(stderr, "Memory allocation failed for 'seen' bitmap\n");
      exit(1);
    }
    int generated = 0;
    while (generated < num_positions) {
      unsigned int rand_val;
      if (RAND_bytes((unsigned char *)&rand_val, sizeof(unsigned int)) != 1) {
        fprintf(stderr, "Error generating random number\n");
        exit(1);
      }
      unsigned int candidate = rand_val % max_positions;
      if (!seen[candidate]) {
        seen[candidate] = 1;
        positions[generated++] = candidate;
      }
    }
    free(seen);
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

void generate_lockers(int num_positions, int num_lockers, int max_bitstring_len,
                      const char *filename) {
  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    fprintf(stderr, "Error opening file %s: %s\n", filename, strerror(errno));
    exit(1);
  }
  if (RAND_load_file("/dev/urandom", 64) != 64) {
    fprintf(stderr, "Error seeding PRNG\n");
    fclose(fp);
    exit(1);
  }
  unsigned int *batch_buffer =
      malloc(sizeof(unsigned int) * num_positions * IO_BATCH_SIZE);
  if (!batch_buffer) {
    fprintf(stderr, "Memory allocation failed for batch buffer\n");
    fclose(fp);
    exit(1);
  }
  printf("Generating %d lockers with %d unique positions each...\n",
         num_lockers, num_positions);
  for (int locker_base = 0; locker_base < num_lockers;
       locker_base += IO_BATCH_SIZE) {
    int current_batch_size = (locker_base + IO_BATCH_SIZE > num_lockers)
                                 ? num_lockers - locker_base
                                 : IO_BATCH_SIZE;
    for (int i = 0; i < current_batch_size; i++) {
      generate_unique_positions(&batch_buffer[i * num_positions], num_positions,
                                max_bitstring_len);
    }
    if (fwrite(batch_buffer, sizeof(unsigned int),
               current_batch_size * num_positions,
               fp) != (size_t)(current_batch_size * num_positions)) {
      fprintf(stderr, "Error writing locker batch to file %s: %s\n", filename,
              strerror(errno));
      free(batch_buffer);
      fclose(fp);
      exit(1);
    }
    printf("\r  Generated %d lockers...", locker_base + current_batch_size);
    fflush(stdout);
  }
  free(batch_buffer);
  fclose(fp);
  printf("\nCompleted generating %d lockers.\n", num_lockers);
}

char *read_single_bitstring(const char *filename, int *length_out) {
  FILE *fp = fopen(filename, "r");
  if (!fp) {
    fprintf(stderr, "Error opening bitstring file %s: %s\n", filename,
            strerror(errno));
    return NULL;
  }
  fseek(fp, 0, SEEK_END);
  long fsize = ftell(fp);
  fseek(fp, 0, SEEK_SET);
  char *buffer = malloc(fsize + 1);
  if (!buffer) {
    fclose(fp);
    fprintf(stderr, "Memory allocation failed for bitstring buffer\n");
    return NULL;
  }
  fread(buffer, 1, fsize, fp);
  fclose(fp);
  char *cleaned_bitstring = malloc(fsize + 1);
  if (!cleaned_bitstring) {
    free(buffer);
    fprintf(stderr, "Memory allocation failed for cleaned bitstring\n");
    return NULL;
  }
  int cleaned_len = 0;
  for (long k = 0; k < fsize; k++) {
    if (buffer[k] == '0' || buffer[k] == '1') {
      cleaned_bitstring[cleaned_len++] = buffer[k];
    }
  }
  cleaned_bitstring[cleaned_len] = '\0';
  free(buffer);
  if (cleaned_len == 0) {
    fprintf(stderr,
            "Error: Bitstring file '%s' contains no valid bits '0' or '1'.\n",
            filename);
    free(cleaned_bitstring);
    return NULL;
  }
  *length_out = cleaned_len;
  return cleaned_bitstring;
}

void extract_bits(const char *bitstring, int bitstring_len,
                  const unsigned int *positions, int num_positions,
                  char *extracted) {
  for (int i = 0; i < num_positions; i++) {
    unsigned int pos = positions[i];
    if (pos >= (unsigned int)bitstring_len) {
      fprintf(stderr, "Error: Position %u exceeds bitstring length %d\n", pos,
              bitstring_len);
      exit(1);
    }
    extracted[i] = bitstring[pos];
  }
  extracted[num_positions] = '\0';
}

void store_bitstring(const char *locker_filename,
                     const char *bitstring_filename,
                     const char *stored_hashes_filename, int num_positions) {
  int bitstring_len = 0;
  char *bitstring = read_single_bitstring(bitstring_filename, &bitstring_len);
  if (!bitstring)
    exit(1);
  printf("Read bitstring (length %d) from %s\n", bitstring_len,
         bitstring_filename);
  FILE *locker_fp = fopen(locker_filename, "rb");
  if (!locker_fp) {
    fprintf(stderr, "Error opening locker file %s: %s\n", locker_filename,
            strerror(errno));
    free(bitstring);
    exit(1);
  }
  fseek(locker_fp, 0, SEEK_END);
  long file_size = ftell(locker_fp);
  fseek(locker_fp, 0, SEEK_SET);
  int num_lockers = file_size / (sizeof(unsigned int) * num_positions);
  printf("Processing %d lockers from %s\n", num_lockers, locker_filename);
  FILE *hash_out_fp = fopen(stored_hashes_filename, "wb");
  if (!hash_out_fp) {
    fprintf(stderr, "Error opening output hash file %s: %s\n",
            stored_hashes_filename, strerror(errno));
    fclose(locker_fp);
    free(bitstring);
    exit(1);
  }
  unsigned int *positions_batch =
      malloc(IO_BATCH_SIZE * num_positions * sizeof(unsigned int));
  unsigned char *hashes_batch = malloc(IO_BATCH_SIZE * HASH_LENGTH);
  if (!positions_batch || !hashes_batch) {
    fprintf(stderr, "Memory allocation failed for store batches\n");
    exit(1);
  }

  EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
  EVP_MAC_CTX *master_ctx = EVP_MAC_CTX_new(mac);
  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0),
      OSSL_PARAM_construct_end()};
  if (!master_ctx ||
      EVP_MAC_init(master_ctx, hmac_key, sizeof(hmac_key) - 1, params) != 1) {
    fprintf(stderr, "Error initializing master HMAC context\n");
    exit(1);
  }

  printf("Processing lockers...\n");
  for (int locker_base = 0; locker_base < num_lockers;
       locker_base += IO_BATCH_SIZE) {
    int current_batch_size = (locker_base + IO_BATCH_SIZE > num_lockers)
                                 ? num_lockers - locker_base
                                 : IO_BATCH_SIZE;
    if (fread(positions_batch, sizeof(unsigned int),
              current_batch_size * num_positions,
              locker_fp) != (size_t)(current_batch_size * num_positions)) {
      fprintf(stderr, "Error reading positions batch\n");
      break;
    }
    for (int i = 0; i < current_batch_size; i++) {
      char extracted[num_positions + 1];
      unsigned char hash_buffer[HASH_LENGTH];
      int locker_index = locker_base + i;
      extract_bits(bitstring, bitstring_len,
                   &positions_batch[i * num_positions], num_positions,
                   extracted);
      compute_locker_hmac(master_ctx, extracted, locker_index, hash_buffer);
      xor_with_crypto_key(hash_buffer);
      memcpy(&hashes_batch[i * HASH_LENGTH], hash_buffer, HASH_LENGTH);
    }
    if (fwrite(hashes_batch, HASH_LENGTH, current_batch_size, hash_out_fp) !=
        (size_t)current_batch_size) {
      fprintf(stderr, "Error writing hash batch\n");
      break;
    }
    printf("\r  Processed %d lockers...", locker_base + current_batch_size);
    fflush(stdout);
  }

  EVP_MAC_CTX_free(master_ctx);
  EVP_MAC_free(mac);

  printf("\nFinished processing. Stored %d hashes in %s\n", num_lockers,
         stored_hashes_filename);
  free(positions_batch);
  free(hashes_batch);
  fclose(locker_fp);
  fclose(hash_out_fp);
  free(bitstring);
}

unsigned char *reproduce_key(const char *locker_filename,
                             const char *bitstring_filename,
                             const char *stored_hashes_filename,
                             int num_positions) {
  int bitstring_len = 0;
  char *bitstring = read_single_bitstring(bitstring_filename, &bitstring_len);
  if (!bitstring)
    return NULL;
  printf("Read input bitstring (length %d) from %s\n", bitstring_len,
         bitstring_filename);
  FILE *locker_fp = fopen(locker_filename, "rb");
  if (!locker_fp) {
    fprintf(stderr, "Error opening locker file %s: %s\n", locker_filename,
            strerror(errno));
    free(bitstring);
    return NULL;
  }
  FILE *stored_hash_fp = fopen(stored_hashes_filename, "rb");
  if (!stored_hash_fp) {
    fprintf(stderr, "Error opening stored hash file %s: %s\n",
            stored_hashes_filename, strerror(errno));
    fclose(locker_fp);
    free(bitstring);
    return NULL;
  }
  fseek(locker_fp, 0, SEEK_END);
  long locker_file_size = ftell(locker_fp);
  fseek(locker_fp, 0, SEEK_SET);
  int num_lockers = locker_file_size / (sizeof(unsigned int) * num_positions);
  fseek(stored_hash_fp, 0, SEEK_END);
  long hash_file_size = ftell(stored_hash_fp);
  fseek(stored_hash_fp, 0, SEEK_SET);
  int num_hashes = hash_file_size / HASH_LENGTH;
  int max_check = (num_lockers < num_hashes) ? num_lockers : num_hashes;
  printf("Verifying against %d lockers...\n", max_check);
  unsigned int *positions_batch =
      malloc(IO_BATCH_SIZE * num_positions * sizeof(unsigned int));
  unsigned char *stored_hashes_batch = malloc(IO_BATCH_SIZE * HASH_LENGTH);
  if (!positions_batch || !stored_hashes_batch) {
    fprintf(stderr, "Memory allocation failed for verify batches\n");
    exit(1);
  }

  EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
  EVP_MAC_CTX *master_ctx = EVP_MAC_CTX_new(mac);
  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0),
      OSSL_PARAM_construct_end()};
  if (!master_ctx ||
      EVP_MAC_init(master_ctx, hmac_key, sizeof(hmac_key) - 1, params) != 1) {
    fprintf(stderr, "Error initializing master HMAC context\n");
    exit(1);
  }

  int match_found = 0;
  int matched_locker_index = -1;
  unsigned char *reproduced_key = NULL;

  for (int locker_base = 0; locker_base < max_check && !match_found;
       locker_base += IO_BATCH_SIZE) {
    int current_batch_size = (locker_base + IO_BATCH_SIZE > max_check)
                                 ? max_check - locker_base
                                 : IO_BATCH_SIZE;
    fread(positions_batch, sizeof(unsigned int),
          current_batch_size * num_positions, locker_fp);
    fread(stored_hashes_batch, HASH_LENGTH, current_batch_size, stored_hash_fp);
    for (int i = 0; i < current_batch_size; i++) {
      char extracted[num_positions + 1];
      unsigned char computed_hash[HASH_LENGTH];
      unsigned char result[HASH_LENGTH];
      int locker_index = locker_base + i;
      extract_bits(bitstring, bitstring_len,
                   &positions_batch[i * num_positions], num_positions,
                   extracted);
      compute_locker_hmac(master_ctx, extracted, locker_index, computed_hash);
      for (int j = 0; j < HASH_LENGTH; j++) {
        result[j] = stored_hashes_batch[i * HASH_LENGTH + j] ^ computed_hash[j];
      }
      if (compare_hashes(result, cryptographic_key)) {
        match_found = 1;
        matched_locker_index = locker_index;
        reproduced_key = malloc(CRYPTO_KEY_LENGTH);
        if (reproduced_key) {
          memcpy(reproduced_key, result, CRYPTO_KEY_LENGTH);
        } else {
          fprintf(stderr, "\nMemory allocation for key failed!\n");
        }
        break;
      }
    }
    printf("\r  Verified %d lockers...", locker_base + current_batch_size);
    fflush(stdout);
  }
  printf("\n");

  EVP_MAC_CTX_free(master_ctx);
  EVP_MAC_free(mac);

  free(positions_batch);
  free(stored_hashes_batch);
  fclose(locker_fp);
  fclose(stored_hash_fp);
  free(bitstring);

  if (match_found) {
    printf("OK (Match found at locker %d)\n", matched_locker_index);
  }

  return reproduced_key;
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

  struct option long_options[] = {{"positions", required_argument, 0, 'p'},
                                  {"lockers", required_argument, 0, 'l'},
                                  {"maxbits", required_argument, 0, 'm'},
                                  {"lockerfile", required_argument, 0, 'f'},
                                  {"bitstring", required_argument, 0, 'b'},
                                  {"storedfile", required_argument, 0, 'o'},
                                  {"cryptokey", required_argument, 0, 'k'},
                                  {0, 0, 0, 0}};
  int opt;
  while ((opt = getopt_long(argc, argv, "p:l:m:f:b:o:k:", long_options,
                            NULL)) != -1) {
    switch (opt) {
    case 'p':
      num_positions = atoi(optarg);
      break;
    case 'l':
      num_lockers_gen = atoi(optarg);
      break;
    case 'm':
      max_bitstring_len = atoi(optarg);
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
      exit(1);
    }
  }
  if (optind < argc) {
    command = argv[optind];
  } else {
    fprintf(stderr,
            "Error: No command specified (generate, store, or verify)\n");
    exit(1);
  }
  if (!load_crypto_key(crypto_key_filename)) {
    printf("Cryptographic key file not found, generating new key...\n");
    generate_crypto_key(crypto_key_filename);
  } else {
    printf("Loaded cryptographic key from %s\n", crypto_key_filename);
  }
  if (strcmp(command, "generate") == 0) {
    generate_lockers(num_positions, num_lockers_gen, max_bitstring_len,
                     locker_filename);
  } else if (strcmp(command, "store") == 0) {
    if (!bitstring_filename) {
      fprintf(stderr, "Error: -b <bitstring_file> is required for 'store'\n");
      exit(1);
    }
    store_bitstring(locker_filename, bitstring_filename, stored_hashes_filename,
                    num_positions);
  } else if (strcmp(command, "verify") == 0) {
    if (!bitstring_filename) {
      fprintf(stderr, "Error: -b <bitstring_file> is required for 'verify'\n");
      exit(1);
    }

    unsigned char *reproduced_key =
        reproduce_key(locker_filename, bitstring_filename,
                      stored_hashes_filename, num_positions);

    if (reproduced_key != NULL) {
      printf("Reproduced Key: ");
      for (int i = 0; i < CRYPTO_KEY_LENGTH; i++) {
        printf("%02x", reproduced_key[i]);
      }
      printf("\n");
      free(reproduced_key);
      return 0;
    } else {
      printf("Verification failed - no match found\n");
      return 1;
    }
  } else {
    fprintf(stderr,
            "Invalid command: %s. Use 'generate', 'store', or 'verify'.\n",
            command);
    exit(1);
  }
  return 0;
}
