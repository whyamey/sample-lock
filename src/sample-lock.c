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

#define DEFAULT_SAMPLES 60
#define DEFAULT_POSITIONS 250000
#define HASH_LENGTH 32

const unsigned char hmac_key[] = "thisisasecretkey1234567890abcdef";

void generate_samples(int num_samples, int num_positions, const char *filename) {
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

    unsigned int *samples = (unsigned int *)malloc(sizeof(unsigned int) * num_samples);
    if (samples == NULL) {
        fprintf(stderr, "Memory allocation failed for samples\n");
        fclose(fp);
        exit(1);
    }

    for (int i = 0; i < num_positions; i++) {
        for (int j = 0; j < num_samples; j++) {
            if (RAND_bytes((unsigned char *)&samples[j], sizeof(samples[j])) != 1) {
                fprintf(stderr, "Error generating random number\n");
                free(samples);
                fclose(fp);
                exit(1);
            }
        }
        if (fwrite(samples, sizeof(unsigned int), num_samples, fp) != (size_t)num_samples) {
             fprintf(stderr, "Error writing samples to file %s: %s\n", filename, strerror(errno));
             free(samples);
             fclose(fp);
             exit(1);
        }
    }

    free(samples);
    fclose(fp);
}

char *read_single_bitstring(const char *filename, int *length_out) {
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        fprintf(stderr, "Error opening bitstring file %s: %s\n", filename, strerror(errno));
        return NULL;
    }

    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    read = getline(&line, &len, fp);
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
    ssize_t original_len_signed = 0;

    original_len_signed = read; 
    while (original_len_signed > 0 && (line[original_len_signed - 1] == '\n' || line[original_len_signed - 1] == ',' || line[original_len_signed - 1] == '\r' || isspace(line[original_len_signed - 1]))) {
        original_len_signed--;
    }


    for (ssize_t k = 0; k < original_len_signed; k++) {
        if (line[k] == '0' || line[k] == '1') {
            cleaned_bitstring[cleaned_len++] = line[k];
        } else if (line[k] == ',') {
            continue;
        } else if (isspace(line[k])) {
            continue;
        }
         else {
            fprintf(stderr, "Invalid character '%c' at position %zd in bitstring file %s.\n", line[k], k, filename);
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


void extract_bits(const char *bitstring, int bitstring_len, const unsigned int *raw_samples, int num_samples, char *extracted) {
    if (bitstring_len <= 0) {
        fprintf(stderr, "Error: Invalid bitstring_len (%d) passed to extract_bits.\n", bitstring_len);
        exit(1);
    }
    for (int i = 0; i < num_samples; i++) {
        int index = raw_samples[i] % bitstring_len;
        extracted[i] = bitstring[index];
    }
    extracted[num_samples] = '\0';
}

void compute_hmac(const char *input, unsigned char *output) {
    unsigned int len = HASH_LENGTH;
    HMAC(EVP_sha256(), hmac_key, sizeof(hmac_key)-1, (const unsigned char*)input, strlen(input), output, &len);
    if (len != HASH_LENGTH) {
         fprintf(stderr, "HMAC output length unexpected (%u != %d)\n", len, HASH_LENGTH);
         exit(1);
    }
}

int compare_hashes(const unsigned char *hash1, const unsigned char *hash2) {
    return CRYPTO_memcmp(hash1, hash2, HASH_LENGTH) == 0;
}

unsigned int *load_all_samples(const char *filename, int num_samples, int *num_positions_out) {
    FILE *sample_fp = fopen(filename, "rb");
    if (sample_fp == NULL) {
        fprintf(stderr, "Error opening sample file %s: %s\n", filename, strerror(errno));
        return NULL;
    }

    fseek(sample_fp, 0, SEEK_END);
    long file_size = ftell(sample_fp);
    fseek(sample_fp, 0, SEEK_SET);

    long expected_sample_set_size = (long)sizeof(unsigned int) * num_samples;
    if (file_size <= 0 || expected_sample_set_size <= 0 || file_size % expected_sample_set_size != 0) { 
        fprintf(stderr, "Error: Sample file '%s' size (%ld) is not a positive multiple of expected sample set size (%ld bytes based on %d samples).\n",
                filename, file_size, expected_sample_set_size, num_samples);
        fclose(sample_fp);
        return NULL;
    }
    *num_positions_out = file_size / expected_sample_set_size;

    unsigned int *all_samples = malloc(file_size);
    if (!all_samples) {
        fprintf(stderr, "Memory allocation failed for loading all samples (%ld bytes)\n", file_size);
        fclose(sample_fp);
        return NULL;
    }

    size_t total_samples_to_read = (size_t)(*num_positions_out) * num_samples;
    size_t samples_read = fread(all_samples, sizeof(unsigned int), total_samples_to_read, sample_fp);

    if (samples_read != total_samples_to_read) {
        fprintf(stderr, "Error reading samples from %s. Expected %zu, got %zu.\n", filename, total_samples_to_read, samples_read);
        free(all_samples);
        fclose(sample_fp);
        return NULL;
    }

    fclose(sample_fp);
    return all_samples;
}


int main(int argc, char *argv[]) {
    int num_samples = DEFAULT_SAMPLES;
    int num_positions_gen = DEFAULT_POSITIONS; 
    char *sample_filename = "samples.bin";
    char *bitstring_filename = NULL;
    char *stored_hashes_filename = "stored_hashes.bin";
    char *command = NULL;
    int generate_mode_pos_set = 0;

    int opt;
    struct option long_options[] = {
        {"samples",     required_argument, 0, 's'},
        {"positions",   required_argument, 0, 'p'},
        {"samplefile",  required_argument, 0, 'f'},
        {"bitstring",   required_argument, 0, 'b'},
        {"storedfile",  required_argument, 0, 'o'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "s:p:f:b:o:", long_options, NULL)) != -1) {
        switch (opt) {
            case 's':
                num_samples = atoi(optarg);
                if (num_samples <= 0) {
                     fprintf(stderr, "Error: Number of samples must be positive.\n");
                     exit(1);
                }
                break;
            case 'p':
                num_positions_gen = atoi(optarg);
                 if (num_positions_gen <= 0) {
                     fprintf(stderr, "Error: Number of positions must be positive.\n");
                     exit(1);
                }
                generate_mode_pos_set = 1;
                break;
            case 'f':
                sample_filename = optarg;
                break;
            case 'b':
                bitstring_filename = optarg;
                break;
            case 'o':
                stored_hashes_filename = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s [command] [options]\n", argv[0]);
                fprintf(stderr, "Commands: sample, store, verify\n");
                fprintf(stderr, "Options:\n");
                fprintf(stderr, "  -s, --samples      Number of samples per position (default: %d)\n", DEFAULT_SAMPLES);
                fprintf(stderr, "  -p, --positions    Number of positions (ONLY for sample generation, default: %d)\n", DEFAULT_POSITIONS);
                fprintf(stderr, "  -f, --samplefile   Filename for samples (default: samples.bin)\n");
                fprintf(stderr, "  -b, --bitstring    Bitstring file (single/comma-sep for verify/store)\n");
                fprintf(stderr, "  -o, --storedfile   Filename for storing/loading HMACs (default: stored_hashes.bin)\n");
                exit(1);
        }
    }


    if (optind < argc) {
        command = argv[optind];
    } else {
        fprintf(stderr, "Error: No command specified (sample, store, or verify)\n");
        exit(1);
    }

    if (strcmp(command, "sample") == 0) {
         if (!generate_mode_pos_set) {
             num_positions_gen = DEFAULT_POSITIONS;
         }
        generate_samples(num_samples, num_positions_gen, sample_filename);
        printf("Generated %d raw samples per position for %d positions into %s\n", num_samples, num_positions_gen, sample_filename);

    } else if (strcmp(command, "store") == 0) {
        if (bitstring_filename == NULL) {
            fprintf(stderr, "Error: -b <input_bitstring_file> is required for 'store'\n");
            exit(1);
        }
        if (generate_mode_pos_set) {
             fprintf(stderr, "Warning: -p/--positions option ignored for 'store'. Number of positions is determined by sample file size.\n");
        }

        int num_positions = 0;
        unsigned int *all_raw_samples = load_all_samples(sample_filename, num_samples, &num_positions);
        if (!all_raw_samples) {
             exit(1);
        }
        printf("Loaded %d sample sets (positions) from %s.\n", num_positions, sample_filename);

        FILE *input_bs_fp = fopen(bitstring_filename, "r"); 
        if (!input_bs_fp) {
             fprintf(stderr, "Error opening bitstring input file %s: %s\n", bitstring_filename, strerror(errno));
             free(all_raw_samples);
             exit(1);
        }

        FILE *hash_out_fp = fopen(stored_hashes_filename, "wb");
        if (!hash_out_fp) {
             fprintf(stderr, "Error opening output hash file %s: %s\n", stored_hashes_filename, strerror(errno));
             fclose(input_bs_fp);
             free(all_raw_samples);
             exit(1);
        }

        char *line = NULL;
        size_t line_buf_len = 0;
        ssize_t line_len_read;
        int processed_lines = 0;
        unsigned long total_hashes_written = 0;

        char *extracted = malloc(num_samples + 1);
        unsigned char *current_block_hashes = malloc((size_t)num_positions * HASH_LENGTH);

        if (!extracted || !current_block_hashes) {
             fprintf(stderr, "Memory allocation failed for store buffers\n");
             if (extracted) free(extracted);
             if (current_block_hashes) free(current_block_hashes);
             fclose(input_bs_fp);
             fclose(hash_out_fp);
             free(all_raw_samples);
             if(line) free(line);
             exit(1);
        }

        printf("Processing bitstrings from %s...\n", bitstring_filename);
        while ((line_len_read = getline(&line, &line_buf_len, input_bs_fp)) != -1) {

            char *cleaned_bitstring = NULL;
            int current_bitstring_len = 0;
            int valid_line = 0; 

            ssize_t current_len_signed = line_len_read; 
            while (current_len_signed > 0 && (line[current_len_signed - 1] == '\n' || line[current_len_signed - 1] == ',' || line[current_len_signed - 1] == '\r' || isspace(line[current_len_signed - 1]))) {
                current_len_signed--;
            }

            if (current_len_signed <= 0) {
                if (line_len_read > 0) {
                     fprintf(stderr, "Warning: Skipping line %d in %s - empty after cleanup.\n", processed_lines + 1, bitstring_filename);
                }
                continue; 
            }

            cleaned_bitstring = malloc((size_t)current_len_signed + 1);
            if (!cleaned_bitstring) {
                 fprintf(stderr, "Error: Memory allocation failed for cleaning line %d\n", processed_lines + 1);
                 continue; 
            }

            int cleaned_idx = 0;
            int format_error = 0;
            for (ssize_t k = 0; k < current_len_signed; k++) { 
                 if (line[k] == '0' || line[k] == '1') {
                    cleaned_bitstring[cleaned_idx++] = line[k];
                 } else if (line[k] == ',') {
                    continue; 
                 } else if (isspace(line[k])) {
                     continue; 
                 } else {
                    fprintf(stderr, "Warning: Skipping invalid line %d in %s (invalid char '%c' at %zd): %.*s\n",
                             processed_lines + 1, bitstring_filename, line[k], k, (int)current_len_signed, line);
                    format_error = 1;
                    break;
                 }
            }
            cleaned_bitstring[cleaned_idx] = '\0'; 

            if (format_error) {
                free(cleaned_bitstring);
                continue; 
            }

            if (cleaned_idx == 0) {
                 fprintf(stderr, "Warning: Skipping line %d in %s - resulted in empty bitstring after cleaning.\n", processed_lines + 1, bitstring_filename);
                 free(cleaned_bitstring);
                 continue; 
            }

            current_bitstring_len = cleaned_idx;
            valid_line = 1;


            if (valid_line) {
                for (int i = 0; i < num_positions; i++) {
                    const unsigned int *current_samples = all_raw_samples + ((size_t)i * num_samples);
                    extract_bits(cleaned_bitstring, current_bitstring_len, current_samples, num_samples, extracted);
                    compute_hmac(extracted, current_block_hashes + ((size_t)i * HASH_LENGTH));
                }

                size_t written = fwrite(current_block_hashes, HASH_LENGTH, num_positions, hash_out_fp);
                if (written != (size_t)num_positions) {
                     fprintf(stderr, "Error writing hashes for line %d to %s: %s\n", processed_lines + 1, stored_hashes_filename, strerror(errno));
                     free(cleaned_bitstring); 
                     free(extracted);
                     free(current_block_hashes);
                     fclose(input_bs_fp);
                     fclose(hash_out_fp);
                     free(all_raw_samples);
                     free(line);
                     exit(1);
                }
                total_hashes_written += written;
                processed_lines++;
                if (processed_lines > 0 && processed_lines % 1000 == 0) { 
                     printf("  Processed %d lines...\n", processed_lines);
                }
            }

            free(cleaned_bitstring); 
        }


        printf("Finished processing. Stored %lu HMACs (%d blocks of %d) in %s\n",
               total_hashes_written, processed_lines, num_positions, stored_hashes_filename);

        free(extracted);
        free(current_block_hashes);
        fclose(input_bs_fp);
        fclose(hash_out_fp);
        free(all_raw_samples);
        if(line) free(line); 


    } else if (strcmp(command, "verify") == 0) {
        if (bitstring_filename == NULL) {
            fprintf(stderr, "Error: -b <input_bitstring_file> is required for 'verify'\n");
            exit(1);
        }
         if (generate_mode_pos_set) {
             fprintf(stderr, "Warning: -p/--positions option ignored for 'verify'. Number of positions is determined by sample file size.\n");
         }

        int input_bitstring_len = 0;
        char *input_bitstring = read_single_bitstring(bitstring_filename, &input_bitstring_len);
        if (!input_bitstring) {
            exit(1);
        }
        printf("Read and cleaned input bitstring (length %d) from %s\n", input_bitstring_len, bitstring_filename);


        int num_positions = 0;
        unsigned int *all_raw_samples = load_all_samples(sample_filename, num_samples, &num_positions);
        if (!all_raw_samples) {
             free(input_bitstring);
             exit(1);
        }
         printf("Loaded %d sample sets (positions) from %s.\n", num_positions, sample_filename);


        unsigned char *generated_hashes = malloc((size_t)num_positions * HASH_LENGTH);
        char *extracted = malloc(num_samples + 1);
        if (!generated_hashes || !extracted) {
             fprintf(stderr, "Memory allocation failed for verify buffers\n");
             if(generated_hashes) free(generated_hashes);
             if(extracted) free(extracted);
             free(all_raw_samples);
             free(input_bitstring);
             exit(1);
        }

        for (int i = 0; i < num_positions; i++) {
            const unsigned int *current_samples = all_raw_samples + ((size_t)i * num_samples);
            extract_bits(input_bitstring, input_bitstring_len, current_samples, num_samples, extracted);
            compute_hmac(extracted, generated_hashes + ((size_t)i * HASH_LENGTH));
        }
        free(extracted);
        free(all_raw_samples); 
        free(input_bitstring); 


        FILE *stored_hash_fp = fopen(stored_hashes_filename, "rb");
        if (!stored_hash_fp) {
            fprintf(stderr, "Error opening stored hash file %s: %s\n", stored_hashes_filename, strerror(errno));
            free(generated_hashes);
            exit(1);
        }

        fseek(stored_hash_fp, 0, SEEK_END);
        long stored_file_size = ftell(stored_hash_fp);
        fseek(stored_hash_fp, 0, SEEK_SET);

        long single_block_size = (long)num_positions * HASH_LENGTH;
        if (stored_file_size <= 0 || single_block_size <= 0 || stored_file_size % single_block_size != 0) {
             fprintf(stderr, "Error: Stored hash file %s size (%ld) is not a positive multiple of expected block size (%ld).\n",
                     stored_hashes_filename, stored_file_size, single_block_size);
             fclose(stored_hash_fp);
             free(generated_hashes);
             exit(1);
        }
        int num_stored_blocks = stored_file_size / single_block_size;
        printf("Found %d hash blocks in %s.\n", num_stored_blocks, stored_hashes_filename);


        unsigned char *stored_block = malloc(single_block_size);
        if (!stored_block) {
            fprintf(stderr, "Memory allocation failed for stored hash block buffer\n");
            fclose(stored_hash_fp);
            free(generated_hashes);
            exit(1);
        }

        int match_found = 0;
        for (int j = 0; j < num_stored_blocks; j++) {
             size_t read_count = fread(stored_block, HASH_LENGTH, num_positions, stored_hash_fp);
             if (read_count != (size_t)num_positions) {
                 fprintf(stderr, "Error reading hash block %d from %s (read %zu, expected %d)", j, stored_hashes_filename, read_count, num_positions);
                  if (feof(stored_hash_fp)) {
                     fprintf(stderr, " (End of file reached prematurely)\n");
                  } else if (ferror(stored_hash_fp)) {
                      fprintf(stderr, " (File read error: %s)\n", strerror(errno));
                  } else {
                      fprintf(stderr, "\n");
                  }
                 match_found = 0;
                 break; 
             }

            for (int i = 0; i < num_positions; i++) {
                 if (compare_hashes(generated_hashes + ((size_t)i * HASH_LENGTH), stored_block + ((size_t)i * HASH_LENGTH))) {
                    match_found = 1;
                    printf("OK (Match found at position %d in stored block %d)\n", i, j);
                    goto end_verify; 
                 }
            }
        }

    end_verify:
        fclose(stored_hash_fp);
        free(stored_block);
        free(generated_hashes);

        if (!match_found) {
            printf("Verification failed\n");
            return 1; 
        }

    } else {
        fprintf(stderr, "Invalid command: %s. Use 'sample', 'store', or 'verify'.\n", command);
        exit(1);
    }

    return 0;
}
