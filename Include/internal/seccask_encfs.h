#ifndef SecCask_ENCFS_H
#define SecCask_ENCFS_H

#include <glib.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#define NUM_DGB_PRINT_BYTES 32

// Filesystem block size: 4 KB
#define FS_BLOCK_SIZE 4096

typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
// typedef unsigned long long uint64_t;


__attribute__((weak)) extern unsigned char *g_component_key;  // 256-bit key
extern GHashTable *g_seccask_fd_hashtable;
extern int g_seccask_encfs_is_debug_mode;

extern char *g_seccask_cipher_mode;


/******************************************************************************
 *  Utility functions
 *****************************************************************************/

/**
 * @brief Check if the path is in the specific directory
 * 
 * @param path the path 
 * @param directory the directory
 * @return 1 if path is in the directory, 0 otherwise
 */
static inline int is_in_dir(const char *path, const char *directory) {
  return strncmp(path, directory, strlen(directory)) == 0;
}

static inline int ends_with(const char *str, const char *suffix) {
  size_t str_len = strlen(str);
  size_t suffix_len = strlen(suffix);

  return (str_len >= suffix_len) && (!memcmp(str + str_len - suffix_len, suffix, suffix_len));
}

/**
 * @brief Compute SHA256 hash of the input data
 * 
 * @param in 
 * @param in_len 
 * @param out 
 */
static inline void seccask_sha256(uint8_t *in, uint32_t in_len, uint8_t *out) {
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, in, in_len);
  SHA256_Final(out, &sha256);
}

static inline void get_fs_block_range(uint32_t fd_offset, size_t len, uint32_t *start_block, uint32_t *end_block) {
  *start_block = fd_offset / FS_BLOCK_SIZE;
  *end_block = (fd_offset + len - 1) / FS_BLOCK_SIZE;
}

/******************************************************************************
 *  AES block cipher
 *****************************************************************************/

typedef struct {
  EVP_CIPHER_CTX *ctx;
  uint32_t last_block;;
  uint8_t counter[FS_BLOCK_SIZE];
  uint8_t ecount_buf[FS_BLOCK_SIZE];
} aes_state_t;

static inline void _sc_aes_handle_errors()
{
    ERR_print_errors_fp(stderr);
    exit(1);
}

/******************************************************************************
 *  Chacha20 stream cipher
 *****************************************************************************/

typedef struct chacha_state {
  /** Initial state for the next iteration **/
  uint32_t h[16];
  size_t nonceSize; /** in bytes **/

  /** How many bytes at the beginning of the key stream
   * have already been used.
   */
  unsigned usedKeyStream;

  uint8_t keyStream[sizeof(uint32_t) * 16];
} chacha_state_t;

int chacha20_init(chacha_state_t **pState, const uint8_t *key, size_t keySize,
                  const uint8_t *nonce, size_t nonceSize);
int chacha20_destroy(chacha_state_t *state);
int chacha20_encrypt(chacha_state_t *state, const uint8_t in[], uint8_t out[],
                     size_t len);
int chacha20_seek(chacha_state_t *state, unsigned long block_high,
                  unsigned long block_low, unsigned offset);

/******************************************************************************
 *  fd entry
 *****************************************************************************/

typedef union cipher_state { 
    chacha_state_t;
    aes_state_t;
} cipher_state_t;

typedef struct fd_entry {
  char *filename;
  cipher_state_t* state;
  int is_binary;
} fd_entry_t;


static inline fd_entry_t *fd_entry_new(const char *filename, const char *component_key,
                                int is_binary) {
  fd_entry_t *fd_entry = (fd_entry_t *)malloc(sizeof(fd_entry_t));
  fd_entry->filename = NULL;
  fd_entry->state = NULL;
  fd_entry->is_binary = is_binary;

  char *a_name = (char *)malloc(strlen(filename) + 1);
  strcpy(a_name, filename);
  fd_entry->filename = a_name;

  if (g_component_key != NULL) {
    if (strcmp(g_seccask_cipher_mode, "Chacha20") == 0) {
      // fd_entry->state = (cipher_state_t *)malloc(sizeof(chacha_state_t));

      chacha20_init((chacha_state_t**) &(fd_entry->state), g_component_key, 32, g_component_key, 8);

    } else if (strcmp(g_seccask_cipher_mode, "AES-256-CTR") == 0) {
      fd_entry->state = (cipher_state_t *)malloc(sizeof(aes_state_t));
      aes_state_t *state = (aes_state_t *)fd_entry->state;

      // Init encrypted counter buf
      memset(state->ecount_buf, 0, FS_BLOCK_SIZE);
      state->last_block = UINT_MAX;
      // Init counter as 0
      memset(state->counter + 8, 0, 8);
      // DEBUG OPTION: set nonce as g_component_key
      memcpy(state->counter, g_component_key, 8);

      if (!(state->ctx = EVP_CIPHER_CTX_new())) _sc_aes_handle_errors();
      if (1 != EVP_EncryptInit_ex(state->ctx, EVP_aes_256_ecb(), NULL, g_component_key, NULL)) _sc_aes_handle_errors();

    } else {
      printf("ERROR: Unknown cipher mode %s\n", g_seccask_cipher_mode);
      exit(1);
    }
  } 

  return fd_entry;
}

static inline void fd_entry_free(fd_entry_t *fd_entry) {
  free(fd_entry->filename);
  if (fd_entry->state != NULL) {
    if (strcmp(g_seccask_cipher_mode, "Chacha20") == 0) {
      chacha20_destroy(fd_entry->state);

    } else if (strcmp(g_seccask_cipher_mode, "AES-256-CTR") == 0) {
      EVP_CIPHER_CTX_free(((aes_state_t *)fd_entry->state)->ctx);
      free(fd_entry->state);

    } else {
      printf("ERROR: Unknown cipher mode %s\n", g_seccask_cipher_mode);
      exit(1);
    }

    fd_entry->state = NULL;
  }
  // Do not free the entry since it's handled by g_free()
  // free(fd_entry);
}

#endif