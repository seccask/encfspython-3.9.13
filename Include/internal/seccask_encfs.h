#ifndef SecCask_ENCFS_H
#define SecCask_ENCFS_H

#include <glib.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#include "internal/flo_shani.h"

#define NUM_DGB_PRINT_BYTES 32

// Filesystem block size (in bytes)
#define FS_BLOCK_SIZE 4096
#define GMAC_DIGEST_LENGTH 16

typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
// typedef unsigned long long uint64_t;


extern __attribute__((weak)) unsigned char *g_component_key;  // 256-bit key
extern GHashTable *g_seccask_fd_hashtable;
extern int g_seccask_encfs_is_debug_mode;

extern char *g_seccask_cipher_mode;

extern uint8_t g_sc_hash[GMAC_DIGEST_LENGTH];
extern uint8_t g_sc_correct_hash[GMAC_DIGEST_LENGTH];
extern uint8_t g_sc_block_buf[FS_BLOCK_SIZE];

extern uint8_t *g_sc_enc_buf;
extern size_t g_sc_enc_buf_size;


#define SECCASK_PROFILE_IO
#undef SECCASK_PROFILE_IO

#ifdef SECCASK_PROFILE_IO

extern int g_sc_is_io_time_enabled;
extern __attribute__((weak)) double g_sc_time_spent_on_io;


#include <dlfcn.h>
/******************************************************************************
 *  Linux timespec helpers
 *****************************************************************************/
#define NSEC_PER_SEC 1000000000

/** \fn struct timespec timespec_normalise(struct timespec ts)
 *  \brief Normalises a timespec structure.
 *
 * Returns a normalised version of a timespec structure, according to the
 * following rules:
 *
 * 1) If tv_nsec is >=1,000,000,00 or <=-1,000,000,000, flatten the surplus
 *    nanoseconds into the tv_sec field.
 *
 * 2) If tv_nsec is negative, decrement tv_sec and roll tv_nsec up to represent
 *    the same value attainable by ADDING nanoseconds to tv_sec.
*/
static inline struct timespec timespec_normalise(struct timespec ts)
{
	while(ts.tv_nsec >= NSEC_PER_SEC)
	{
		++(ts.tv_sec);
		ts.tv_nsec -= NSEC_PER_SEC;
	}
	
	while(ts.tv_nsec <= -NSEC_PER_SEC)
	{
		--(ts.tv_sec);
		ts.tv_nsec += NSEC_PER_SEC;
	}
	
	if(ts.tv_nsec < 0)
	{
		/* Negative nanoseconds isn't valid according to POSIX.
		 * Decrement tv_sec and roll tv_nsec over.
		*/
		
		--(ts.tv_sec);
		ts.tv_nsec = (NSEC_PER_SEC + ts.tv_nsec);
	}
	
	return ts;
}


/** \fn double timespec_to_double(struct timespec ts)
 *  \brief Converts a timespec to a fractional number of seconds.
*/
static inline double timespec_to_double(struct timespec ts)
{
	return ((double)(ts.tv_sec) + ((double)(ts.tv_nsec) / NSEC_PER_SEC));
}

/** \fn struct timespec timespec_sub(struct timespec ts1, struct timespec ts2)
 *  \brief Returns the result of subtracting ts2 from ts1.
*/
static inline struct timespec timespec_sub(struct timespec ts1, struct timespec ts2)
{
	/* Normalise inputs to prevent tv_nsec rollover if whole-second values
	 * are packed in it.
	*/
	ts1 = timespec_normalise(ts1);
	ts2 = timespec_normalise(ts2);
	
	ts1.tv_sec  -= ts2.tv_sec;
	ts1.tv_nsec -= ts2.tv_nsec;
	
	return timespec_normalise(ts1);
}

/******************************************************************************
 *  Linux timespec helpers END
 *****************************************************************************/


  // printf("%s\n", __func__);
#define SECCASK_PROFILE_IO_INIT \
  struct timespec time1, time2; \
  clock_gettime(CLOCK_REALTIME, &time1); 

#define SECCASK_PROFILE_IO_RECORD \
  if (g_sc_is_io_time_enabled) { \
    clock_gettime(CLOCK_REALTIME, &time2); \
    double time_spent = timespec_to_double(timespec_sub(time2, time1)); \
    g_sc_time_spent_on_io += time_spent; \
  }

#else
#define SECCASK_PROFILE_IO_INIT ;
#define SECCASK_PROFILE_IO_RECORD ;
#endif

/******************************************************************************
 *  AES cipher
 *****************************************************************************/

typedef struct {
  EVP_CIPHER_CTX *ctx;
  uint32_t last_block;
  uint8_t counter[FS_BLOCK_SIZE];
  uint8_t ecount_buf[FS_BLOCK_SIZE];
} aes_state_t;

static inline void _sc_aes_handle_errors()
{
    ERR_print_errors_fp(stderr);
    exit(1);
}


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
 * @brief Compute SHA256 hash of the input data (Intel SHA Extension)
 * 
 * @param in 
 * @param in_len 
 * @param out 
 */
static inline void seccask_sha256_shani(uint8_t *in, uint32_t in_len, uint8_t *out) {
  sha256_update_shani(in, in_len, out);
}

/**
 * @brief Compute SHA256 hash of the input data (Hardware implementation)
 * 
 * @param in 
 * @param in_len 
 * @param out 
 */
static inline void seccask_sha256_avx2(uint8_t *in, uint32_t in_len, uint8_t *out) {
  EVP_MD_CTX *mdctx;

	if((mdctx = EVP_MD_CTX_new()) == NULL)
		_sc_aes_handle_errors();

	if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
		_sc_aes_handle_errors();

	if(1 != EVP_DigestUpdate(mdctx, in, in_len))
		_sc_aes_handle_errors();

	// if((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
	// 	_sc_aes_handle_errors();

	if(1 != EVP_DigestFinal_ex(mdctx, out, NULL))
		_sc_aes_handle_errors();

	EVP_MD_CTX_free(mdctx);

  // SHA256_Init(&sha256);
  // SHA256_Update(&sha256, in, in_len);
  // SHA256_Final(out, &sha256);
}

/**
 * @brief Compute SHA256 hash of the input data (Software implementation)
 * 
 * @param in 
 * @param in_len 
 * @param out 
 */
static inline void seccask_sha256_sw(uint8_t *in, uint32_t in_len, uint8_t *out) {
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, in, in_len);
  SHA256_Final(out, &sha256);
}

static inline void seccask_sha256(uint8_t *in, uint32_t in_len, uint8_t *out) {
  // seccask_sha256_shani(in, in_len, out);
  seccask_sha256_avx2(in, in_len, out);
}

static inline void seccask_sha256_fsblock(uint8_t *in, uint8_t *out) {
  // seccask_sha256_shani(in, FS_BLOCK_SIZE, out);
  seccask_sha256_avx2(in, FS_BLOCK_SIZE, out);
}

static inline void get_fs_block_range(uint32_t fd_offset, size_t len, uint32_t *start_block, uint32_t *end_block) {
  *start_block = fd_offset / FS_BLOCK_SIZE;
  *end_block = (fd_offset + len - 1) / FS_BLOCK_SIZE;
}

static inline void get_fs_block_range_ex(uint32_t fd_offset, size_t len, uint32_t *start_block, uint32_t *end_block, uint32_t *bytes_after_start_block, uint32_t *bytes_before_end_block) {
  *start_block = fd_offset / FS_BLOCK_SIZE;
  *end_block = (fd_offset + len - 1) / FS_BLOCK_SIZE;
  *bytes_after_start_block = fd_offset % FS_BLOCK_SIZE;
  *bytes_before_end_block = (*end_block + 1) * FS_BLOCK_SIZE - (fd_offset + len);
}

static uint8_t g_stub_mem[FS_BLOCK_SIZE] = {0};

static inline void seccask_gmac_one_block(uint8_t *in, uint8_t *out) {
  EVP_CIPHER_CTX *ctx;
  int outlen;

  if(!(ctx = EVP_CIPHER_CTX_new()))
    _sc_aes_handle_errors();

    /* Set cipher type and mode */
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        printf("EVP_EncryptInit_ex: failed\n");
        _sc_aes_handle_errors();
    }

    /* Initialise key and IV */
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, g_component_key, g_component_key)) {
        printf("EVP_EncryptInit_ex: set key failed\n");
        _sc_aes_handle_errors();
    }

    /* Zero or more calls to specify any AAD */
    if (!EVP_EncryptUpdate(ctx, NULL, &outlen, in, FS_BLOCK_SIZE)) {
        printf("EVP_EncryptUpdate: setting AAD failed\n");
        _sc_aes_handle_errors();
    }

    /* Finalise: note get no output for GMAC */
    if (!EVP_EncryptFinal_ex(ctx, g_stub_mem, &outlen)) {
        printf("EVP_EncryptFinal_ex: failed\n");
        _sc_aes_handle_errors();
    }

    /* Get tag */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, out)) {
        printf("EVP_CIPHER_CTX_ctrl: failed\n");
        _sc_aes_handle_errors();
    }

    EVP_CIPHER_CTX_free(ctx);

    // if (g_seccask_encfs_is_debug_mode) {
    //   printf("seccask_gmac_one_block: GMAC=");
    //   for (int i = 0; i < 16; i++) {
    //     printf("%02x", out[i]);
    //   }
    //   printf("\n");
    // }
}

/******************************************************************************
 *  Chacha20 cipher
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
  FILE *hash_file;
} fd_entry_t;


static inline fd_entry_t *fd_entry_new(const char *filename, const char *component_key,
                                int is_binary) {
  fd_entry_t *fd_entry = (fd_entry_t *)malloc(sizeof(fd_entry_t));
  fd_entry->filename = NULL;
  fd_entry->state = NULL;
  fd_entry->hash_file = NULL;
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
    // fd_entry->state = NULL;
  }
  if (fd_entry->hash_file != NULL) {
    fclose(fd_entry->hash_file);
    // fd_entry->hash_file = NULL;
  }
  // Do not free the entry since it's handled by g_free()
  // free(fd_entry);
}

#endif