/**
 * @file __seccask_encfs_aes.c
 * @brief AES-CTR / AES-GCM with OpenSSL C Library
 */

#include "internal/seccask_encfs_aes.h"


static int aes_init_counter(uint32_t fd_offset, aes_state_t *state,
                            uint32_t *in_block_offset) {
  uint32_t block = fd_offset / FS_BLOCK_SIZE;
  *in_block_offset = fd_offset % FS_BLOCK_SIZE;

  if (state->last_block == block) {
    if (g_seccask_encfs_is_debug_mode) {
      printf("aes_init_counter: fd_offset=%d, block=%d, offset=%d, cached\n",
             fd_offset, state->last_block, *in_block_offset);
    }
    return 0;
  }

  state->last_block = block;
  uint8_t *counter = state->counter;

  for (int i = 0; i < 4; i++) {
    *(counter + 14 - i) = ((state->last_block) >> (i * 8)) & 0xff;
  }

  for (int block_i = 1; block_i < (FS_BLOCK_SIZE / AES_BLOCK_SIZE); block_i++) {
    memcpy(counter + (block_i * AES_BLOCK_SIZE),
           counter + ((block_i - 1) * AES_BLOCK_SIZE), AES_BLOCK_SIZE);
    uint8_t *cur_pos;
    for (cur_pos = counter + (block_i * AES_BLOCK_SIZE) + 15;
         cur_pos >= counter; cur_pos--) {
      (*cur_pos) += 1;
      if (*cur_pos != 0) {
        break;
      }
    }
  }

  if (g_seccask_encfs_is_debug_mode) {
    printf("aes_init_counter: fd_offset=%d, block=%d, offset=%d, counter=",
           fd_offset, state->last_block, *in_block_offset);
    for (int i = 0; i < AES_BLOCK_SIZE * 2; i++) {
      printf(" %02x", counter[i]);
    }
    printf("\n");
    fflush(stdout);
  }

  return 1;
}

/**
 * @brief Increase counter to next fs block.
 * Since the counter is 128-bit, every fs block will be aligned to 4 KB /
 * 128-bit = 256 = 0x01_00.
 *
 * @param counter
 */
static void aes_increase_counter(uint8_t *counter) {
  /* Ver2 */
  for (int block_i = 0; block_i < (FS_BLOCK_SIZE / AES_BLOCK_SIZE); block_i++) {
    for (uint8_t *cur_pos = counter + (block_i * AES_BLOCK_SIZE) + 14;
         cur_pos >= counter + (block_i * AES_BLOCK_SIZE); cur_pos--) {
      (*cur_pos) += 1;
      if (*cur_pos != 0) {
        break;
      }
    }
  }
  /* Ver2 End */

  /* Ver1 */
  // for (cur_pos = counter + 14; cur_pos >= counter; cur_pos--) {
  //   (*cur_pos) += 1;
  //   if (*cur_pos != 0) {
  //     break;
  //   }
  // }

  // for (int block_i = 1; block_i < (FS_BLOCK_SIZE / AES_BLOCK_SIZE);
  // block_i++) {
  //   memcpy(counter + (block_i * AES_BLOCK_SIZE),
  //          counter + ((block_i - 1) * AES_BLOCK_SIZE),
  //          AES_BLOCK_SIZE);
  //   uint8_t* cur_pos;
  //   for (cur_pos = counter + (block_i * AES_BLOCK_SIZE) + 15; cur_pos >=
  //   counter; cur_pos--) {
  //     (*cur_pos) += 1;
  //     if (*cur_pos != 0) {
  //       break;
  //     }
  //   }
  // }
  /* Ver1 End */

  // if (g_seccask_encfs_is_debug_mode) {
  //   printf("aes_inc_counter: counter=");
  //   for (int i = 0; i < AES_BLOCK_SIZE * 2; i++) {
  //     printf(" %02x", counter[i]);
  //   }
  //   printf("\n");
  //   fflush(stdout);
  // }
}

void *aes_ctr_encdec(aes_state_t *state, int fd, const uint8_t *src,
                     uint32_t len, uint32_t read_bytes) {
  return aes_ctr_encdec_ex(state, fd, src, len, read_bytes, NULL);
  // return aes_ctr_encdec_bbb(state, fd, src, len, read_bytes);
}

/**
 * @brief Byte-by-byte encryption/decryption.
 *
 * @param state
 * @param fd
 * @param src
 * @param len
 * @param read_bytes
 * @return void*
 */
inline void *aes_ctr_encdec_bbb(aes_state_t *state, int fd, const uint8_t *src,
                                uint32_t len, uint32_t read_bytes) {
  int nb;
  uint32_t in_block_offset;
  uint32_t num_remain_bytes = len;

  uint8_t *dest = (uint8_t *)malloc(len);
  uint32_t current_fd_offset = lseek(fd, 0, SEEK_CUR) - read_bytes;

  uint8_t *curr_src = src;
  uint8_t *curr_dest = dest;

  if (g_seccask_encfs_is_debug_mode) {
    printf("aes_ctr_enc: offset=%d src=%p dest=%p len=%d\n", current_fd_offset,
           src, dest, len);
  }

  if (aes_init_counter(current_fd_offset, state, &in_block_offset) == 1) {
    EVP_EncryptUpdate(state->ctx, state->ecount_buf, &nb, state->counter,
                      FS_BLOCK_SIZE);
  } else {
    // skip ecount_buf generation since it is cached
  }

  while (num_remain_bytes--) {
    *(curr_dest++) = *(curr_src++) ^ (state->ecount_buf)[in_block_offset];
    in_block_offset = (in_block_offset + 1) % FS_BLOCK_SIZE;

    if (in_block_offset == 0) {
      aes_increase_counter(state->counter);
      EVP_EncryptUpdate(state->ctx, state->ecount_buf, &nb, state->counter,
                        FS_BLOCK_SIZE);
    }
  }

  return (void *)dest;
}

inline void *aes_ctr_encdec_ex(aes_state_t *state, int fd, const uint8_t *src,
                               uint32_t len, uint32_t read_bytes,
                               uint8_t *dst) {
  int nb;
  uint32_t in_block_offset;
  // uint32_t num_remain_bytes = len;

  uint8_t *dest;
  if (dst == NULL) {
    dest = (uint8_t *)malloc(len);
  } else {
    dest = dst;
  }
  uint32_t current_fd_offset = lseek(fd, 0, SEEK_CUR) - read_bytes;

  uint8_t *curr_src = src;
  uint8_t *curr_dest = dest;

  if (aes_init_counter(current_fd_offset, state, &in_block_offset) == 1) {
    // fflush(stdout);
    EVP_EncryptUpdate(state->ctx, state->ecount_buf, &nb, state->counter,
                      FS_BLOCK_SIZE);
    // if (nb != FS_BLOCK_SIZE) {
    //   _sc_aes_handle_errors();
    // }
  } else {
    // skip ecount_buf generation since it is cached
  }

  if (g_seccask_encfs_is_debug_mode) {
    printf("aes_ctr_enc: offset=%d src=%p dest=%p len=%u, ibo=%u\n",
           current_fd_offset, src, dest, len, in_block_offset);
  }

  // if (g_seccask_encfs_is_debug_mode) {
  //   printf("aes_ctr_enc: new cipher block=");
  //   for (int i = 0; i < FS_BLOCK_SIZE; i++) {
  //     printf(" %02x", (state->ecount_buf)[i]);
  //   }
  //   printf("\n");
  //   fflush(stdout);
  // }

  uint32_t bytes_to_next_aligned =
      (FS_BLOCK_SIZE - in_block_offset) % FS_BLOCK_SIZE;
  if (bytes_to_next_aligned > len) {
    bytes_to_next_aligned = len;
  }
  uint32_t num_blocks = (len - bytes_to_next_aligned) / FS_BLOCK_SIZE;
  uint32_t num_offset = (len - bytes_to_next_aligned) % FS_BLOCK_SIZE;

  if (g_seccask_encfs_is_debug_mode) {
    printf("aes_ctr_enc: p1=%u bytes, p2=%u blocks, p3=%u bytes\n",
           bytes_to_next_aligned, num_blocks, num_offset);
  }

  for (int i = 0; i < bytes_to_next_aligned; i++) {
    *(curr_dest++) = *(curr_src++) ^ state->ecount_buf[in_block_offset + i];
  }
  in_block_offset = (in_block_offset + bytes_to_next_aligned) % FS_BLOCK_SIZE;

  // if (g_seccask_encfs_is_debug_mode) {
  //   printf("aes_ctr_enc: p2=%u blocks\n", num_blocks);
  // }

  if (bytes_to_next_aligned > 0 && (num_blocks > 0 || num_offset > 0)) {
    state->last_block += 1;
    aes_increase_counter(state->counter);
    EVP_EncryptUpdate(state->ctx, state->ecount_buf, &nb, state->counter,
                      FS_BLOCK_SIZE);
  }
  while (num_blocks > 0) {
    uint8_t *restrict s = curr_src;
    uint8_t *restrict d = curr_dest;
    uint8_t *restrict e = state->ecount_buf;
    // uint8_t * s = curr_src;
    // uint8_t * d = curr_dest;
    // uint8_t * e = state->ecount_buf;

    for (int i = 0; i < FS_BLOCK_SIZE; i++) {
      d[i] = s[i] ^ e[i];
    }

    curr_src += FS_BLOCK_SIZE;
    curr_dest += FS_BLOCK_SIZE;

    num_blocks--;
    state->last_block += 1;
    aes_increase_counter(state->counter);
    EVP_EncryptUpdate(state->ctx, state->ecount_buf, &nb, state->counter,
                      FS_BLOCK_SIZE);
  }

  // if (g_seccask_encfs_is_debug_mode) {
  //   printf("aes_ctr_enc: p3=%u bytes\n", num_offset);
  // }

  if (num_offset > 0) {
    for (int i = 0; i < num_offset; i++) {
      *(curr_dest++) = *(curr_src++) ^ (state->ecount_buf)[in_block_offset + i];
      // in_block_offset = (in_block_offset + 1) % FS_BLOCK_SIZE;

      // if (in_block_offset == 0) {
      //   aes_increase_counter(state->counter);

      //   EVP_EncryptUpdate(state->ctx, state->ecount_buf, &nb, state->counter,
      //   FS_BLOCK_SIZE);

      // if (g_seccask_encfs_is_debug_mode) {
      //   printf("aes_ctr_enc: new cipher block=");
      //   for (int i = 0; i < FS_BLOCK_SIZE; i++) {
      //     printf(" %02x", (state->ecount_buf)[i]);
      //   }
      //   printf("\n");
      //   fflush(stdout);
      // }
      // }
    }
  }

  if (g_seccask_encfs_is_debug_mode) {
    printf("aes_ctr_enc: end\n");
  }

  return (void *)dest;
}

void *aes_gcm_encdec(aes_state_t *state, int fd, const uint8_t *src,
                     uint32_t len, uint32_t read_bytes, uint8_t *mac) {
  return NULL;
}
