/**
 * @file __seccask_encfs_aes.c
 * @brief AES-CTR with OpenSSL C Library
 */

#include "internal/seccask_encfs_aes.h"


static int aes_init_counter(uint32_t fd_offset, aes_state_t *state, uint32_t *in_block_offset) {
  uint32_t block = fd_offset / FS_BLOCK_SIZE;
  *in_block_offset = fd_offset % FS_BLOCK_SIZE;

  if (state->last_block == block) {
    if  (g_seccask_encfs_is_debug_mode) {
      printf("aes_init_counter: fd_offset=%d, block=%d, offset=%d, cached\n", fd_offset, state->last_block, *in_block_offset);
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
           counter + ((block_i - 1) * AES_BLOCK_SIZE), 
           AES_BLOCK_SIZE);
    uint8_t* cur_pos;
    for (cur_pos = counter + (block_i * AES_BLOCK_SIZE) + 15; cur_pos >= counter; cur_pos--) {
      (*cur_pos) += 1;
      if (*cur_pos != 0) {
        break;
      }
    }
  }

  if (g_seccask_encfs_is_debug_mode) {
    printf("aes_init_counter: fd_offset=%d, block=%d, offset=%d, counter=", fd_offset, state->last_block, *in_block_offset);
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
 * Since the counter is 128-bit, every fs block will be aligned to 4 KB / 128-bit = 256 = 0x01_00.
 * 
 * @param counter 
 */
static void aes_increase_counter(uint8_t *counter) {
  uint8_t* cur_pos;

  for (cur_pos = counter + 14; cur_pos >= counter; cur_pos--) {
    (*cur_pos) += 1;
    if (*cur_pos != 0) {
      break;
    }
  }

  for (int block_i = 1; block_i < (FS_BLOCK_SIZE / AES_BLOCK_SIZE); block_i++) {
    memcpy(counter + (block_i * AES_BLOCK_SIZE), 
           counter + ((block_i - 1) * AES_BLOCK_SIZE), 
           AES_BLOCK_SIZE);
    uint8_t* cur_pos;
    for (cur_pos = counter + (block_i * AES_BLOCK_SIZE) + 15; cur_pos >= counter; cur_pos--) {
      (*cur_pos) += 1;
      if (*cur_pos != 0) {
        break;
      }
    }
  }

  // if (g_seccask_encfs_is_debug_mode) {
  //   printf("aes_inc_counter: counter=");
  //   for (int i = 0; i < AES_BLOCK_SIZE * 2; i++) {
  //     printf(" %02x", counter[i]);
  //   }
  //   printf("\n");
  //   fflush(stdout);
  // }
}

void *aes_ctr_encdec(aes_state_t *state, int fd, const uint8_t *src, uint32_t len, uint32_t read_bytes) {
  int nb;
  uint32_t in_block_offset;
  uint32_t num_remain_bytes = len;

  uint8_t *dest = (uint8_t *)malloc(len);
  uint32_t current_fd_offset = lseek(fd, 0, SEEK_CUR) - read_bytes;

  uint8_t *curr_src = src;
  uint8_t *curr_dest = dest;
  
  if (g_seccask_encfs_is_debug_mode) {
    printf("aes_ctr_enc: offset=%d src=%p dest=%p len=%d\n", current_fd_offset, src, dest, len);
  }

  if (aes_init_counter(current_fd_offset, state, &in_block_offset) == 1) {
    fflush(stdout);
    EVP_EncryptUpdate(state->ctx, state->ecount_buf, &nb, state->counter, FS_BLOCK_SIZE);
    if (nb != FS_BLOCK_SIZE) {
      _sc_aes_handle_errors();
    }
  } else {
    // skip ecount_buf generation since it is cached
  }


  // if (g_seccask_encfs_is_debug_mode) {
  //   printf("aes_ctr_enc: new cipher block=");
  //   for (int i = 0; i < FS_BLOCK_SIZE; i++) {
  //     printf(" %02x", (state->ecount_buf)[i]);
  //   }
  //   printf("\n");
  //   fflush(stdout);
  // }

  while (num_remain_bytes--) {
    *(curr_dest++) = *(curr_src++) ^ (state->ecount_buf)[in_block_offset];
    in_block_offset = (in_block_offset + 1) % FS_BLOCK_SIZE;

    if (in_block_offset == 0) {
      aes_increase_counter(state->counter);

      EVP_EncryptUpdate(state->ctx, state->ecount_buf, &nb, state->counter, FS_BLOCK_SIZE);

      // if (g_seccask_encfs_is_debug_mode) {
      //   printf("aes_ctr_enc: new cipher block=");
      //   for (int i = 0; i < FS_BLOCK_SIZE; i++) {
      //     printf(" %02x", (state->ecount_buf)[i]);
      //   }
      //   printf("\n");
      //   fflush(stdout);
      // }
    }
  }

  // if (g_seccask_encfs_is_debug_mode) {
  //   printf("aes_ctr_enc: end\n");
  // }

  return (void *)dest;
}