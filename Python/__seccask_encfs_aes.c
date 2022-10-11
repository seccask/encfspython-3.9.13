/**
 * @file __seccask_encfs_aes.c
 * @brief AES-CTR with OpenSSL C Library
 */

#include "internal/seccask_encfs_aes.h"


static uint16_t aes_init_counter(uint32_t fd_offset, uint8_t *counter) {
  uint32_t block = fd_offset / AES_BLOCK_SIZE;
  uint16_t offset = fd_offset % AES_BLOCK_SIZE;
  
  for (int i = 0; i < 4; i++) {
    *(counter + 15 - i) = (block >> (i * 8)) & 0xff;
  }

  if (g_seccask_encfs_is_debug_mode) {
    printf("aes_init_counter: fd_offset=%d, block=%d, offset=%d, counter=", fd_offset, block, offset);
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
      printf(" %02x", counter[i]);
    }
    printf("\n");
    fflush(stdout);
  }

  return offset;
}

static void aes_increase_counter(uint8_t *counter) {
  uint8_t* cur_pos;

  for (cur_pos = counter + 15; cur_pos >= counter; cur_pos--) {
    (*cur_pos)++;
    if (*cur_pos != 0) {
      break;
    }
  }

  // if (g_seccask_encfs_is_debug_mode) {
  //   printf("aes_init_counter: counter=");
  //   for (int i = 0; i < AES_BLOCK_SIZE; i++) {
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

  in_block_offset = aes_init_counter(current_fd_offset, state->counter);

  EVP_EncryptUpdate(state->ctx, state->ecount_buf, &nb, state->counter, AES_BLOCK_SIZE);

  // if (g_seccask_encfs_is_debug_mode) {
  //   printf("aes_ctr_enc: new cipher block=");
  //   for (int i = 0; i < AES_BLOCK_SIZE; i++) {
  //     printf(" %02x", (state->ecount_buf)[i]);
  //   }
  //   printf("\n");
  //   fflush(stdout);
  // }

  for (; num_remain_bytes > 0; num_remain_bytes--) {
    *(curr_dest++) = *(curr_src++) ^ (state->ecount_buf)[in_block_offset];
    in_block_offset = (in_block_offset + 1) % AES_BLOCK_SIZE;

    if (in_block_offset == 0) {
      aes_increase_counter(state->counter);

      EVP_EncryptUpdate(state->ctx, state->ecount_buf, &nb, state->counter, AES_BLOCK_SIZE);

      // if (g_seccask_encfs_is_debug_mode) {
      //   printf("aes_ctr_enc: new cipher block=");
      //   for (int i = 0; i < AES_BLOCK_SIZE; i++) {
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