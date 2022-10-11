#ifndef SecCask_ENCFS_CHACHA_H
#define SecCask_ENCFS_CHACHA_H

#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "internal/seccask_encfs.h"

// inline fd_entry_t *fd_entry_new(const char *filename, const char *component_key,
//                                 int is_binary) {
//   fd_entry_t *fd_entry = (fd_entry_t *)malloc(sizeof(fd_entry_t));
//   fd_entry->filename = NULL;
//   fd_entry->ctx = NULL;
//   fd_entry->is_binary = is_binary;

//   char *a_name = (char *)malloc(strlen(filename) + 1);
//   strcpy(a_name, filename);
//   fd_entry->filename = a_name;

//   if (g_component_key != NULL) {
//     chacha20_init(&(fd_entry->ctx), g_component_key, 32, g_component_key, 8);
//   }

//   return fd_entry;
// }

// inline void fd_entry_free(fd_entry_t *fd_entry) {
//   free(fd_entry->filename);
//   if (fd_entry->ctx != NULL) {
//     chacha20_destroy(fd_entry->ctx);
//   }
//   // Do not free the entry since it's handled by g_free()
//   // free(fd_entry);
// }

inline void *chacha_encdec(chacha_state_t *state, const uint8_t *src,
                           uint32_t len) {
  uint8_t *dest = (uint8_t *)malloc(len);
  if (g_seccask_encfs_is_debug_mode) {
    printf("chacha_encdec: srf=%p dest=%p len=%d\n", src, dest, len);
  }
  chacha20_encrypt(state, src, dest, len);
  return (void *)dest;
}

inline void chacha_goto(chacha_state_t *state, int fd, int read_bytes) {
  uint32_t position = lseek(fd, 0, SEEK_CUR) - read_bytes;

  uint32_t block = position / 64;
  uint32_t offset = position % 64;
  chacha20_seek(state, block >> 32, block & 0xffffffff, offset);
  if (g_seccask_encfs_is_debug_mode) {
    printf("chacha_goto: position=%u block=%u offset=%u\n", position, block, offset);
  }
}
#endif
