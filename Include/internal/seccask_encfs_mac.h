#ifndef SecCask_ENCFS_MAC_H
#define SecCask_ENCFS_MAC_H

#include "internal/seccask_encfs.h"


void seccask_write_mac(int gil_held, int fd, off_t start_offset, size_t len, FILE *hash_file);
void seccask_write_mac_2(int gil_held, int fd, off_t start_offset, size_t len, FILE *hash_file, const void *enc_buf);

/* Assume GIL held by current thread */
void seccask_read_check_mac(int fd, off_t start_offset, size_t len, FILE *hash_file);
/* Assume GIL held by current thread */
void seccask_read_check_mac_2(int fd, off_t start_offset, size_t len, FILE *hash_file, const void *buf);

#endif
