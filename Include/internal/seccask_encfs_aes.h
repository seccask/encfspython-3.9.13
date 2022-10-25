#ifndef SecCask_ENCFS_AES_H
#define SecCask_ENCFS_AES_H

#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "internal/seccask_encfs.h"

void *aes_ctr_encdec(aes_state_t *state, int fd, const uint8_t *src, uint32_t len, uint32_t read_bytes);
void *aes_ctr_encdec_bbb(aes_state_t *state, int fd, const uint8_t *src, uint32_t len, uint32_t read_bytes);
void *aes_ctr_encdec_ex(aes_state_t *state, int fd, const uint8_t *src, uint32_t len, uint32_t read_bytes, uint8_t *dst);

#endif
