#include "Python.h"
#include "internal/seccask_encfs_mac.h"

/* Option 1: SHA-256 as MAC */
// #define SECCASK_MAC_FUNC seccask_sha256_fsblock
/* Option 2: GMAC as MAC (Same as GCM) */
#define SECCASK_MAC_FUNC seccask_gmac_one_block

/******************************************************************************
 *  Message Authentication Code (MAC) - Generation & Verification
 *****************************************************************************/

void seccask_write_mac(int gil_held, int fd, off_t start_offset, size_t count,
                       FILE *hash_file) {
  // uint8_t *g_sc_hash = (uint8_t *) malloc(GMAC_DIGEST_LENGTH);
  // uint8_t *g_sc_correct_hash = (uint8_t *) malloc(GMAC_DIGEST_LENGTH);
  // uint8_t *g_sc_block_buf = (uint8_t *) malloc(FS_BLOCK_SIZE);
  uint32_t start_block, end_block;
  ssize_t hash_n;
  get_fs_block_range(start_offset, count, &start_block, &end_block);
  if (g_seccask_encfs_is_debug_mode) {
    printf("ENCFSENCFS write hash start_block = %d, end_block = %d\n",
           start_block, end_block);
  }

  // errno = 0;
  lseek(fd, start_block * FS_BLOCK_SIZE, SEEK_SET);
  // if (errno) {
  //     printf("ERROR: lseek() failed with %s\n", strerror(errno));
  //     exit(1);
  // }
  fseek(hash_file, start_block * GMAC_DIGEST_LENGTH, SEEK_SET);

  for (uint32_t i = start_block; i <= end_block; i++) {
    if (i == end_block) {
      memset(g_sc_block_buf, 0, FS_BLOCK_SIZE);
    }

    if (gil_held) {
      Py_BEGIN_ALLOW_THREADS 
      hash_n = read(fd, g_sc_block_buf, FS_BLOCK_SIZE);
      Py_END_ALLOW_THREADS
    } else {
      hash_n = read(fd, g_sc_block_buf, FS_BLOCK_SIZE);
    }
    if (hash_n < 0) {
      printf("ERROR: read() failed with %s\n", strerror(errno));
      exit(1);
    }

    SECCASK_MAC_FUNC(g_sc_block_buf, g_sc_hash);

    if (gil_held) {
      Py_BEGIN_ALLOW_THREADS 
      fwrite(g_sc_hash, GMAC_DIGEST_LENGTH, 1, hash_file);
      Py_END_ALLOW_THREADS
    } else {
      fwrite(g_sc_hash, GMAC_DIGEST_LENGTH, 1, hash_file);
    }
  }
}

void seccask_write_mac_2(int gil_held, int fd, off_t start_offset, size_t len,
                         FILE *hash_file, const void *enc_buf) {
  uint32_t start_block, end_block, bytes_after_start_block,
      bytes_before_end_block;
  get_fs_block_range_ex(start_offset, len, &start_block, &end_block,
                        &bytes_after_start_block, &bytes_before_end_block);

  lseek(fd, start_block * FS_BLOCK_SIZE, SEEK_SET);
  fseek(hash_file, start_block * GMAC_DIGEST_LENGTH, SEEK_SET);

  if (g_seccask_encfs_is_debug_mode) {
    printf(
        "ENCFSENCFS read  hash fd_offset = %u, len = %u, start_block = %u, "
        "end_block = %u, bytes_after_start_block = %u, bytes_before_end_block "
        "= %u\n",
        start_offset, len, start_block, end_block, bytes_after_start_block,
        bytes_before_end_block);
  }

  uint32_t i = 0;
  ssize_t read_n = 0;
  if (bytes_after_start_block > 0) {
    Py_BEGIN_ALLOW_THREADS 
    read_n = read(fd, g_sc_block_buf, bytes_after_start_block);
    Py_END_ALLOW_THREADS 

    if (g_seccask_encfs_is_debug_mode) {
      printf("ENCFSENCFS read  hash first block read %d bytes\n", read_n);
    }

    ssize_t remain_bytes = FS_BLOCK_SIZE - bytes_after_start_block;
    i += remain_bytes;

    if (remain_bytes <= len) {
      memcpy(g_sc_block_buf + bytes_after_start_block, enc_buf, remain_bytes);
      if (g_seccask_encfs_is_debug_mode) {
        printf("ENCFSENCFS read  hash first block copy %d bytes to buf\n",
               remain_bytes);
      }
    } else {
      memcpy(g_sc_block_buf + bytes_after_start_block, enc_buf, len);
      i = len;
      if (g_seccask_encfs_is_debug_mode) {
        printf("ENCFSENCFS read  hash first block copy %d bytes to buf\n",
               len);
      }

      Py_BEGIN_ALLOW_THREADS 
      read_n = read(fd, g_sc_block_buf + FS_BLOCK_SIZE - remain_bytes, remain_bytes);
      Py_END_ALLOW_THREADS

      if (read_n < remain_bytes) {
        if (g_seccask_encfs_is_debug_mode) {
          printf("ENCFSENCFS read  hash first block fill %d bytes with 0\n",
                 remain_bytes - read_n);
        }
        memset(g_sc_block_buf + FS_BLOCK_SIZE - (remain_bytes - read_n), 0,
               remain_bytes - read_n);
      }
    }

    SECCASK_MAC_FUNC(g_sc_block_buf, g_sc_hash);

    if (gil_held) {
      Py_BEGIN_ALLOW_THREADS 
      fwrite(g_sc_hash, GMAC_DIGEST_LENGTH, 1, hash_file);
      Py_END_ALLOW_THREADS
    } else {
      fwrite(g_sc_hash, GMAC_DIGEST_LENGTH, 1, hash_file);
    }
  }

  for (; i < len; i += FS_BLOCK_SIZE) {
    if (i + FS_BLOCK_SIZE >= len &&
        bytes_before_end_block >
            0) {  // the last block requires further reading
      memcpy(g_sc_block_buf, enc_buf + i, len - i);
      if (g_seccask_encfs_is_debug_mode) {
        printf("ENCFSENCFS read  hash last block copy %d bytes to buf\n",
               len - i);
      }

      lseek(fd, (end_block + 1) * FS_BLOCK_SIZE - bytes_before_end_block,
            SEEK_SET);
      memset(g_sc_block_buf + FS_BLOCK_SIZE - bytes_before_end_block, 0,
             bytes_before_end_block);

      Py_BEGIN_ALLOW_THREADS 
      read_n = read(fd, 
                    g_sc_block_buf + FS_BLOCK_SIZE - bytes_before_end_block,
                    bytes_before_end_block);
      Py_END_ALLOW_THREADS

      if (g_seccask_encfs_is_debug_mode) {
        printf(
            "ENCFSENCFS read  hash last block read %u bytes to buf from offset "
            "%u\n",
            bytes_before_end_block,
            (end_block + 1) * FS_BLOCK_SIZE - bytes_before_end_block);
      }

      SECCASK_MAC_FUNC(g_sc_block_buf, g_sc_hash);
    } else {
      SECCASK_MAC_FUNC(enc_buf + i, g_sc_hash);
    }

    if (gil_held) {
      Py_BEGIN_ALLOW_THREADS 
      fwrite(g_sc_hash, GMAC_DIGEST_LENGTH, 1, hash_file);
      Py_END_ALLOW_THREADS
    } else {
      fwrite(g_sc_hash, GMAC_DIGEST_LENGTH, 1, hash_file);
    }
  }
}

void seccask_read_check_mac(int fd, off_t start_offset,
                            size_t len, FILE *hash_file) {
  // uint8_t *g_sc_hash = (uint8_t *) malloc(GMAC_DIGEST_LENGTH);
  // uint8_t *g_sc_correct_hash = (uint8_t *) malloc(GMAC_DIGEST_LENGTH);
  // uint8_t *g_sc_block_buf = (uint8_t *) malloc(FS_BLOCK_SIZE);
  uint32_t start_block, end_block;
  get_fs_block_range(start_offset, len, &start_block, &end_block);
  if (g_seccask_encfs_is_debug_mode) {
    printf("ENCFSENCFS read  hash start_block = %d, end_block = %d\n",
    start_block, end_block);
  }

  lseek(fd, start_block * FS_BLOCK_SIZE, SEEK_SET);
  fseek(hash_file, start_block * GMAC_DIGEST_LENGTH, SEEK_SET);

  for (uint32_t i = start_block; i <= end_block; i++) {
    if (i == end_block) {
        memset(g_sc_block_buf, 0, FS_BLOCK_SIZE);
    }

    Py_BEGIN_ALLOW_THREADS
    read(fd, g_sc_block_buf, FS_BLOCK_SIZE);
    Py_END_ALLOW_THREADS

    SECCASK_MAC_FUNC(g_sc_block_buf, g_sc_hash);

    Py_BEGIN_ALLOW_THREADS
    fread(g_sc_correct_hash, 1, GMAC_DIGEST_LENGTH, hash_file);
    Py_END_ALLOW_THREADS

    if (memcmp(g_sc_hash, g_sc_correct_hash, GMAC_DIGEST_LENGTH) != 0) {
      printf("UNAUTHORIZED MODIFICATION DETECTED !!! UNAUTHORIZED MODIFICATION DETECTED !!!\n");
      // printf("FILE: %s\n",entry->filename);
      printf("REASON: Hash of block %d is incorrect\n", i); exit(1);
    }
  }
}

void seccask_read_check_mac_2(int fd, off_t start_offset,
                              size_t len, FILE *hash_file, const void *buf) {
  uint32_t start_block, end_block, bytes_after_start_block,
      bytes_before_end_block;
  get_fs_block_range_ex(start_offset, len, &start_block, &end_block,
                        &bytes_after_start_block, &bytes_before_end_block);

  lseek(fd, start_block * FS_BLOCK_SIZE, SEEK_SET);
  fseek(hash_file, start_block * GMAC_DIGEST_LENGTH, SEEK_SET);

  if (g_seccask_encfs_is_debug_mode) {
    printf(
        "ENCFSENCFS read  hash fd_offset = %u, len = %u, start_block = %u, "
        "end_block = %u, bytes_after_start_block = %u, bytes_before_end_block "
        "= %u\n",
        start_offset, len, start_block, end_block, bytes_after_start_block,
        bytes_before_end_block);
  }

  uint32_t i = 0;
  ssize_t read_n = 0;
  if (bytes_after_start_block > 0) {
    Py_BEGIN_ALLOW_THREADS 
    read_n = read(fd, g_sc_block_buf, bytes_after_start_block);
    Py_END_ALLOW_THREADS 
    if (g_seccask_encfs_is_debug_mode) {
      printf("ENCFSENCFS read  hash first block read %d bytes\n", read_n);
    }

    ssize_t remain_bytes = FS_BLOCK_SIZE - bytes_after_start_block;
    i += remain_bytes;

    if (remain_bytes <= len) {
      memcpy(g_sc_block_buf + bytes_after_start_block, buf, remain_bytes);
      if (g_seccask_encfs_is_debug_mode) {
        printf("ENCFSENCFS read  hash first block copy %d bytes to buf\n",
               remain_bytes);
      }
    } else {
      memcpy(g_sc_block_buf + bytes_after_start_block, buf, len);
      i = len;
      if (g_seccask_encfs_is_debug_mode) {
        printf("ENCFSENCFS read  hash first block copy %d bytes to buf\n", len);
      }

      Py_BEGIN_ALLOW_THREADS 
      read_n =read(fd, 
                   g_sc_block_buf + FS_BLOCK_SIZE - remain_bytes, 
                   remain_bytes);
      Py_END_ALLOW_THREADS

      if (read_n < remain_bytes) {
        if (g_seccask_encfs_is_debug_mode) {
          printf("ENCFSENCFS read  hash first block fill %d bytes with 0\n",
                 remain_bytes - read_n);
        }
        memset(g_sc_block_buf + FS_BLOCK_SIZE - (remain_bytes - read_n), 0,
               remain_bytes - read_n);
      }
    }

    SECCASK_MAC_FUNC(g_sc_block_buf, g_sc_hash);

    Py_BEGIN_ALLOW_THREADS 
    fread(g_sc_correct_hash, 1, GMAC_DIGEST_LENGTH, hash_file);
    Py_END_ALLOW_THREADS

    if (memcmp(g_sc_hash, g_sc_correct_hash, GMAC_DIGEST_LENGTH) != 0) {
      printf(
          "UNAUTHORIZED MODIFICATION DETECTED !!! UNAUTHORIZED MODIFICATION "
          "DETECTED !!!\n");
      // printf("FILE: %s\n", entry->filename);
      printf("REASON: Hash of block %d is incorrect\n", start_block);
      exit(1);
    }
  }

  for (; i < len; i += FS_BLOCK_SIZE) {
    if (i + FS_BLOCK_SIZE >= len && bytes_before_end_block > 0) {
      // the last block requires further reading
      memcpy(g_sc_block_buf, buf + i, len - i);
      if (g_seccask_encfs_is_debug_mode) {
        printf("ENCFSENCFS read  hash last block copy %d bytes to buf\n",
               len - i);
      }

      lseek(fd, (end_block + 1) * FS_BLOCK_SIZE - bytes_before_end_block,
            SEEK_SET);
      memset(g_sc_block_buf + FS_BLOCK_SIZE - bytes_before_end_block, 0,
             bytes_before_end_block);

      Py_BEGIN_ALLOW_THREADS 
      read_n = read(fd, 
                    g_sc_block_buf + FS_BLOCK_SIZE - bytes_before_end_block,
                    bytes_before_end_block);
      Py_END_ALLOW_THREADS

      if (g_seccask_encfs_is_debug_mode) {
        printf(
            "ENCFSENCFS read  hash last block read %u bytes to buf from offset "
            "%u\n",
            bytes_before_end_block,
            (end_block + 1) * FS_BLOCK_SIZE - bytes_before_end_block);
      }

      SECCASK_MAC_FUNC(g_sc_block_buf, g_sc_hash);
    } else {
      SECCASK_MAC_FUNC(buf + i, g_sc_hash);
    }

    Py_BEGIN_ALLOW_THREADS 
    fread(g_sc_correct_hash, 1, GMAC_DIGEST_LENGTH, hash_file);
    Py_END_ALLOW_THREADS

    if (memcmp(g_sc_hash, g_sc_correct_hash, GMAC_DIGEST_LENGTH) != 0) {
      printf(
          "UNAUTHORIZED MODIFICATION DETECTED !!! UNAUTHORIZED MODIFICATION "
          "DETECTED !!!\n");
      // printf("FILE: %s\n", entry->filename);
      int hash_offset = ftell(hash_file);
      printf("REASON: Hash of block %d is incorrect\n",
             (hash_offset / GMAC_DIGEST_LENGTH) - 1);
      printf("Expected: ");
      for (int i = 0; i < GMAC_DIGEST_LENGTH; i++) {
        printf("%02x", g_sc_correct_hash[i]);
      }
      printf("\n");
      printf("Actual: ");
      for (int i = 0; i < GMAC_DIGEST_LENGTH; i++) {
        printf("%02x", g_sc_hash[i]);
      }
      printf("\n");
      exit(1);
    }
  }
}