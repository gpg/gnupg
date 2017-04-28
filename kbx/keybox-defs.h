/* keybox-defs.h - internal Keybox definitions
 *	Copyright (C) 2001, 2004 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef KEYBOX_DEFS_H
#define KEYBOX_DEFS_H 1

#ifdef GPG_ERR_SOURCE_DEFAULT
# if GPG_ERR_SOURCE_DEFAULT != GPG_ERR_SOURCE_KEYBOX
#  error GPG_ERR_SOURCE_DEFAULT already defined
# endif
#else
# define GPG_ERR_SOURCE_DEFAULT  GPG_ERR_SOURCE_KEYBOX
#endif
#include <gpg-error.h>
#define map_assuan_err(a) \
        map_assuan_err_with_source (GPG_ERR_SOURCE_DEFAULT, (a))

#include <sys/types.h> /* off_t */

/* We include the type definitions from jnlib instead of defining our
   owns here.  This will not allow us build KBX in a standalone way
   but there is currently no need for it anyway.  Same goes for
   stringhelp.h which for example provides a replacement for stpcpy -
   fixme: Better use the LIBOBJ mechnism. */
#include "../common/types.h"
#include "../common/stringhelp.h"
#include "../common/dotlock.h"
#include "../common/logging.h"

#include "keybox.h"


typedef struct keyboxblob *KEYBOXBLOB;


typedef struct keybox_name *KB_NAME;
struct keybox_name
{
  /* Link to the next resources, so that we can walk all
     resources.  */
  KB_NAME next;

  /* True if this is a keybox with secret keys.  */
  int secret;

  /* A table with all the handles accessing this resources.
     HANDLE_TABLE_SIZE gives the allocated length of this table unused
     entrues are set to NULL.  HANDLE_TABLE may be NULL. */
  KEYBOX_HANDLE *handle_table;
  size_t handle_table_size;

  /* The lock handle or NULL it not yet initialized.  */
  dotlock_t lockhd;

  /* Not yet used.  */
  int is_locked;

  /* Not yet used.  */
  int did_full_scan;

  /* The name of the resource file. */
  char fname[1];
};


struct keybox_found_s
{
  KEYBOXBLOB blob;
  size_t pk_no;
  size_t uid_no;
};

struct keybox_handle {
  KB_NAME kb;
  int secret;             /* this is for a secret keybox */
  FILE *fp;
  int eof;
  int error;
  int ephemeral;
  int for_openpgp;        /* Used by gpg.  */
  struct keybox_found_s found;
  struct keybox_found_s saved_found;
  struct {
    char *name;
    char *pattern;
  } word_match;
};


/* Openpgp helper structures. */
struct _keybox_openpgp_key_info
{
  struct _keybox_openpgp_key_info *next;
  int algo;
  unsigned char keyid[8];
  int fprlen;  /* Either 16 or 20 */
  unsigned char fpr[20];
};

struct _keybox_openpgp_uid_info
{
  struct _keybox_openpgp_uid_info *next;
  size_t off;
  size_t len;
};

struct _keybox_openpgp_info
{
  int is_secret;        /* True if this is a secret key. */
  unsigned int nsubkeys;/* Total number of subkeys.  */
  unsigned int nuids;   /* Total number of user IDs in the keyblock. */
  unsigned int nsigs;   /* Total number of signatures in the keyblock. */

  /* Note, we use 2 structs here to better cope with the most common
     use of having one primary and one subkey - this allows us to
     statically allocate this structure and only malloc stuff for more
     than one subkey. */
  struct _keybox_openpgp_key_info primary;
  struct _keybox_openpgp_key_info subkeys;
  struct _keybox_openpgp_uid_info uids;
};
typedef struct _keybox_openpgp_info *keybox_openpgp_info_t;


/* Don't know whether this is needed: */
/*  static struct { */
/*    int dry_run; */
/*    int quiet; */
/*    int verbose; */
/*    int preserve_permissions; */
/*  } keybox_opt; */

/*-- keybox-init.c --*/
void _keybox_close_file (KEYBOX_HANDLE hd);


/*-- keybox-blob.c --*/
gpg_error_t _keybox_create_openpgp_blob (KEYBOXBLOB *r_blob,
                                         keybox_openpgp_info_t info,
                                         const unsigned char *image,
                                         size_t imagelen,
                                         int as_ephemeral);
#ifdef KEYBOX_WITH_X509
int _keybox_create_x509_blob (KEYBOXBLOB *r_blob, ksba_cert_t cert,
                              unsigned char *sha1_digest, int as_ephemeral);
#endif /*KEYBOX_WITH_X509*/

int  _keybox_new_blob (KEYBOXBLOB *r_blob,
                       unsigned char *image, size_t imagelen,
                       off_t off);
void _keybox_release_blob (KEYBOXBLOB blob);
const unsigned char *_keybox_get_blob_image (KEYBOXBLOB blob, size_t *n);
off_t _keybox_get_blob_fileoffset (KEYBOXBLOB blob);
void _keybox_update_header_blob (KEYBOXBLOB blob, int for_openpgp);

/*-- keybox-openpgp.c --*/
gpg_error_t _keybox_parse_openpgp (const unsigned char *image, size_t imagelen,
                                   size_t *nparsed,
                                   keybox_openpgp_info_t info);
void _keybox_destroy_openpgp_info (keybox_openpgp_info_t info);


/*-- keybox-file.c --*/
int _keybox_read_blob (KEYBOXBLOB *r_blob, FILE *fp, int *skipped_deleted);
int _keybox_write_blob (KEYBOXBLOB blob, FILE *fp);

/*-- keybox-search.c --*/
gpg_err_code_t _keybox_get_flag_location (const unsigned char *buffer,
                                          size_t length,
                                          int what,
                                          size_t *flag_off, size_t *flag_size);

static inline int
blob_get_type (KEYBOXBLOB blob)
{
  const unsigned char *buffer;
  size_t length;

  buffer = _keybox_get_blob_image (blob, &length);
  if (length < 32)
    return -1; /* blob too short */

  return buffer[4];
}


/*-- keybox-dump.c --*/
int _keybox_dump_blob (KEYBOXBLOB blob, FILE *fp);
int _keybox_dump_file (const char *filename, int stats_only, FILE *outfp);
int _keybox_dump_find_dups (const char *filename, int print_them, FILE *outfp);
int _keybox_dump_cut_records (const char *filename, unsigned long from,
                              unsigned long to, FILE *outfp);


/*-- keybox-util.c --*/
void *_keybox_malloc (size_t n);
void *_keybox_calloc (size_t n, size_t m);
void *_keybox_realloc (void *p, size_t n);
void  _keybox_free (void *p);

#define xtrymalloc(a)    _keybox_malloc ((a))
#define xtrycalloc(a,b)  _keybox_calloc ((a),(b))
#define xtryrealloc(a,b) _keybox_realloc((a),(b))
#define xfree(a)         _keybox_free ((a))


#define DIM(v) (sizeof(v)/sizeof((v)[0]))
#define DIMof(type,member)   DIM(((type *)0)->member)
#ifndef STR
#  define STR(v) #v
#endif
#define STR2(v) STR(v)

/*
  a couple of handy macros
*/

#define return_if_fail(expr) do {                        \
    if (!(expr)) {                                       \
        fprintf (stderr, "%s:%d: assertion '%s' failed\n", \
                 __FILE__, __LINE__, #expr );            \
        return;	                                         \
    } } while (0)
#define return_null_if_fail(expr) do {                   \
    if (!(expr)) {                                       \
        fprintf (stderr, "%s:%d: assertion '%s' failed\n", \
                 __FILE__, __LINE__, #expr );            \
        return NULL;	                                 \
    } } while (0)
#define return_val_if_fail(expr,val) do {                \
    if (!(expr)) {                                       \
        fprintf (stderr, "%s:%d: assertion '%s' failed\n", \
                 __FILE__, __LINE__, #expr );            \
        return (val);	                                 \
    } } while (0)
#define never_reached() do {                                   \
        fprintf (stderr, "%s:%d: oops; should never get here\n", \
                 __FILE__, __LINE__ );                         \
    } while (0)


/* some macros to replace ctype ones and avoid locale problems */
#define digitp(p)   (*(p) >= '0' && *(p) <= '9')
#define hexdigitp(a) (digitp (a)                     \
                      || (*(a) >= 'A' && *(a) <= 'F')  \
                      || (*(a) >= 'a' && *(a) <= 'f'))
/* the atoi macros assume that the buffer has only valid digits */
#define atoi_1(p)   (*(p) - '0' )
#define atoi_2(p)   ((atoi_1(p) * 10) + atoi_1((p)+1))
#define atoi_4(p)   ((atoi_2(p) * 100) + atoi_2((p)+2))
#define xtoi_1(p)   (*(p) <= '9'? (*(p)- '0'): \
                     *(p) <= 'F'? (*(p)-'A'+10):(*(p)-'a'+10))
#define xtoi_2(p)   ((xtoi_1(p) * 16) + xtoi_1((p)+1))


#endif /*KEYBOX_DEFS_H*/
