/* keybox-defs.h - interal Keybox defintions
 *	Copyright (C) 2001 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifndef KEYBOX_DEFS_H
#define KEYBOX_DEFS_H 1

#include <sys/types.h> /* off_t */
#include "keybox.h"

#ifdef GPG_ERR_SOURCE_DEFAULT
#error GPG_ERR_SOURCE_DEFAULT already defined
#endif
#define GPG_ERR_SOURCE_DEFAULT  GPG_ERR_SOURCE_KEYBOX
#include <gpg-error.h>


#ifndef HAVE_BYTE_TYPEDEF
typedef unsigned char byte; /* fixme */
#endif
#ifndef HAVE_U16_TYPEDEF
typedef unsigned short u16; /* fixme */
#endif
#ifndef HAVE_U32_TYPEDEF
typedef unsigned int u32; /* fixme */
#endif

enum {
  BLOBTYPE_EMPTY = 0,
  BLOBTYPE_HEADER = 1,
  BLOBTYPE_PGP = 2,
  BLOBTYPE_X509 = 3
};


typedef struct keyboxblob *KEYBOXBLOB;


typedef struct keybox_name *KB_NAME;
typedef struct keybox_name const * CONST_KB_NAME;
struct keybox_name {
  struct keybox_name *next;
  int secret;
  /*DOTLOCK lockhd;*/
  int is_locked;
  int did_full_scan;
  char fname[1];
};



struct keybox_handle {
  CONST_KB_NAME kb;
  int secret;             /* this is for a secret keybox */
  FILE *fp;
  int eof;
  int error;
  int ephemeral;  
  struct {
    KEYBOXBLOB blob;
    off_t offset;
    size_t pk_no;
    size_t uid_no;
    unsigned int n_packets; /*used for delete and update*/
  } found;
  struct {
    char *name;
    char *pattern;
  } word_match;
};


/* Don't know whether this is needed: */
/*  static struct { */
/*    const char *homedir; */
/*    int dry_run; */
/*    int quiet; */
/*    int verbose; */
/*    int preserve_permissions; */
/*  } keybox_opt; */


/*-- keybox-blob.c --*/
#ifdef KEYBOX_WITH_OPENPGP
  /* fixme */
#endif /*KEYBOX_WITH_OPENPGP*/
#ifdef KEYBOX_WITH_X509
int _keybox_create_x509_blob (KEYBOXBLOB *r_blob, KsbaCert cert,
                              unsigned char *sha1_digest, int as_ephemeral);
#endif /*KEYBOX_WITH_X509*/

int  _keybox_new_blob (KEYBOXBLOB *r_blob, char *image, size_t imagelen,
                       off_t off);
void _keybox_release_blob (KEYBOXBLOB blob);
const char *_keybox_get_blob_image (KEYBOXBLOB blob, size_t *n);
off_t _keybox_get_blob_fileoffset (KEYBOXBLOB blob);

/*-- keybox-file.c --*/
int _keybox_read_blob (KEYBOXBLOB *r_blob, FILE *fp);
int _keybox_write_blob (KEYBOXBLOB blob, FILE *fp);

/*-- keybox-dump.c --*/
int _keybox_dump_blob (KEYBOXBLOB blob, FILE *fp);
int _keybox_dump_file (const char *filename, FILE *outfp);


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
  #define STR(v) #v
#endif
#define STR2(v) STR(v)

/*
  a couple of handy macros 
*/

#define return_if_fail(expr) do {                        \
    if (!(expr)) {                                       \
        fprintf (stderr, "%s:%d: assertion `%s' failed\n", \
                 __FILE__, __LINE__, #expr );            \
        return;	                                         \
    } } while (0)
#define return_null_if_fail(expr) do {                   \
    if (!(expr)) {                                       \
        fprintf (stderr, "%s:%d: assertion `%s' failed\n", \
                 __FILE__, __LINE__, #expr );            \
        return NULL;	                                 \
    } } while (0)
#define return_val_if_fail(expr,val) do {                \
    if (!(expr)) {                                       \
        fprintf (stderr, "%s:%d: assertion `%s' failed\n", \
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


