/* filter.h
 * Copyright (C) 1998, 1999, 2000, 2001, 2003,
 *               2005 Free Software Foundation, Inc.
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
#ifndef G10_FILTER_H
#define G10_FILTER_H

#include "../common/types.h"
#include "dek.h"

typedef struct {
    gcry_md_hd_t md;      /* catch all */
    gcry_md_hd_t md2;     /* if we want to calculate an alternate hash */
    size_t maxbuf_size;
} md_filter_context_t;

typedef struct {
    int  refcount;          /* Initialized to 1.  */

    /* these fields may be initialized */
    int what;		    /* what kind of armor headers to write */
    int only_keyblocks;     /* skip all headers but ".... key block" */
    int dearmor_mode;       /* dearmor all kind of stuff.  */
    const char *hdrlines;   /* write these headerlines */

    /* these fields must be initialized to zero */
    int no_openpgp_data;    /* output flag: "No valid OpenPGP data found" */

    /* the following fields must be initialized to zero */
    int inp_checked;	    /* set if the input has been checked */
    int inp_bypass;	    /* set if the input is not armored */
    int in_cleartext;	    /* clear text message */
    int not_dash_escaped;   /* clear text is not dash escaped */
    int hashes; 	    /* detected hash algorithms */
    int faked;		    /* we are faking a literal data packet */
    int truncated;	    /* number of truncated lines */
    int qp_detected;
    int dearmor_state;      /* helper for dearmor_mode.  */
    byte eol[3];            /* The end of line characters as a
			       zero-terminated string.  Defaults
			       (eol[0]=='\0') to whatever the local
			       platform uses. */

    byte *buffer;	    /* malloced buffer */
    unsigned buffer_size;   /* and size of this buffer */
    unsigned buffer_len;    /* used length of the buffer */
    unsigned buffer_pos;    /* read position */

    byte radbuf[4];
    int idx, idx2;
    gcry_md_hd_t crc_md;

    int status; 	    /* an internal state flag */
    int cancel;
    int any_data;	    /* any valid armored data seen */
    int pending_lf;	    /* used together with faked */
} armor_filter_context_t;



struct compress_filter_context_s {
    int status;
    void *opaque;   /* (used for z_stream) */
    byte *inbuf;
    unsigned inbufsize;
    byte *outbuf;
    unsigned outbufsize;
    int algo;	 /* compress algo */
    int algo1hack;
    int new_ctb;
    void (*release)(struct compress_filter_context_s*);
};
typedef struct compress_filter_context_s compress_filter_context_t;


typedef struct
{
  /* Object with the key and algo */
  DEK *dek;

  /* Length of the data to encrypt if known - 32 bit because OpenPGP
   * requires partial encoding for a larger data size.  */
  u32 datalen;

  /* The current cipher handle.  */
  gcry_cipher_hd_t cipher_hd;

  /* Various processing flags.  */
  unsigned int wrote_header : 1;
  unsigned int short_blklen_warn : 1;
  unsigned long short_blklen_count;

  /* The encoded chunk byte for AEAD.  */
  byte chunkbyte;

  /* The decoded CHUNKBYTE.  */
  uint64_t chunksize;

  /* The chunk index for AEAD.  */
  uint64_t chunkindex;

  /* The number of bytes in the current chunk.  */
  uint64_t chunklen;

  /* The total count of encrypted plaintext octets.  Note that we
   * don't care about encrypting more than 16 Exabyte. */
  uint64_t total;

  /* The hash context and a buffer used for MDC.  */
  gcry_md_hd_t mdc_hash;
  byte enchash[20];

  /* The start IV for AEAD encryption.   */
  byte startiv[16];

  /* Using a large buffer for encryption makes processing easier and
   * also makes sure the data is well aligned.  */
  char *buffer;
  size_t bufsize;  /* Allocated length.  */
  size_t buflen;   /* Used length.       */

} cipher_filter_context_t;



typedef struct {
    byte *buffer;	    /* malloced buffer */
    unsigned buffer_size;   /* and size of this buffer */
    unsigned buffer_len;    /* used length of the buffer */
    unsigned buffer_pos;    /* read position */
    int truncated;	    /* number of truncated lines */
    int not_dash_escaped;
    int escape_from;
    gcry_md_hd_t md;
    int pending_lf;
    int pending_esc;
} text_filter_context_t;


typedef struct {
    char *what;		        /* description */
    u32 last_time;		/* last time reported */
    uint64_t last;		/* last amount reported */
    uint64_t offset;	        /* current amount */
    uint64_t total;	        /* total amount */
    int  refcount;
} progress_filter_context_t;

/* encrypt_filter_context_t defined in main.h */

/*-- mdfilter.c --*/
int md_filter( void *opaque, int control, iobuf_t a, byte *buf, size_t *ret_len);
void free_md_filter_context( md_filter_context_t *mfx );

/*-- armor.c --*/
armor_filter_context_t *new_armor_context (void);
void release_armor_context (armor_filter_context_t *afx);
int push_armor_filter (armor_filter_context_t *afx, iobuf_t iobuf);
int use_armor_filter( iobuf_t a );

/*-- compress.c --*/
gpg_error_t push_compress_filter (iobuf_t out, compress_filter_context_t *zfx,
                                  int algo);
gpg_error_t push_compress_filter2 (iobuf_t out,compress_filter_context_t *zfx,
                                   int algo, int rel);

/*-- cipher.c --*/
int cipher_filter_cfb (void *opaque, int control,
                       iobuf_t chain, byte *buf, size_t *ret_len);

/*-- cipher-aead.c --*/
int cipher_filter_aead (void *opaque, int control,
                        iobuf_t chain, byte *buf, size_t *ret_len);

/*-- textfilter.c --*/
int text_filter( void *opaque, int control,
		 iobuf_t chain, byte *buf, size_t *ret_len);
int copy_clearsig_text (iobuf_t out, iobuf_t inp, gcry_md_hd_t md,
                        int escape_dash, int escape_from);

/*-- progress.c --*/
progress_filter_context_t *new_progress_context (void);
void release_progress_context (progress_filter_context_t *pfx);
void handle_progress (progress_filter_context_t *pfx,
		      iobuf_t inp, const char *name);

#endif /*G10_FILTER_H*/
