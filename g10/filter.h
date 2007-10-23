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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#ifndef G10_FILTER_H
#define G10_FILTER_H

#include "types.h"
#include "cipher.h"

typedef struct {
    MD_HANDLE md;      /* catch all */
    MD_HANDLE md2;     /* if we want to calculate an alternate hash */
    size_t maxbuf_size;
} md_filter_context_t;

typedef struct {
    int refcount;           /* Reference counter.  If 0 this structure
                               is not allocated on the heap. */

    /* these fields may be initialized */
    int what;		    /* what kind of armor headers to write */
    int only_keyblocks;     /* skip all headers but ".... key block" */
    const char *hdrlines;   /* write these headerlines */

    /* these fileds must be initialized to zero */
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
    int pgp2mode;
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
    u32 crc;

    int status; 	    /* an internal state flag */
    int cancel;
    int any_data;	    /* any valid armored data seen */
    int pending_lf;	    /* used together with faked */
} armor_filter_context_t;

struct unarmor_pump_s;
typedef struct unarmor_pump_s *UnarmorPump;


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


typedef struct {
    DEK *dek;
    u32 datalen;
    CIPHER_HANDLE cipher_hd;
    int header;
    MD_HANDLE mdc_hash;
    byte enchash[20];
    int create_mdc; /* flag will be set by the cipher filter */
} cipher_filter_context_t;



typedef struct {
    byte *buffer;	    /* malloced buffer */
    unsigned buffer_size;   /* and size of this buffer */
    unsigned buffer_len;    /* used length of the buffer */
    unsigned buffer_pos;    /* read position */
    int truncated;	    /* number of truncated lines */
    int not_dash_escaped;
    int escape_from;
    MD_HANDLE md;
    int pending_lf;
    int pending_esc;
} text_filter_context_t;


typedef struct {
    char *what;		        /* description */
    u32 last_time;		/* last time reported */
    unsigned long last;		/* last amount reported */
    unsigned long offset;	/* current amount */
    unsigned long total;	/* total amount */
} progress_filter_context_t;

/* encrypt_filter_context_t defined in main.h */

/*-- mdfilter.c --*/
int md_filter( void *opaque, int control, IOBUF a, byte *buf, size_t *ret_len);
void free_md_filter_context( md_filter_context_t *mfx );

/*-- armor.c --*/
armor_filter_context_t *new_armor_context (void);
void release_armor_context (armor_filter_context_t *afx);
int push_armor_filter (armor_filter_context_t *afx, IOBUF iobuf);
int use_armor_filter( IOBUF a );
int armor_filter( void *opaque, int control,
		  IOBUF chain, byte *buf, size_t *ret_len);
UnarmorPump unarmor_pump_new (void);
void        unarmor_pump_release (UnarmorPump x);
int         unarmor_pump (UnarmorPump x, int c);

/*-- compress.c --*/
void push_compress_filter(IOBUF out,compress_filter_context_t *zfx,int algo);
void push_compress_filter2(IOBUF out,compress_filter_context_t *zfx,
			   int algo,int rel);

/*-- cipher.c --*/
int cipher_filter( void *opaque, int control,
		   IOBUF chain, byte *buf, size_t *ret_len);

/*-- textfilter.c --*/
int text_filter( void *opaque, int control,
		 IOBUF chain, byte *buf, size_t *ret_len);
int copy_clearsig_text( IOBUF out, IOBUF inp, MD_HANDLE md,
			  int escape_dash, int escape_from, int pgp2mode );

/*-- progress.c --*/
int progress_filter (void *opaque, int control,
		     IOBUF a, byte *buf, size_t *ret_len);
void handle_progress (progress_filter_context_t *pfx,
		      IOBUF inp, const char *name);

#endif /*G10_FILTER_H*/
