/* iobuf.h - I/O buffer
 * Copyright (C) 1998, 1999, 2000, 2001, 2003 Free Software Foundation, Inc.
 *
 * This file is part of GNUPG.
 *
 * GNUPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GNUPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef GNUPG_COMMON_IOBUF_H
#define GNUPG_COMMON_IOBUF_H

#include "../include/types.h" /* fixme: should be moved elsewhere. */


#define DBG_IOBUF   iobuf_debug_mode


#define IOBUFCTRL_INIT	    1
#define IOBUFCTRL_FREE	    2
#define IOBUFCTRL_UNDERFLOW 3
#define IOBUFCTRL_FLUSH     4
#define IOBUFCTRL_DESC	    5
#define IOBUFCTRL_CANCEL    6
#define IOBUFCTRL_USER	    16

typedef struct iobuf_struct *iobuf_t;
typedef struct iobuf_struct *IOBUF;  /* Compatibility with gpg 1.4. */

/* fixme: we should hide most of this stuff */
struct iobuf_struct
{
  int use;			/* 1 input , 2 output, 3 temp */
  off_t nlimit;
  off_t nbytes;			/* Used together with nlimit. */
  off_t ntotal;			/* Total bytes read (position of stream). */
  int nofast;			/* Used by the iobuf_get (). */
  void *directfp;
  struct
  {
    size_t size;		/* Allocated size */
    size_t start;		/* Number of invalid bytes at the
                                   begin of the buffer */
    size_t len;			/* Currently filled to this size */
    byte *buf;
  } d;

  int filter_eof;
  int error;
  int (*filter) (void *opaque, int control,
		 iobuf_t chain, byte * buf, size_t * len);
  void *filter_ov;		/* Value for opaque */
  int filter_ov_owner;
  char *real_fname;
  iobuf_t chain;		/* Next iobuf used for i/o if any
                                   (passed to filter) */
  int no, subno;
  const char *desc;
  void *opaque;			/* Can be used to hold any information
                                   this value is copied to all
                                   instances */
};

#ifndef EXTERN_UNLESS_MAIN_MODULE
#if defined (__riscos__) && !defined (INCLUDED_BY_MAIN_MODULE)
#define EXTERN_UNLESS_MAIN_MODULE extern
#else
#define EXTERN_UNLESS_MAIN_MODULE
#endif
#endif
EXTERN_UNLESS_MAIN_MODULE int iobuf_debug_mode;

void iobuf_enable_special_filenames (int yes);
int  iobuf_is_pipe_filename (const char *fname);
iobuf_t iobuf_alloc (int use, size_t bufsize);
iobuf_t iobuf_temp (void);
iobuf_t iobuf_temp_with_content (const char *buffer, size_t length);
iobuf_t iobuf_open (const char *fname);
iobuf_t iobuf_fdopen (int fd, const char *mode);
iobuf_t iobuf_sockopen (int fd, const char *mode);
iobuf_t iobuf_create (const char *fname);
iobuf_t iobuf_append (const char *fname);
iobuf_t iobuf_openrw (const char *fname);
int iobuf_ioctl (iobuf_t a, int cmd, int intval, void *ptrval);
int iobuf_close (iobuf_t iobuf);
int iobuf_cancel (iobuf_t iobuf);

int iobuf_push_filter (iobuf_t a, int (*f) (void *opaque, int control,
					  iobuf_t chain, byte * buf,
					  size_t * len), void *ov);
int iobuf_push_filter2 (iobuf_t a,
			int (*f) (void *opaque, int control, iobuf_t chain,
				  byte * buf, size_t * len), void *ov,
			int rel_ov);
int iobuf_flush (iobuf_t a);
void iobuf_clear_eof (iobuf_t a);
#define iobuf_set_error(a)    do { (a)->error = 1; } while(0)
#define iobuf_error(a)	      ((a)->error)

void iobuf_set_limit (iobuf_t a, off_t nlimit);

off_t iobuf_tell (iobuf_t a);
int iobuf_seek (iobuf_t a, off_t newpos);

int iobuf_readbyte (iobuf_t a);
int iobuf_read (iobuf_t a, void *buf, unsigned buflen);
void iobuf_unread (iobuf_t a, const unsigned char *buf, unsigned int buflen);
unsigned iobuf_read_line (iobuf_t a, byte ** addr_of_buffer,
			  unsigned *length_of_buffer, unsigned *max_length);
int iobuf_peek (iobuf_t a, byte * buf, unsigned buflen);
int iobuf_writebyte (iobuf_t a, unsigned c);
int iobuf_write (iobuf_t a, const void *buf, unsigned buflen);
int iobuf_writestr (iobuf_t a, const char *buf);

void iobuf_flush_temp (iobuf_t temp);
int iobuf_write_temp (iobuf_t a, iobuf_t temp);
size_t iobuf_temp_to_buffer (iobuf_t a, byte * buffer, size_t buflen);

off_t iobuf_get_filelength (iobuf_t a, int *overflow);
#define IOBUF_FILELENGTH_LIMIT 0xffffffff
int  iobuf_get_fd (iobuf_t a);
const char *iobuf_get_real_fname (iobuf_t a);
const char *iobuf_get_fname (iobuf_t a);

void iobuf_set_partial_block_mode (iobuf_t a, size_t len);

void iobuf_skip_rest (iobuf_t a, unsigned long n, int partial);


/* get a byte form the iobuf; must check for eof prior to this function
 * this function returns values in the range 0 .. 255 or -1 to indicate EOF
 * iobuf_get_noeof() does not return -1 to indicate EOF, but masks the
 * returned value to be in the range 0 ..255.
 */
#define iobuf_get(a)  \
     (	((a)->nofast || (a)->d.start >= (a)->d.len )?  \
	iobuf_readbyte((a)) : ( (a)->nbytes++, (a)->d.buf[(a)->d.start++] ) )
#define iobuf_get_noeof(a)    (iobuf_get((a))&0xff)

/* write a byte to the iobuf and return true on write error
 * This macro does only write the low order byte
 */
#define iobuf_put(a,c)	iobuf_writebyte(a,c)

#define iobuf_where(a)	"[don't know]"
#define iobuf_id(a)	((a)->no)

#define iobuf_get_temp_buffer(a) ( (a)->d.buf )
#define iobuf_get_temp_length(a) ( (a)->d.len )
#define iobuf_is_temp(a)	 ( (a)->use == 3 )

#endif /*GNUPG_COMMON_IOBUF_H*/
