/* iobuf.h - I/O buffer
 *	Copyright (c) 1997 by Werner Koch (dd9jn)
 *
 * This file is part of G10.
 *
 * G10 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * G10 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifndef G10_IOBUF_H
#define G10_IOBUF_H

#include "types.h"


#define DBG_IOBUF   iobuf_debug_mode


#define IOBUFCTRL_INIT	    1
#define IOBUFCTRL_FREE	    2
#define IOBUFCTRL_UNDERFLOW 3
#define IOBUFCTRL_FLUSH     4
#define IOBUFCTRL_DESC	    5
#define IOBUFCTRL_USER	    16

typedef struct iobuf_struct *IOBUF;

struct iobuf_struct {
    int usage;		 /* 1 input , 2 output, 3 temp */
    unsigned long nlimit;
    unsigned long nbytes;
    struct {
	size_t size;   /* allocated size */
	size_t start;  /* number of invalid bytes at the begin of the buffer */
	size_t len;    /* currently filled to this size */
	byte *buf;
    } d;
    struct {
	size_t size;
	size_t len;
	char *buf;
    } recorder;
    int filter_eof;
    int (*filter)( void *opaque, int control,
		   IOBUF chain, byte *buf, size_t *len);
    void *filter_ov;	/* value for opaque */
    IOBUF chain;	/* next iobuf used for i/o if any (passed to filter) */
    int no, subno;
    const char *desc;
    void *opaque;      /* can be used to old any information	*/
		       /* this value is copied to all instances */
};

int iobuf_debug_mode;

IOBUF iobuf_alloc(int usage, size_t bufsize);
IOBUF iobuf_temp(void);
IOBUF iobuf_open( const char *fname );
IOBUF iobuf_create( const char *fname );
int   iobuf_close( IOBUF iobuf );
int   iobuf_cancel( IOBUF iobuf );

int iobuf_push_filter( IOBUF a, int (*f)(void *opaque, int control,
		       IOBUF chain, byte *buf, size_t *len), void *ov );
int iobuf_pop_filter( IOBUF a, int (*f)(void *opaque, int control,
		      IOBUF chain, byte *buf, size_t *len), void *ov );
int iobuf_flush(IOBUF a);
void iobuf_clear_eof(IOBUF a);

void iobuf_set_limit( IOBUF a, unsigned long nlimit );

int  iobuf_readbyte(IOBUF a);
int  iobuf_writebyte(IOBUF a, unsigned c);
int  iobuf_write(IOBUF a, byte *buf, unsigned buflen );
int  iobuf_writestr(IOBUF a, const char *buf );

int  iobuf_write_temp( IOBUF a, IOBUF temp );
size_t iobuf_temp_to_buffer( IOBUF a, byte *buffer, size_t buflen );

void iobuf_start_recorder( IOBUF a );
void iobuf_push_recorder( IOBUF a, int c );
char *iobuf_stop_recorder( IOBUF a, size_t *n );

u32 iobuf_get_filelength( IOBUF a );
const char *iobuf_get_fname( IOBUF a );

void iobuf_set_block_mode( IOBUF a, size_t n );
int  iobuf_in_block_mode( IOBUF a );

/* get a byte form the iobuf; must check for eof prior to this function
 * this function returns values in the range 0 .. 255 or -1 to indicate EOF
 * iobuf_get_noeof() does not return -1 to indicate EOF, but masks the
 * returned value to be in the range 0 ..255.
 */
#define iobuf_get(a)  \
     (	((a)->recorder.buf || (a)->nlimit \
	 || (a)->d.start >= (a)->d.len )?  \
	iobuf_readbyte((a)) : ( (a)->nbytes++, (a)->d.buf[(a)->d.start++] ) )
#define iobuf_get_noeof(a)    (iobuf_get((a))&0xff)


/* write a byte to the iobuf and return true on write error
 * This macro does only write the low order byte
 */
#define iobuf_put(a,c)	iobuf_writebyte(a,c)

#define iobuf_where(a)	"[don't know]"
#define iobuf_id(a)	((a)->no)

#define iobuf_get_temp_length(a) ( (a)->d.len )
#define iobuf_is_temp(a)	 ( (a)->usage == 3 )

#endif /*G10_IOBUF_H*/
