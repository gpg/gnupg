/* filter.h
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
#ifndef G10_FILTER_H
#define G10_FILTER_H

#include "cipher.h"

typedef struct {
    MD5HANDLE md5;	/* if !NULL create md5	*/
    RMDHANDLE rmd160;	/* if !NULL create rmd160  */
    size_t maxbuf_size;
} md_filter_context_t;

typedef struct {
    int status;
    int what;
    byte radbuf[4];
    int  idx, idx2;
    u32 crc;
    int inp_checked;   /* set if inp has been checked */
    int inp_bypass;    /* set if the input is not armored */
    int inp_eof;
} armor_filter_context_t;


/*-- mdfilter.c --*/
int md_filter( void *opaque, int control, IOBUF a, byte *buf, size_t *ret_len);

/*-- armor.c --*/
int armor_filter( void *opaque, int control,
		  IOBUF chain, byte *buf, size_t *ret_len);

#endif /*G10_FILTER_H*/
