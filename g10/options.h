/* options.h
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
#ifndef G10_OPTIONS_H
#define G10_OPTIONS_H

struct {
    int verbose;
    unsigned debug;
    int armor;
    int compress;
    char *outfile;
    int outfile_is_stdout;
    int batch;	    /* run in batch mode */
    int answer_yes; /* answer yes on most questions */
    int answer_no;  /* answer no on most questions */
    int check_sigs; /* check key signatures */
    int cache_all;
    int reserved2;
    int reserved3;
    int reserved4;
    int reserved5;
    int reserved6;
    int reserved7;
    int reserved8;
    int reserved9;
    int reserved10;
    int reserved11;
    int reserved12;
    int reserved13;
    int reserved14;
    int reserved15;
} opt;


#define DBG_PACKET_VALUE  1	/* debug packet reading/writing */
#define DBG_MPI_VALUE	  2	/* debug mpi details */
#define DBG_CIPHER_VALUE  4	/* debug cipher handling */
				/* (may reveal sensitive data) */
#define DBG_FILTER_VALUE  8	/* debug internal filter handling */
#define DBG_IOBUF_VALUE   16	/* debug iobuf stuff */
#define DBG_MEMORY_VALUE  32	/* debug memory allocation stuff */
#define DBG_CACHE_VALUE   64	/* debug the cacheing */
#define DBG_MEMSTAT_VALUE 128	/* show memory statistics */


#define DBG_PACKET (opt.debug & DBG_PACKET_VALUE)
#define DBG_FILTER (opt.debug & DBG_FILTER_VALUE)
#define DBG_CACHE  (opt.debug & DBG_CACHE_VALUE)


#endif /*G10_OPTIONS_H*/
