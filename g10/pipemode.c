/* pipemode.c - pipemode handler
 *	Copyright (C) 2000 Free Software Foundation, Inc.
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "options.h"
#include "packet.h"
#include "errors.h"
#include "iobuf.h"
#include "keydb.h"
#include "memory.h"
#include "util.h"
#include "main.h"
#include "status.h"
#include "filter.h"


#define CONTROL_PACKET_SPACE 30 

enum pipemode_state_e {
    STX_init = 0,
    STX_wait_operation,
    STX_begin,
    STX_text,
    STX_wait_init
};


struct pipemode_context_s {
    enum pipemode_state_e state;
    int operation;
    int stop;
};


static size_t
make_control ( byte *buf, int code, int operation )
{
    const byte *sesmark;
    size_t sesmarklen, n=0;;

    sesmark = get_session_marker( &sesmarklen );
    if ( sesmarklen > 20 )
        BUG();

    buf[n++] = 0xff; /* new format, type 63, 1 length byte */
    n++;   /* length will fixed below */
    memcpy(buf+n, sesmark, sesmarklen ); n+= sesmarklen;
    buf[n++] = 2;    /* control type: pipemode marker */
    buf[n++] = code;
    buf[n++] = operation;
    buf[1] = n-2;
    return n;
}


static int
pipemode_filter( void *opaque, int control,
	         IOBUF a, byte *buf, size_t *ret_len)
{ 
    size_t size = *ret_len;
    struct pipemode_context_s *stx = opaque;
    int rc=0;
    size_t n = 0;
    int esc = 0;

    if( control == IOBUFCTRL_UNDERFLOW ) {
        *ret_len = 0;
        /* reserve some space for one control packet */
        if ( size <= CONTROL_PACKET_SPACE )
            BUG();
        size -= CONTROL_PACKET_SPACE;


        while ( n < size ) {
            int c = iobuf_get (a);
            if (c == -1) {
                if ( stx->state != STX_init ) {
                    log_error ("EOF encountered at wrong state\n");
                    stx->stop = 1;
                    return -1;
                }
                break;
            }
            if ( esc ) {
                switch (c) {
                  case '@':  
                    if ( stx->state == STX_text ) {
                        buf[n++] = c;
                        break;
                    }
                    log_error ("@@ not allowed in current state\n");
                    return -1;
                  case '<': /* begin of stream part */
                    if ( stx->state != STX_init ) {
                        log_error ("nested begin of stream\n");
                        stx->stop = 1;
                        return -1;
                    }
                    stx->state = STX_wait_operation;
                    break;
                   case '>': /* end of stream part */
                     if ( stx->state != STX_wait_init ) {
                        log_error ("invalid state for @>\n");
                        stx->stop = 1;
                        return -1;
                    }
                    stx->state = STX_init;
                    break;
                  case 'V': /* operation = verify */
                  case 'E': /* operation = encrypt */
                  case 'S': /* operation = sign */
                  case 'B': /* operation = detach sign */
                  case 'C': /* operation = clearsign */
                  case 'D': /* operation = decrypt */
                    if ( stx->state != STX_wait_operation ) {
                        log_error ("invalid state for operation code\n");
                        stx->stop = 1;
                        return -1;
                    }
                    stx->operation = c;
                    stx->state = STX_begin;
                    n += make_control ( buf, 1, stx->operation );
                    goto leave;

                  case 't': /* plaintext text follows */
                    if ( stx->state != STX_begin ) {
                        log_error ("invalid state for @t\n");
                        stx->stop = 1;
                        return -1;
                    }
                    if ( stx->operation != 'E' ) {
                        log_error ("invalid operation for @t\n");
                        stx->stop = 1;
                        return -1;
                    }
                    stx->state = STX_text;
                    n += make_control ( buf, 2, c );
                    goto leave;

                  case '.': /* ready */
                    if ( stx->state == STX_text ) 
                        ;
                    else {
                        log_error ("invalid state for @.\n");
                        stx->stop = 1;
                        return -1;
                    }
                    stx->state = STX_wait_init;
                    n += make_control ( buf, 3, c );
                    goto leave;

                 default:      
                    log_error ("invalid escape sequence 0x%02x in stream\n",
                               c);
                    stx->stop = 1;
                    return -1;
                }
                esc = 0;
            }
            else if (c == '@') 
                esc = 1;
            else
                buf[n++] = c;
        }

      leave:      
        if ( !n ) {
            stx->stop = 1;
            rc = -1; /* eof */
        }
	*ret_len = n;
    }
    else if( control == IOBUFCTRL_DESC )
	*(char**)buf = "pipemode_filter";
    return rc;
}



void
run_in_pipemode(void)
{
    IOBUF fp;
    armor_filter_context_t afx;
    struct pipemode_context_s stx;
    int rc;

    memset( &afx, 0, sizeof afx);
    memset( &stx, 0, sizeof stx);

    fp = iobuf_open("-");
    iobuf_push_filter (fp, pipemode_filter, &stx );

    if( !opt.no_armor ) 
        iobuf_push_filter( fp, armor_filter, &afx );
   
    do {
        log_debug ("pipemode: begin proc_packets\n");
        rc = proc_packets( NULL, fp );
        log_debug ("pipemode: end   proc_packets: %s\n", g10_errstr (rc));
    } while ( !stx.stop );
  
}





