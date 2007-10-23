/* pipemode.c - pipemode handler
 * Copyright (C) 1998, 1990, 2000, 2001 Free Software Foundation, Inc.
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
#define FAKED_LITERAL_PACKET_SPACE (9+2+2)


enum pipemode_state_e {
    STX_init = 0,
    STX_wait_operation,
    STX_begin,
    STX_text,
    STX_detached_signature,
    STX_detached_signature_wait_text,
    STX_signed_data,
    STX_wait_init
};

struct pipemode_context_s {
    enum pipemode_state_e state;
    int operation;
    int stop;
    int block_mode;
    UnarmorPump unarmor_ctx;
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
    buf[n++] = CTRLPKT_PIPEMODE;    
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
        if ( size <= CONTROL_PACKET_SPACE+FAKED_LITERAL_PACKET_SPACE )
            BUG();
        size -= CONTROL_PACKET_SPACE+FAKED_LITERAL_PACKET_SPACE;

        if ( stx->block_mode ) {
            /* reserve 2 bytes for the block length */
            buf[n++] = 0;
            buf[n++] = 0;
        }
            

        while ( n < size ) {
            /* FIXME: we have to make sure that we have a large enough
             * buffer for a control packet even after we already read 
             * something. The easest way to do this is probably by ungetting
             * the control sequence and returning the buffer we have
             * already assembled */
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
                    else if ( stx->state == STX_detached_signature ) {
                        esc = 0;
                        goto do_unarmor; /* not a very elegant solution */
                    }
                    else if ( stx->state == STX_detached_signature_wait_text) {
                        esc = 0;
                        break; /* just ignore it in this state */
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
                    stx->block_mode = 0;
                    unarmor_pump_release (stx->unarmor_ctx);
                    stx->unarmor_ctx = NULL;
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
                    if ( stx->operation == 'B') {
                        stx->state = STX_detached_signature;
                        if ( !opt.no_armor )
                            stx->unarmor_ctx = unarmor_pump_new ();
                    }
                    else
                        stx->state = STX_begin;
                    n += make_control ( buf+n, 1, stx->operation );
                    /* must leave after a control packet */
                    goto leave;

                  case 't': /* plaintext text follows */
                    if ( stx->state == STX_detached_signature_wait_text ) 
                        stx->state = STX_detached_signature;
                    if ( stx->state == STX_detached_signature ) {
                        if ( stx->operation != 'B' ) {
                            log_error ("invalid operation for this state\n");
                            stx->stop = 1;
                            return -1;
                        }
                        stx->state = STX_signed_data;
                        n += make_control ( buf+n, 2, 'B' );
                        /* and now we fake a literal data packet much the same
                         * as in armor.c */
                        buf[n++] = 0xaf; /* old packet format, type 11,
                                            var length */
                        buf[n++] = 0;	 /* set the length header */
                        buf[n++] = 6;
                        buf[n++] = 'b';  /* we ignore it anyway */
                        buf[n++] = 0;	 /* namelength */
                        memset(buf+n, 0, 4); /* timestamp */
                        n += 4;
                        /* and return now so that we are sure to have
                         * more space in the bufer for the next control
                         * packet */
                        stx->block_mode = 1;
                        goto leave2;
                    }
                    else {
                        log_error ("invalid state for @t\n");
                        stx->stop = 1;
                        return -1;
                    }
                    break;

                  case '.': /* ready */
                    if ( stx->state == STX_signed_data ) { 
                        if (stx->block_mode) {
                            buf[0] = (n-2) >> 8;
                            buf[1] = (n-2);
                            if ( buf[0] || buf[1] ) {
                                /* end of blocks marker */
                                buf[n++] = 0;
                                buf[n++] = 0;
                            }
                            stx->block_mode = 0;
                        }
                        n += make_control ( buf+n, 3, 'B' );
                    }
                    else {
                        log_error ("invalid state for @.\n");
                        stx->stop = 1;
                        return -1;
                    }
                    stx->state = STX_wait_init;
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
            else if (stx->unarmor_ctx) {
          do_unarmor: /* used to handle a @@ */
                c = unarmor_pump (stx->unarmor_ctx, c);
                if ( !(c & ~255) )
                    buf[n++] = c;
                else if ( c < 0 ) {
                    /* end of armor or error - we don't care becuase
                      the armor can be modified anyway.  The unarmored
                      stuff should stand for itself. */ 
                    unarmor_pump_release (stx->unarmor_ctx);
                    stx->unarmor_ctx = NULL;
                    stx->state = STX_detached_signature_wait_text;
                }
            }
            else if (stx->state == STX_detached_signature_wait_text)
                ; /* just wait */
            else
                buf[n++] = c; 
        }

      leave:      
        if ( !n ) {
            stx->stop = 1;
            rc = -1; /* eof */
        }
        if ( stx->block_mode ) {
            /* fixup the block length */
            buf[0] = (n-2) >> 8;
            buf[1] = (n-2);
        }
      leave2:
        /*log_hexdump ("pipemode:", buf, n );*/
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

    do {
        write_status (STATUS_BEGIN_STREAM);
        rc = proc_packets( NULL, fp );
        write_status (STATUS_END_STREAM);
    } while ( !stx.stop );
  
}






