/* decrypt.c - verify signed data
 * Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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
#include "i18n.h"



/****************
 * Assume that the input is an encrypted message and decrypt
 * (and if signed, verify the signature on) it.
 * This command differs from the default operation, as it never
 * writes to the filename which is included in the file and it
 * rejects files which don't begin with an encrypted message.
 */

int
decrypt_message( const char *filename )
{
    IOBUF fp;
    armor_filter_context_t afx;
    int rc;
    int no_out=0;

    /* open the message file */
    fp = iobuf_open(filename);
    if( !fp ) {
	log_error(_("can't open `%s'\n"), print_fname_stdin(filename));
	return G10ERR_OPEN_FILE;
    }

    if( !opt.no_armor ) {
	if( use_armor_filter( fp ) ) {
	    memset( &afx, 0, sizeof afx);
	    iobuf_push_filter( fp, armor_filter, &afx );
	}
    }

    if( !opt.outfile ) {
	no_out = 1;
	opt.outfile = "-";
    }
    rc = proc_encryption_packets( NULL, fp );
    if( no_out )
       opt.outfile = NULL;
    iobuf_close(fp);
    return rc;
}



