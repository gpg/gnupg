/* verify.c - verify signed data
 *	Copyright (C) 1998 Free Software Foundation, Inc.
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
#include "filter.h"
#include "ttyio.h"
#include "i18n.h"



/****************
 * Assume that the input is a signature and verify it without
 * generating any output.  With no arguments, the signature packet
 * is read from stdin (it may be a detached signature when not
 * used in batch mode). If only a sigfile is given, it may be a complete
 * signature or a detached signature in which case the signed stuff
 * is expected from stdin. With more than 1 argument, the first should
 * be a detached signature and the remaining files are the signed stuff.
 */

int
verify_signatures( int nfiles, char **files )
{
    IOBUF fp;
    armor_filter_context_t afx;
    const char *sigfile;
    int i, rc;
    STRLIST sl;

    sigfile = nfiles? *files : NULL;

    /* open the signature file */
    fp = iobuf_open(sigfile);
    if( !fp ) {
	log_error(_("can't open `%s'\n"), print_fname_stdin(sigfile));
	return G10ERR_OPEN_FILE;
    }

    if( !opt.no_armor ) {
	if( use_armor_filter( fp ) ) {
	    memset( &afx, 0, sizeof afx);
	    iobuf_push_filter( fp, armor_filter, &afx );
	}
    }

    sl = NULL;
    for(i=1 ; i < nfiles; i++ )
	add_to_strlist( &sl, files[i] );
    rc = proc_signature_packets( NULL, fp, sl, sigfile );
    free_strlist(sl);
    iobuf_close(fp);
    return rc;
}



