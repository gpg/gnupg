/* overwrite.c
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include "util.h"
#include "memory.h"
#include "ttyio.h"
#include "options.h"
#include "main.h"


/****************
 * Check wether FNAME exists and ask if it's okay to overwrite an
 * existing one.
 * Returns: -1 : Do not overwrite
 *	    0 : it's okay to overwrite or the file does not exist
 *	    >0 : other error
 */
int
overwrite_filep( const char *fname )
{
    if( !access( fname, F_OK ) ) {
	char *p;
	int okay;
	int first = 1;

	if( opt.answer_yes )
	    okay = 1;
	else if( opt.answer_no || opt.batch )
	    okay = 2;
	else
	    okay = 0;

	while( !okay ) {
	if( !okay )
	    if( first ) {
		tty_printf("File '%s' exists. ", fname);
		first = 0;
	    }
	    p = tty_get("Overwrite (y/N)? ");
	    tty_kill_prompt();
	    if( (*p == 'y' || *p == 'Y') && !p[1] )
		okay = 1;
	    else if( !*p || ((*p == 'n' || *p == 'N') && !p[1]) )
		okay = 2;
	    else
		okay = 0;
	    m_free(p);
	}
	if( okay == 2 )
	    return -1;
	/* fixme: add some backup stuff */
    }
    return 0;
}


