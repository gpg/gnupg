/* signal.c - signal handling
 *	Copyright (C) 1998 Free Software Foundation, Inc.
 *
 * This file is part of GNUPG.
 *
 * GNUPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUPG is distributed in the hope that it will be useful,
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
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "options.h"
#include "errors.h"
#include "memory.h"
#include "util.h"
#include "main.h"
#include "ttyio.h"



static RETSIGTYPE
print_and_exit( int sig )
{
    const char *p;

    /* Hmm, use only safe functions (we should do an autoconf test) */
    write( 2, "\nCaught ", 8 );
  #if SYS_SIGLIST_DECLARED
    p = sys_siglist[sig];
    write( 2, p, strlen(p) );
  #else
    write( 2, "a signal", 8 );
  #endif
    write( 2, "... exiting\n", 12 );
    secmem_term();
    exit(2); /* not correct but .. */
}


void
init_signals()
{
  #if 0
    struct sigaction nact;

    nact.sa_handler = print_and_exit;
    sigemptyset (&nact.sa_mask);
    nact.sa_flags = 0;

    sigaction( SIGINT, &nact, NULL );
    sigaction( SIGHUP, &nact, NULL );
    sigaction( SIGTERM, &nact, NULL );
 #endif
}


