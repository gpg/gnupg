/* shmtest.c
 * Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */


#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#ifdef HAVE_SYS_IPC_H
#include <sys/types.h>
#include <sys/ipc.h>
#endif
#ifdef HAVE_SYS_SHM_H
#include <sys/shm.h>
#endif
#include "util.h"
#include "ttyio.h"
#include "i18n.h"

#ifdef HAVE_DOSISH_SYSTEM
int main( int argc, char **argv )
{
    fprintf(stderr, "Sorry, not yet available for DOSish systems\n");
    exit(1);
}
#else

static int serverpid = -1;

static void
my_usage(void)
{
    fprintf(stderr, "usage: shmtest gpg-command-line\n");
    exit(1);
}

const char *
strusage( int level )
{
    return default_strusage(level);
}

static void
i18n_init(void)
{
#ifdef ENABLE_NLS
    setlocale( LC_ALL, "" );
    bindtextdomain (PACKAGE, LOCALEDIR);
    textdomain( PACKAGE );
#endif
}


static void
do_get_string( int mode, const char *keyword, byte *area, size_t areasize )
{
    size_t n, len;
    char *p=NULL;
    int yes=0;

    n = area[0] << 8 | area[1];
    /* fixme: do some sanity checks here */
    if( mode == 1 )
	p = tty_get( keyword );
    else if( mode == 3 )
	p = tty_get_hidden( keyword );
    else
	yes = tty_get_answer_is_yes( keyword );
    if( p ) {
	len = strlen(p);
	memcpy( area+n+2, p, len );
	area[n] = len >> 8;
	area[n+1] = len;
	xfree(p);
    }
    else { /* bool */
	area[n] = 0;
	area[n+1] = 1;
	area[n+2] = yes;
    }
    area[3] = 1; /* we should better use a semaphore */
    kill( serverpid, SIGUSR1 );
}



int
main(int argc, char **argv)
{
    void  *area = NULL;
    size_t areasize = 4096;
    int shm_id = -1;
    FILE *fp;
    char buf[200];
    char *p, *p2;
    size_t n;
    int i;

    log_set_name("shmtest");
    i18n_init();
#ifndef USE_SHM_COPROCESSING
    log_info("SHM_COPRPOCESSING is not available\n");
#else
    if( argc < 1 )
	my_usage();

    for(n=0,i=1; i < argc; i++ )
	n += strlen(argv[i]) + 1;
    p = xmalloc( 100 + n );
    strcpy( p, "../g10/gpg --status-fd 1 --run-as-shm-coprocess 0");
    for(i=1; i < argc; i++ ) {
	strcat(p, " " );
	strcat(p, argv[i] );
    }

    fp = popen( p, "r" );
    xfree( p );
    if( !fp )
	log_error("popen failed: %s\n", strerror(errno));

    while ( fgets (buf, sizeof (buf) - 1, fp ) != NULL ) {
	size_t len = strlen(buf);
	if( len >= 9 && !memcmp( buf, "[GNUPG:] ", 9 ) ) {
	    int word=0;
	    int is_info = 0, is_get = 0;

	    for( p = strtok(buf+9, " \n"); p ; p = strtok(NULL, " \n")) {
		word++;
		if( word==1 && !strcmp(p,"SHM_INFO") ) {
		    if( !area )
			is_info=1;
		    else
			log_error("duplicate SHM_INFO ignored\n" );
		}
		else if( is_info && (p2 = strchr(p, '=' )) ) {
		    int val;
		    *p2++ = 0;
		    val = atoi(p2); /* should be atou() for some values */
		    if( !strcmp(p, "pv" ) ) {
			if( atoi(p2) != 1 )
			    log_fatal("invalid protocol version %d\n", val );
			is_info = 2;
		    }
		    else if( !strcmp(p, "pid" ) )
			serverpid = val;
		    else if( !strcmp(p, "shmid" ) )
			shm_id = val;
		}
		else if( word == 1 && !strcmp(p,"SHM_GET") )
		    is_get = 1;
		else if( word == 1 && !strcmp(p,"SHM_GET_BOOL") )
		    is_get = 2;
		else if( word == 1 && !strcmp(p,"SHM_GET_HIDDEN") )
		    is_get = 3;
		else if( word == 2 && is_get )	{
		    do_get_string( is_get, p, area, areasize );
		    break;
		}
		else if( word == 1 )
		    log_info("Status: %s\n", p);
	    }
	    if( is_info ) {
		if( is_info < 2 )
		    log_fatal("SHM info without protocol version\n");
		if( serverpid == -1 )
		    log_fatal("SHM info without server's pid\n");
		if( shm_id == -1 )
		    log_fatal("SHM info without id\n");
		log_info("Shared memory info: server=%d shm_id=%d\n",
							    serverpid, shm_id);
		area = shmat( shm_id, 0, 0 );
		if( area == (void*)-1 )
		    log_fatal("attach to shared memory failed: %s\n",
							    strerror(errno));
	    }
	}
	else
	    fputs (buf, stdout);
    }


    if( pclose(fp) )
	log_error("pclose failed\n");

    return 0;
#endif
}

#endif
