/* checksig.c - check a signature
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

#include "packet.h"
#include "iobuf.h"
#include "memory.h"
#include "util.h"
#include "cipher.h"

static void
usage(void)
{
    fprintf(stderr, "usage: checksig textfile sigfile\n");
    exit(1);
}


int
main(int argc, char **argv)
{
    IOBUF a;
    PACKET pkt;
    PKT_signature *sig;
    int rc, result, c;
    FILE *fp;
    MD5HANDLE md5;

    if( argc != 3 )
	usage();
    argc--; argv++;


    if( !(a = iobuf_open(argv[1])) )
	log_fatal("can't open '%s'\n", argv[1]);

    init_packet(&pkt);
    while( (rc=parse_packet(a, &pkt)) != -1 ) {
	if( !rc && pkt.pkttype == PKT_SECKEY_ENC ) {
	    sig = pkt.pkt.signature;
	    printf("sig: keyid=%08lX%08lX: ", sig->keyid[0], sig->keyid[1] );
	    if( sig->pubkey_algo == PUBKEY_ALGO_RSA ) {
		if( sig->d.rsa.digest_algo == DIGEST_ALGO_MD5 ) {
		    if( !(fp = fopen(*argv, "rb")) )
			log_fatal("can't open '%s'\n", *argv);
		    md5 = md5_open(0);
		    while( (c=getc(fp)) != EOF )
			md5_putchar(md5, c );
		    fclose(fp);
		    result = md5_signature_check( sig, md5 );
		    md5_close(md5);
		}
		else
		    result = G10ERR_DIGEST_ALGO;
	    }
	    else
		result = G10ERR_PUBKEY_ALGO;

	    if( !result )
		fputs( "signature is good", stdout );
	    else if( result == G10ERR_DIGEST_ALGO )
		printf( "Unknown digest algorithm %d", sig->d.rsa.digest_algo);
	    else if( result == G10ERR_PUBKEY_ALGO )
		printf( "Unknown pubkey algorithm %d", sig->pubkey_algo);
	    else
		fputs( g10_errstr(result), stdout);
	    putchar('\n');
	}
	free_packet(&pkt);
    }

    iobuf_close(a);
    return 0;
}


