/* tdbdump.c
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
#include <ctype.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "errors.h"
#include "iobuf.h"
#include "keydb.h"
#include "memory.h"
#include "util.h"
#include "trustdb.h"
#include "options.h"
#include "packet.h"
#include "main.h"
#include "i18n.h"
#include "tdbio.h"


#define HEXTOBIN(x) ( (x) >= '0' && (x) <= '9' ? ((x)-'0') : \
		      (x) >= 'A' && (x) <= 'F' ? ((x)-'A'+10) : ((x)-'a'+10))

/****************
 * Read a record but die if it does not exist
 * fixme: duplicate: remove it
 */
#if 0
static void
read_record( ulong recno, TRUSTREC *rec, int rectype )
{
    int rc = tdbio_read_record( recno, rec, rectype );
    if( !rc )
	return;
    log_error(_("trust record %lu, req type %d: read failed: %s\n"),
				    recno, rectype,  g10_errstr(rc) );
    tdbio_invalid();
}
#endif
/****************
 * Wirte a record but die on error
 */
static void
write_record( TRUSTREC *rec )
{
    int rc = tdbio_write_record( rec );
    if( !rc )
	return;
    log_error(_("trust record %lu, type %d: write failed: %s\n"),
			    rec->recnum, rec->rectype, g10_errstr(rc) );
    tdbio_invalid();
}


/****************
 * sync the db
 */
static void
do_sync(void)
{
    int rc = tdbio_sync();
    if( !rc )
	return;
    log_error(_("trustdb: sync failed: %s\n"), g10_errstr(rc) );
    g10_exit(2);
}

#if 0
static int
print_sigflags( FILE *fp, unsigned flags )
{
    if( flags & SIGF_CHECKED ) {
	fprintf(fp,"%c%c%c",
	   (flags & SIGF_VALID)   ? 'V':'-',
	   (flags & SIGF_EXPIRED) ? 'E':'-',
	   (flags & SIGF_REVOKED) ? 'R':'-');
    }
    else if( flags & SIGF_NOPUBKEY)
	fputs("?--", fp);
    else
	fputs("---", fp);
    return 3;
}
#endif


/****************
 * Walk through the signatures of a public key.
 * The caller must provide a context structure, with all fields set
 * to zero, but the local_id field set to the requested key;
 * This function does not change this field.  On return the context
 * is filled with the local-id of the signature and the signature flag.
 * No fields should be changed (clearing all fields and setting
 * pubkeyid is okay to continue with an other pubkey)
 * Returns: 0 - okay, -1 for eof (no more sigs) or any other errorcode
 * FIXME: Do we really need this large and complicated function?
 */
#if 0
static int
walk_sigrecs( SIGREC_CONTEXT *c )
{
    TRUSTREC *r;
    ulong rnum;

    if( c->ctl.eof )
	return -1;
    r = &c->ctl.rec;
    if( !c->ctl.init_done ) {
	c->ctl.init_done = 1;
	read_record( c->lid, r, 0 );
	if( r->rectype != RECTYPE_DIR ) {
	    c->ctl.eof = 1;
	    return -1;	/* return eof */
	}
	c->ctl.nextuid = r->r.dir.uidlist;
	/* force a read */
	c->ctl.index = SIGS_PER_RECORD;
	r->r.sig.next = 0;
    }

    /* need a loop to skip over deleted sigs */
    do {
	if( c->ctl.index >= SIGS_PER_RECORD ) { /* read the record */
	    rnum = r->r.sig.next;
	    if( !rnum && c->ctl.nextuid ) { /* read next uid record */
		read_record( c->ctl.nextuid, r, RECTYPE_UID );
		c->ctl.nextuid = r->r.uid.next;
		rnum = r->r.uid.siglist;
	    }
	    if( !rnum ) {
		c->ctl.eof = 1;
		return -1;  /* return eof */
	    }
	    read_record( rnum, r, RECTYPE_SIG );
	    if( r->r.sig.lid != c->lid ) {
		log_error(_("chained sigrec %lu has a wrong owner\n"), rnum );
		c->ctl.eof = 1;
		tdbio_invalid();
	    }
	    c->ctl.index = 0;
	}
    } while( !r->r.sig.sig[c->ctl.index++].lid );

    c->sig_lid = r->r.sig.sig[c->ctl.index-1].lid;
    c->sig_flag = r->r.sig.sig[c->ctl.index-1].flag;
    return 0;
}
#endif

#if 0
static int
do_list_sigs( ulong root, ulong pk_lid, int depth,
	      LOCAL_ID_TABLE lids, unsigned *lineno )
{
    SIGREC_CONTEXT sx;
    int rc;
    u32 keyid[2];

    memset( &sx, 0, sizeof sx );
    sx.lid = pk_lid;
    for(;;) {
	rc = walk_sigrecs( &sx ); /* should we replace it and use */
	if( rc )
	    break;
	rc = keyid_from_lid( sx.sig_lid, keyid );
	if( rc ) {
	    printf("%6u: %*s????????.%lu:", *lineno, depth*4, "", sx.sig_lid );
	    print_sigflags( stdout, sx.sig_flag );
	    putchar('\n');
	    ++*lineno;
	}
	else {
	    printf("%6u: %*s%08lX.%lu:", *lineno, depth*4, "",
			      (ulong)keyid[1], sx.sig_lid );
	    print_sigflags( stdout, sx.sig_flag );
	    putchar(' ');
	    /* check whether we already checked this pk_lid */
	    if( !qry_lid_table_flag( ultikey_table, sx.sig_lid, NULL ) ) {
		print_user_id("[ultimately trusted]", keyid);
		++*lineno;
	    }
	    else if( sx.sig_lid == pk_lid ) {
		printf("[self-signature]\n");
		++*lineno;
	    }
	    else if( sx.sig_lid == root ) {
		printf("[closed]\n");
		++*lineno;
	    }
	    else if( ins_lid_table_item( lids, sx.sig_lid, *lineno ) ) {
		unsigned refline;
		qry_lid_table_flag( lids, sx.sig_lid, &refline );
		printf("[see line %u]\n", refline);
		++*lineno;
	    }
	    else if( depth+1 >= MAX_LIST_SIGS_DEPTH  ) {
		print_user_id( "[too deeply nested]", keyid );
		++*lineno;
	    }
	    else {
		print_user_id( "", keyid );
		++*lineno;
		rc = do_list_sigs( root, sx.sig_lid, depth+1, lids, lineno );
		if( rc )
		    break;
	    }
	}
    }
    return rc==-1? 0 : rc;
}
#endif
/****************
 * List all signatures of a public key
 */
static int
list_sigs( ulong pubkey_id )
{
    int rc=0;
  #if 0
    u32 keyid[2];
    LOCAL_ID_TABLE lids;
    unsigned lineno = 1;

    rc = keyid_from_lid( pubkey_id, keyid );
    if( rc )
	return rc;
    printf("Signatures of %08lX.%lu ", (ulong)keyid[1], pubkey_id );
    print_user_id("", keyid);
    printf("----------------------\n");

    lids = new_lid_table();
    rc = do_list_sigs( pubkey_id, pubkey_id, 0, lids, &lineno );
    putchar('\n');
    release_lid_table(lids);
  #endif
    return rc;
}

/****************
 * List all records of a public key
 */
static int
list_records( ulong lid )
{
    int rc;
    TRUSTREC dr, ur, rec;
    ulong recno;

    rc = tdbio_read_record( lid, &dr, RECTYPE_DIR );
    if( rc ) {
	log_error(_("lid %lu: read dir record failed: %s\n"),
						lid, g10_errstr(rc));
	return rc;
    }
    tdbio_dump_record( &dr, stdout );

    for( recno=dr.r.dir.keylist; recno; recno = rec.r.key.next ) {
	rc = tdbio_read_record( recno, &rec, 0 );
	if( rc ) {
	    log_error(_("lid %lu: read key record failed: %s\n"),
						lid, g10_errstr(rc));
	    return rc;
	}
	tdbio_dump_record( &rec, stdout );
    }

    for( recno=dr.r.dir.uidlist; recno; recno = ur.r.uid.next ) {
	rc = tdbio_read_record( recno, &ur, RECTYPE_UID );
	if( rc ) {
	    log_error(_("lid %lu: read uid record failed: %s\n"),
						lid, g10_errstr(rc));
	    return rc;
	}
	tdbio_dump_record( &ur, stdout );
	/* preference records */
	for(recno=ur.r.uid.prefrec; recno; recno = rec.r.pref.next ) {
	    rc = tdbio_read_record( recno, &rec, RECTYPE_PREF );
	    if( rc ) {
		log_error(_("lid %lu: read pref record failed: %s\n"),
						    lid, g10_errstr(rc));
		return rc;
	    }
	    tdbio_dump_record( &rec, stdout );
	}
	/* sig records */
	for(recno=ur.r.uid.siglist; recno; recno = rec.r.sig.next ) {
	    rc = tdbio_read_record( recno, &rec, RECTYPE_SIG );
	    if( rc ) {
		log_error(_("lid %lu: read sig record failed: %s\n"),
						    lid, g10_errstr(rc));
		return rc;
	    }
	    tdbio_dump_record( &rec, stdout );
	}
    }

    /* add cache record dump here */



    return rc;
}


/****************
 * Dump the complte trustdb or only the entries of one key.
 */
void
list_trustdb( const char *username )
{
    TRUSTREC rec;

    init_trustdb();

    if( username && *username == '#' ) {
	int rc;
	ulong lid = atoi(username+1);

	if( (rc = list_records( lid)) )
	    log_error(_("user '%s' read problem: %s\n"),
					    username, g10_errstr(rc));
	else if( (rc = list_sigs( lid )) )
	    log_error(_("user '%s' list problem: %s\n"),
					    username, g10_errstr(rc));
    }
    else if( username ) {
	PKT_public_key *pk = m_alloc_clear( sizeof *pk );
	int rc;

	if( (rc = get_pubkey_byname( NULL, pk, username, NULL )) )
	    log_error(_("user '%s' not found: %s\n"), username, g10_errstr(rc) );
	else if( (rc=tdbio_search_dir_bypk( pk, &rec )) && rc != -1 )
	    log_error(_("problem finding '%s' in trustdb: %s\n"),
						username, g10_errstr(rc));
	else if( rc == -1 )
	    log_error(_("user '%s' not in trustdb\n"), username);
	else if( (rc = list_records( pk->local_id)) )
	    log_error(_("user '%s' read problem: %s\n"),
						username, g10_errstr(rc));
	else if( (rc = list_sigs( pk->local_id )) )
	    log_error(_("user '%s' list problem: %s\n"),
						username, g10_errstr(rc));
	free_public_key( pk );
    }
    else {
	ulong recnum;
	int i;

	printf("TrustDB: %s\n", tdbio_get_dbname() );
	for(i=9+strlen(tdbio_get_dbname()); i > 0; i-- )
	    putchar('-');
	putchar('\n');
	for(recnum=0; !tdbio_read_record( recnum, &rec, 0); recnum++ )
	    tdbio_dump_record( &rec, stdout );
    }
}





/****************
 * Print a list of all defined owner trust value.
 */
void
export_ownertrust()
{
    TRUSTREC rec;
    TRUSTREC rec2;
    ulong recnum;
    int i;
    byte *p;
    int rc;

    init_trustdb();
    printf(_("# List of assigned trustvalues, created %s\n"
	     "# (Use \"gpg --import-ownertrust\" to restore them)\n"),
	   asctimestamp( make_timestamp() ) );
    for(recnum=0; !tdbio_read_record( recnum, &rec, 0); recnum++ ) {
	if( rec.rectype == RECTYPE_DIR ) {
	    if( !rec.r.dir.keylist ) {
		log_error(_("directory record w/o primary key\n"));
		continue;
	    }
	    if( !rec.r.dir.ownertrust )
		continue;
	    rc = tdbio_read_record( rec.r.dir.keylist, &rec2, RECTYPE_KEY);
	    if( rc ) {
		log_error(_("error reading key record: %s\n"), g10_errstr(rc));
		continue;
	    }
	    p = rec2.r.key.fingerprint;
	    for(i=0; i < rec2.r.key.fingerprint_len; i++, p++ )
		printf("%02X", *p );
	    printf(":%u:\n", (unsigned)rec.r.dir.ownertrust );
	}
    }
}


void
import_ownertrust( const char *fname )
{
    FILE *fp;
    int is_stdin=0;
    char line[256];
    char *p;
    size_t n, fprlen;
    unsigned otrust;

    init_trustdb();
    if( !fname || (*fname == '-' && !fname[1]) ) {
	fp = stdin;
	fname = "[stdin]";
	is_stdin = 1;
    }
    else if( !(fp = fopen( fname, "r" )) ) {
	log_error_f(fname, _("can't open file: %s\n"), strerror(errno) );
	return;
    }

    while( fgets( line, DIM(line)-1, fp ) ) {
	TRUSTREC rec;
	int rc;

	if( !*line || *line == '#' )
	    continue;
	n = strlen(line);
	if( line[n-1] != '\n' ) {
	    log_error_f(fname, _("line too long\n") );
	    /* ... or last line does not have a LF */
	    break; /* can't continue */
	}
	for(p = line; *p && *p != ':' ; p++ )
	    if( !isxdigit(*p) )
		break;
	if( *p != ':' ) {
	    log_error_f(fname, _("error: missing colon\n") );
	    continue;
	}
	fprlen = p - line;
	if( fprlen != 32 && fprlen != 40 ) {
	    log_error_f(fname, _("error: invalid fingerprint\n") );
	    continue;
	}
	if( sscanf(p, ":%u:", &otrust ) != 1 ) {
	    log_error_f(fname, _("error: no ownertrust value\n") );
	    continue;
	}
	if( !otrust )
	    continue; /* no otrust defined - no need to update or insert */
	/* convert the ascii fingerprint to binary */
	for(p=line, fprlen=0; *p != ':'; p += 2 )
	    line[fprlen++] = HEXTOBIN(p[0]) * 16 + HEXTOBIN(p[1]);
	line[fprlen] = 0;

      repeat:
	rc = tdbio_search_dir_byfpr( line, fprlen, 0, &rec );
	if( !rc ) { /* found: update */
	    if( rec.r.dir.ownertrust )
		log_info("LID %lu: changing trust from %u to %u\n",
			  rec.r.dir.lid, rec.r.dir.ownertrust, otrust );
	    else
		log_info("LID %lu: setting trust to %u\n",
				   rec.r.dir.lid, otrust );
	    rec.r.dir.ownertrust = otrust;
	    write_record( &rec );
	}
	else if( rc == -1 ) { /* not found; get the key from the ring */
	    PKT_public_key *pk = m_alloc_clear( sizeof *pk );

	    log_info_f(fname, _("key not in trustdb, searching ring.\n"));
	    rc = get_pubkey_byfprint( pk, line, fprlen );
	    if( rc )
		log_info_f(fname, _("key not in ring: %s\n"), g10_errstr(rc));
	    else {
		rc = query_trust_record( pk );	/* only as assertion */
		if( rc != -1 )
		    log_error_f(fname, _("Oops: key is now in trustdb???\n"));
		else {
		    rc = insert_trust_record_by_pk( pk );
		    if( !rc )
			goto repeat; /* update the ownertrust */
		    log_error_f(fname, _("insert trust record failed: %s\n"),
							   g10_errstr(rc) );
		}
	    }
	}
	else /* error */
	    log_error_f(fname, _("error finding dir record: %s\n"),
						    g10_errstr(rc));
    }
    if( ferror(fp) )
	log_error_f(fname, _("read error: %s\n"), strerror(errno) );
    if( !is_stdin )
	fclose(fp);
    do_sync();
    sync_trustdb();
}

