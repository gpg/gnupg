/* tdbio.c
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
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "errors.h"
#include "iobuf.h"
#include "memory.h"
#include "util.h"
#include "options.h"
#include "main.h"
#include "i18n.h"
#include "trustdb.h"
#include "tdbio.h"



static char *db_name;
static int  db_fd = -1;


static void open_db(void);


int
tdbio_set_dbname( const char *new_dbname, int create )
{
    char *fname;

    fname = new_dbname? m_strdup( new_dbname )
		      : make_filename(opt.homedir, "trustdb.gpg", NULL );

    if( access( fname, R_OK ) ) {
	if( errno != ENOENT ) {
	    log_error_f( fname, _("can't access: %s\n"), strerror(errno) );
	    m_free(fname);
	    return G10ERR_TRUSTDB;
	}
	if( create ) {
	    FILE *fp;
	    TRUSTREC rec;
	    int rc;
	    char *p = strrchr( fname, '/' );

	    assert(p);
	    *p = 0;
	    if( access( fname, F_OK ) ) {
		if( strlen(fname) >= 7
		    && !strcmp(fname+strlen(fname)-7, "/.gnupg" ) ) {
		  #if __MINGW32__
		    if( mkdir( fname ) )
		  #else
		    if( mkdir( fname, S_IRUSR|S_IWUSR|S_IXUSR ) )
		  #endif
			log_fatal_f( fname, _("can't create directory: %s\n"),
							    strerror(errno) );
		}
		else
		    log_fatal_f(fname, _("directory does not exist!\n") );
	    }
	    *p = '/';

	    fp =fopen( fname, "w" );
	    if( !fp )
		log_fatal_f( fname, _("can't create: %s\n"), strerror(errno) );
	    fclose(fp);
	    m_free(db_name);
	    db_name = fname;
	    db_fd = open( db_name, O_RDWR );
	    if( db_fd == -1 )
		log_fatal_f( db_name, _("can't open: %s\n"), strerror(errno) );

	    memset( &rec, 0, sizeof rec );
	    rec.r.ver.version = 2;
	    rec.r.ver.created = make_timestamp();
	    rec.rectype = RECTYPE_VER;
	    rec.recnum = 0;
	    rc = tdbio_write_record( &rec );
	    if( rc )
		log_fatal_f( fname, _("failed to create version record: %s"),
							       g10_errstr(rc));
	    /* and read again to check that we are okay */
	    if( tdbio_read_record( 0, &rec, RECTYPE_VER ) )
		log_fatal_f( db_name, "invalid trust-db created\n" );
	    return 0;
	}
    }
    m_free(db_name);
    db_name = fname;
    return 0;
}


const char *
tdbio_get_dbname()
{
    return db_name;
}



static void
open_db()
{
    TRUSTREC rec;
    assert( db_fd == -1 );

    db_fd = open( db_name, O_RDWR );
    if( db_fd == -1 )
	log_fatal_f( db_name, _("can't open: %s\n"), strerror(errno) );
    if( tdbio_read_record( 0, &rec, RECTYPE_VER ) )
	log_fatal_f( db_name, _("invalid trust-db\n") );
    /* fixme: check ->locked and other stuff */
}


/****************
 * Return the record number of the keyhash tbl or create a new one.
 */
static ulong
get_keyhashrec()
{
    static ulong keyhashtbl; /* record number of the key hashtable */
    TRUSTREC vr;
    int rc;

    if( keyhashtbl )
	return keyhashtbl;

    rc = tdbio_read_record( 0, &vr, RECTYPE_VER );
    if( rc )
	log_fatal_f( db_name, _("error reading version record: %s\n"),
							g10_errstr(rc) );
    if( vr.r.ver.keyhashtbl )
	keyhashtbl = vr.r.ver.keyhashtbl;
    else {
	TRUSTREC rec;
	off_t offset;
	ulong recnum;
	int i, n;

	offset = lseek( db_fd, 0, SEEK_END );
	if( offset == -1 )
	    log_fatal("trustdb: lseek to end failed: %s\n", strerror(errno) );
	recnum = offset / TRUST_RECORD_LEN;
	assert(recnum); /* this is will never be the first record */

	keyhashtbl = recnum;
	/* Now write the records */
	n = (256+ITEMS_PER_HTBL_RECORD-1) / ITEMS_PER_HTBL_RECORD;
	for(i=0; i < n; i++, recnum++ ) {
	     memset( &rec, 0, sizeof rec );
	     rec.rectype = RECTYPE_HTBL; /* free record */
	     rec.recnum = recnum;
	     rc = tdbio_write_record( &rec );
	     if( rc )
		 log_fatal_f(db_name,_("failed to create hashtable: %s\n"),
						     g10_errstr(rc));
	}
	/* update the version record */
	vr.r.ver.keyhashtbl = keyhashtbl;
	rc = tdbio_write_record( &vr );
	if( rc )
	    log_fatal_f( db_name, _("error updating version record: %s\n"),
							     g10_errstr(rc));
    }
    return keyhashtbl;
}


/****************
 * Update the key hashtbl or create the table if it does not exist
 */
static int
update_keyhashtbl( TRUSTREC *kr )
{
    TRUSTREC lastrec, rec;
    ulong hashrec, item;
    int msb;
    int level=0;
    int rc, i;

    hashrec = get_keyhashrec();
  next_level:
    msb = kr->r.key.fingerprint[level];
    hashrec += msb / ITEMS_PER_HTBL_RECORD;
    rc = tdbio_read_record( hashrec, &rec, RECTYPE_HTBL );
    if( rc ) {
	log_error( db_name, "update_keyhashtbl read failed: %s\n",
							g10_errstr(rc) );
	return rc;
    }

    item = rec.r.htbl.item[msb % ITEMS_PER_HTBL_RECORD];
    if( !item ) { /* insert new one */
	rec.r.htbl.item[msb % ITEMS_PER_HTBL_RECORD] = kr->recnum;
	rc = tdbio_write_record( &rec );
	if( rc ) {
	    log_error( db_name, "update_keyhashtbl write htbl failed: %s\n",
							    g10_errstr(rc) );
	    return rc;
	}
    }
    else if( item != kr->recnum ) {  /* must do an update */
	lastrec = rec;
	rc = tdbio_read_record( item, &rec, 0 );
	if( rc ) {
	    log_error( db_name, "update_keyhashtbl read item failed: %s\n",
							    g10_errstr(rc) );
	    return rc;
	}
	if( rec.rectype == RECTYPE_HTBL ) {
	    hashrec = item;
	    level++;
	    if( level >= kr->r.key.fingerprint_len ) {
		log_error( db_name, "keyhashtbl has invalid indirections\n");
		return G10ERR_TRUSTDB;
	    }
	    goto next_level;
	}
	else if( rec.rectype == RECTYPE_HLST ) { /* extend list */
	    /* see whether the key is already in this list */
	    for(;;) {
		for(i=0; i < ITEMS_PER_HLST_RECORD; i++ ) {
		    if( rec.r.hlst.rnum[i] == kr->recnum ) {
			log_debug("HTBL: no update needed for keyrec %lu\n",
				    kr->recnum );
			return 0;
		    }
		}
		if( rec.r.hlst.next ) {
		    rc = tdbio_read_record( rec.r.hlst.next,
							&rec, RECTYPE_HLST);
		    if( rc ) {
			log_error( db_name,
				   "scan keyhashtbl read hlst failed: %s\n",
							     g10_errstr(rc) );
			return rc;
		    }
		}
		else
		    break; /* not there */
	    }
	    /* find the next free entry and put it in */
	    for(;;) {
		for(i=0; i < ITEMS_PER_HLST_RECORD; i++ ) {
		    if( !rec.r.hlst.rnum[i] ) {
			rec.r.hlst.rnum[i] = kr->recnum;
			rc = tdbio_write_record( &rec );
			if( rc )
			    log_error( db_name,
				   "update_keyhashtbl write hlst failed: %s\n",
							      g10_errstr(rc) );
			return rc; /* ready */
		    }
		}
		if( rec.r.hlst.next ) {
		    rc = tdbio_read_record( rec.r.hlst.next,
						      &rec, RECTYPE_HLST );
		    if( rc ) {
			log_error( db_name,
				   "update_keyhashtbl read hlst failed: %s\n",
							     g10_errstr(rc) );
			return rc;
		    }
		}
		else { /* add a new list record */
		    rec.r.hlst.next = item = tdbio_new_recnum();
		    rc = tdbio_write_record( &rec );
		    if( rc ) {
			log_error( db_name,
			       "update_keyhashtbl write hlst failed: %s\n",
							  g10_errstr(rc) );
			return rc;
		    }
		    memset( &rec, 0, sizeof rec );
		    rec.rectype = RECTYPE_HLST;
		    rec.recnum = item;
		    rec.r.hlst.rnum[0] = kr->recnum;
		    if( rc )
			log_error( db_name,
			       "update_keyhashtbl write ext hlst failed: %s\n",
							  g10_errstr(rc) );
		    return rc; /* ready */
		}
	    }
	}
	else if( rec.rectype == RECTYPE_KEY ) { /* insert a list record */
	    if( rec.recnum == kr->recnum ) {
		log_debug("HTBL: no update needed for keyrec %lu\n",
							 kr->recnum );
		return 0;
	    }
	    item = rec.recnum; /* save number of key record */
	    memset( &rec, 0, sizeof rec );
	    rec.rectype = RECTYPE_HLST;
	    rec.recnum = tdbio_new_recnum();
	    rec.r.hlst.rnum[0] = item;	     /* old keyrecord */
	    rec.r.hlst.rnum[1] = kr->recnum; /* and new one */
	    rc = tdbio_write_record( &rec );
	    if( rc ) {
		log_error( db_name,
		       "update_keyhashtbl write new hlst failed: %s\n",
						  g10_errstr(rc) );
		return rc;
	    }
	    /* update the hashtable record */
	    lastrec.r.htbl.item[msb % ITEMS_PER_HTBL_RECORD] = rec.recnum;
	    rc = tdbio_write_record( &lastrec );
	    if( rc )
		log_error( db_name,
		       "update_keyhashtbl update htbl failed: %s\n",
						  g10_errstr(rc) );
	    return rc; /* ready */
	}
	else {
	    log_error( db_name, "keyhashtbl %lu points to an invalid record\n",
								    item);
	    return G10ERR_TRUSTDB;
	}
    }

    return 0;
}



void
tdbio_dump_record( TRUSTREC *rec, FILE *fp  )
{
    int i;
    ulong rnum = rec->recnum;
    byte *p;

    fprintf(fp, "rec %5lu, ", rnum );

    switch( rec->rectype ) {
      case 0: fprintf(fp, "free\n");
	break;
      case RECTYPE_VER: fprintf(fp, "version, keyhashtbl=%lu\n",
	    rec->r.ver.keyhashtbl );
	break;
      case RECTYPE_DIR:
	fprintf(fp, "dir %lu, keys=%lu, uids=%lu, cach=%lu, ot=%02x",
		    rec->r.dir.lid,
		    rec->r.dir.keylist,
		    rec->r.dir.uidlist,
		    rec->r.dir.cacherec,
		    rec->r.dir.ownertrust );
	if( rec->r.dir.dirflags & DIRF_ERROR )
	    fputs(", error", fp );
	if( rec->r.dir.dirflags & DIRF_CHECKED )
	    fputs(", checked", fp );
	if( rec->r.dir.dirflags & DIRF_REVOKED )
	    fputs(", revoked", fp );
	if( rec->r.dir.dirflags & DIRF_MISKEY )
	    fputs(", miskey", fp );
	putc('\n', fp);
	break;
      case RECTYPE_KEY:
	fprintf(fp, "key %lu, next=%lu, algo=%d, ",
		   rec->r.key.lid,
		   rec->r.key.next,
		   rec->r.key.pubkey_algo );
	for(i=0; i < rec->r.key.fingerprint_len; i++ )
	    fprintf(fp, "%02X", rec->r.key.fingerprint[i] );
	if( rec->r.key.keyflags & KEYF_REVOKED )
	    fputs(", revoked", fp );
	putc('\n', fp);
	break;
      case RECTYPE_UID:
	fprintf(fp, "uid %lu, next=%lu, pref=%lu, sig=%lu, hash=%02X%02X",
		    rec->r.uid.lid,
		    rec->r.uid.next,
		    rec->r.uid.prefrec,
		    rec->r.uid.siglist,
		    rec->r.uid.namehash[18], rec->r.uid.namehash[19]);
	if( rec->r.uid.uidflags & UIDF_REVOKED )
	    fputs(", revoked", fp );
	putc('\n', fp);
	break;
      case RECTYPE_PREF:
	fprintf(fp, "pref %lu, next=%lu,",
		    rec->r.pref.lid, rec->r.pref.next);
	for(i=0,p=rec->r.pref.data; i < ITEMS_PER_PREF_RECORD; i+=2,p+=2 ) {
	    if( *p )
		fprintf(fp, " %c%d", *p == PREFTYPE_SYM    ? 'S' :
				     *p == PREFTYPE_HASH   ? 'H' :
				     *p == PREFTYPE_COMPR  ? 'Z' : '?', p[1]);
	}
	putc('\n', fp);
	break;
      case RECTYPE_SIG:
	fprintf(fp, "sig %lu, next=%lu,",
			 rec->r.sig.lid, rec->r.sig.next );
	for(i=0; i < SIGS_PER_RECORD; i++ ) {
	    if( rec->r.sig.sig[i].lid )
		fprintf(fp, " %lu:%02x", rec->r.sig.sig[i].lid,
					  rec->r.sig.sig[i].flag );
	}
	putc('\n', fp);
	break;
      case RECTYPE_CACH:
	fprintf(fp, "cach\n");
	break;
      case RECTYPE_HTBL:
	fprintf(fp, "htbl,");
	for(i=0; i < ITEMS_PER_HTBL_RECORD; i++ )
	    fprintf(fp, " %lu", rec->r.htbl.item[i] );
	putc('\n', fp);
	break;
      case RECTYPE_HLST:
	fprintf(fp, "hlst, next=%lu,", rec->r.hlst.next );
	for(i=0; i < ITEMS_PER_HLST_RECORD; i++ )
	    fprintf(fp, " %lu", rec->r.hlst.rnum[i] );
	putc('\n', fp);
	break;
      default:
	fprintf(fp, "unknown type %d\n", rec->rectype );
	break;
    }
}

/****************
 * read the record with number recnum
 * returns: -1 on error, 0 on success
 */
int
tdbio_read_record( ulong recnum, TRUSTREC *rec, int expected )
{
    byte buf[TRUST_RECORD_LEN], *p;
    int rc = 0;
    int n, i;

    if( db_fd == -1 )
	open_db();
    if( lseek( db_fd, recnum * TRUST_RECORD_LEN, SEEK_SET ) == -1 ) {
	log_error(_("trustdb: lseek failed: %s\n"), strerror(errno) );
	return G10ERR_READ_FILE;
    }
    n = read( db_fd, buf, TRUST_RECORD_LEN);
    if( !n ) {
	return -1; /* eof */
    }
    else if( n != TRUST_RECORD_LEN ) {
	log_error(_("trustdb: read failed (n=%d): %s\n"), n, strerror(errno) );
	return G10ERR_READ_FILE;
    }
    rec->recnum = recnum;
    p = buf;
    rec->rectype = *p++;
    if( expected && rec->rectype != expected ) {
	log_error("%lu: read expected rec type %d, got %d\n",
		    recnum, expected, rec->rectype );
	return G10ERR_TRUSTDB;
    }
    p++;    /* skip reserved byte */
    switch( rec->rectype ) {
      case 0:  /* unused (free) record */
	break;
      case RECTYPE_VER: /* version record */
	if( memcmp(buf+1, "gpg", 3 ) ) {
	    log_error_f( db_name, _("not a trustdb file\n") );
	    rc = G10ERR_TRUSTDB;
	}
	p += 2; /* skip "pgp" */
	rec->r.ver.version  = *p++;
	p += 3; /* reserved bytes */
	p += 4; /* lock flags */
	rec->r.ver.created  = buftoulong(p); p += 4;
	rec->r.ver.modified = buftoulong(p); p += 4;
	rec->r.ver.validated= buftoulong(p); p += 4;
	rec->r.ver.keyhashtbl=buftoulong(p); p += 4;
	if( recnum ) {
	    log_error_f( db_name, "version record with recnum %lu\n",
							     (ulong)recnum );
	    rc = G10ERR_TRUSTDB;
	}
	else if( rec->r.ver.version != 2 ) {
	    log_error_f( db_name, "invalid file version %d\n",
							rec->r.ver.version );
	    rc = G10ERR_TRUSTDB;
	}
	break;
      case RECTYPE_DIR:   /*directory record */
	rec->r.dir.lid	    = buftoulong(p); p += 4;
	rec->r.dir.keylist  = buftoulong(p); p += 4;
	rec->r.dir.uidlist  = buftoulong(p); p += 4;
	rec->r.dir.cacherec = buftoulong(p); p += 4;
	rec->r.dir.ownertrust = *p++;
	rec->r.dir.dirflags   = *p++;
	if( rec->r.dir.lid != recnum ) {
	    log_error_f( db_name, "dir LID != recnum (%lu,%lu)\n",
					 rec->r.dir.lid, (ulong)recnum );
	    rc = G10ERR_TRUSTDB;
	}
	break;
      case RECTYPE_KEY:   /* public key record */
	rec->r.key.lid	    = buftoulong(p); p += 4;
	rec->r.key.next     = buftoulong(p); p += 4;
	p += 7;
	rec->r.key.keyflags = *p++;
	rec->r.key.pubkey_algo = *p++;
	rec->r.key.fingerprint_len = *p++;
	if( rec->r.key.fingerprint_len < 1 || rec->r.key.fingerprint_len > 20 )
	    rec->r.key.fingerprint_len = 20;
	memcpy( rec->r.key.fingerprint, p, 20);
	break;
      case RECTYPE_UID:   /* user id record */
	rec->r.uid.lid	    = buftoulong(p); p += 4;
	rec->r.uid.next     = buftoulong(p); p += 4;
	rec->r.uid.prefrec  = buftoulong(p); p += 4;
	rec->r.uid.siglist  = buftoulong(p); p += 4;
	rec->r.uid.uidflags = *p++;
	p ++;
	memcpy( rec->r.uid.namehash, p, 20);
	break;
      case RECTYPE_PREF:  /* preference record */
	rec->r.pref.lid     = buftoulong(p); p += 4;
	rec->r.pref.next    = buftoulong(p); p += 4;
	memcpy( rec->r.pref.data, p, 30 );
	break;
      case RECTYPE_SIG:
	rec->r.sig.lid	   = buftoulong(p); p += 4;
	rec->r.sig.next    = buftoulong(p); p += 4;
	for(i=0; i < SIGS_PER_RECORD; i++ ) {
	    rec->r.sig.sig[i].lid  = buftoulong(p); p += 4;
	    rec->r.sig.sig[i].flag = *p++;
	}
	break;
      case RECTYPE_CACH:   /* cache record (FIXME)*/
	rec->r.cache.lid    = buftoulong(p); p += 4;
	memcpy(rec->r.cache.blockhash, p, 20); p += 20;
	rec->r.cache.trustlevel = *p++;
	break;
      case RECTYPE_HTBL:
	for(i=0; i < ITEMS_PER_HTBL_RECORD; i++ ) {
	    rec->r.htbl.item[i] = buftoulong(p); p += 4;
	}
	break;
      case RECTYPE_HLST:
	rec->r.hlst.next = buftoulong(p); p += 4;
	for(i=0; i < ITEMS_PER_HLST_RECORD; i++ ) {
	    rec->r.hlst.rnum[i] = buftoulong(p); p += 4;
	}
	break;
      default:
	log_error_f( db_name, "invalid record type %d at recnum %lu\n",
					      rec->rectype, (ulong)recnum );
	rc = G10ERR_TRUSTDB;
	break;
    }

    return rc;
}

/****************
 * Write the record at RECNUM
 * FIXME: create/update keyhash record.
 */
int
tdbio_write_record( TRUSTREC *rec )
{
    byte buf[TRUST_RECORD_LEN], *p;
    int rc = 0;
    int i, n;
    ulong recnum = rec->recnum;

    if( db_fd == -1 )
	open_db();

    memset(buf, 0, TRUST_RECORD_LEN);
    p = buf;
    *p++ = rec->rectype; p++;
    switch( rec->rectype ) {
      case 0:  /* unused record */
	break;
      case RECTYPE_VER: /* version record */
	if( recnum )
	    BUG();
	memcpy(p-1, "gpg", 3 ); p += 2;
	*p++ = rec->r.ver.version;
	p += 7; /* skip reserved bytes and lock flags */
	ulongtobuf(p, rec->r.ver.created); p += 4;
	ulongtobuf(p, rec->r.ver.modified); p += 4;
	ulongtobuf(p, rec->r.ver.validated); p += 4;
	ulongtobuf(p, rec->r.ver.keyhashtbl); p += 4;
	break;

      case RECTYPE_DIR:   /*directory record */
	ulongtobuf(p, rec->r.dir.lid); p += 4;
	ulongtobuf(p, rec->r.dir.keylist); p += 4;
	ulongtobuf(p, rec->r.dir.uidlist); p += 4;
	ulongtobuf(p, rec->r.dir.cacherec); p += 4;
	*p++ = rec->r.dir.ownertrust;
	*p++ = rec->r.dir.dirflags;
	assert( rec->r.dir.lid == recnum );
	break;

      case RECTYPE_KEY:
	ulongtobuf(p, rec->r.key.lid); p += 4;
	ulongtobuf(p, rec->r.key.next); p += 4;
	p += 7;
	*p++ = rec->r.key.keyflags;
	*p++ = rec->r.key.pubkey_algo;
	*p++ = rec->r.key.fingerprint_len;
	memcpy( p, rec->r.key.fingerprint, 20); p += 20;
	break;

      case RECTYPE_UID:   /* user id record */
	ulongtobuf(p, rec->r.uid.lid); p += 4;
	ulongtobuf(p, rec->r.uid.next); p += 4;
	ulongtobuf(p, rec->r.uid.prefrec); p += 4;
	ulongtobuf(p, rec->r.uid.siglist); p += 4;
	*p++ = rec->r.uid.uidflags;
	p++;
	memcpy( p, rec->r.uid.namehash, 20 ); p += 20;
	break;

      case RECTYPE_PREF:
	ulongtobuf(p, rec->r.pref.lid); p += 4;
	ulongtobuf(p, rec->r.pref.next); p += 4;
	memcpy( p, rec->r.pref.data, 30 );
	break;

      case RECTYPE_SIG:
	ulongtobuf(p, rec->r.sig.lid); p += 4;
	ulongtobuf(p, rec->r.sig.next); p += 4;
	for(i=0; i < SIGS_PER_RECORD; i++ ) {
	    ulongtobuf(p, rec->r.sig.sig[i].lid); p += 4;
	    *p++ = rec->r.sig.sig[i].flag;
	}
	break;

      case RECTYPE_CACH:   /* FIXME*/
	ulongtobuf(p, rec->r.cache.lid); p += 4;
	memcpy(p, rec->r.cache.blockhash, 20); p += 20;
	*p++ = rec->r.cache.trustlevel;
	break;

      case RECTYPE_HTBL:
	for(i=0; i < ITEMS_PER_HTBL_RECORD; i++ ) {
	    ulongtobuf( p, rec->r.htbl.item[i]); p += 4;
	}
	break;

      case RECTYPE_HLST:
	ulongtobuf( p, rec->r.hlst.next); p += 4;
	for(i=0; i < ITEMS_PER_HLST_RECORD; i++ ) {
	    ulongtobuf( p, rec->r.hlst.rnum[i]); p += 4;
	}
	break;

      default:
	BUG();
    }

    if( lseek( db_fd, recnum * TRUST_RECORD_LEN, SEEK_SET ) == -1 ) {
	log_error(_("trustdb: lseek failed: %s\n"), strerror(errno) );
	return G10ERR_WRITE_FILE;
    }
    n = write( db_fd, buf, TRUST_RECORD_LEN);
    if( n != TRUST_RECORD_LEN ) {
	log_error(_("trustdb: write failed (n=%d): %s\n"), n, strerror(errno) );
	return G10ERR_WRITE_FILE;
    }
    else if( rec->rectype == RECTYPE_KEY )
	rc = update_keyhashtbl( rec );

    return rc;
}

int
tdbio_delete_record( ulong recnum )
{
    TRUSTREC rec;

    rec.recnum = recnum;
    rec.rectype = 0;
    return tdbio_write_record( &rec );
}

/****************
 * create a new record and return its record number
 */
ulong
tdbio_new_recnum()
{
    off_t offset;
    ulong recnum;
    TRUSTREC rec;
    int rc;

    /* fixme: look for unused records */
    offset = lseek( db_fd, 0, SEEK_END );
    if( offset == -1 )
	log_fatal("trustdb: lseek to end failed: %s\n", strerror(errno) );
    recnum = offset / TRUST_RECORD_LEN;
    assert(recnum); /* this is will never be the first record */

    /* we must write a record, so that the next call to this function
     * returns another recnum */
    memset( &rec, 0, sizeof rec );
    rec.rectype = 0; /* free record */
    rec.recnum = recnum;
    rc = tdbio_write_record( &rec );
    if( rc )
	log_fatal_f(db_name,_("failed to append a record: %s\n"),
					    g10_errstr(rc));
    return recnum ;
}



/****************
 * Search the trustdb for a key which matches PK and return the dir record
 * The local_id of PK is set to the correct value
 */
int
tdbio_search_dir_bypk( PKT_public_key *pk, TRUSTREC *rec )
{
    byte *fingerprint;
    size_t fingerlen;
    u32 keyid[2];
    int rc;

    keyid_from_pk( pk, keyid );
    fingerprint = fingerprint_from_pk( pk, NULL, &fingerlen );
    rc = tdbio_search_dir_byfpr( fingerprint, fingerlen,
				 pk->pubkey_algo, rec );

    if( !rc ) {
	if( pk->local_id && pk->local_id != rec->recnum )
	    log_error_f(db_name,
		       "found record, but LID from memory does "
		       "not match recnum (%lu,%lu)\n",
				      pk->local_id, rec->recnum );
	pk->local_id = rec->recnum;
    }
    return rc;
}


int
tdbio_search_dir_byfpr( const byte *fingerprint, size_t fingerlen,
			int pubkey_algo, TRUSTREC *rec )
{
    ulong recnum;
    int rc;
    ulong hashrec, item;
    int msb;
    int level=0;

    assert( fingerlen == 20 || fingerlen == 16 );

    /* locate the key using the hash table */
    hashrec = get_keyhashrec();
  next_level:
    msb = fingerprint[level];
    hashrec += msb / ITEMS_PER_HTBL_RECORD;
    rc = tdbio_read_record( hashrec, rec, RECTYPE_HTBL );
    if( rc ) {
	log_error( db_name, "scan keyhashtbl failed: %s\n", g10_errstr(rc) );
	return rc;
    }

    item = rec->r.htbl.item[msb % ITEMS_PER_HTBL_RECORD];
    if( !item )
	return -1; /* not found */

    rc = tdbio_read_record( item, rec, 0 );
    if( rc ) {
	log_error( db_name, "keyhashtbl read failed: %s\n", g10_errstr(rc) );
	return rc;
    }
    if( rec->rectype == RECTYPE_HTBL ) {
	hashrec = item;
	level++;
	if( level >= fingerlen ) {
	    log_error( db_name, "keyhashtbl has invalid indirections\n");
	    return G10ERR_TRUSTDB;
	}
	goto next_level;
    }
    else if( rec->rectype == RECTYPE_HLST ) {
	for(;;) {
	    int i;

	    for(i=0; i < ITEMS_PER_HLST_RECORD; i++ ) {
		if( rec->r.hlst.rnum[i] ) {
		    TRUSTREC tmp;

		    rc = tdbio_read_record( rec->r.hlst.rnum[i],
					     &tmp, RECTYPE_KEY );
		    if( rc ) {
			log_error( db_name,
				   "scan keyhashtbl read key failed: %s\n",
							     g10_errstr(rc) );
			return rc;
		    }
		    if( (!pubkey_algo || tmp.r.key.pubkey_algo == pubkey_algo)
			&& tmp.r.key.fingerprint_len == fingerlen
			&& !memcmp(tmp.r.key.fingerprint,
					    fingerprint, fingerlen) ) {
			*rec = tmp;
			goto found;
		    }
		}
	    }
	    if( rec->r.hlst.next ) {
		rc = tdbio_read_record( rec->r.hlst.next, rec, RECTYPE_HLST );
		if( rc ) {
		    log_error( db_name,
			       "scan keyhashtbl read hlst failed: %s\n",
							 g10_errstr(rc) );
		    return rc;
		}
	    }
	    else
		return -1; /* not found */
	}
      found:
	;
    }
    else if( rec->rectype == RECTYPE_KEY ) {
	/* must check that it is the requested key */
	if( (pubkey_algo && rec->r.key.pubkey_algo != pubkey_algo)
	    || rec->r.key.fingerprint_len != fingerlen
	    || memcmp(rec->r.key.fingerprint, fingerprint, fingerlen) )
	    return -1; /* no: not found */
    }
    else {
	log_error( db_name, "keyhashtbl %lu points to an invalid record\n",
								item);
	return G10ERR_TRUSTDB;
    }

    recnum = rec->r.key.lid;
    /* Now read the dir record */
    rc = tdbio_read_record( recnum, rec, RECTYPE_DIR);
    if( rc )
	log_error_f(db_name, "can't read dirrec %lu: %s\n",
						recnum, g10_errstr(rc) );

    return rc;
}

static int
del_reclist( ulong recno, int type )
{
    TRUSTREC rec;
    int rc;

    while( recno ) {
	rc = tdbio_read_record( recno, &rec, type);
	if( rc ) {
	    log_error_f(db_name, "can't read record %lu: %s\n",
						recno, g10_errstr(rc));
	    return rc;
	}
	switch( type ) {
	    case RECTYPE_PREF: recno = rec.r.pref.next; break;
	    case RECTYPE_UID:  recno = rec.r.uid.next;	break;
	    default: BUG();
	}
	rc = tdbio_delete_record( rec.recnum );
	if( rc ) {
	    log_error_f(db_name, "can't delete record %lu: %s\n",
						rec.recnum, g10_errstr(rc));
	    return rc;
	}
    }
    return 0;
}

/****************
 * Delete the Userid UIDLID from DIRLID
 */
int
tdbio_delete_uidrec( ulong dirlid, ulong uidlid )
{
    TRUSTREC dirrec, rec;
    ulong recno;
    int rc;

    rc = tdbio_read_record( dirlid, &dirrec, RECTYPE_DIR);
    if( rc ) {
	log_error_f(db_name, "can't read dirrec %lu: %s\n", dirlid, g10_errstr(rc));
	return rc;
    }
    recno = dirrec.r.dir.uidlist;
    for( ; recno; recno = rec.r.uid.next ) {
	rc = tdbio_read_record( recno, &rec, RECTYPE_UID);
	if( rc ) {
	    log_error_f(db_name, "can't read uidrec %lu: %s\n",
						    recno, g10_errstr(rc));
	    return rc;
	}
	if( recno == uidlid ) {
	    rc = del_reclist( rec.r.uid.prefrec, RECTYPE_PREF );
	    if( rc )
		return rc;
	    rc = del_reclist( rec.r.uid.siglist, RECTYPE_SIG );
	    if( rc )
		return rc;
	    rc = tdbio_delete_record( recno );
	    if( rc ) {
		log_error_f(db_name, "can't delete uidrec %lu: %s\n",
						    recno, g10_errstr(rc));
		return rc;
	    }
	    dirrec.r.dir.uidlist = 0;
	    rc = tdbio_write_record( &dirrec );
	    if( rc ) {
		log_error_f(db_name, "can't update dirrec %lu: %s\n",
						  dirrec.recnum, g10_errstr(rc));
		return rc;
	    }
	    return 0;
	}
    }
    return -1; /* not found */
}


