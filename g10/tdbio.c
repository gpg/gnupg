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



static void create_db( const char *fname );
static void open_db(void);

/**************************************************
 ************** read and write helpers ************
 **************************************************/

static void
fwrite_8(FILE *fp, byte a)
{
    if( putc( a & 0xff, fp ) == EOF )
	log_fatal("error writing byte to trustdb: %s\n", strerror(errno) );
}


static void
fwrite_32( FILE*fp, ulong a)
{
    putc( (a>>24) & 0xff, fp );
    putc( (a>>16) & 0xff, fp );
    putc( (a>> 8) & 0xff, fp );
    if( putc( a & 0xff, fp ) == EOF )
	log_fatal("error writing ulong to trustdb: %s\n", strerror(errno) );
}

static void
fwrite_zeros( FILE *fp, size_t n)
{
    while( n-- )
	if( putc( 0, fp ) == EOF )
	    log_fatal("error writing zeros to trustdb: %s\n", strerror(errno) );
}




/**************************************************
 ************** read and write stuff **************
 **************************************************/

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
	    create_db( fname );
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



/****************
 * Create a new trustdb
 */
static void
create_db( const char *fname )
{
    FILE *fp;

    fp =fopen( fname, "w" );
    if( !fp )
	log_fatal_f( fname, _("can't create %s: %s\n"), strerror(errno) );
    fwrite_8( fp, 1 );
    fwrite_8( fp, 'g' );
    fwrite_8( fp, 'p' );
    fwrite_8( fp, 'g' );
    fwrite_8( fp, 1 );	/* version */
    fwrite_zeros( fp, 3 ); /* reserved */
    fwrite_32( fp, 0 ); /* not locked */
    fwrite_32( fp, make_timestamp() ); /* created */
    fwrite_32( fp, 0 ); /* not yet modified */
    fwrite_32( fp, 0 ); /* not yet validated*/
    fwrite_32( fp, 0 ); /* reserved */
    fwrite_8( fp, 3 );	/* marginals needed */
    fwrite_8( fp, 1 );	/* completes needed */
    fwrite_8( fp, 4 );	/* max_cet_depth */
    fwrite_zeros( fp, 9 ); /* filler */
    fclose(fp);
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


void
tdbio_dump_record( ulong rnum, TRUSTREC *rec, FILE *fp	)
{
    int i, any;

    fprintf(fp, "rec %5lu, type=", rnum );

    switch( rec->rectype ) {
      case 0: fprintf(fp, "free\n");
	break;
      case RECTYPE_VER: fprintf(fp, "version\n");
	break;
      case RECTYPE_DIR:
	fprintf(fp, "dir keyid=%08lX, key=%lu, ctl=%lu, sig=%lu",
		    (ulong)rec->r.dir.keyid[1],
		    rec->r.dir.keyrec, rec->r.dir.ctlrec, rec->r.dir.sigrec );
	if( rec->r.dir.no_sigs == 1 )
	    fputs(", (none)", fp );
	else if( rec->r.dir.no_sigs == 2 )
	    fputs(", (invalid)", fp );
	else if( rec->r.dir.no_sigs == 3 )
	    fputs(", (revoked)", fp );
	else if( rec->r.dir.no_sigs )
	    fputs(", (??)", fp );
	putc('\n', fp);
	break;
      case RECTYPE_KEY: fprintf(fp,
		    "key %08lX, own=%lu, ownertrust=%02x, fl=%d\n",
		   (ulong)rec->r.key.keyid[1],
		   rec->r.key.owner, rec->r.key.ownertrust,
		   rec->r.key.fingerprint_len );
	break;
      case RECTYPE_UID:
	if( !rec->r.uid.subtype )
	    fprintf(fp,
		    "uid %02x%02x, owner=%lu, chain=%lu, pref=%lu, otr=%02x\n",
		   rec->r.uid.namehash[18], rec->r.uid.namehash[19],
		   rec->r.uid.owner, rec->r.uid.chain, (ulong)rec->r.uid.prefrec,
		   rec->r.uid.ownertrust );
	else
	    fprintf(fp,
		    "uid subtype%d, owner=%lu, chain=%lu\n",
		   rec->r.uid.subtype, rec->r.uid.owner, rec->r.uid.chain);
	break;
      case RECTYPE_CTL: fprintf(fp, "ctl\n");
	break;
      case RECTYPE_SIG:
	fprintf(fp, "sigrec, owner=%lu, chain=%lu\n",
			 rec->r.sig.owner, rec->r.sig.chain );
	for(i=any=0; i < SIGS_PER_RECORD; i++ ) {
	    if( rec->r.sig.sig[i].local_id ) {
		if( !any ) {
		    putc('\t', fp);
		    any++;
		}
		fprintf(fp, "  %lu:%02x", rec->r.sig.sig[i].local_id,
					      rec->r.sig.sig[i].flag );
	    }
	}
	if( any )
	    putc('\n', fp);
	break;
      default:
	fprintf(fp, "%d (unknown)\n", rec->rectype );
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
    p = buf;
    rec->rectype = *p++;
    if( expected && rec->rectype != expected ) {
	log_error("%lu: read expected rec type %d, got %d\n",
		    recnum, expected, rec->rectype );
	return G10ERR_TRUSTDB;
    }
    p++;
    switch( rec->rectype ) {
      case 0:  /* unused record */
	break;
      case RECTYPE_VER: /* version record */
	/* g10 was the original name */
	if( memcmp(buf+1, "gpg", 3 ) && memcmp(buf+1, "g10", 3 ) ) {
	    log_error_f( db_name, _("not a trustdb file\n") );
	    rc = G10ERR_TRUSTDB;
	}
	p += 2; /* skip magic */
	rec->r.ver.version  = *p++;
	rec->r.ver.locked   = buftoulong(p); p += 4;
	rec->r.ver.created  = buftoulong(p); p += 4;
	rec->r.ver.modified = buftoulong(p); p += 4;
	rec->r.ver.validated= buftoulong(p); p += 4;
	rec->r.ver.marginals_needed = *p++;
	rec->r.ver.completes_needed = *p++;
	rec->r.ver.max_cert_depth = *p++;
	if( recnum ) {
	    log_error_f( db_name, "version record with recnum %lu\n",
							     (ulong)recnum );
	    rc = G10ERR_TRUSTDB;
	}
	if( rec->r.ver.version != 1 ) {
	    log_error_f( db_name, "invalid file version %d\n",
							rec->r.ver.version );
	    rc = G10ERR_TRUSTDB;
	}
	break;
      case RECTYPE_DIR:   /*directory record */
	rec->r.dir.local_id = buftoulong(p); p += 4;
	rec->r.dir.keyid[0] = buftou32(p); p += 4;
	rec->r.dir.keyid[1] = buftou32(p); p += 4;
	rec->r.dir.keyrec   = buftoulong(p); p += 4;
	rec->r.dir.ctlrec   = buftoulong(p); p += 4;
	rec->r.dir.sigrec   = buftoulong(p); p += 4;
	rec->r.dir.no_sigs = *p++;
	if( rec->r.dir.local_id != recnum ) {
	    log_error_f( db_name, "dir local_id != recnum (%lu,%lu)\n",
					(ulong)rec->r.dir.local_id,
					(ulong)recnum );
	    rc = G10ERR_TRUSTDB;
	}
	break;
      case RECTYPE_KEY:   /* public key record */
	rec->r.key.owner    = buftoulong(p); p += 4;
	rec->r.dir.keyid[0] = buftou32(p); p += 4;
	rec->r.dir.keyid[1] = buftou32(p); p += 4;
	rec->r.key.pubkey_algo = *p++;
	rec->r.key.fingerprint_len = *p++;
	if( rec->r.key.fingerprint_len < 1 || rec->r.key.fingerprint_len > 20 )
	    rec->r.key.fingerprint_len = 20;
	memcpy( rec->r.key.fingerprint, p, 20); p += 20;
	rec->r.key.ownertrust = *p++;
	break;
      case RECTYPE_CTL:   /* control record */
	rec->r.ctl.owner    = buftoulong(p); p += 4;
	memcpy(rec->r.ctl.blockhash, p, 20); p += 20;
	rec->r.ctl.trustlevel = *p++;
	break;
      case RECTYPE_SIG:
	rec->r.sig.owner   = buftoulong(p); p += 4;
	rec->r.sig.chain   = buftoulong(p); p += 4;
	for(i=0; i < SIGS_PER_RECORD; i++ ) {
	    rec->r.sig.sig[i].local_id = buftoulong(p); p += 4;
	    rec->r.sig.sig[i].flag = *p++;
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
 */
int
tdbio_write_record( ulong recnum, TRUSTREC *rec )
{
    byte buf[TRUST_RECORD_LEN], *p;
    int rc = 0;
    int i, n;

    if( db_fd == -1 )
	open_db();

    memset(buf, 0, TRUST_RECORD_LEN);
    p = buf;
    *p++ = rec->rectype; p++;
    switch( rec->rectype ) {
      case 0:  /* unused record */
	break;
      case 1: /* version record */
	BUG();
	break;

      case RECTYPE_DIR:   /*directory record */
	ulongtobuf(p, rec->r.dir.local_id); p += 4;
	u32tobuf(p, rec->r.key.keyid[0]); p += 4;
	u32tobuf(p, rec->r.key.keyid[1]); p += 4;
	ulongtobuf(p, rec->r.dir.keyrec); p += 4;
	ulongtobuf(p, rec->r.dir.ctlrec); p += 4;
	ulongtobuf(p, rec->r.dir.sigrec); p += 4;
	*p++ = rec->r.dir.no_sigs;
	assert( rec->r.dir.local_id == recnum );
	break;

      case RECTYPE_KEY:
	ulongtobuf(p, rec->r.key.owner); p += 4;
	u32tobuf(p, rec->r.key.keyid[0]); p += 4;
	u32tobuf(p, rec->r.key.keyid[1]); p += 4;
	*p++ = rec->r.key.pubkey_algo;
	*p++ = rec->r.key.fingerprint_len;
	memcpy( p, rec->r.key.fingerprint, 20); p += 20;
	*p++ = rec->r.key.ownertrust;
	break;

      case RECTYPE_CTL:   /* control record */
	ulongtobuf(p, rec->r.ctl.owner); p += 4;
	memcpy(p, rec->r.ctl.blockhash, 20); p += 20;
	*p++ = rec->r.ctl.trustlevel;
	break;

      case RECTYPE_SIG:
	ulongtobuf(p, rec->r.sig.owner); p += 4;
	ulongtobuf(p, rec->r.sig.chain); p += 4;
	for(i=0; i < SIGS_PER_RECORD; i++ ) {
	    ulongtobuf(p, rec->r.sig.sig[i].local_id); p += 4;
	    *p++ = rec->r.sig.sig[i].flag;
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

    return rc;
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
    rc = tdbio_write_record(recnum, &rec );
    if( rc )
	log_fatal_f(db_name,_("failed to append a record: %s\n"),
					    g10_errstr(rc));
    return recnum ;
}



/****************
 * Search the trustdb for a key which matches PK and return the dir record
 * The local_id of PK is set to the correct value
 *
 * Note: To increase performance, we could use a index search here.
 */
int
tdbio_search_record( PKT_public_key *pk, TRUSTREC *rec )
{
    ulong recnum;
    u32 keyid[2];
    byte *fingerprint;
    size_t fingerlen;
    int rc;

    keyid_from_pk( pk, keyid );
    fingerprint = fingerprint_from_pk( pk, &fingerlen );
    assert( fingerlen == 20 || fingerlen == 16 );

    for(recnum=1; !(rc=tdbio_read_record( recnum, rec, 0)); recnum++ ) {
	if( rec->rectype != RECTYPE_DIR )
	    continue;
	if( rec->r.dir.keyid[0] == keyid[0]
	    && rec->r.dir.keyid[1] == keyid[1]){
	    TRUSTREC keyrec;

	    if( tdbio_read_record( rec->r.dir.keyrec, &keyrec, RECTYPE_KEY ) ) {
		log_error("%lu: ooops: invalid key record\n", recnum );
		break;
	    }
	    if( keyrec.r.key.pubkey_algo == pk->pubkey_algo
		&& !memcmp(keyrec.r.key.fingerprint, fingerprint, fingerlen) ){
		if( pk->local_id && pk->local_id != recnum )
		    log_error_f(db_name,
			       "found record, but local_id from memory does "
			       "not match recnum (%lu,%lu)\n",
				     (ulong)pk->local_id, (ulong)recnum );
		pk->local_id = recnum;
		return 0;
	    }
	}
    }
    if( rc != -1 )
	log_error_f( db_name, _("search_db failed: %s\n"), g10_errstr(rc) );
    return rc;
}


