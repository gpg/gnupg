/* ringedit.c -  Function for key ring editing
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


/****************
 * This module supplies function for:
 *
 *  - Search for a key block (pubkey and all other stuff) and return a
 *    handle for it.
 *
 *  - Lock/Unlock a key block
 *
 *  - Read a key block into a tree
 *
 *  - Update a key block
 *
 *  - Insert a new key block
 *
 *  - Delete a key block
 *
 */



#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h> /* for truncate */
#include <assert.h>
#ifdef HAVE_LIBGDBM
  #include <gdbm.h>
#endif
#include "util.h"
#include "packet.h"
#include "memory.h"
#include "mpi.h"
#include "iobuf.h"
#include "keydb.h"
#include "host2net.h"
#include "options.h"
#include "main.h"
#include "i18n.h"




struct resource_table_struct {
    int used;
    int secret; /* this is a secret keyring */
    char *fname;
    IOBUF iobuf;
  #ifdef HAVE_LIBGDBM
    GDBM_FILE dbf;
  #endif
    enum resource_type rt;
    DOTLOCK lockhd;
    int    is_locked;
};
typedef struct resource_table_struct RESTBL;

#define MAX_RESOURCES 10
static RESTBL resource_table[MAX_RESOURCES];
static int default_public_resource;
static int default_secret_resource;

static int search( PACKET *pkt, KBPOS *kbpos, int secret );


static int keyring_search( PACKET *pkt, KBPOS *kbpos, IOBUF iobuf,
						const char *fname );
static int keyring_read( KBPOS *kbpos, KBNODE *ret_root );
static int keyring_enum( KBPOS *kbpos, KBNODE *ret_root, int skipsigs );
static int keyring_copy( KBPOS *kbpos, int mode, KBNODE root );

#ifdef HAVE_LIBGDBM
static int do_gdbm_store( KBPOS *kbpos, KBNODE root, int update );
static int do_gdbm_locate( GDBM_FILE dbf, KBPOS *kbpos,
					  const byte *fpr, int fprlen );
static int do_gdbm_locate_by_keyid( GDBM_FILE dbf, KBPOS *kbpos, u32 *keyid );
static int do_gdbm_read( KBPOS *kbpos, KBNODE *ret_root );
static int do_gdbm_enum( KBPOS *kbpos, KBNODE *ret_root );
#endif


static RESTBL *
check_pos( KBPOS *kbpos )
{
    if( kbpos->resno < 0 || kbpos->resno >= MAX_RESOURCES )
	return NULL;
    if( !resource_table[kbpos->resno].used )
	return NULL;
    return resource_table + kbpos->resno;
}

#ifdef HAVE_LIBGDBM
static void
fatal_gdbm_error( const char *string )
{
    log_fatal("gdbm failed: %s\n", string);
}

#endif /* HAVE_LIBGDBM */


/****************
 * Hmmm, how to avoid deadlock? They should not happen if everyone
 * locks the key resources in the same order; but who knows.
 * A solution is to use only one lock file in the gnupg homedir but
 * what will happen with key resources which normally don't belong
 * to the gpg homedir?
 */
static void
lock_rentry( RESTBL *rentry )
{
    if( !rentry->lockhd ) {
	rentry->lockhd = create_dotlock( rentry->fname );
	if( !rentry->lockhd )
	    log_fatal("can't allocate lock for `%s'\n", rentry->fname );
	rentry->is_locked = 0;
    }
    if( !rentry->is_locked ) {
	if( make_dotlock( rentry->lockhd, -1 ) )
	    log_fatal("can't lock `%s'\n", rentry->fname );
	rentry->is_locked = 1;
    }
}

static void
unlock_rentry( RESTBL *rentry )
{
    if( opt.lock_once )
	return;
    if( !release_dotlock( rentry->lockhd ) )
	rentry->is_locked = 0;
}


/****************************************************************
 ****************** public functions ****************************
 ****************************************************************/

/****************
 * Get the name of the keyrings, start with a sequence number pointing to a 0.
 */
const char *
enum_keyblock_resources( int *sequence, int secret )
{
    int i = *sequence;
    const char *name = NULL;

    for(; i < MAX_RESOURCES; i++ )
	if( resource_table[i].used && !resource_table[i].secret == !secret ) {
	    if( resource_table[i].fname ) {
		name = resource_table[i].fname;
		break;
	    }
	}
    *sequence = ++i;
    return name;
}


/****************
 * Register a resource (which currently may only be a keyring file).
 * The first keyring which is added by this function is
 * created if it does not exist.
 * Note: this function may be called before secure memory is
 * available.
 */
int
add_keyblock_resource( const char *url, int force, int secret )
{
    static int any_secret, any_public;
    const char *resname = url;
    IOBUF iobuf = NULL;
    int i;
    char *filename = NULL;
    int rc = 0;
    enum resource_type rt = rt_UNKNOWN;
    const char *created_fname = NULL;

    /* Do we have an URL?
     *	gnupg-gdbm:filename  := this is a GDBM resource
     *	gnupg-ring:filename  := this is a plain keyring
     *	filename := See what is is, but create as plain keyring.
     */
    if( strlen( resname ) > 11 ) {
	if( !strncmp( resname, "gnupg-ring:", 11 ) ) {
	    rt = rt_RING;
	    resname += 11;
	}
	else if( !strncmp( resname, "gnupg-gdbm:", 11 ) ) {
	    rt = rt_GDBM;
	    resname += 11;
	}
      #ifndef HAVE_DRIVE_LETTERS
	else if( strchr( resname, ':' ) ) {
	    log_error("%s: invalid URL\n", url );
	    rc = G10ERR_GENERAL;
	    goto leave;
	}
      #endif
    }

    if( *resname != '/' ) { /* do tilde expansion etc */
	if( strchr(resname, '/') )
	    filename = make_filename(resname, NULL);
	else
	    filename = make_filename(opt.homedir, resname, NULL);
    }
    else
	filename = m_strdup( resname );

    if( !force )
	force = secret? !any_secret : !any_public;

    for(i=0; i < MAX_RESOURCES; i++ )
	if( !resource_table[i].used )
	    break;
    if( i == MAX_RESOURCES ) {
	rc = G10ERR_RESOURCE_LIMIT;
	goto leave;
    }

    /* see whether we can determine the filetype */
    if( rt == rt_UNKNOWN ) {
	FILE *fp = fopen( filename, "rb" );

	if( fp ) {
	    u32 magic;

	    if( fread( &magic, 4, 1, fp) == 1 ) {
		if( magic == 0x13579ace )
		    rt = rt_GDBM;
		else if( magic == 0xce9a5713 )
		    log_error("%s: endianess does not match\n", url );
		else
		    rt = rt_RING;
	    }
	    else /* maybe empty: assume ring */
		rt = rt_RING;
	    fclose( fp );
	}
	else /* no file yet: create ring */
	    rt = rt_RING;
    }

    switch( rt ) {
      case rt_UNKNOWN:
	log_error("%s: unknown resource type\n", url );
	rc = G10ERR_GENERAL;
	goto leave;

      case rt_RING:
	iobuf = iobuf_open( filename );
	if( !iobuf && !force ) {
	    rc = G10ERR_OPEN_FILE;
	    goto leave;
	}

	if( !iobuf ) {
	    char *last_slash_in_filename;

	    last_slash_in_filename = strrchr(filename, '/');
	    *last_slash_in_filename = 0;

	    if( access(filename, F_OK) ) {
		/* on the first time we try to create the default homedir and
		 * in this case the process will be terminated, so that on the
		 * next invocation it can read the options file in on startup
		 */
		try_make_homedir( filename );
		rc = G10ERR_OPEN_FILE;
		goto leave;
	    }

	    *last_slash_in_filename = '/';

	    iobuf = iobuf_create( filename );
	    if( !iobuf ) {
		log_error(_("%s: can't create keyring: %s\n"),
					    filename, strerror(errno));
		rc = G10ERR_OPEN_FILE;
		goto leave;
	    }
	    else {
	      #ifndef HAVE_DOSISH_SYSTEM
		if( secret ) {
		    if( chmod( filename, S_IRUSR | S_IWUSR ) ) {
			log_error("%s: chmod failed: %s\n",
						filename, strerror(errno) );
			rc = G10ERR_WRITE_FILE;
			goto leave;
		    }
		}
	      #endif
		if( !opt.quiet )
		    log_info(_("%s: keyring created\n"), filename );
                created_fname = filename;
	    }
	}
      #if HAVE_DOSISH_SYSTEM || 1
	iobuf_close( iobuf );
	iobuf = NULL;
        if (created_fname) /* must invalidate that ugly cache */
            iobuf_ioctl (NULL, 2, 0, (char*)created_fname);
      #endif
	break;

    #ifdef HAVE_LIBGDBM
      case rt_GDBM:
	resource_table[i].dbf = gdbm_open( filename, 0,
					   force? GDBM_WRCREAT : GDBM_WRITER,
					   S_IRUSR | S_IWUSR |
					   S_IRGRP | S_IWGRP | S_IROTH,
					   fatal_gdbm_error );
	if( !resource_table[i].dbf ) {
	    log_error("%s: can't open gdbm file: %s\n",
			    filename, gdbm_strerror(gdbm_errno));
	    rc = G10ERR_OPEN_FILE;
	    goto leave;
	}
	break;
    #endif

      default:
	log_error("%s: unsupported resource type\n", url );
	rc = G10ERR_GENERAL;
	goto leave;
    }

  #ifndef HAVE_DOSISH_SYSTEM
  #if 0 /* fixme: check directory permissions and print a warning */
    if( secret ) {
    }
  #endif
  #endif

    /* fixme: avoid duplicate resources */
    resource_table[i].used = 1;
    resource_table[i].secret = !!secret;
    resource_table[i].fname = m_strdup(filename);
    resource_table[i].iobuf = iobuf;
    resource_table[i].rt    = rt;
    if( secret )
	default_secret_resource = i;
    else
	default_public_resource = i;

  leave:
    if( rc )
	log_error("keyblock resource `%s': %s\n", filename, g10_errstr(rc) );
    else if( secret )
	any_secret = 1;
    else
	any_public = 1;
    m_free( filename );
    return rc;
}

/****************
 * Return the resource name of the keyblock associated with KBPOS.
 */
const char *
keyblock_resource_name( KBPOS *kbpos )
{
    RESTBL *rentry;

    if( !(rentry = check_pos( kbpos )) || !rentry->fname )
	log_bug("no name for keyblock resource %d\n", kbpos->resno );
    return rentry->fname;
}


/****************
 * Get a keyblock handle KBPOS from a filename. This can be used
 * to get a handle for insert_keyblock for a new keyblock.
 * Using a filename of NULL returns the default resource
 */
int
get_keyblock_handle( const char *filename, int secret, KBPOS *kbpos )
{
    int i = 0;

    if( !filename )
	i = secret? default_secret_resource : default_public_resource;

    for(; i < MAX_RESOURCES; i++ ) {
	if( resource_table[i].used && !resource_table[i].secret == !secret ) {
	    /* fixme: dos needs case insensitive file compare */
	    if( !filename || !strcmp( resource_table[i].fname, filename ) ) {
		memset( kbpos, 0, sizeof *kbpos );
		kbpos->resno = i;
		kbpos->rt = resource_table[i].rt;
		return 0;
	    }
	}
    }
    return -1; /* not found */
}


/****************
 * Return the filename of the firstkeyblock resource which is intended
 * for write access. This will either be the default resource or in
 * case this is not writable one of the others.  If no writable is found,
 * the default filename in the homedirectory will be returned.
 * Caller must free, will never return NULL.
 */
char *
get_writable_keyblock_file( int secret )
{
    int i = secret? default_secret_resource : default_public_resource;

    if( resource_table[i].used && !resource_table[i].secret == !secret ) {
	if( !access( resource_table[i].fname, R_OK|W_OK ) ) {
	    return m_strdup( resource_table[i].fname );
	}
    }
    for(i=0; i < MAX_RESOURCES; i++ ) {
	if( resource_table[i].used && !resource_table[i].secret == !secret ) {
	    if( !access( resource_table[i].fname, R_OK|W_OK ) ) {
		return m_strdup( resource_table[i].fname );
	    }
	}
    }
    /* Assume the home dir is always writable */
    return  make_filename(opt.homedir, secret? "secring.gpg"
					     : "pubring.gpg", NULL );
}


/****************
 * Search a keyblock which starts with the given packet and puts all
 * information into KBPOS, which can be used later to access this key block.
 * This function looks into all registered keyblock sources.
 * PACKET must be a packet with either a secret_key or a public_key
 *
 * This function is intended to check whether a given certificate
 * is already in a keyring or to prepare it for editing.
 *
 * Returns: 0 if found, -1 if not found or an errorcode.
 */
static int
search( PACKET *pkt, KBPOS *kbpos, int secret )
{
    int i, rc, last_rc=-1;

    for(i=0; i < MAX_RESOURCES; i++ ) {
	if( resource_table[i].used && !resource_table[i].secret == !secret ) {
	    switch( resource_table[i].rt ) {
	      case rt_RING:
		rc = keyring_search( pkt, kbpos, resource_table[i].iobuf,
						 resource_table[i].fname );
		break;
	     #ifdef HAVE_LIBGDBM
	      case rt_GDBM: {
		    PKT_public_key *req_pk = pkt->pkt.public_key;
		    byte fpr[20];
		    size_t fprlen;

		    fingerprint_from_pk( req_pk, fpr, &fprlen );
		    rc = do_gdbm_locate( resource_table[i].dbf,
					 kbpos, fpr, fprlen );
		}
		break;
	     #endif
	      default: BUG();
	    }

	    kbpos->rt = resource_table[i].rt;
	    if( !rc ) {
		kbpos->resno = i;
		kbpos->fp = NULL;
		return 0;
	    }
	    if( rc != -1 ) {
		log_error("error searching resource %d: %s\n",
						  i, g10_errstr(rc));
		last_rc = rc;
	    }
	}
    }
    return last_rc;
}


/****************
 * Combined function to search for a username and get the position
 * of the keyblock.
 */
int
find_keyblock_byname( KBPOS *kbpos, const char *username )
{
    PACKET pkt;
    PKT_public_key *pk = m_alloc_clear( sizeof *pk );
    int rc;

    rc = get_pubkey_byname( NULL, pk, username, NULL );
    if( rc ) {
	free_public_key(pk);
	return rc;
    }

    init_packet( &pkt );
    pkt.pkttype = PKT_PUBLIC_KEY;
    pkt.pkt.public_key = pk;
    rc = search( &pkt, kbpos, 0 );
    free_public_key(pk);
    return rc;
}


/****************
 * Combined function to search for a key and get the position
 * of the keyblock.
 */
int
find_keyblock_bypk( KBPOS *kbpos, PKT_public_key *pk )
{
    PACKET pkt;
    int rc;

    init_packet( &pkt );
    pkt.pkttype = PKT_PUBLIC_KEY;
    pkt.pkt.public_key = pk;
    rc = search( &pkt, kbpos, 0 );
    return rc;
}

/****************
 * Combined function to search for a key and get the position
 * of the keyblock.
 */
int
find_keyblock_bysk( KBPOS *kbpos, PKT_secret_key *sk )
{
    PACKET pkt;
    int rc;

    init_packet( &pkt );
    pkt.pkttype = PKT_SECRET_KEY;
    pkt.pkt.secret_key = sk;
    rc = search( &pkt, kbpos, 0 );
    return rc;
}


/****************
 * Combined function to search for a username and get the position
 * of the keyblock. This function does not unprotect the secret key.
 */
int
find_secret_keyblock_byname( KBPOS *kbpos, const char *username )
{
    PACKET pkt;
    PKT_secret_key *sk = m_alloc_clear( sizeof *sk );
    int rc;

    rc = get_seckey_byname( sk, username, 0 );
    if( rc ) {
	free_secret_key(sk);
	return rc;
    }

    init_packet( &pkt );
    pkt.pkttype = PKT_SECRET_KEY;
    pkt.pkt.secret_key = sk;
    rc = search( &pkt, kbpos, 1 );
    free_secret_key(sk);
    return rc;
}


/****************
 * Locate a keyblock in a database which is capable of direct access
 * Put all information into KBPOS, which can be later be to access this
 * key block.
 * This function looks into all registered keyblock sources.
 *
 * Returns: 0 if found,
 *	    -1 if not found
 *	    G10ERR_UNSUPPORTED if no resource is able to handle this
 *	    or another errorcode.
 */
int
locate_keyblock_by_fpr( KBPOS *kbpos, const byte *fpr, int fprlen, int secret )
{
    RESTBL *rentry;
    int i, rc, any=0, last_rc=-1;


    for(i=0, rentry = resource_table; i < MAX_RESOURCES; i++, rentry++ ) {
	if( rentry->used && !rentry->secret == !secret ) {
	    kbpos->rt = rentry->rt;
	    switch( rentry->rt ) {
	     #ifdef HAVE_LIBGDBM
	      case rt_GDBM:
		any = 1;
		rc = do_gdbm_locate( rentry->dbf, kbpos, fpr, fprlen );
		break;
	     #endif
	      default:
		rc = G10ERR_UNSUPPORTED;
		break;
	    }

	    if( !rc ) {
		kbpos->resno = i;
		kbpos->fp = NULL;
		return 0;
	    }
	    else if( rc != -1 && rc != G10ERR_UNSUPPORTED ) {
		log_error("error searching resource %d: %s\n",
						  i, g10_errstr(rc));
		last_rc = rc;
	    }
	}
    }

    return (last_rc == -1 && !any)? G10ERR_UNSUPPORTED : last_rc;
}


int
locate_keyblock_by_keyid( KBPOS *kbpos, u32 *keyid, int shortkid, int secret )
{
    RESTBL *rentry;
    int i, rc, any=0, last_rc=-1;

    if( shortkid )
	return G10ERR_UNSUPPORTED;

    for(i=0, rentry = resource_table; i < MAX_RESOURCES; i++, rentry++ ) {
	if( rentry->used && !rentry->secret == !secret ) {
	    kbpos->rt = rentry->rt;
	    switch( rentry->rt ) {
	     #ifdef HAVE_LIBGDBM
	      case rt_GDBM:
		any = 1;
		rc = do_gdbm_locate_by_keyid( rentry->dbf, kbpos, keyid );
		break;
	     #endif
	      default:
		rc = G10ERR_UNSUPPORTED;
		break;
	    }

	    if( !rc ) {
		kbpos->resno = i;
		kbpos->fp = NULL;
		return 0;
	    }
	    else if( rc != -1 && rc != G10ERR_UNSUPPORTED ) {
		log_error("error searching resource %d: %s\n",
						  i, g10_errstr(rc));
		last_rc = rc;
	    }
	}
    }

    return (last_rc == -1 && !any)? G10ERR_UNSUPPORTED : last_rc;
}




/****************
 * Lock the keyblock; wait until it's available
 * This function may change the internal data in kbpos, in cases
 * when the keyblock to be locked has been modified.
 * fixme: remove this function and add an option to search()?
 */
int
lock_keyblock( KBPOS *kbpos )
{
    if( !check_pos(kbpos) )
	return G10ERR_GENERAL;
    return 0;
}

/****************
 * Release a lock on a keyblock
 */
void
unlock_keyblock( KBPOS *kbpos )
{
    if( !check_pos(kbpos) )
	BUG();
}

/****************
 * Read a complete keyblock and return the root in ret_root.
 */
int
read_keyblock( KBPOS *kbpos, KBNODE *ret_root )
{
    if( !check_pos(kbpos) )
	return G10ERR_GENERAL;

    switch( kbpos->rt ) {
      case rt_RING:
	return keyring_read( kbpos, ret_root );
     #ifdef HAVE_LIBGDBM
      case rt_GDBM:
	return do_gdbm_read( kbpos, ret_root );
     #endif
      default: BUG();
    }
}


/****************
 * This functions can be used to read through a complete keyring.
 * Mode is: 0 = open
 *	    1 = read
 *	    2 = close
 *	    5 = open secret keyrings
 *	    11 = read but skip signature and comment packets.
 *	    all others are reserved!
 * Note that you do not need a search prior to this function,
 * only a handle is needed.
 * NOTE: It is not allowed to do an insert/update/delete with this
 *	 keyblock, if you want to do this, use search/read!
 */
int
enum_keyblocks( int mode, KBPOS *kbpos, KBNODE *ret_root )
{
    int rc = 0;
    RESTBL *rentry;

    if( !mode || mode == 5 || mode == 100 ) {
	int i;

	kbpos->fp = NULL;
	kbpos->rt = rt_UNKNOWN;
	if( !mode ) {
	    kbpos->secret = 0;
	    i = 0;
	}
	else if( mode == 5 ) {
	    kbpos->secret = 1;
	    mode = 0;
	    i = 0;
	}
	else
	    i = kbpos->resno+1;
	for(; i < MAX_RESOURCES; i++ )
	    if( resource_table[i].used
		&& !resource_table[i].secret == !kbpos->secret )
		break;
	if( i == MAX_RESOURCES )
	    return -1; /* no resources */
	kbpos->resno = i;
	rentry = check_pos( kbpos );
	kbpos->rt = resource_table[i].rt;
	kbpos->valid = 0;
	switch( kbpos->rt ) {
	  case rt_RING:
	    kbpos->fp = iobuf_open( rentry->fname );
	    if( !kbpos->fp ) {
		log_error("can't open `%s'\n", rentry->fname );
		return G10ERR_OPEN_FILE;
	    }
	    break;
	 #ifdef HAVE_LIBGDBM
	  case rt_GDBM:
	    /* FIXME: make sure that there is only one enum at a time */
	    kbpos->offset = 0;
	    break;
	 #endif
	  default: BUG();
	}
	kbpos->pkt = NULL;
    }
    else if( mode == 1 || mode == 11 ) {
	int cont;
	do {
	    cont = 0;
	    switch( kbpos->rt ) {
	      case rt_RING:
		if( !kbpos->fp )
		    return G10ERR_GENERAL;
		rc = keyring_enum( kbpos, ret_root, mode == 11 );
		break;
	     #ifdef HAVE_LIBGDBM
	      case rt_GDBM:
		rc = do_gdbm_enum( kbpos, ret_root );
		break;
	     #endif
	      default: BUG();
	    }

	    if( rc == -1 ) {
		assert( !kbpos->pkt );
		rentry = check_pos( kbpos );
		assert(rentry);
		/* close */
		enum_keyblocks(2, kbpos, ret_root );
		/* and open the next one */
		rc = enum_keyblocks(100, kbpos, ret_root );
		if( !rc )
		    cont = 1;
	    }
	} while(cont);
    }
    else {
	switch( kbpos->rt ) {
	  case rt_RING:
	    if( kbpos->fp ) {
		iobuf_close( kbpos->fp );
		kbpos->fp = NULL;
	    }
	    break;
	  case rt_GDBM:
	    break;
	  case rt_UNKNOWN:
	    /* this happens when we have no keyring at all */
	    return rc;

	  default:
	    BUG();
	}
	/* release pending packet */
	free_packet( kbpos->pkt );
	m_free( kbpos->pkt );
    }
    return rc;
}




/****************
 * Insert the keyblock described by ROOT into the keyring described
 * by KBPOS.  This actually appends the data to the keyfile.
 */
int
insert_keyblock( KBPOS *kbpos, KBNODE root )
{
    int rc;

    if( !check_pos(kbpos) )
	return G10ERR_GENERAL;

    switch( kbpos->rt ) {
      case rt_RING:
	rc = keyring_copy( kbpos, 1, root );
	break;
     #ifdef HAVE_LIBGDBM
      case rt_GDBM:
	rc = do_gdbm_store( kbpos, root, 0 );
	break;
     #endif
      default: BUG();
    }

    return rc;
}

/****************
 * Delete the keyblock described by KBPOS.
 * The current code simply changes the keyblock in the keyring
 * to packet of type 0 with the correct length.  To help detect errors,
 * zero bytes are written.
 */
int
delete_keyblock( KBPOS *kbpos )
{
    int rc;

    if( !check_pos(kbpos) )
	return G10ERR_GENERAL;

    switch( kbpos->rt ) {
      case rt_RING:
	rc = keyring_copy( kbpos, 2, NULL );
	break;
     #ifdef HAVE_LIBGDBM
      case rt_GDBM:
	log_debug("deleting gdbm keyblock is not yet implemented\n");
	rc = 0;
	break;
     #endif
      default: BUG();
    }

    return rc;
}


/****************
 * Update the keyblock at KBPOS with the one in ROOT.
 */
int
update_keyblock( KBPOS *kbpos, KBNODE root )
{
    int rc;

    if( !check_pos(kbpos) )
	return G10ERR_GENERAL;

    switch( kbpos->rt ) {
      case rt_RING:
	rc = keyring_copy( kbpos, 3, root );
	break;
     #ifdef HAVE_LIBGDBM
      case rt_GDBM:
	rc = do_gdbm_store( kbpos, root, 1 );
	break;
     #endif
      default: BUG();
    }

    return rc;
}



/****************************************************************
 ********** Implemenation of a user ID database    **************
 ****************************************************************/
#if 0
/****************
 * Layout of the user ID db
 *
 * This user ID DB provides fast lookup of user ID, but the user ids are
 * not in any specific order.
 *
 * A string "GnuPG user db", a \n.
 * user ids of one key, delimited by \t,
 * a # or ^ followed by a 20 byte fingerprint, followed by an \n
 * The literal characters %, \n, \t, #, ^ must be replaced by a percent sign
 * and their hex value.
 *
 * (We use Boyer/Moore pattern matching)
 */

/****************
 * This compiles pattern to the distance table, the table will be allocate
 * here and must be freed by using free().
 * Returns: Ptr to new allocated Table
 *	    Caller must free the table.
 */

static size_t *
compile_bm_table( const byte *pattern, size_t len )
{
    ushort *dist;
    int i;

    dist = m_alloc_clear( 256 * sizeof *dist );
    for(i=0; i < 256; i++ )
	dist[i] = len;
    for(i=0; i < len-1; i++ )
	dTbl[p[i]] = len-i-1;
    return dist;
}




/****************
 * Search BUF of BUFLEN for pattern P of length PATLEN.
 * dist is the Boyer/Moore distance table of 256 Elements,
 * case insensitive search is done if IGNCASE is true (In this case
 * the distance table has to compiled from uppercase chacaters and
 * PAT must also be uppercase.
 * Returns: Prt to maching string in BUF, or NULL if not found.
 */

static const *
do_bm_search( const byte *buf, size_t buflen,
	      const byte *pat, size_t patlen, size_t *dist, int igncase )
{
    int i, j, k;

    if( igncase ) {
	int c, c1;

	for( i = --patlen; i < buflen; i += dist[c1] )
	    for( j=patlen, k=i, c1=c=toupper(buf[k]); c == pat[j];
					  j--, k--, c=toupper(buf[k]) ) {
		if( !j )
		    return buf+k;
	    }
    }
    else {
	for( i = --patlen; i < buflen; i += dist[buf[i]] )
	    for( j=patlen, k=i; buf[k] == pat[j]; j--, k-- ) {
		if( !j )
		    return buf+k;
	    }
    }
    return NULL;
}


typedef struct {
    size_t dist[256];
} *SCAN_USER_HANDLE;

static SCAN_USER_HANDLE
scan_user_file_open( const byte *name )
{
    SCAN_USER_HANDLE hd;
    size_t *dist;
    int i;

    hd = m_alloc_clear( sizeof *hd );
    dist = hd->dist;
    /* compile the distance table */
    for(i=0; i < 256; i++ )
	dist[i] = len;
    for(i=0; i < len-1; i++ )
	dTbl[p[i]] = len-i-1;
    /* setup other things */

    return hd;
}

static int
scan_user_file_close( SCAN_USER_HANDLE hd )
{
    m_free( hd );
}

static int
scan_user_file_read( SCAN_USER_HANDLE hd, byte *fpr )
{
    char record[1000];

    /* read a record */


}
#endif



/****************************************************************
 ********** Functions which operates on regular keyrings ********
 ****************************************************************/

static int
cmp_seckey( PKT_secret_key *req_sk, PKT_secret_key *sk )
{
    int n,i;

    assert( req_sk->pubkey_algo == sk->pubkey_algo );

    n = pubkey_get_nskey( req_sk->pubkey_algo );
    for(i=0; i < n; i++ ) {
        /* Note: becuase v4 protected keys have nothing in the
         * mpis except for the first one, we skip all NULL MPIs.
         * This might not be always correct in cases where the both
         * keys do not match in their secret parts but we can ignore that
         * because the need for this function is quite ugly. */
	if( req_sk->skey[1] && sk->skey[i]
             && mpi_cmp( req_sk->skey[i], sk->skey[i] ) )
	    return -1;
    }
    return 0;
}

static int
cmp_pubkey( PKT_public_key *req_pk, PKT_public_key *pk )
{
    int n, i;

    assert( req_pk->pubkey_algo == pk->pubkey_algo );

    n = pubkey_get_npkey( req_pk->pubkey_algo );
    for(i=0; i < n; i++ ) {
	if( mpi_cmp( req_pk->pkey[i], pk->pkey[i] )  )
	    return -1;
    }
    return 0;
}

/****************
 * search one keyring, return 0 if found, -1 if not found or an errorcode.
 */
static int
keyring_search( PACKET *req, KBPOS *kbpos, IOBUF iobuf, const char *fname )
{
    int rc;
    PACKET pkt;
    int save_mode;
    off_t offset;
    int pkttype = req->pkttype;
    PKT_public_key *req_pk = req->pkt.public_key;
    PKT_secret_key *req_sk = req->pkt.secret_key;

    init_packet(&pkt);
    save_mode = set_packet_list_mode(0);
    kbpos->rt = rt_RING;
    kbpos->valid = 0;

  #if HAVE_DOSISH_SYSTEM || 1
    assert(!iobuf);
    iobuf = iobuf_open( fname );
    if( !iobuf ) {
	log_error("%s: can't open keyring file\n", fname);
	rc = G10ERR_KEYRING_OPEN;
	goto leave;
    }
  #else
    if( iobuf_seek( iobuf, 0 ) ) {
	log_error("can't rewind keyring file\n");
	rc = G10ERR_KEYRING_OPEN;
	goto leave;
    }
  #endif

    while( !(rc=search_packet(iobuf, &pkt, pkttype, &offset)) ) {
	if( pkt.pkttype == PKT_SECRET_KEY ) {
	    PKT_secret_key *sk = pkt.pkt.secret_key;

	    if(   req_sk->timestamp == sk->timestamp
	       && req_sk->pubkey_algo == sk->pubkey_algo
	       && !cmp_seckey( req_sk, sk) )
		break; /* found */
	}
	else if( pkt.pkttype == PKT_PUBLIC_KEY ) {
	    PKT_public_key *pk = pkt.pkt.public_key;

	    if(   req_pk->timestamp == pk->timestamp
	       && req_pk->pubkey_algo == pk->pubkey_algo
	       && !cmp_pubkey( req_pk, pk ) )
		break; /* found */
	}
	else
	    BUG();
	free_packet(&pkt);
    }
    if( !rc ) {
	kbpos->offset = offset;
	kbpos->valid = 1;
    }

  leave:
    free_packet(&pkt);
    set_packet_list_mode(save_mode);
  #if HAVE_DOSISH_SYSTEM || 1
    iobuf_close(iobuf);
  #endif
    return rc;
}


static int
keyring_read( KBPOS *kbpos, KBNODE *ret_root )
{
    PACKET *pkt;
    int rc;
    RESTBL *rentry;
    KBNODE root = NULL;
    IOBUF a;
    int in_cert = 0;

    if( !(rentry=check_pos(kbpos)) )
	return G10ERR_GENERAL;

    a = iobuf_open( rentry->fname );
    if( !a ) {
	log_error("can't open `%s'\n", rentry->fname );
	return G10ERR_OPEN_FILE;
    }

    if( !kbpos->valid )
       log_debug("kbpos not valid in keyring_read\n" );
    if( iobuf_seek( a, kbpos->offset ) ) {
       log_error("can't seek\n");
	iobuf_close(a);
	return G10ERR_KEYRING_OPEN;
    }

    pkt = m_alloc( sizeof *pkt );
    init_packet(pkt);
    kbpos->count=0;
    while( (rc=parse_packet(a, pkt)) != -1 ) {
	if( rc ) {  /* ignore errors */
	    if( rc != G10ERR_UNKNOWN_PACKET ) {
		log_error("read_keyblock: read error: %s\n", g10_errstr(rc) );
		rc = G10ERR_INV_KEYRING;
		goto ready;
	    }
	    kbpos->count++;
	    free_packet( pkt );
	    init_packet( pkt );
	    continue;
	}
	/* make a linked list of all packets */
	switch( pkt->pkttype ) {
	  case PKT_COMPRESSED:
	    log_error("skipped compressed packet in keyring\n" );
	    free_packet(pkt);
	    init_packet(pkt);
	    break;

	  case PKT_PUBLIC_KEY:
	  case PKT_SECRET_KEY:
	    if( in_cert )
		goto ready;
	    in_cert = 1;
	  default:
	    kbpos->count++;
	    if( !root )
		root = new_kbnode( pkt );
	    else
		add_kbnode( root, new_kbnode( pkt ) );
	    pkt = m_alloc( sizeof *pkt );
	    init_packet(pkt);
	    break;
	}
    }
  ready:
    kbpos->valid = 0;
    if( rc == -1 && root )
	rc = 0;

    if( rc )
	release_kbnode( root );
    else
	*ret_root = root;
    free_packet( pkt );
    m_free( pkt );
    iobuf_close(a);
    return rc;
}


static int
keyring_enum( KBPOS *kbpos, KBNODE *ret_root, int skipsigs )
{
    PACKET *pkt;
    int rc;
    RESTBL *rentry;
    KBNODE root = NULL;

    if( !(rentry=check_pos(kbpos)) )
	return G10ERR_GENERAL;

    if( kbpos->pkt ) {
	root = new_kbnode( kbpos->pkt );
	kbpos->pkt = NULL;
    }

    pkt = m_alloc( sizeof *pkt );
    init_packet(pkt);
    while( (rc=parse_packet(kbpos->fp, pkt)) != -1 ) {
	if( rc ) {  /* ignore errors */
	    if( rc != G10ERR_UNKNOWN_PACKET ) {
		log_error("read_keyblock: read error: %s\n", g10_errstr(rc) );
		rc = G10ERR_INV_KEYRING;
		goto ready;
	    }
	    free_packet( pkt );
	    init_packet( pkt );
	    continue;
	}
	/* make a linked list of all packets */
	switch( pkt->pkttype ) {
	  case PKT_COMPRESSED:
	    log_error("skipped compressed packet in keyring\n" );
	    free_packet(pkt);
	    init_packet(pkt);
	    break;

	  case PKT_PUBLIC_KEY:
	  case PKT_SECRET_KEY:
	    if( root ) { /* store this packet */
		kbpos->pkt = pkt;
		pkt = NULL;
		goto ready;
	    }
	    root = new_kbnode( pkt );
	    pkt = m_alloc( sizeof *pkt );
	    init_packet(pkt);
	    break;

	  default:
	    /* skip pakets at the beginning of a keyring, until we find
	     * a start packet; issue a warning if it is not a comment */
	    if( !root && pkt->pkttype != PKT_COMMENT
		      && pkt->pkttype != PKT_OLD_COMMENT ) {
		break;
	    }
	    if( !root || (skipsigs && ( pkt->pkttype == PKT_SIGNATURE
				      ||pkt->pkttype == PKT_COMMENT
				      ||pkt->pkttype == PKT_OLD_COMMENT )) ) {
		init_packet(pkt);
		break;
	    }
	    add_kbnode( root, new_kbnode( pkt ) );
	    pkt = m_alloc( sizeof *pkt );
	    init_packet(pkt);
	    break;
	}
    }
  ready:
    if( rc == -1 && root )
	rc = 0;

    if( rc )
	release_kbnode( root );
    else
	*ret_root = root;
    free_packet( pkt );
    m_free( pkt );

    return rc;
}


/****************
 * Perform insert/delete/update operation.
 * mode 1 = insert
 *	2 = delete
 *	3 = update
 */
static int
keyring_copy( KBPOS *kbpos, int mode, KBNODE root )
{
    RESTBL *rentry;
    IOBUF fp, newfp;
    int rc=0;
    char *bakfname = NULL;
    char *tmpfname = NULL;

    if( !(rentry = check_pos( kbpos )) )
	return G10ERR_GENERAL;
    if( kbpos->fp )
	BUG(); /* not allowed with such a handle */

    if( opt.dry_run )
	return 0;

    lock_rentry( rentry );

    /* open the source file */
    fp = iobuf_open( rentry->fname );
    if( mode == 1 && !fp && errno == ENOENT ) { /* no file yet */
	KBNODE kbctx, node;

	/* insert: create a new file */
	newfp = iobuf_create( rentry->fname );
	if( !newfp ) {
	    log_error(_("%s: can't create: %s\n"), rentry->fname, strerror(errno));
	    unlock_rentry( rentry );
	    return G10ERR_OPEN_FILE;
	}
	else if( !opt.quiet )
	    log_info(_("%s: keyring created\n"), rentry->fname );

	kbctx=NULL;
	while( (node = walk_kbnode( root, &kbctx, 0 )) ) {
	    if( (rc = build_packet( newfp, node->pkt )) ) {
		log_error("build_packet(%d) failed: %s\n",
			    node->pkt->pkttype, g10_errstr(rc) );
		iobuf_cancel(newfp);
		unlock_rentry( rentry );
		return G10ERR_WRITE_FILE;
	    }
	}
	if( iobuf_close(newfp) ) {
	    log_error("%s: close failed: %s\n", rentry->fname, strerror(errno));
	    unlock_rentry( rentry );
	    return G10ERR_CLOSE_FILE;
	}
	if( chmod( rentry->fname, S_IRUSR | S_IWUSR ) ) {
	    log_error("%s: chmod failed: %s\n",
				    rentry->fname, strerror(errno) );
	    unlock_rentry( rentry );
	    return G10ERR_WRITE_FILE;
	}
	return 0;
    }
    if( !fp ) {
	log_error("%s: can't open: %s\n", rentry->fname, strerror(errno) );
	rc = G10ERR_OPEN_FILE;
	goto leave;
    }

    /* create the new file */
  #ifdef USE_ONLY_8DOT3
    /* Here is another Windoze bug?:
     * you cant rename("pubring.gpg.tmp", "pubring.gpg");
     * but	rename("pubring.gpg.tmp", "pubring.aaa");
     * works.  So we replace .gpg by .bak or .tmp
     */
    if( strlen(rentry->fname) > 4
	&& !strcmp(rentry->fname+strlen(rentry->fname)-4, ".gpg") ) {
	bakfname = m_alloc( strlen( rentry->fname ) + 1 );
	strcpy(bakfname,rentry->fname);
	strcpy(bakfname+strlen(rentry->fname)-4, ".bak");
	tmpfname = m_alloc( strlen( rentry->fname ) + 1 );
	strcpy(tmpfname,rentry->fname);
	strcpy(tmpfname+strlen(rentry->fname)-4, ".tmp");
    }
    else { /* file does not end with gpg; hmmm */
	bakfname = m_alloc( strlen( rentry->fname ) + 5 );
	strcpy(stpcpy(bakfname,rentry->fname),".bak");
	tmpfname = m_alloc( strlen( rentry->fname ) + 5 );
	strcpy(stpcpy(tmpfname,rentry->fname),".tmp");
    }
  #else
    bakfname = m_alloc( strlen( rentry->fname ) + 2 );
    strcpy(stpcpy(bakfname,rentry->fname),"~");
    tmpfname = m_alloc( strlen( rentry->fname ) + 5 );
    strcpy(stpcpy(tmpfname,rentry->fname),".tmp");
  #endif
    newfp = iobuf_create( tmpfname );
    if( !newfp ) {
	log_error("%s: can't create: %s\n", tmpfname, strerror(errno) );
	iobuf_close(fp);
	rc = G10ERR_OPEN_FILE;
	goto leave;
    }

    if( mode == 1 ) { /* insert */
	/* copy everything to the new file */
	rc = copy_all_packets( fp, newfp );
	if( rc != -1 ) {
	    log_error("%s: copy to %s failed: %s\n",
		      rentry->fname, tmpfname, g10_errstr(rc) );
	    iobuf_close(fp);
	    iobuf_cancel(newfp);
	    goto leave;
	}
	rc = 0;
    }

    if( mode == 2 || mode == 3 ) { /* delete or update */
	/* copy first part to the new file */
	rc = copy_some_packets( fp, newfp, kbpos->offset );
	if( rc ) { /* should never get EOF here */
	    log_error("%s: copy to %s failed: %s\n",
		      rentry->fname, tmpfname, g10_errstr(rc) );
	    iobuf_close(fp);
	    iobuf_cancel(newfp);
	    goto leave;
	}
	/* skip this keyblock */
	assert( kbpos->count );
	rc = skip_some_packets( fp, kbpos->count );
	if( rc ) {
	    log_error("%s: skipping %u packets failed: %s\n",
			    rentry->fname, kbpos->count, g10_errstr(rc));
	    iobuf_close(fp);
	    iobuf_cancel(newfp);
	    goto leave;
	}
    }

    if( mode == 1 || mode == 3 ) { /* insert or update */
	KBNODE kbctx, node;

	/* append the new data */
	kbctx=NULL;
	while( (node = walk_kbnode( root, &kbctx, 0 )) ) {
	    if( (rc = build_packet( newfp, node->pkt )) ) {
		log_error("build_packet(%d) failed: %s\n",
			    node->pkt->pkttype, g10_errstr(rc) );
		iobuf_close(fp);
		iobuf_cancel(newfp);
		rc = G10ERR_WRITE_FILE;
		goto leave;
	    }
	}
	kbpos->valid = 0;
    }

    if( mode == 2 || mode == 3 ) { /* delete or update */
	/* copy the rest */
	rc = copy_all_packets( fp, newfp );
	if( rc != -1 ) {
	    log_error("%s: copy to %s failed: %s\n",
		      rentry->fname, tmpfname, g10_errstr(rc) );
	    iobuf_close(fp);
	    iobuf_cancel(newfp);
	    goto leave;
	}
	rc = 0;
    }

    /* close both files */
    if( iobuf_close(fp) ) {
	log_error("%s: close failed: %s\n", rentry->fname, strerror(errno) );
	rc = G10ERR_CLOSE_FILE;
	goto leave;
    }
    if( iobuf_close(newfp) ) {
	log_error("%s: close failed: %s\n", tmpfname, strerror(errno) );
	rc = G10ERR_CLOSE_FILE;
	goto leave;
    }
    /* if the new file is a secring, restrict the permissions */
  #ifndef HAVE_DOSISH_SYSTEM
    if( rentry->secret ) {
	if( chmod( tmpfname, S_IRUSR | S_IWUSR ) ) {
	    log_error("%s: chmod failed: %s\n",
				    tmpfname, strerror(errno) );
	    rc = G10ERR_WRITE_FILE;
	    goto leave;
	}
    }
  #endif

    /* rename and make backup file */
    if( !rentry->secret ) {  /* but not for secret keyrings */
        iobuf_ioctl (NULL, 2, 0, bakfname );
        iobuf_ioctl (NULL, 2, 0, rentry->fname );
      #ifdef HAVE_DOSISH_SYSTEM
	remove( bakfname );
      #endif
	if( rename( rentry->fname, bakfname ) ) {
	    log_error("%s: rename to %s failed: %s\n",
				    rentry->fname, bakfname, strerror(errno) );
	    rc = G10ERR_RENAME_FILE;
	    goto leave;
	}
    }
    iobuf_ioctl (NULL, 2, 0, tmpfname );
    iobuf_ioctl (NULL, 2, 0, rentry->fname );
  #ifdef HAVE_DOSISH_SYSTEM
    remove( rentry->fname );
  #endif
    if( rename( tmpfname, rentry->fname ) ) {
	log_error("%s: rename to %s failed: %s\n",
			    tmpfname, rentry->fname,strerror(errno) );
	rc = G10ERR_RENAME_FILE;
	if( rentry->secret ) {
	    log_info(_(
		"WARNING: 2 files with confidential information exists.\n"));
	    log_info(_("%s is the unchanged one\n"), rentry->fname );
	    log_info(_("%s is the new one\n"), tmpfname );
	    log_info(_("Please fix this possible security flaw\n"));
	}
	goto leave;
    }

  leave:
    unlock_rentry( rentry );
    m_free(bakfname);
    m_free(tmpfname);
    return rc;
}


#ifdef HAVE_LIBGDBM
/****************************************************************
 ********** Functions which operates on GDM files ***************
 ****************************************************************/

#if MAX_FINGERPRINT_LEN > 20
  #error A GDBM keyring assumes that fingerprints are less than 21
#endif

/****************
 * Insert the keyblock into the GDBM database
 */

static int
do_gdbm_store( KBPOS *kbpos, KBNODE root, int update )
{
    RESTBL *rentry;
    PKT_public_key *pk;
    KBNODE kbctx, node;
    IOBUF fp = NULL;
    byte fpr[20];
    byte contbuf[21];
    byte keybuf[21];
    size_t fprlen;
    datum key, content;
    int i, rc;

    if( !(rentry = check_pos( kbpos )) )
	return G10ERR_GENERAL;

    if( opt.dry_run )
	return 0;

    /* construct the fingerprint which is used as the primary key */
    node = find_kbnode( root, PKT_PUBLIC_KEY );
    if( !node )
	log_bug("a gdbm database can't store secret keys\n");
    pk = node->pkt->pkt.public_key;

    fingerprint_from_pk( pk, fpr, &fprlen );
    for(i=fprlen; i < DIM(fpr); i++ )
	fpr[i] = 0;

    /* build the keyblock */
    kbctx=NULL;
    fp = iobuf_temp();
    iobuf_put( fp, 1 ); /* data is a keyblock */
    while( (node = walk_kbnode( root, &kbctx, 0 )) ) {
	if( (rc = build_packet( fp, node->pkt )) ) {
	    log_error("build_packet(%d) failed: %s\n",
			node->pkt->pkttype, g10_errstr(rc) );
	    rc = G10ERR_WRITE_FILE;
	    goto leave;
	}
    }
    /* store data and key */
    *keybuf = 1;   /* key is a padded fingerprint */
    memcpy(keybuf+1, fpr, 20 );
    key.dptr  = keybuf;
    key.dsize = 21;
    content.dptr  = iobuf_get_temp_buffer( fp );
    content.dsize = iobuf_get_temp_length( fp );
    rc = gdbm_store( rentry->dbf, key, content,
				  update? GDBM_REPLACE : GDBM_INSERT );
    if( rc == 1 && !update )
	rc = gdbm_store( rentry->dbf, key, content, GDBM_REPLACE );

    if( rc ) {
	log_error("%s: gdbm_store failed: %s\n", rentry->fname,
			    rc == 1 ? "already stored"
				    : gdbm_strerror(gdbm_errno) );
	rc = G10ERR_WRITE_FILE;
	goto leave;
    }
    /* now store all keyids */
    *contbuf = 2;  /* data is a list of fingerprints */
    memcpy(contbuf+1, fpr, 20 );
    content.dptr = contbuf;
    content.dsize= 21;
    kbctx=NULL;
    while( (node = walk_kbnode( root, &kbctx, 0 )) ) {
	if(    node->pkt->pkttype == PKT_PUBLIC_KEY
	    || node->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
	    u32 aki[2];

	    keyid_from_pk( node->pkt->pkt.public_key, aki );
	    *keybuf = 2; /* key is a 8 byte keyid */
	    u32tobuf( keybuf+1	, aki[0] );
	    u32tobuf( keybuf+5, aki[1] );
	    key.dptr = keybuf;
	    key.dsize= 9;
	    /* fixme: must be more clever when a insert failed:
	     *	      build a list of fingerprints in this case */
	    rc = gdbm_store( rentry->dbf, key, content,
					  update? GDBM_REPLACE : GDBM_INSERT );
	    if( rc ) {
		log_info("%s: gdbm_store keyid failed: %s\n", rentry->fname,
				    rc == 1 ? "already stored"
					    : gdbm_strerror(gdbm_errno) );
		rc = 0;
	    }
	}
    }

  leave:
    iobuf_close(fp); /* don't need a cancel because it is a temp iobuf */
    return rc;
}



/****************
 * search one keybox, return 0 if found, -1 if not found or an errorcode.
 */
static int
do_gdbm_locate( GDBM_FILE dbf, KBPOS *kbpos, const byte *fpr, int fprlen )
{
    byte *keybuf = kbpos->keybuf;
    datum key;
    int i;

    *keybuf = 1;
    for(i=0; i < fprlen; i++ )
	keybuf[i+1] = fpr[i];
    for(; i < 20; i++ )
	keybuf[i+1] = 0;

    /* fetch the data */
    key.dptr  = keybuf;
    key.dsize = 21;
    if( !gdbm_exists( dbf, key ) )
	return -1; /* not found */
    return 0;
}

/****************
 * locate by keyid.
 * FIXME: we must have a way to enumerate thru the list opf fingerprints
 */
static int
do_gdbm_locate_by_keyid( GDBM_FILE dbf, KBPOS *kbpos, u32 *keyid )
{
    byte keybuf[9];
    datum key, content;
    int rc;

    /* construct the fingerprint which is used as the primary key */
    *keybuf = 2;
    u32tobuf( keybuf+1, keyid[0] );
    u32tobuf( keybuf+5, keyid[1] );

    /* fetch the data */
    key.dptr  = keybuf;
    key.dsize = 9;
    content = gdbm_fetch( dbf, key );
    if( !content.dptr )
	return -1;

    if( content.dsize < 2 ) {
	log_error("gdbm_fetch did not return enough data\n" );
	free( content.dptr ); /* can't use m_free() here */
	return G10ERR_INV_KEYRING;
    }
    if( *content.dptr != 2 ) {
	log_error("gdbm_fetch returned unexpected type %d\n",
		    *(byte*)content.dptr );
	free( content.dptr ); /* can't use m_free() here */
	return G10ERR_INV_KEYRING;
    }
    if( content.dsize < 21 ) {
	log_error("gdbm_fetch did not return a complete fingerprint\n" );
	free( content.dptr ); /* can't use m_free() here */
	return G10ERR_INV_KEYRING;
    }
    if( content.dsize > 21 )
	log_info("gdbm_fetch: WARNING: more than one fingerprint\n" );

    rc = do_gdbm_locate( dbf, kbpos, content.dptr+1, 20 );
    free( content.dptr ); /* can't use m_free() here */
    return rc;
}



static int
do_gdbm_read( KBPOS *kbpos, KBNODE *ret_root )
{
    PACKET *pkt;
    int rc;
    RESTBL *rentry;
    KBNODE root = NULL;
    IOBUF a;
    datum key, content;

    if( !(rentry=check_pos(kbpos)) )
	return G10ERR_GENERAL;

    key.dptr  = kbpos->keybuf;
    key.dsize = 21;
    content = gdbm_fetch( rentry->dbf, key );
    if( !content.dptr ) {
	log_error("gdbm_fetch failed: %s\n", gdbm_strerror(gdbm_errno) );
	return G10ERR_INV_KEYRING;
    }
    if( content.dsize < 2 ) {
	log_error("gdbm_fetch did not return enough data\n" );
	free( content.dptr ); /* can't use m_free() here */
	return G10ERR_INV_KEYRING;
    }
    if( *content.dptr != 1 ) {
	log_error("gdbm_fetch returned unexpected type %d\n",
		    *(byte*)content.dptr );
	free( content.dptr ); /* can't use m_free() here */
	return G10ERR_INV_KEYRING;
    }

    a = iobuf_temp_with_content( content.dptr+1, content.dsize-1 );
    free( content.dptr ); /* can't use m_free() here */

    pkt = m_alloc( sizeof *pkt );
    init_packet(pkt);
    kbpos->count=0;
    while( (rc=parse_packet(a, pkt)) != -1 ) {
	if( rc ) {  /* ignore errors */
	    if( rc != G10ERR_UNKNOWN_PACKET ) {
		log_error("read_keyblock: read error: %s\n", g10_errstr(rc) );
		rc = G10ERR_INV_KEYRING;
		break;
	    }
	    kbpos->count++;
	    free_packet( pkt );
	    init_packet( pkt );
	    continue;
	}
	/* make a linked list of all packets */
	kbpos->count++;
	if( !root )
	    root = new_kbnode( pkt );
	else
	    add_kbnode( root, new_kbnode( pkt ) );
	pkt = m_alloc( sizeof *pkt );
	init_packet(pkt);
    }
    if( rc == -1 && root )
	rc = 0;
    if( rc )
	release_kbnode( root );
    else
	*ret_root = root;
    free_packet( pkt );
    m_free( pkt );
    iobuf_close(a);
    return rc;
}


/****************
 * Enum over keyblok data
 */
static int
do_gdbm_enum( KBPOS *kbpos, KBNODE *ret_root )
{
    RESTBL *rentry;
    datum key, helpkey;

    if( !(rentry=check_pos(kbpos)) )
	return G10ERR_GENERAL;

    if( !kbpos->offset ) {
	kbpos->offset = 1;
	key = gdbm_firstkey( rentry->dbf );
    }
    else {
	helpkey.dptr = kbpos->keybuf;
	helpkey.dsize= 21;
	key = gdbm_nextkey( rentry->dbf, helpkey );
    }
    while( key.dptr && (!key.dsize || *key.dptr != 1) ) {
	helpkey = key;
	key = gdbm_nextkey( rentry->dbf, helpkey );
	free( helpkey.dptr ); /* free and not m_free() ! */
    }
    if( !key.dptr )
	return -1; /* eof */

    if( key.dsize < 21 ) {
	free( key.dptr ); /* free and not m_free() ! */
	log_error("do_gdm_enum: key is too short\n" );
	return G10ERR_INV_KEYRING;
    }
    memcpy( kbpos->keybuf, key.dptr, 21 );
    free( key.dptr ); /* free and not m_free() ! */
    return do_gdbm_read( kbpos, ret_root );
}

#endif /*HAVE_LIBGDBM*/
