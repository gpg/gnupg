/* ringedit.c -  Function for key ring editing
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
 * FIXME:  Keep track of all nodes, so that a change is propagated
 *	   to all nodes. (or use shallow copies and ref-counting?)
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
#include "util.h"
#include "packet.h"
#include "memory.h"
#include "mpi.h"
#include "iobuf.h"
#include "keydb.h"
#include "options.h"
#include "i18n.h"


struct resource_table_struct {
    int used;
    int secret; /* this is a secret keyring */
    char *fname;
    IOBUF iobuf;
};
typedef struct resource_table_struct RESTBL;

#define MAX_RESOURCES 10
static RESTBL resource_table[MAX_RESOURCES];

static int search( PACKET *pkt, KBPOS *kbpos, int secret );


static int keyring_search( PACKET *pkt, KBPOS *kbpos, IOBUF iobuf,
						const char *fname );
static int keyring_read( KBPOS *kbpos, KBNODE *ret_root );
static int keyring_enum( KBPOS *kbpos, KBNODE *ret_root, int skipsigs );
static int keyring_copy( KBPOS *kbpos, int mode, KBNODE root );



static RESTBL *
check_pos( KBPOS *kbpos )
{
    if( kbpos->resno < 0 || kbpos->resno >= MAX_RESOURCES )
	return NULL;
    if( !resource_table[kbpos->resno].used )
	return NULL;
    return resource_table + kbpos->resno;
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
    return NULL; /* not found */
}



/****************
 * Register a resource (which currently may only be a keyring file).
 * The first keyring which is added by this function is
 * created if it does not exist.
 * Note: this function may be called before secure memory is
 * available.
 */
int
add_keyblock_resource( const char *resname, int force, int secret )
{
    static int any_secret, any_public;
    IOBUF iobuf;
    int i, force;
    char *filename;
    int rc = 0;

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

    iobuf = iobuf_fopen( filename, "rb" );
    if( !iobuf && !force ) {
	rc = G10ERR_OPEN_FILE;
	goto leave;
    }

    if( !iobuf ) {
	iobuf = iobuf_create( filename );
	if( !iobuf ) {
	    log_error("%s: can't create: %s\n", filename, strerror(errno));
	    rc = G10ERR_OPEN_FILE;
	    goto leave;
	}
	else
	    log_info("%s: keyring created\n", filename );
    }

  #ifdef __MINGW32__
    /* must close it again */
    iobuf_close( iobuf );
    iobuf = NULL;
  #endif

    resource_table[i].used = 1;
    resource_table[i].secret = !!secret;
    resource_table[i].fname = m_strdup(filename);
    resource_table[i].iobuf = iobuf;
  leave:
    if( rc )
	log_error("keyblock resource '%s': %s\n", filename, g10_errstr(rc) );
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
    int i;

    for(i=0; i < MAX_RESOURCES; i++ )
	if( resource_table[i].used && !resource_table[i].secret == !secret ) {
	    /* fixme: dos needs case insensitive file compare */
	    if( !filename || !strcmp( resource_table[i].fname, filename ) ) {
		memset( kbpos, 0, sizeof *kbpos );
		kbpos->resno = i;
		return 0;
	    }
	}
    return -1; /* not found */
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
	    /* note: here we have to add different search functions,
	     * depending on the type of the resource */
	    rc = keyring_search( pkt, kbpos, resource_table[i].iobuf,
					     resource_table[i].fname );
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

    rc = get_pubkey_byname( pk, username );
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
    return keyring_read( kbpos, ret_root );
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
	kbpos->fp = iobuf_fopen( rentry->fname, "rb" );
	if( !kbpos->fp ) {
	    log_error("can't open '%s'\n", rentry->fname );
	    return G10ERR_OPEN_FILE;
	}
	kbpos->pkt = NULL;
    }
    else if( mode == 1 || mode == 11 ) {
	int cont;
	do {
	    cont = 0;
	    if( !kbpos->fp )
		return G10ERR_GENERAL;
	    rc = keyring_enum( kbpos, ret_root, mode == 11 );
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
    else if( kbpos->fp ) {
	iobuf_close( kbpos->fp );
	kbpos->fp = NULL;
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

    rc = keyring_copy( kbpos, 1, root );

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

    rc = keyring_copy( kbpos, 2, NULL );

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

    rc = keyring_copy( kbpos, 3, root );

    return rc;
}


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
	if( mpi_cmp( req_sk->skey[i], sk->skey[i] ) )
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
    ulong offset;
    int pkttype = req->pkttype;
    PKT_public_key *req_pk = req->pkt.public_key;
    PKT_secret_key *req_sk = req->pkt.secret_key;

    init_packet(&pkt);
    save_mode = set_packet_list_mode(0);

  #if __MINGW32__
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
    if( !rc )
	kbpos->offset = offset;

  leave:
    free_packet(&pkt);
    set_packet_list_mode(save_mode);
  #if __MINGW32__
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

    a = iobuf_fopen( rentry->fname, "rb" );
    if( !a ) {
	log_error("can't open '%s'\n", rentry->fname );
	return G10ERR_OPEN_FILE;
    }

    if( iobuf_seek( a, kbpos->offset ) ) {
	log_error("can't seek to %lu\n", kbpos->offset);
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
		log_info("keyring_enum: skipped packet of type %d\n",
			    pkt->pkttype );
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

    /* open the source file */
    fp = iobuf_fopen( rentry->fname, "rb" );
    if( mode == 1 && !fp && errno == ENOENT ) { /* no file yet */
	KBNODE kbctx, node;

	/* insert: create a new file */
	newfp = iobuf_create( rentry->fname );
	if( !newfp ) {
	    log_error("%s: can't create: %s\n", rentry->fname, strerror(errno));
	    return G10ERR_OPEN_FILE;
	}
	else
	    log_info("%s: keyring created\n", rentry->fname );

	kbctx=NULL;
	while( (node = walk_kbnode( root, &kbctx, 0 )) ) {
	    if( (rc = build_packet( newfp, node->pkt )) ) {
		log_error("build_packet(%d) failed: %s\n",
			    node->pkt->pkttype, g10_errstr(rc) );
		iobuf_cancel(newfp);
		return G10ERR_WRITE_FILE;
	    }
	}
	if( iobuf_close(newfp) ) {
	    log_error("%s: close failed: %s\n", rentry->fname, strerror(errno));
	    return G10ERR_CLOSE_FILE;
	}
	if( chmod( rentry->fname, S_IRUSR | S_IWUSR ) ) {
	    log_error("%s: chmod failed: %s\n",
				    rentry->fname, strerror(errno) );
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
  #ifdef __MINGW32__
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
  #ifndef __MINGW32__
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
      #ifdef __MINGW32__
	remove( bakfname );
      #endif
	if( rename( rentry->fname, bakfname ) ) {
	    log_error("%s: rename to %s failed: %s\n",
				    rentry->fname, bakfname, strerror(errno) );
	    rc = G10ERR_RENAME_FILE;
	    goto leave;
	}
    }
  #ifdef __MINGW32__
    remove( rentry->fname );
  #endif
    if( rename( tmpfname, rentry->fname ) ) {
	log_error("%s: rename to %s failed: %s\n",
			    tmpfname, rentry->fname,strerror(errno) );
	rc = G10ERR_RENAME_FILE;
	if( rentry->secret ) {
	    log_info(_(
		"Warning: 2 files with confidential information exists.\n"));
	    log_info(_("%s is the unchanged one\n"), rentry->fname );
	    log_info(_("%s is the new one\n"), tmpfname );
	    log_info(_("Please fix this possible security flaw\n"));
	}
	goto leave;
    }

  leave:
    m_free(bakfname);
    m_free(tmpfname);
    return rc;
}


/****************************************************************
 ********** Functions which operates on databases ***************
 ****************************************************************/
/* ... */

