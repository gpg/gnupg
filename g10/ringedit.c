/* ringedit.c -  Function for key ring editing
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
#include <assert.h>
#include "util.h"
#include "packet.h"
#include "memory.h"
#include "mpi.h"
#include "iobuf.h"
#include "keydb.h"
#include <unistd.h> /* for truncate */


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


static int keyring_search( PACKET *pkt, KBPOS *kbpos, IOBUF iobuf );
static int keyring_search2( PUBKEY_FIND_INFO info, KBPOS *kbpos,
						   const char *fname);
static int keyring_read( KBPOS *kbpos, KBNODE *ret_root );
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
 * Register a resource (which currently may ionly be a keyring file).
 */
int
add_keyblock_resource( const char *filename, int force, int secret )
{
    IOBUF iobuf;
    int i;

    for(i=0; i < MAX_RESOURCES; i++ )
	if( !resource_table[i].used )
	    break;
    if( i == MAX_RESOURCES )
	return G10ERR_RESOURCE_LIMIT;

    iobuf = iobuf_open( filename );
    if( !iobuf && !force )
	return G10ERR_OPEN_FILE;
    resource_table[i].used = 1;
    resource_table[i].secret = !!secret;
    resource_table[i].fname = m_strdup(filename);
    resource_table[i].iobuf = iobuf;
    return 0;
}


/****************
 * Get a keyblock handle KBPOS from a filename. This can be used
 * to get a handle for insert_keyblock for a new keyblock.
 */
int
get_keyblock_handle( const char *filename, int secret, KBPOS *kbpos )
{
    int i;

    for(i=0; i < MAX_RESOURCES; i++ )
	if( resource_table[i].used && !resource_table[i].secret == !secret ) {
	    /* fixme: dos needs case insensitive file compare */
	    if( !strcmp( resource_table[i].fname, filename ) ) {
		memset( kbpos, 0, sizeof *kbpos );
		kbpos->resno = i;
		return 0;
	    }
	}
    return -1; /* not found */
}


/****************
 * Find a keyblock from the informations provided in INFO
 * This can only be used fro public keys
 */
int
find_keyblock( PUBKEY_FIND_INFO info, KBPOS *kbpos )
{
    int i, rc, last_rc=-1;

    for(i=0; i < MAX_RESOURCES; i++ ) {
	if( resource_table[i].used && !resource_table[i].secret ) {
	    /* note: here we have to add different search functions,
	     * depending on the type of the resource */
	    rc = keyring_search2( info, kbpos, resource_table[i].fname );
	    if( !rc ) {
		kbpos->resno = i;
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
 * Search a keyblock which starts with the given packet and put all
 * informations into KBPOS, which can be used later to access this key block.
 * This function looks into all registered keyblock sources.
 * PACKET must be a packet with either a secret_cert or a public_cert
 *
 * This function is intended to check wether a given certificate
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
	    rc = keyring_search( pkt, kbpos, resource_table[i].iobuf );
	    if( !rc ) {
		kbpos->resno = i;
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
    PKT_public_cert *pkc = m_alloc_clear( sizeof *pkc );
    int rc;

    rc = get_pubkey_byname( pkc, username );
    if( rc ) {
	free_public_cert(pkc);
	return rc;
    }

    init_packet( &pkt );
    pkt.pkttype = PKT_PUBLIC_CERT;
    pkt.pkt.public_cert = pkc;
    rc = search( &pkt, kbpos, 0 );
    free_public_cert(pkc);
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
    PKT_secret_cert *skc = m_alloc_clear( sizeof *skc );
    int rc;

    rc = get_seckey_byname( skc, username, 0 );
    if( rc ) {
	free_secret_cert(skc);
	return rc;
    }

    init_packet( &pkt );
    pkt.pkttype = PKT_SECRET_CERT;
    pkt.pkt.secret_cert = skc;
    rc = search( &pkt, kbpos, 1 );
    free_secret_cert(skc);
    return rc;
}


/****************
 * Lock the keyblock; wait until it's available
 * This function may change the internal data in kbpos, in cases
 * when the to be locked keyblock has been modified.
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
 * to packet of type 0 with the correct length.  To help detecting errors,
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


/****************
 * search one keyring, return 0 if found, -1 if not found or an errorcode.
 */
static int
keyring_search( PACKET *req, KBPOS *kbpos, IOBUF iobuf )
{
    int rc;
    PACKET pkt;
    int save_mode;
    ulong offset;
    int pkttype = req->pkttype;
    PKT_public_cert *req_pkc = req->pkt.public_cert;
    PKT_secret_cert *req_skc = req->pkt.secret_cert;

    init_packet(&pkt);
    save_mode = set_packet_list_mode(0);

    if( iobuf_seek( iobuf, 0 ) ) {
	log_error("can't rewind keyring file: %s\n", g10_errstr(rc));
	rc = G10ERR_KEYRING_OPEN;
	goto leave;
    }

    while( !(rc=search_packet(iobuf, &pkt, pkttype, &offset)) ) {
	if( pkt.pkttype == PKT_SECRET_CERT ) {
	    PKT_secret_cert *skc = pkt.pkt.secret_cert;

	    if(   req_skc->timestamp == skc->timestamp
	       && req_skc->valid_days == skc->valid_days
	       && req_skc->pubkey_algo == skc->pubkey_algo
	       && (   ( skc->pubkey_algo == PUBKEY_ALGO_ELGAMAL
			&& !mpi_cmp( req_skc->d.elg.p, skc->d.elg.p )
			&& !mpi_cmp( req_skc->d.elg.g, skc->d.elg.g )
			&& !mpi_cmp( req_skc->d.elg.y, skc->d.elg.y )
			&& !mpi_cmp( req_skc->d.elg.x, skc->d.elg.x )
		      )
		   || ( skc->pubkey_algo == PUBKEY_ALGO_RSA
			&& !mpi_cmp( req_skc->d.rsa.rsa_n, skc->d.rsa.rsa_n )
			&& !mpi_cmp( req_skc->d.rsa.rsa_e, skc->d.rsa.rsa_e )
			&& !mpi_cmp( req_skc->d.rsa.rsa_d, skc->d.rsa.rsa_d )
		      )
		  )
	      )
		break; /* found */
	}
	else if( pkt.pkttype == PKT_PUBLIC_CERT ) {
	    PKT_public_cert *pkc = pkt.pkt.public_cert;

	    if(   req_pkc->timestamp == pkc->timestamp
	       && req_pkc->valid_days == pkc->valid_days
	       && req_pkc->pubkey_algo == pkc->pubkey_algo
	       && (   ( pkc->pubkey_algo == PUBKEY_ALGO_ELGAMAL
			&& !mpi_cmp( req_pkc->d.elg.p, pkc->d.elg.p )
			&& !mpi_cmp( req_pkc->d.elg.g, pkc->d.elg.g )
			&& !mpi_cmp( req_pkc->d.elg.y, pkc->d.elg.y )
		      )
		   || ( pkc->pubkey_algo == PUBKEY_ALGO_RSA
			&& !mpi_cmp( req_pkc->d.rsa.rsa_n, pkc->d.rsa.rsa_n )
			&& !mpi_cmp( req_pkc->d.rsa.rsa_e, pkc->d.rsa.rsa_e )
		      )
		  )
	      )
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
    return rc;
}

/****************
 * search one keyring, return 0 if found, -1 if not found or an errorcode.
 * this version uses the finger print and other informations
 */
static int
keyring_search2( PUBKEY_FIND_INFO info, KBPOS *kbpos, const char *fname )
{
    int rc;
    PACKET pkt;
    int save_mode;
    ulong offset;
    IOBUF iobuf;

    init_packet(&pkt);
    save_mode = set_packet_list_mode(0);

    iobuf = iobuf_open( fname );
    if( !iobuf ) {
	log_error("can't open '%s'\n", fname );
	rc = G10ERR_OPEN_FILE;
	goto leave;
    }

    while( !(rc=search_packet(iobuf, &pkt, PKT_PUBLIC_CERT, &offset)) ) {
	PKT_public_cert *pkc = pkt.pkt.public_cert;
	u32 keyid[2];

	assert( pkt.pkttype == PKT_PUBLIC_CERT );
	keyid_from_pkc( pkc, keyid );
	if( keyid[0] == info->keyid[0] && keyid[1] == info->keyid[1]
	    && pkc->pubkey_algo == info->pubkey_algo ) {
	    /* fixme: shall we check nbits too? (good for rsa keys) */
	    /* fixme: check userid???? */
	    size_t len;
	    byte *fp = fingerprint_from_pkc( pkc, &len );

	    if( !memcmp( fp, info->fingerprint, len ) ) {
		m_free(fp);
		break; /* found */
	    }
	    m_free(fp);
	}
	free_packet(&pkt);
    }
    if( !rc )
	kbpos->offset = offset;

  leave:
    iobuf_close(iobuf);
    free_packet(&pkt);
    set_packet_list_mode(save_mode);
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
	log_error("can't open '%s'\n", rentry->fname );
	return G10ERR_OPEN_FILE;
    }

    if( iobuf_seek( a, kbpos->offset ) ) {
	log_error("can't seek to %lu: %s\n", kbpos->offset, g10_errstr(rc));
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
	    continue;
	}
	/* make a linked list of all packets */
	switch( pkt->pkttype ) {
	  case PKT_PUBLIC_CERT:
	  case PKT_SECRET_CERT:
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
    else {
	*ret_root = root;
    }
    free_packet( pkt );
    m_free( pkt );
    iobuf_close(a);
    return rc;
}



/****************
 * Peromf insert/delete/update operation.
 * mode 1 = insert
 *	2 = delete
 *	3 = update
 */
static int
keyring_copy( KBPOS *kbpos, int mode, KBNODE root )
{
    RESTBL *rentry;
    IOBUF fp, newfp;
    int rc;
    char *bakfname = NULL;
    char *tmpfname = NULL;

    if( !(rentry = check_pos( kbpos )) )
	return G10ERR_GENERAL;

    /* open the source file */
    fp = iobuf_open( rentry->fname );
    if( mode == 1 && !fp && errno == ENOENT ) { /* no file yet */
	KBNODE kbctx, node;

	/* insert: create a new file */
	newfp = iobuf_create( rentry->fname );
	if( !newfp ) {
	    log_error("%s: can't create: %s\n", rentry->fname, strerror(errno));
	    return G10ERR_OPEN_FILE;
	}

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
    bakfname = m_alloc( strlen( rentry->fname ) + 2 );
    strcpy(stpcpy(bakfname,rentry->fname),"~");
    tmpfname = m_alloc( strlen( rentry->fname ) + 5 );
    strcpy(stpcpy(tmpfname,rentry->fname),".tmp");
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
    iobuf_close(fp);
    if( iobuf_close(newfp) ) {
	log_error("%s: close failed: %s\n", tmpfname, strerror(errno) );
	rc = G10ERR_CLOSE_FILE;
	goto leave;
    }
    /* if the new file is a secring, restrict the permissions */
    if( rentry->secret ) {
	if( chmod( tmpfname, S_IRUSR | S_IWUSR ) ) {
	    log_error("%s: chmod failed: %s\n",
				    tmpfname, strerror(errno) );
	    rc = G10ERR_WRITE_FILE;
	    goto leave;
	}
    }
    /* rename and make backup file */
    if( rename( rentry->fname, bakfname ) ) {
	log_error("%s: rename to %s failed: %s\n",
				rentry->fname, bakfname, strerror(errno) );
	rc = G10ERR_RENAME_FILE;
	goto leave;
    }
    if( rename( tmpfname, rentry->fname ) ) {
	log_error("%s: rename to %s failed: %s\n",
			    tmpfname, rentry->fname,strerror(errno) );
	rc = G10ERR_RENAME_FILE;
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

