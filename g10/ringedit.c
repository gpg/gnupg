/* ringedit.c -  Function for key ring editing
 *	Copyright (C) 1998, 2000 Free Software Foundation, Inc.
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

#include <gcrypt.h>
#include "util.h"
#include "packet.h"
#include "iobuf.h"
#include "keydb.h"
#include "host2net.h"
#include "options.h"
#include "main.h"
#include "i18n.h"
#include "kbx.h"




struct resource_table_struct {
    int used;
    int secret; /* this is a secret keyring */
    char *fname;
    IOBUF iobuf;
    enum resource_type rt;
    DOTLOCK lockhd;
    int    is_locked;
};
typedef struct resource_table_struct RESTBL;


struct keyblock_pos_struct {
    int   resno;     /* resource number */
    enum resource_type rt;
    ulong offset;    /* position information */
    unsigned count;  /* length of the keyblock in packets */
    IOBUF  fp;	     /* used by enum_keyblocks */
    int secret;      /* working on a secret keyring */
    PACKET *pkt;     /* ditto */
    int valid;
    ulong save_offset;
};




#define MAX_RESOURCES 10
static RESTBL resource_table[MAX_RESOURCES];
static int default_public_resource;
static int default_secret_resource;

static int keyring_enum( KBPOS kbpos, KBNODE *ret_root, int skipsigs );
static int keyring_copy( KBPOS kbpos, int mode, KBNODE root );

static int do_kbxf_enum( KBPOS kbpos, KBNODE *ret_root, int skipsigs );
static int do_kbxf_copy( KBPOS kbpos, int mode, KBNODE root );


static RESTBL *
check_pos( KBPOS kbpos )
{
    if( kbpos->resno < 0 || kbpos->resno >= MAX_RESOURCES )
	return NULL;
    if( !resource_table[kbpos->resno].used )
	return NULL;
    return resource_table + kbpos->resno;
}


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


    /* Do we have an URL?
     *	gnupg-kbxf:filename  := this is a KBX file resource
     *	gnupg-ring:filename  := this is a plain keyring
     *	filename := See what is is, but create as plain keyring.
     */
    if( strlen( resname ) > 11 ) {
	if( !strncmp( resname, "gnupg-ring:", 11 ) ) {
	    rt = rt_RING;
	    resname += 11;
	}
	else if( !strncmp( resname, "gnupg-kbxf:", 11 ) ) {
	    rt = rt_KBXF;
	    resname += 11;
	}
      #ifndef HAVE_DRIVE_LETTERS
	else if( strchr( resname, ':' ) ) {
	    log_error("%s: invalid URL\n", url );
	    rc = GPGERR_GENERAL;
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
	filename = gcry_xstrdup( resname );

    if( !force )
	force = secret? !any_secret : !any_public;

    for(i=0; i < MAX_RESOURCES; i++ )
	if( !resource_table[i].used )
	    break;
    if( i == MAX_RESOURCES ) {
	rc = GPGERR_RESOURCE_LIMIT;
	goto leave;
    }

    /* see whether we can determine the filetype */
    if( rt == rt_UNKNOWN ) {
	FILE *fp = fopen( filename, "rb" );

	if( fp ) {
	    u32 magic;

	    if( fread( &magic, 4, 1, fp) == 1 ) {
                char buf[8];

                rt = rt_RING;
                if( fread( buf, 8, 1, fp) == 1 ) {
                    if( !memcmp( buf+4, "KBXf", 4 )
                        && buf[0] == 1 && buf[1] == 1 ) {
                        rt = rt_KBXF;
                    }
                }
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
	rc = GPGERR_GENERAL;
	goto leave;

      case rt_RING:
      case rt_KBXF:
	iobuf = iobuf_open( filename );
	if( !iobuf && !force ) {
	    rc = GPGERR_OPEN_FILE;
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
		rc = GPGERR_OPEN_FILE;
		goto leave;
	    }

	    *last_slash_in_filename = '/';

	    iobuf = iobuf_create( filename );
	    if( !iobuf ) {
		log_error(_("%s: can't create keyring: %s\n"),
					    filename, strerror(errno));
		rc = GPGERR_OPEN_FILE;
		goto leave;
	    }
	    else {
	      #ifndef HAVE_DOSISH_SYSTEM
		if( secret ) {
		    if( chmod( filename, S_IRUSR | S_IWUSR ) ) {
			log_error("%s: chmod failed: %s\n",
						filename, strerror(errno) );
			rc = GPGERR_WRITE_FILE;
			goto leave;
		    }
		}
	      #endif
		if( !opt.quiet )
		    log_info(_("%s: keyring created\n"), filename );
	    }
	}
      #if HAVE_DOSISH_SYSTEM || 1
	iobuf_close( iobuf );
	iobuf = NULL;
	/* must close it again */
      #endif
	break;


      default:
	log_error("%s: unsupported resource type\n", url );
	rc = GPGERR_GENERAL;
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
    resource_table[i].fname = gcry_xstrdup(filename);
    resource_table[i].iobuf = iobuf;
    resource_table[i].rt    = rt;
    if( secret )
	default_secret_resource = i;
    else
	default_public_resource = i;

  leave:
    if( rc )
	log_error("keyblock resource `%s': %s\n", filename, gpg_errstr(rc) );
    else if( secret )
	any_secret = 1;
    else
	any_public = 1;
    gcry_free( filename );
    return rc;
}

/****************
 * Return the resource name of the keyblock associated with KBPOS.
 */
const char *
keyblock_resource_name( KBPOS kbpos )
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
get_keyblock_handle( const char *filename, int secret, KBPOS kbpos )
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
	    return gcry_xstrdup( resource_table[i].fname );
	}
    }
    for(i=0; i < MAX_RESOURCES; i++ ) {
	if( resource_table[i].used && !resource_table[i].secret == !secret ) {
	    if( !access( resource_table[i].fname, R_OK|W_OK ) ) {
		return gcry_xstrdup( resource_table[i].fname );
	    }
	}
    }
    /* Assume the home dir is always writable */
    return  make_filename(opt.homedir, secret? "secring.gpg"
					     : "pubring.gpg", NULL );
}


void
ringedit_copy_kbpos ( KBPOS d, KBPOS s )
{
    *d = *s;
}


/****************
 * Lock the keyblock; wait until it's available
 * This function may change the internal data in kbpos, in cases
 * when the keyblock to be locked has been modified.
 * fixme: remove this function and add an option to search()?
 */
static int
lock_keyblock( KBPOS kbpos )
{
    if( !check_pos(kbpos) )
	return GPGERR_GENERAL;
    return 0;
}

/****************
 * Release a lock on a keyblock
 */
static void
unlock_keyblock( KBPOS kbpos )
{
    if( !check_pos(kbpos) )
	BUG();
}


static int
enum_keyrings_open_helper( KBPOS kbpos, int where )
{
    int i = where;
    RESTBL *rentry;

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
      case rt_KBXF:
        kbpos->fp = iobuf_open( rentry->fname );
        if ( !kbpos->fp ) {
            log_error("can't open `%s'\n", rentry->fname );
            return GPGERR_OPEN_FILE;
        }
        break;
    
       default: BUG();
    }
    kbpos->pkt = NULL;
    return 0;
}


/****************
 * This set of functions is used to scan over all keyrings.
 * The mode in enum_keyblocks_next() is used liek this:
 * Mode is: 1 = read
 *	    11 = read but skip signature and comment packets.
 */
int
enum_keyblocks_begin( KBPOS *rkbpos, int use_secret )
{
    int rc, i;
    KBPOS kbpos;
    
    *rkbpos = NULL;

    kbpos = gcry_xcalloc( 1, sizeof *kbpos );
    kbpos->fp = NULL;
    kbpos->rt = rt_UNKNOWN;
    if( !use_secret ) {
        kbpos->secret = 0;
        i = 0;
    }
    else {
        kbpos->secret = 1;
        i = 0;
    }
    
    rc = enum_keyrings_open_helper( kbpos, i );
    if ( rc ) {
        gcry_free( kbpos );
        return rc;
    }
    /* return the handle */
    *rkbpos = kbpos;
    return 0;
}

void
enum_keyblocks_end( KBPOS kbpos )
{
    if ( !kbpos )
        return;
    switch( kbpos->rt ) {
     case rt_RING:
     case rt_KBXF:
       if( kbpos->fp ) {
           iobuf_close( kbpos->fp );
           kbpos->fp = NULL;
       }
       break;
     case rt_UNKNOWN:
       /* this happens when we have no keyring at all */
       gcry_free( kbpos );
       return;

     default:
       BUG();
    }
    /* release pending packet */
    free_packet( kbpos->pkt );
    gcry_free( kbpos->pkt );
    gcry_free( kbpos );
}

int
enum_keyblocks_next( KBPOS kbpos, int mode, KBNODE *ret_root )
{
    int cont, rc = 0;
    RESTBL *rentry;

    if( mode != 1 && mode != 11 ) 
        return GPGERR_INV_ARG;

    do {
        cont = 0;
        switch( kbpos->rt ) {
          case rt_RING:
            if( !kbpos->fp )
                return GPGERR_GENERAL;
            rc = keyring_enum( kbpos, ret_root, mode == 11 );
            break;
          case rt_KBXF:
            if( !kbpos->fp )
                return GPGERR_GENERAL;
            rc = do_kbxf_enum( kbpos, ret_root, mode == 11 );
            break;
          default: BUG();
        }

        if( rc == -1 ) {
            RESTBL *rentry;
            int i;

            assert( !kbpos->pkt );
            rentry = check_pos( kbpos );
            assert(rentry);
            i = kbpos->resno+1;
            /* first close */
            if( kbpos->fp ) {
                iobuf_close( kbpos->fp );
                kbpos->fp = NULL;
            }
            free_packet( kbpos->pkt );
            gcry_free( kbpos->pkt );
            kbpos->pkt = NULL;
            /* and then open the next one */
            rc = enum_keyrings_open_helper( kbpos, i );
            if ( !rc ) 
                cont = 1;
            /* hmm, that is not really correct: if we got an error kbpos
             * might be not well anymore */
        }
    } while(cont);

    return rc;
}




/****************
 * Insert the keyblock described by ROOT into the keyring described
 * by KBPOS.  This actually appends the data to the keyfile.
 */
int
insert_keyblock( KBNODE root )
{
    int rc;
#if 0
    if( !check_pos(kbpos) )
	return GPGERR_GENERAL;

    switch( kbpos->rt ) {
      case rt_RING:
	rc = keyring_copy( kbpos, 1, root );
	break;
      case rt_KBXF:
	rc = do_kbxf_copy( kbpos, 1, root );
	break;
      default: BUG();
    }
#endif
    return rc;
}

/****************
 * Delete the keyblock described by KBPOS.
 * The current code simply changes the keyblock in the keyring
 * to packet of type 0 with the correct length.  To help detect errors,
 * zero bytes are written.
 */
int
delete_keyblock( KBNODE keyblock )
{
    int rc;
  #if 0
    if( !check_pos(kbpos) )
	return GPGERR_GENERAL;

    switch( kbpos->rt ) {
      case rt_RING:
	rc = keyring_copy( kbpos, 2, NULL );
	break;
      case rt_KBXF:
	rc = do_kbxf_copy( kbpos, 2, NULL );
	break;
      default: BUG();
    }
  #endif
    return rc;
}


/****************
 * Update the keyblock in the ring (or whatever resource) one in ROOT.
 */
int
update_keyblock( KBNODE root )
{
    int rc;
    struct keyblock_pos_struct kbpos;
    
    /* We need to get the file position of original keyblock first */
    if ( root->pkt->pkttype == PKT_PUBLIC_KEY )
        rc = find_kblocation_bypk( &kbpos, root->pkt->pkt.public_key );
    else if ( root->pkt->pkttype == PKT_SECRET_KEY )
        rc = find_kblocation_bysk( &kbpos, root->pkt->pkt.secret_key );
    else
        BUG();

    if ( rc )
        return rc;

    if( !check_pos(&kbpos) )
	return GPGERR_GENERAL;

    switch( kbpos.rt ) {
      case rt_RING:
	rc = keyring_copy( &kbpos, 3, root );
	break;
      case rt_KBXF:
	rc = do_kbxf_copy( &kbpos, 3, root );
	break;
      default: BUG();
    }

    return rc;
}



/****************************************************************
 ********** Functions which operates on regular keyrings ********
 ****************************************************************/

static int
keyring_enum( KBPOS kbpos, KBNODE *ret_root, int skipsigs )
{
    PACKET *pkt;
    int rc;
    RESTBL *rentry;
    KBNODE root = NULL;
    ulong offset, first_offset=0;

    if( !(rentry=check_pos(kbpos)) )
	return GPGERR_GENERAL;

    if( kbpos->pkt ) {
	root = new_kbnode( kbpos->pkt );
        first_offset = kbpos->save_offset;
	kbpos->pkt = NULL;
    }
    kbpos->valid = 0;

    pkt = gcry_xmalloc( sizeof *pkt );
    init_packet(pkt);
    while( (rc=parse_packet(kbpos->fp, pkt, &offset )) != -1 ) {
	if( rc ) {  /* ignore errors */
	    if( rc != GPGERR_UNKNOWN_PACKET ) {
		log_error("keyring_enum: read error: %s\n", gpg_errstr(rc) );
		rc = GPGERR_INV_KEYRING;
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
	    if( root ) { /* save this packet */
		kbpos->pkt = pkt;
                kbpos->save_offset = offset;
		pkt = NULL;
		goto ready;
	    }
	    root = new_kbnode( pkt );
            first_offset = offset;
	    pkt = gcry_xmalloc( sizeof *pkt );
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
	    pkt = gcry_xmalloc( sizeof *pkt );
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
        if ( root ) {
            kbpos->offset = first_offset;
            kbpos->valid = 1;
        }
	*ret_root = root;
    }
    free_packet( pkt );
    gcry_free( pkt );

    return rc;
}


/****************
 * Perform insert/delete/update operation.
 * mode 1 = insert
 *	2 = delete
 *	3 = update
 */
static int
keyring_copy( KBPOS kbpos, int mode, KBNODE root )
{
    RESTBL *rentry;
    IOBUF fp, newfp;
    int rc=0;
    char *bakfname = NULL;
    char *tmpfname = NULL;
#warning We need to lock the keyring while we are editing it.
    /* rethink this whole module */

    if( !(rentry = check_pos( kbpos )) )
	return GPGERR_GENERAL;

    if( opt.dry_run )
	return 0;

    lock_rentry( rentry );

    /* open the source file */
    if( kbpos->fp ) {
	/* BUG(); not allowed with such a handle */
        log_debug("keyring_copy: closing fp %p\n", kbpos->fp );
        iobuf_close (kbpos->fp);
        kbpos->fp = NULL;
        kbpos->valid = 0;
    }
    fp = iobuf_open( rentry->fname );
    if( mode == 1 && !fp && errno == ENOENT ) { /* no file yet */
	KBNODE kbctx, node;

	/* insert: create a new file */
	newfp = iobuf_create( rentry->fname );
	if( !newfp ) {
	    log_error(_("%s: can't create: %s\n"), rentry->fname, strerror(errno));
	    unlock_rentry( rentry );
	    return GPGERR_OPEN_FILE;
	}
	else if( !opt.quiet )
	    log_info(_("%s: keyring created\n"), rentry->fname );

	kbctx=NULL;
	while( (node = walk_kbnode( root, &kbctx, 0 )) ) {
	    if( (rc = build_packet( newfp, node->pkt )) ) {
		log_error("build_packet(%d) failed: %s\n",
			    node->pkt->pkttype, gpg_errstr(rc) );
		iobuf_cancel(newfp);
		unlock_rentry( rentry );
		return GPGERR_WRITE_FILE;
	    }
	}
	if( iobuf_close(newfp) ) {
	    log_error("%s: close failed: %s\n", rentry->fname, strerror(errno));
	    unlock_rentry( rentry );
	    return GPGERR_CLOSE_FILE;
	}
	if( chmod( rentry->fname, S_IRUSR | S_IWUSR ) ) {
	    log_error("%s: chmod failed: %s\n",
				    rentry->fname, strerror(errno) );
	    unlock_rentry( rentry );
	    return GPGERR_WRITE_FILE;
	}
	return 0;
    }
    if( !fp ) {
	log_error("%s: can't open: %s\n", rentry->fname, strerror(errno) );
	rc = GPGERR_OPEN_FILE;
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
	bakfname = gcry_xmalloc( strlen( rentry->fname ) + 1 );
	strcpy(bakfname,rentry->fname);
	strcpy(bakfname+strlen(rentry->fname)-4, ".bak");
	tmpfname = gcry_xmalloc( strlen( rentry->fname ) + 1 );
	strcpy(tmpfname,rentry->fname);
	strcpy(tmpfname+strlen(rentry->fname)-4, ".tmp");
    }
    else { /* file does not end with gpg; hmmm */
	bakfname = gcry_xmalloc( strlen( rentry->fname ) + 5 );
	strcpy(stpcpy(bakfname,rentry->fname),".bak");
	tmpfname = gcry_xmalloc( strlen( rentry->fname ) + 5 );
	strcpy(stpcpy(tmpfname,rentry->fname),".tmp");
    }
  #else
    bakfname = gcry_xmalloc( strlen( rentry->fname ) + 2 );
    strcpy(stpcpy(bakfname,rentry->fname),"~");
    tmpfname = gcry_xmalloc( strlen( rentry->fname ) + 5 );
    strcpy(stpcpy(tmpfname,rentry->fname),".tmp");
  #endif
    newfp = iobuf_create( tmpfname );
    if( !newfp ) {
	log_error("%s: can't create: %s\n", tmpfname, strerror(errno) );
	iobuf_close(fp);
	rc = GPGERR_OPEN_FILE;
	goto leave;
    }

    if( mode == 1 ) { /* insert */
	/* copy everything to the new file */
	rc = copy_all_packets( fp, newfp );
	if( rc != -1 ) {
	    log_error("%s: copy to %s failed: %s\n",
		      rentry->fname, tmpfname, gpg_errstr(rc) );
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
		      rentry->fname, tmpfname, gpg_errstr(rc) );
	    iobuf_close(fp);
	    iobuf_cancel(newfp);
	    goto leave;
	}
	/* skip this keyblock */
	assert( kbpos->count );
	rc = skip_some_packets( fp, kbpos->count );
	if( rc ) {
	    log_error("%s: skipping %u packets failed: %s\n",
			    rentry->fname, kbpos->count, gpg_errstr(rc));
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
			    node->pkt->pkttype, gpg_errstr(rc) );
		iobuf_close(fp);
		iobuf_cancel(newfp);
		rc = GPGERR_WRITE_FILE;
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
		      rentry->fname, tmpfname, gpg_errstr(rc) );
	    iobuf_close(fp);
	    iobuf_cancel(newfp);
	    goto leave;
	}
	rc = 0;
    }

    /* close both files */
    if( iobuf_close(fp) ) {
	log_error("%s: close failed: %s\n", rentry->fname, strerror(errno) );
	rc = GPGERR_CLOSE_FILE;
	goto leave;
    }
    if( iobuf_close(newfp) ) {
	log_error("%s: close failed: %s\n", tmpfname, strerror(errno) );
	rc = GPGERR_CLOSE_FILE;
	goto leave;
    }
    /* if the new file is a secring, restrict the permissions */
  #ifndef HAVE_DOSISH_SYSTEM
    if( rentry->secret ) {
	if( chmod( tmpfname, S_IRUSR | S_IWUSR ) ) {
	    log_error("%s: chmod failed: %s\n",
				    tmpfname, strerror(errno) );
	    rc = GPGERR_WRITE_FILE;
	    goto leave;
	}
    }
  #endif

    /* rename and make backup file */
    if( !rentry->secret ) {  /* but not for secret keyrings */
      #ifdef HAVE_DOSISH_SYSTEM
	remove( bakfname );
      #endif
	if( rename( rentry->fname, bakfname ) ) {
	    log_error("%s: rename to %s failed: %s\n",
				    rentry->fname, bakfname, strerror(errno) );
	    rc = GPGERR_RENAME_FILE;
	    goto leave;
	}
    }
  #ifdef HAVE_DOSISH_SYSTEM
    remove( rentry->fname );
  #endif
    if( rename( tmpfname, rentry->fname ) ) {
	log_error("%s: rename to %s failed: %s\n",
			    tmpfname, rentry->fname,strerror(errno) );
	rc = GPGERR_RENAME_FILE;
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
    gcry_free(bakfname);
    gcry_free(tmpfname);
    return rc;
}


/****************************************************************
 ********** Functions which operate on KBX files ****************
 ****************************************************************/

static int
do_kbxf_enum( KBPOS kbpos, KBNODE *ret_root, int skipsigs )
{
    PACKET *pkt;
    int rc;
    RESTBL *rentry;
    KBNODE root = NULL;

    if( !(rentry=check_pos(kbpos)) )
	return GPGERR_GENERAL;

    if( kbpos->pkt ) {
	root = new_kbnode( kbpos->pkt );
	kbpos->pkt = NULL;
    }

    pkt = gcry_xmalloc( sizeof *pkt );
    init_packet(pkt);
    while( (rc=parse_packet(kbpos->fp, pkt, NULL)) != -1 ) {
	if( rc ) {  /* ignore errors */
	    if( rc != GPGERR_UNKNOWN_PACKET ) {
		log_error("do_kbxf_enum: read error: %s\n", gpg_errstr(rc) );
		rc = GPGERR_INV_KEYRING;
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
	    pkt = gcry_xmalloc( sizeof *pkt );
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
	    pkt = gcry_xmalloc( sizeof *pkt );
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
    gcry_free( pkt );

    return rc;
}


/****************
 * Perform insert/delete/update operation.
 * mode 1 = insert
 *	2 = delete
 *	3 = update
 */
static int
do_kbxf_copy( KBPOS kbpos, int mode, KBNODE root )
{
    RESTBL *rentry;
    IOBUF fp, newfp;
    int rc=0;
    char *bakfname = NULL;
    char *tmpfname = NULL;

    if( !(rentry = check_pos( kbpos )) )
	return GPGERR_GENERAL;
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
	    return GPGERR_OPEN_FILE;
	}
	else if( !opt.quiet )
	    log_info(_("%s: keyring created\n"), rentry->fname );

	kbctx=NULL;
	while( (node = walk_kbnode( root, &kbctx, 0 )) ) {
	    if( (rc = build_packet( newfp, node->pkt )) ) {
		log_error("build_packet(%d) failed: %s\n",
			    node->pkt->pkttype, gpg_errstr(rc) );
		iobuf_cancel(newfp);
		unlock_rentry( rentry );
		return GPGERR_WRITE_FILE;
	    }
	}
	if( iobuf_close(newfp) ) {
	    log_error("%s: close failed: %s\n", rentry->fname, strerror(errno));
	    unlock_rentry( rentry );
	    return GPGERR_CLOSE_FILE;
	}
	if( chmod( rentry->fname, S_IRUSR | S_IWUSR ) ) {
	    log_error("%s: chmod failed: %s\n",
				    rentry->fname, strerror(errno) );
	    unlock_rentry( rentry );
	    return GPGERR_WRITE_FILE;
	}
	return 0;
    }
    if( !fp ) {
	log_error("%s: can't open: %s\n", rentry->fname, strerror(errno) );
	rc = GPGERR_OPEN_FILE;
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
	bakfname = gcry_xmalloc( strlen( rentry->fname ) + 1 );
	strcpy(bakfname,rentry->fname);
	strcpy(bakfname+strlen(rentry->fname)-4, ".bak");
	tmpfname = gcry_xmalloc( strlen( rentry->fname ) + 1 );
	strcpy(tmpfname,rentry->fname);
	strcpy(tmpfname+strlen(rentry->fname)-4, ".tmp");
    }
    else { /* file does not end with gpg; hmmm */
	bakfname = gcry_xmalloc( strlen( rentry->fname ) + 5 );
	strcpy(stpcpy(bakfname,rentry->fname),".bak");
	tmpfname = gcry_xmalloc( strlen( rentry->fname ) + 5 );
	strcpy(stpcpy(tmpfname,rentry->fname),".tmp");
    }
  #else
    bakfname = gcry_xmalloc( strlen( rentry->fname ) + 2 );
    strcpy(stpcpy(bakfname,rentry->fname),"~");
    tmpfname = gcry_xmalloc( strlen( rentry->fname ) + 5 );
    strcpy(stpcpy(tmpfname,rentry->fname),".tmp");
  #endif
    newfp = iobuf_create( tmpfname );
    if( !newfp ) {
	log_error("%s: can't create: %s\n", tmpfname, strerror(errno) );
	iobuf_close(fp);
	rc = GPGERR_OPEN_FILE;
	goto leave;
    }

    if( mode == 1 ) { /* insert */
	/* copy everything to the new file */
	rc = copy_all_packets( fp, newfp );
	if( rc != -1 ) {
	    log_error("%s: copy to %s failed: %s\n",
		      rentry->fname, tmpfname, gpg_errstr(rc) );
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
		      rentry->fname, tmpfname, gpg_errstr(rc) );
	    iobuf_close(fp);
	    iobuf_cancel(newfp);
	    goto leave;
	}
	/* skip this keyblock */
	assert( kbpos->count );
	rc = skip_some_packets( fp, kbpos->count );
	if( rc ) {
	    log_error("%s: skipping %u packets failed: %s\n",
			    rentry->fname, kbpos->count, gpg_errstr(rc));
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
			    node->pkt->pkttype, gpg_errstr(rc) );
		iobuf_close(fp);
		iobuf_cancel(newfp);
		rc = GPGERR_WRITE_FILE;
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
		      rentry->fname, tmpfname, gpg_errstr(rc) );
	    iobuf_close(fp);
	    iobuf_cancel(newfp);
	    goto leave;
	}
	rc = 0;
    }

    /* close both files */
    if( iobuf_close(fp) ) {
	log_error("%s: close failed: %s\n", rentry->fname, strerror(errno) );
	rc = GPGERR_CLOSE_FILE;
	goto leave;
    }
    if( iobuf_close(newfp) ) {
	log_error("%s: close failed: %s\n", tmpfname, strerror(errno) );
	rc = GPGERR_CLOSE_FILE;
	goto leave;
    }
    /* if the new file is a secring, restrict the permissions */
  #ifndef HAVE_DOSISH_SYSTEM
    if( rentry->secret ) {
	if( chmod( tmpfname, S_IRUSR | S_IWUSR ) ) {
	    log_error("%s: chmod failed: %s\n",
				    tmpfname, strerror(errno) );
	    rc = GPGERR_WRITE_FILE;
	    goto leave;
	}
    }
  #endif

    /* rename and make backup file */
    if( !rentry->secret ) {  /* but not for secret keyrings */
      #ifdef HAVE_DOSISH_SYSTEM
	remove( bakfname );
      #endif
	if( rename( rentry->fname, bakfname ) ) {
	    log_error("%s: rename to %s failed: %s\n",
				    rentry->fname, bakfname, strerror(errno) );
	    rc = GPGERR_RENAME_FILE;
	    goto leave;
	}
    }
  #ifdef HAVE_DOSISH_SYSTEM
    remove( rentry->fname );
  #endif
    if( rename( tmpfname, rentry->fname ) ) {
	log_error("%s: rename to %s failed: %s\n",
			    tmpfname, rentry->fname,strerror(errno) );
	rc = GPGERR_RENAME_FILE;
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
    gcry_free(bakfname);
    gcry_free(tmpfname);
    return rc;
}




