/* getkey.c -  Get a key from the database
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
#include <assert.h>
#include <ctype.h>
#include "util.h"
#include "packet.h"
#include "memory.h"
#include "iobuf.h"
#include "keydb.h"
#include "options.h"

#define MAX_PKC_CACHE_ENTRIES 500


typedef struct keyid_list {
    struct keyid_list *next;
    u32 keyid[2];
} *keyid_list_t;

typedef struct user_id_db {
    struct user_id_db *next;
    u32 keyid[2];
    int len;
    char name[1];
} *user_id_db_t;

typedef struct pkc_cache_entry {
    struct pkc_cache_entry *next;
    u32 keyid[2];
    PKT_public_cert *pkc;
} *pkc_cache_entry_t;

typedef struct enum_seckey_context {
    int eof;
    STRLIST sl;
    IOBUF iobuf;
} enum_seckey_context_t;


static STRLIST keyrings;
static STRLIST secret_keyrings;

static keyid_list_t unknown_keyids;
static user_id_db_t user_id_db;
static pkc_cache_entry_t pkc_cache;
static int pkc_cache_entries;	/* number of entries in pkc cache */


static int lookup( PKT_public_cert *pkc,
		   int mode,  u32 *keyid, const char *name );
static int lookup_skc( PKT_secret_cert *skc,
		   int mode,  u32 *keyid, const char *name );

/* note this function may be called before secure memory is
 * available */
void
add_keyring( const char *name )
{
    STRLIST sl;
    int rc;

    if( *name != '/' ) { /* do tilde expansion etc */
	char *p ;

	if( strchr(name, '/') )
	    p = make_filename(name, NULL);
	else
	    p = make_filename(opt.homedir, name, NULL);
	sl = m_alloc( sizeof *sl + strlen(p) );
	strcpy(sl->d, p );
	m_free(p);
    }
    else {
	sl = m_alloc( sizeof *sl + strlen(name) );
	strcpy(sl->d, name );
    }
    sl->next = keyrings;
    keyrings = sl;

    /* fixme: We should remove much out of this module and
     * combine it with the keyblock stuff from ringedit.c
     * For now we will simple add the filename as keyblock resource
     */
    rc = add_keyblock_resource( sl->d, 0, 0 );
    if( rc )
	log_error("keyblock resource '%s': %s\n", sl->d, g10_errstr(rc) );
}


/****************
 * Get the name of the keyrings, start with a sequence number of 0.
 */
const char *
get_keyring( int sequence )
{
    STRLIST sl;

    for(sl = keyrings; sl && sequence; sl = sl->next, sequence-- )
	;
    return sl? sl->d : NULL;
}


void
add_secret_keyring( const char *name )
{
    STRLIST sl;
    int rc;

    if( *name != '/' ) { /* do tilde expansion etc */
	char *p ;

	if( strchr(name, '/') )
	    p = make_filename(name, NULL);
	else
	    p = make_filename(opt.homedir, name, NULL);
	sl = m_alloc( sizeof *sl + strlen(p) );
	strcpy(sl->d, p );
	m_free(p);
    }
    else {
	sl = m_alloc( sizeof *sl + strlen(name) );
	strcpy(sl->d, name );
    }
    sl->next = secret_keyrings;
    secret_keyrings = sl;

    /* fixme: We should remove much out of this mpdule and
     * combine it with the keyblock stuff from ringedit.c
     * For now we will simple add the filename as keyblock resource
     */
    rc = add_keyblock_resource( sl->d, 0, 1 );
    if( rc )
	log_error("secret keyblock resource '%s': %s\n", sl->d, g10_errstr(rc));
}


static void
cache_public_cert( PKT_public_cert *pkc )
{
    pkc_cache_entry_t ce;
    u32 keyid[2];

    if( pkc->pubkey_algo == PUBKEY_ALGO_ELGAMAL
	|| pkc->pubkey_algo == PUBKEY_ALGO_DSA
	|| pkc->pubkey_algo == PUBKEY_ALGO_RSA ) {
	keyid_from_pkc( pkc, keyid );
    }
    else
	return; /* don't know how to get the keyid */

    for( ce = pkc_cache; ce; ce = ce->next )
	if( ce->keyid[0] == keyid[0] && ce->keyid[1] == keyid[1] ) {
	    if( DBG_CACHE )
		log_debug("cache_public_cert: already in cache\n");
	    return;
	}

    if( pkc_cache_entries > MAX_PKC_CACHE_ENTRIES ) {
	/* FIMXE: use another algorithm to free some cache slots */
	if( pkc_cache_entries == MAX_PKC_CACHE_ENTRIES )  {
	    pkc_cache_entries++;
	    log_info("too many entries in pkc cache - disabled\n");
	}
	ce = pkc_cache;
	free_public_cert( ce->pkc );
    }
    else {
	pkc_cache_entries++;
	ce = m_alloc( sizeof *ce );
	ce->next = pkc_cache;
	pkc_cache = ce;
    }
    ce->pkc = copy_public_cert( NULL, pkc );
    ce->keyid[0] = keyid[0];
    ce->keyid[1] = keyid[1];
}


/****************
 * Store the association of keyid and userid
 */
void
cache_user_id( PKT_user_id *uid, u32 *keyid )
{
    user_id_db_t r;

    for(r=user_id_db; r; r = r->next )
	if( r->keyid[0] == keyid[0] && r->keyid[1] == keyid[1] ) {
	    if( DBG_CACHE )
	       log_debug("cache_user_id: already in cache\n");
	    return;
	}

    r = m_alloc( sizeof *r + uid->len-1 );
    r->keyid[0] = keyid[0];
    r->keyid[1] = keyid[1];
    r->len = uid->len;
    memcpy(r->name, uid->name, r->len);
    r->next = user_id_db;
    user_id_db = r;
}



/****************
 * Get a public key and store it into the allocated pkc
 * can be called with PKC set to NULL to just read it into some
 * internal structures.
 */
int
get_pubkey( PKT_public_cert *pkc, u32 *keyid )
{
    keyid_list_t kl;
    int internal = 0;
    int rc = 0;
    pkc_cache_entry_t ce;


    /* lets see wether we checked the keyid already */
    for( kl = unknown_keyids; kl; kl = kl->next )
	if( kl->keyid[0] == keyid[0] && kl->keyid[1] == keyid[1] )
	    return G10ERR_NO_PUBKEY; /* already checked and not found */

    /* Try to get it from our cache */
    for( ce = pkc_cache; ce; ce = ce->next )
	if( ce->keyid[0] == keyid[0] && ce->keyid[1] == keyid[1] ) {
	    if( pkc )
		copy_public_cert( pkc, ce->pkc );
	    return 0;
	}
    /* more init stuff */
    if( !pkc ) {
	pkc = m_alloc_clear( sizeof *pkc );
	internal++;
    }


    /* do a lookup */
    rc = lookup( pkc, 11, keyid, NULL );
    if( !rc )
	goto leave;

    /* not found: store it for future reference */
    kl = m_alloc( sizeof *kl );
    kl->keyid[0] = keyid[0];
    kl->keyid[1] = keyid[1];
    kl->next = unknown_keyids;
    unknown_keyids = kl;
    rc = G10ERR_NO_PUBKEY;

  leave:
    if( !rc )
	cache_public_cert( pkc );
    if( internal )
	m_free(pkc);
    return rc;
}


static int
hextobyte( const byte *s )
{
    int c;

    if( *s >= '0' && *s <= '9' )
	c = 16 * (*s - '0');
    else if( *s >= 'A' && *s <= 'F' )
	c = 16 * (10 + *s - 'A');
    else if( *s >= 'a' && *s <= 'f' )
	c = 16 * (10 + *s - 'a');
    else
	return -1;
    s++;
    if( *s >= '0' && *s <= '9' )
	c += *s - '0';
    else if( *s >= 'A' && *s <= 'F' )
	c += 10 + *s - 'A';
    else if( *s >= 'a' && *s <= 'f' )
	c += 10 + *s - 'a';
    else
	return -1;
    return c;
}


/****************
 * Try to get the pubkey by the userid. This functions looks for the
 * first pubkey certificate which has the given name in a user_id.
 * if pkc has the pubkey algo set, the function will only return
 * a pubkey with that algo.
 *
 * - If the username starts with 8,9,16 or 17 hex-digits (the first one
 *   must be in the range 0..9), this is considered a keyid; depending
 *   on the length a short or complete one.
 * - If the username starts with 32,33,40 or 41 hex-digits (the first one
 *   must be in the range 0..9), this is considered a fingerprint.
 *   (Not yet implemented)
 * - If the username starts with a left angle, we assume it is a complete
 *   email address and look only at this part.
 * - If the username starts with a '.', we assume it is the ending
 *   part of an email address
 * - If the username starts with an '@', we assume it is a part of an
 *   email address
 * - If the userid start with an '=' an exact compare is done; this may
 *   also follow the keyid in which case both parts are matched.
 * - If the userid starts with a '*' a case insensitive substring search is
 *   done (This is also the default).
 */
int
get_pubkey_byname( PKT_public_cert *pkc, const char *name )
{
    int internal = 0;
    int rc = 0;
    const char *s;
    u32 keyid[2] = {0}; /* init to avoid compiler warning */
    byte fprint[20];
    int mode = 0;

    /* check what kind of name it is */
    for(s = name; *s && isspace(*s); s++ )
	;
    if( isdigit( *s ) ) { /* a keyid or a fingerprint */
	int i, j;
	char buf[9];

	if( *s == '0' && s[1] == 'x' && isxdigit(s[2]) )
	    s += 2; /*kludge to allow 0x034343434 */
	for(i=0; isxdigit(s[i]); i++ )
	    ;
	if( s[i] && !isspace(s[i]) ) /* not terminated by EOS or blank*/
	    rc = G10ERR_INV_USER_ID;
	else if( i == 8 || (i == 9 && *s == '0') ) { /* short keyid */
	    if( i==9 )
		s++;
	    keyid[1] = strtoul( s, NULL, 16 );
	    mode = 10;
	}
	else if( i == 16 || (i == 17 && *s == '0') ) { /* complete keyid */
	    if( i==17 )
		s++;
	    mem2str(buf, s, 9 );
	    keyid[0] = strtoul( buf, NULL, 16 );
	    keyid[1] = strtoul( s+8, NULL, 16 );
	    mode = 11;
	}
	else if( i == 32 || ( i == 33 && *s == '0' ) ) { /* md5 fingerprint */
	    if( i==33 )
		s++;
	    memset(fprint+16, 4, 0);
	    for(j=0; !rc && j < 16; j++, s+=2 ) {
		int c = hextobyte( s );
		if( c == -1 )
		    rc = G10ERR_INV_USER_ID;
		else
		    fprint[j] = c;
	    }
	    mode = 16;
	}
	else if( i == 40 || ( i == 41 && *s == '0' ) ) { /* sha1/rmd160 fprint*/
	    if( i==33 )
		s++;
	    for(j=0; !rc && j < 20; j++, s+=2 ) {
		int c = hextobyte( s );
		if( c == -1 )
		    rc = G10ERR_INV_USER_ID;
		else
		    fprint[j] = c;
	    }
	    mode = 20;
	}
	else
	    rc = G10ERR_INV_USER_ID;
    }
    else if( *s == '=' ) { /* exact search */
	mode = 1;
	s++;
    }
    else if( *s == '*' ) { /* substring search */
	mode = 2;
	s++;
    }
    else if( *s == '<' ) { /* an email address */
	mode = 3;
    }
    else if( *s == '@' ) { /* a part of an email address */
	mode = 4;
	s++;
    }
    else if( *s == '.' ) { /* an email address, compare from end */
	mode = 5;
	s++;
    }
    else if( *s == '#' ) { /* use local id */
	rc = G10ERR_INV_USER_ID; /* not yet implemented */
    }
    else if( !*s )  /* empty string */
	rc = G10ERR_INV_USER_ID;
    else
	mode = 2;

    if( rc )
	goto leave;

    if( !pkc ) {
	pkc = m_alloc_clear( sizeof *pkc );
	internal++;
    }

    rc = mode < 16? lookup( pkc, mode, keyid, name )
		  : lookup( pkc, mode, keyid, fprint );

  leave:
    if( internal )
	m_free(pkc);
    return rc;
}


/****************
 * Get a secret key and store it into skey
 */
int
get_seckey( PKT_secret_cert *skc, u32 *keyid )
{
    int rc;

    rc = lookup_skc( skc, 11, keyid, NULL );
    if( !rc ) {
	/* check the secret key (this may prompt for a passprase to
	 * unlock the secret key
	 */
	rc = check_secret_key( skc );
    }

    return rc;
}

/****************
 * Check wether the secret key is available
 * Returns: 0 := key is available
 *	    G10ERR_NO_SECKEY := not availabe
 */
int
seckey_available( u32 *keyid )
{
    PKT_secret_cert *skc;
    int rc;

    skc = m_alloc_clear( sizeof *skc );
    rc = lookup_skc( skc, 11, keyid, NULL );
    free_secret_cert( skc );
    return rc;
}



/****************
 * Get a secret key by name and store it into skc
 * If NAME is NULL use the default certificate
 */
int
get_seckey_byname( PKT_secret_cert *skc, const char *name, int unprotect )
{
    int rc;

    /* fixme: add support for compare_name */
    rc = lookup_skc( skc, name? 2:15, NULL, name );
    if( !rc && unprotect )
	rc = check_secret_key( skc );

    return rc;
}


static int
compare_name( const char *uid, size_t uidlen, const char *name, int mode )
{
    int i;

    if( mode == 1 ) {  /* exact match */
	for(i=0; name[i] && uidlen; i++, uidlen-- )
	    if( uid[i] != name[i] )
		break;
	if( !uidlen && !name[i] )
	    return 0; /* found */
    }
    else if( mode == 2 ) { /* case insensitive substring */
	if( memistr( uid, uidlen, name ) )
	    return 0;
    }
    else if( mode == 3 ) { /* case insensitive email address */
	/* FIXME: not yet implemented */
	if( memistr( uid, uidlen, name ) )
	    return 0;
    }
    else if( mode == 4 ) { /* email substring */
	/* FIXME: not yet implemented */
	if( memistr( uid, uidlen, name ) )
	    return 0;
    }
    else if( mode == 5 ) { /* email from end */
	/* FIXME: not yet implemented */
	if( memistr( uid, uidlen, name ) )
	    return 0;
    }
    else
	BUG();

    return -1; /* not found */
}


/****************
 * Lookup a key by scanning all keyrings
 *   mode 1 = lookup by NAME (exact)
 *	  2 = lookup by NAME (substring)
 *	  3 = lookup by NAME (email address)
 *	  4 = email address (substring)
 *	  5 = email address (compare from end)
 *	 10 = lookup by short KEYID (don't care about keyid[0])
 *	 11 = lookup by long  KEYID
 *	 15 = Get the first key.
 *	 16 = lookup by 16 byte fingerprint which is stored in NAME
 *	 20 = lookup by 20 byte fingerprint which is stored in NAME
 * Caller must provide an empty PKC, if the pubkey_algo is filled in, only
 * a key of this algo will be returned.
 */
static int
lookup( PKT_public_cert *pkc, int mode,  u32 *keyid, const char *name )
{
    int rc;
    KBNODE keyblock = NULL;
    KBPOS kbpos;

    rc = enum_keyblocks( 0, &kbpos, &keyblock );
    if( rc ) {
	if( rc == -1 )
	    rc = G10ERR_NO_PUBKEY;
	else if( rc )
	    log_error("enum_keyblocks(open) failed: %s\n", g10_errstr(rc) );
	goto leave;
    }

    while( !(rc = enum_keyblocks( 1, &kbpos, &keyblock )) ) {
	KBNODE k, kk;
	if( mode < 10 ) { /* name lookup */
	    for(k=keyblock; k; k = k->next ) {
		if( k->pkt->pkttype == PKT_USER_ID
		    && !compare_name( k->pkt->pkt.user_id->name,
				      k->pkt->pkt.user_id->len, name, mode)) {
		    /* we found a matching name, look for the key */
		    for(kk=keyblock; kk; kk = kk->next )
			if( (	 kk->pkt->pkttype == PKT_PUBLIC_CERT
			      || kk->pkt->pkttype == PKT_PUBKEY_SUBCERT )
			    && ( !pkc->pubkey_algo
				 || pkc->pubkey_algo
				    == kk->pkt->pkt.public_cert->pubkey_algo))
			break;
		    if( kk ) {
			u32 aki[2];
			keyid_from_pkc( kk->pkt->pkt.public_cert, aki );
			cache_user_id( k->pkt->pkt.user_id, aki );
			k = kk;
			break;
		    }
		    else
			log_error("No key for userid\n");
		}
	    }
	}
	else { /* keyid or fingerprint lookup */
	    for(k=keyblock; k; k = k->next ) {
		if(    k->pkt->pkttype == PKT_PUBLIC_CERT
		    || k->pkt->pkttype == PKT_PUBKEY_SUBCERT ) {
		    if( mode == 10 || mode == 11 ) {
			u32 aki[2];
			keyid_from_pkc( k->pkt->pkt.public_cert, aki );
			if( aki[1] == keyid[1]
			    && ( mode == 10 || aki[0] == keyid[0] )
			    && ( !pkc->pubkey_algo
				 || pkc->pubkey_algo
				    == k->pkt->pkt.public_cert->pubkey_algo) ){
			    /* cache the userid */
			    for(kk=keyblock; kk; kk = kk->next )
				if( kk->pkt->pkttype == PKT_USER_ID )
				    break;
			    if( kk )
				cache_user_id( kk->pkt->pkt.user_id, aki );
			    else
				log_error("No userid for key\n");
			    break; /* found */
			}
		    }
		    else if( mode == 15 ) { /* get the first key */
			if( !pkc->pubkey_algo
			    || pkc->pubkey_algo
				  == k->pkt->pkt.public_cert->pubkey_algo )
			    break;
		    }
		    else if( mode == 16 || mode == 20 ) {
			size_t an;
			byte *afp = fingerprint_from_pkc(
					k->pkt->pkt.public_cert, &an );
			if( an == mode && !memcmp( afp, name, an)
			    && ( !pkc->pubkey_algo
				 || pkc->pubkey_algo
				    == k->pkt->pkt.public_cert->pubkey_algo) ) {
			    m_free(afp);
			    break;
			}
			m_free(afp);
		    }
		    else
			BUG();
		} /* end compare public keys */
	    }
	}
	if( k ) { /* found */
	    assert(    k->pkt->pkttype == PKT_PUBLIC_CERT
		    || k->pkt->pkttype == PKT_PUBKEY_SUBCERT );
	    copy_public_cert( pkc, k->pkt->pkt.public_cert );
	    break; /* enumeration */
	}
	release_kbnode( keyblock );
	keyblock = NULL;
    }
    if( rc == -1 )
	rc = G10ERR_NO_PUBKEY;
    else if( rc )
	log_error("enum_keyblocks(read) failed: %s\n", g10_errstr(rc));

  leave:
    enum_keyblocks( 2, &kbpos, &keyblock ); /* close */
    release_kbnode( keyblock );
    return rc;
}

/****************
 * Ditto for secret keys
 */
static int
lookup_skc( PKT_secret_cert *skc, int mode,  u32 *keyid, const char *name )
{
    int rc;
    KBNODE keyblock = NULL;
    KBPOS kbpos;

    rc = enum_keyblocks( 5 /* open secret */, &kbpos, &keyblock );
    if( rc ) {
	if( rc == -1 )
	    rc = G10ERR_NO_PUBKEY;
	else if( rc )
	    log_error("enum_keyblocks(open secret) failed: %s\n", g10_errstr(rc) );
	goto leave;
    }

    while( !(rc = enum_keyblocks( 1, &kbpos, &keyblock )) ) {
	KBNODE k, kk;
	if( mode < 10 ) { /* name lookup */
	    for(k=keyblock; k; k = k->next ) {
		if( k->pkt->pkttype == PKT_USER_ID
		    && !compare_name( k->pkt->pkt.user_id->name,
				      k->pkt->pkt.user_id->len, name, mode)) {
		    /* we found a matching name, look for the key */
		    for(kk=keyblock; kk; kk = kk->next )
			if( (	 kk->pkt->pkttype == PKT_SECRET_CERT
			      || kk->pkt->pkttype == PKT_SECKEY_SUBCERT )
			    && ( !skc->pubkey_algo
				 || skc->pubkey_algo
				    == kk->pkt->pkt.secret_cert->pubkey_algo))
			break;
		    if( kk ) {
			u32 aki[2];
			keyid_from_skc( kk->pkt->pkt.secret_cert, aki );
			cache_user_id( k->pkt->pkt.user_id, aki );
			k = kk;
			break;
		    }
		    else
			log_error("No key for userid (in skc)\n");
		}
	    }
	}
	else { /* keyid or fingerprint lookup */
	    for(k=keyblock; k; k = k->next ) {
		if(    k->pkt->pkttype == PKT_SECRET_CERT
		    || k->pkt->pkttype == PKT_SECKEY_SUBCERT ) {
		    if( mode == 10 || mode == 11 ) {
			u32 aki[2];
			keyid_from_skc( k->pkt->pkt.secret_cert, aki );
			if( aki[1] == keyid[1]
			    && ( mode == 10 || aki[0] == keyid[0] )
			    && ( !skc->pubkey_algo
				 || skc->pubkey_algo
				    == k->pkt->pkt.secret_cert->pubkey_algo) ){
			    /* cache the userid */
			    for(kk=keyblock; kk; kk = kk->next )
				if( kk->pkt->pkttype == PKT_USER_ID )
				    break;
			    if( kk )
				cache_user_id( kk->pkt->pkt.user_id, aki );
			    else
				log_error("No userid for key\n");
			    break; /* found */
			}
		    }
		    else if( mode == 15 ) { /* get the first key */
			if( !skc->pubkey_algo
			    || skc->pubkey_algo
				  == k->pkt->pkt.secret_cert->pubkey_algo )
			    break;
		    }
		    else if( mode == 16 || mode == 20 ) {
			size_t an;
			byte *afp = fingerprint_from_skc(
					k->pkt->pkt.secret_cert, &an );
			if( an == mode && !memcmp( afp, name, an)
			    && ( !skc->pubkey_algo
				 || skc->pubkey_algo
				    == k->pkt->pkt.secret_cert->pubkey_algo) ) {
			    m_free(afp);
			    break;
			}
			m_free(afp);
		    }
		    else
			BUG();
		} /* end compare secret keys */
	    }
	}
	if( k ) { /* found */
	    assert(    k->pkt->pkttype == PKT_SECRET_CERT
		    || k->pkt->pkttype == PKT_SECKEY_SUBCERT );
	    copy_secret_cert( skc, k->pkt->pkt.secret_cert );
	    break; /* enumeration */
	}
	release_kbnode( keyblock );
	keyblock = NULL;
    }
    if( rc == -1 )
	rc = G10ERR_NO_PUBKEY;
    else if( rc )
	log_error("enum_keyblocks(read) failed: %s\n", g10_errstr(rc));

  leave:
    enum_keyblocks( 2, &kbpos, &keyblock ); /* close */
    release_kbnode( keyblock );
    return rc;
}



/****************
 * Enumerate all secret keys.  Caller must use these procedure:
 *  1) create a void pointer and initialize it to NULL
 *  2) pass this void pointer by reference to this function
 *     and provide space for the secret key (pass a buffer for skc)
 *  3) call this function as long as it does not return -1
 *     to indicate EOF.
 *  4) Always call this function a last time with SKC set to NULL,
 *     so that can free it's context.
 *
 * Return
 */
int
enum_secret_keys( void **context, PKT_secret_cert *skc )
{
    int rc=0;
    PACKET pkt;
    int save_mode;
    enum_seckey_context_t *c = *context;

    if( !c ) { /* make a new context */
	c = m_alloc_clear( sizeof *c );
	*context = c;
	c->sl = secret_keyrings;
    }

    if( !skc ) { /* free the context */
	m_free( c );
	*context = NULL;
	return 0;
    }

    if( c->eof )
	return -1;

    for( ; c->sl; c->sl = c->sl->next ) {
	if( !c->iobuf ) {
	    if( !(c->iobuf = iobuf_open( c->sl->d ) ) ) {
		log_error("enum_secret_keys: can't open '%s'\n", c->sl->d );
		continue; /* try next file */
	    }
	}

	save_mode = set_packet_list_mode(0);
	init_packet(&pkt);
	while( (rc=parse_packet(c->iobuf, &pkt)) != -1 ) {
	    if( rc )
		; /* e.g. unknown packet */
	    else if( pkt.pkttype == PKT_SECRET_CERT ) {
		copy_secret_cert( skc, pkt.pkt.secret_cert );
		set_packet_list_mode(save_mode);
		return 0; /* found */
	    }
	    free_packet(&pkt);
	}
	set_packet_list_mode(save_mode);
	iobuf_close(c->iobuf); c->iobuf = NULL;
    }
    c->eof = 1;
    return -1;
}


/****************
 * Return a string with a printable representation of the user_id.
 * this string must be freed by m_free.
 */
char*
get_user_id_string( u32 *keyid )
{
    user_id_db_t r;
    char *p;
    int pass=0;
    /* try it two times; second pass reads from keyrings */
    do {
	for(r=user_id_db; r; r = r->next )
	    if( r->keyid[0] == keyid[0] && r->keyid[1] == keyid[1] ) {
		p = m_alloc( r->len + 10 );
		sprintf(p, "%08lX %.*s", (ulong)keyid[1], r->len, r->name );
		return p;
	    }
    } while( ++pass < 2 && !get_pubkey( NULL, keyid ) );
    p = m_alloc( 15 );
    sprintf(p, "%08lX [?]", (ulong)keyid[1] );
    return p;
}

char*
get_user_id( u32 *keyid, size_t *rn )
{
    user_id_db_t r;
    char *p;
    int pass=0;
    /* try it two times; second pass reads from keyrings */
    do {
	for(r=user_id_db; r; r = r->next )
	    if( r->keyid[0] == keyid[0] && r->keyid[1] == keyid[1] ) {
		p = m_alloc( r->len );
		memcpy(p, r->name, r->len );
		*rn = r->len;
		return p;
	    }
    } while( ++pass < 2 && !get_pubkey( NULL, keyid ) );
    p = m_alloc( 19 );
    memcpy(p, "[User id not found]", 19 );
    *rn = 19;
    return p;
}


