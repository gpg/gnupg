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

#define DEFINES_GETKEY_CTX 1

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
#include "main.h"
#include "i18n.h"

#define MAX_UNK_CACHE_ENTRIES 1000   /* we use a linked list - so I guess
				      * this is a reasonable limit */
#define MAX_PK_CACHE_ENTRIES	50
#define MAX_UID_CACHE_ENTRIES	50


struct getkey_ctx_s {
    int mode;
    int internal;
    u32 keyid[2];
    char *namebuf;
    const char *name;
    int primary;
    KBNODE keyblock;
    KBPOS kbpos;
    int last_rc;
    ulong count;
};






static struct {
    int any;
    int okay_count;
    int nokey_count;
    int error_count;
} lkup_stats[21];




#if MAX_UNK_CACHE_ENTRIES
  typedef struct keyid_list {
      struct keyid_list *next;
      u32 keyid[2];
  } *keyid_list_t;
  static keyid_list_t unknown_keyids;
  static int unk_cache_entries;   /* number of entries in unknown keys cache */
  static int unk_cache_disabled;
#endif

#if MAX_PK_CACHE_ENTRIES
  typedef struct pk_cache_entry {
      struct pk_cache_entry *next;
      u32 keyid[2];
      PKT_public_key *pk;
  } *pk_cache_entry_t;
  static pk_cache_entry_t pk_cache;
  static int pk_cache_entries;	 /* number of entries in pk cache */
  static int pk_cache_disabled;
#endif

#if MAX_UID_CACHE_ENTRIES < 5
    #error we really need the userid cache
#endif
typedef struct user_id_db {
    struct user_id_db *next;
    u32 keyid[2];
    int len;
    char name[1];
} *user_id_db_t;
static user_id_db_t user_id_db;
static int uid_cache_entries;	/* number of entries in uid cache */



static int lookup( GETKEY_CTX *ctx, PKT_public_key *pk,
		   int mode,  u32 *keyid, const char *name,
		   KBNODE *ret_keyblock, int primary  );
static void lookup_close( GETKEY_CTX ctx );
static int  lookup_read( GETKEY_CTX ctx,
			 PKT_public_key *pk, KBNODE *ret_keyblock );
static int lookup_sk( PKT_secret_key *sk,
		   int mode,  u32 *keyid, const char *name, int primary );



static void
print_stats()
{
    int i;
    for(i=0; i < DIM(lkup_stats); i++ ) {
	if( lkup_stats[i].any )
	    fprintf(stderr,
		    "lookup stats: mode=%-2d  ok=%-6d  nokey=%-6d  err=%-6d\n",
		    i,
		    lkup_stats[i].okay_count,
		    lkup_stats[i].nokey_count,
		    lkup_stats[i].error_count );
    }
}



static void
cache_public_key( PKT_public_key *pk )
{
  #if MAX_PK_CACHE_ENTRIES
    pk_cache_entry_t ce;
    u32 keyid[2];

    if( pk_cache_disabled )
	return;

    if( is_ELGAMAL(pk->pubkey_algo)
	|| pk->pubkey_algo == PUBKEY_ALGO_DSA
	|| is_RSA(pk->pubkey_algo) ) {
	keyid_from_pk( pk, keyid );
    }
    else
	return; /* don't know how to get the keyid */

    for( ce = pk_cache; ce; ce = ce->next )
	if( ce->keyid[0] == keyid[0] && ce->keyid[1] == keyid[1] ) {
	    if( DBG_CACHE )
		log_debug("cache_public_key: already in cache\n");
	    return;
	}

    if( pk_cache_entries >= MAX_PK_CACHE_ENTRIES ) {
	/* fixme: use another algorithm to free some cache slots */
	pk_cache_disabled=1;
	if( opt.verbose )
	    log_info(_("too many entries in pk cache - disabled\n"));
	return;
    }
    pk_cache_entries++;
    ce = m_alloc( sizeof *ce );
    ce->next = pk_cache;
    pk_cache = ce;
    ce->pk = copy_public_key( NULL, pk );
    ce->keyid[0] = keyid[0];
    ce->keyid[1] = keyid[1];
  #endif
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

    if( uid_cache_entries >= MAX_UID_CACHE_ENTRIES ) {
	/* fixme: use another algorithm to free some cache slots */
	r = user_id_db;
	user_id_db = r->next;
	m_free(r);
	uid_cache_entries--;
    }
    r = m_alloc( sizeof *r + uid->len-1 );
    r->keyid[0] = keyid[0];
    r->keyid[1] = keyid[1];
    r->len = uid->len;
    memcpy(r->name, uid->name, r->len);
    r->next = user_id_db;
    user_id_db = r;
    uid_cache_entries++;
}



/****************
 * Get a public key and store it into the allocated pk
 * can be called with PK set to NULL to just read it into some
 * internal structures.
 */
int
get_pubkey( PKT_public_key *pk, u32 *keyid )
{
    int internal = 0;
    int rc = 0;

  #if MAX_UNK_CACHE_ENTRIES
    {	/* let's see whether we checked the keyid already */
	keyid_list_t kl;
	for( kl = unknown_keyids; kl; kl = kl->next )
	    if( kl->keyid[0] == keyid[0] && kl->keyid[1] == keyid[1] )
		return G10ERR_NO_PUBKEY; /* already checked and not found */
    }
  #endif

  #if MAX_PK_CACHE_ENTRIES
    {	/* Try to get it from the cache */
	pk_cache_entry_t ce;
	for( ce = pk_cache; ce; ce = ce->next ) {
	    if( ce->keyid[0] == keyid[0] && ce->keyid[1] == keyid[1] ) {
		if( pk )
		    copy_public_key( pk, ce->pk );
		return 0;
	    }
	}
    }
  #endif
    /* more init stuff */
    if( !pk ) {
	pk = m_alloc_clear( sizeof *pk );
	internal++;
    }


    /* do a lookup */
    rc = lookup( NULL, pk, 11, keyid, NULL, NULL, 0 );
    if( !rc )
	goto leave;

  #if MAX_UNK_CACHE_ENTRIES
    /* not found: store it for future reference */
    if( unk_cache_disabled )
	;
    else if( ++unk_cache_entries > MAX_UNK_CACHE_ENTRIES ) {
	unk_cache_disabled = 1;
	if( opt.verbose )
	    log_info(_("too many entries in unk cache - disabled\n"));
    }
    else {
	keyid_list_t kl;

	kl = m_alloc( sizeof *kl );
	kl->keyid[0] = keyid[0];
	kl->keyid[1] = keyid[1];
	kl->next = unknown_keyids;
	unknown_keyids = kl;
    }
  #endif
    rc = G10ERR_NO_PUBKEY;

  leave:
    if( !rc )
	cache_public_key( pk );
    if( internal )
	free_public_key(pk);
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
 * Return the type of the user id:
 *
 *  0 = Invalid user ID
 *  1 = exact match
 *  2 = match a substring
 *  3 = match an email address
 *  4 = match a substring of an email address
 *  5 = match an email address, but compare from end
 * 10 = it is a short KEYID (don't care about keyid[0])
 * 11 = it is a long  KEYID
 * 16 = it is a 16 byte fingerprint
 * 20 = it is a 20 byte fingerprint
 *
 * if fprint is not NULL, it should be an array of at least 20 bytes.
 *
 * Rules used:
 * - If the username starts with 8,9,16 or 17 hex-digits (the first one
 *   must be in the range 0..9), this is considered a keyid; depending
 *   on the length a short or complete one.
 * - If the username starts with 32,33,40 or 41 hex-digits (the first one
 *   must be in the range 0..9), this is considered a fingerprint.
 * - If the username starts with a left angle, we assume it is a complete
 *   email address and look only at this part.
 * - If the username starts with a '.', we assume it is the ending
 *   part of an email address
 * - If the username starts with an '@', we assume it is a part of an
 *   email address
 * - If the userid start with an '=' an exact compare is done.
 * - If the userid starts with a '*' a case insensitive substring search is
 *   done (This is the default).
 */

int
classify_user_id( const char *name, u32 *keyid, byte *fprint,
		  const char **retstr, size_t *retlen )
{
    const char *s;
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
	    return 0;
	else if( i == 8 || (i == 9 && *s == '0') ) { /* short keyid */
	    if( i==9 )
		s++;
	    if( keyid ) {
		keyid[0] = 0;
		keyid[1] = strtoul( s, NULL, 16 );
	    }
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
	    for(j=0; j < 16; j++, s+=2 ) {
		int c = hextobyte( s );
		if( c == -1 )
		    return 0;
		fprint[j] = c;
	    }
	    mode = 16;
	}
	else if( i == 40 || ( i == 41 && *s == '0' ) ) { /* sha1/rmd160 fprint*/
	    if( i==33 )
		s++;
	    for(j=0; j < 20; j++, s+=2 ) {
		int c = hextobyte( s );
		if( c == -1 )
		    return 0;
		fprint[j] = c;
	    }
	    mode = 20;
	}
	else
	    return 0;
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
	return 0;
    }
    else if( !*s )  /* empty string */
	return 0;
    else
	mode = 2;

    if( retstr )
	*retstr = s;
    if( retlen )
	*retlen = strlen(s);

    return mode;
}



/****************
 * Try to get the pubkey by the userid. This function looks for the
 * first pubkey certificate which has the given name in a user_id.
 * if pk has the pubkey algo set, the function will only return
 * a pubkey with that algo.
 */

static int
key_byname( int secret, GETKEY_CTX *retctx,
	    PKT_public_key *pk, PKT_secret_key *sk,
	    const char *name, KBNODE *ret_kb )
{
    int internal = 0;
    int rc = 0;
    const char *s;
    u32 keyid[2] = {0}; /* init to avoid compiler warning */
    byte fprint[20];
    int mode;

    mode = classify_user_id( name, keyid, fprint, &s, NULL );
    if( !mode ) {
	rc = G10ERR_INV_USER_ID;
	goto leave;
    }

    if( secret ) {
	if( !sk ) {
	    sk = m_alloc_clear( sizeof *sk );
	    internal++;
	}
	rc = mode < 16? lookup_sk( sk, mode, keyid, s, 1 )
		      : lookup_sk( sk, mode, keyid, fprint, 1 );
    }
    else {
	if( !pk ) {
	    pk = m_alloc_clear( sizeof *pk );
	    internal++;
	}
	rc = mode < 16? lookup( retctx, pk, mode, keyid, s, ret_kb, 1 )
		      : lookup( retctx, pk, mode, keyid, fprint, ret_kb, 1 );
    }


  leave:
    if( internal && secret )
	m_free( sk );
    else if( internal )
	m_free( pk );
    return rc;
}

int
get_pubkey_byname( GETKEY_CTX *retctx, PKT_public_key *pk,
		   const char *name, KBNODE *ret_keyblock )
{
    int rc;

    if( !pk ) {
	/* fixme: key_byname should not need a pk in this case */
	pk = m_alloc_clear( sizeof *pk );
	rc = key_byname( 0, retctx, pk, NULL, name, ret_keyblock );
	free_public_key( pk );
    }
    else
	rc = key_byname( 0, retctx, pk, NULL, name, ret_keyblock );
    return rc;
}

int
get_pubkey_next( GETKEY_CTX ctx, PKT_public_key *pk, KBNODE *ret_keyblock )
{
    int rc;

    if( !pk ) {
	/* fixme: lookup_read should not need a pk in this case */
	pk = m_alloc_clear( sizeof *pk );
	rc = lookup_read( ctx, pk, ret_keyblock );
	free_public_key( pk );
    }
    else
	rc = lookup_read( ctx, pk, ret_keyblock );
    return rc;
}

void
get_pubkey_end( GETKEY_CTX ctx )
{
    if( ctx ) {
	lookup_close( ctx );
	m_free( ctx );
    }
}

/****************
 * Search for a key with the given fingerprint.
 */
int
get_pubkey_byfprint( PKT_public_key *pk, const byte *fprint, size_t fprint_len)
{
    int rc;

    if( fprint_len == 20 || fprint_len == 16 )
	rc = lookup( NULL, pk, fprint_len, NULL, fprint, NULL, 0 );
    else
	rc = G10ERR_GENERAL; /* Oops */
    return rc;
}

/****************
 * Search for a key with the given fingerprint and return the
 * complete keyblock which may have more than only this key.
 */
int
get_keyblock_byfprint( KBNODE *ret_keyblock, const byte *fprint,
						size_t fprint_len )
{
    int rc;
    PKT_public_key *pk = m_alloc_clear( sizeof *pk );

    if( fprint_len == 20 || fprint_len == 16 )
	rc = lookup( NULL, pk, fprint_len, NULL, fprint, ret_keyblock, 0 );
    else
	rc = G10ERR_GENERAL; /* Oops */

    free_public_key( pk );
    return rc;
}

/****************
 * Get a secret key and store it into sk
 */
int
get_seckey( PKT_secret_key *sk, u32 *keyid )
{
    int rc;

    rc = lookup_sk( sk, 11, keyid, NULL, 0 );
    if( !rc ) {
	/* check the secret key (this may prompt for a passprase to
	 * unlock the secret key
	 */
	rc = check_secret_key( sk, 0 );
    }

    return rc;
}

/****************
 * Check whether the secret key is available
 * Returns: 0 := key is available
 *	    G10ERR_NO_SECKEY := not availabe
 */
int
seckey_available( u32 *keyid )
{
    PKT_secret_key *sk;
    int rc;

    sk = m_alloc_clear( sizeof *sk );
    rc = lookup_sk( sk, 11, keyid, NULL, 0 );
    free_secret_key( sk );
    return rc;
}



/****************
 * Get a secret key by name and store it into sk
 * If NAME is NULL use the default key
 */
int
get_seckey_byname( PKT_secret_key *sk, const char *name, int unprotect )
{
    int rc;

    if( !name && opt.def_secret_key && *opt.def_secret_key )
	rc = key_byname( 1, NULL, NULL, sk, opt.def_secret_key, NULL );
    else if( !name ) /* use the first one as default key */
	rc = lookup_sk( sk, 15, NULL, NULL, 1 );
    else
	rc = key_byname( 1, NULL, NULL, sk, name, NULL );
    if( !rc && unprotect )
	rc = check_secret_key( sk, 0 );

    return rc;
}


static int
compare_name( const char *uid, size_t uidlen, const char *name, int mode )
{
    int i;
    const char *s, *se;

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
    else if( mode >= 3 && mode <= 5 ) { /* look at the email address */
	for( i=0, s= uid; i < uidlen && *s != '<'; s++, i++ )
	    ;
	if( i < uidlen )  {
	    /* skip opening delim and one char and look for the closing one*/
	    s++; i++;
	    for( se=s+1, i++; i < uidlen && *se != '>'; se++, i++ )
		;
	    if( i < uidlen ) {
		i = se - s;
		if( mode == 3 ) { /* exact email address */
		    if( strlen(name)-2 == i && !memicmp( s, name+1, i) )
			return 0;
		}
		else if( mode == 4 ) {	/* email substring */
		    if( memistr( s, i, name ) )
			return 0;
		}
		else { /* email from end */
		    /* nyi */
		}
	    }
	}
    }
    else
	BUG();

    return -1; /* not found */
}



/****************
 * Assume that knode points to a public key packet  and keyblock is
 * the entire keyblock.  This function adds all relevant information from
 * a selfsignature to the public key.
 */

static void
merge_one_pk_and_selfsig( KBNODE keyblock, KBNODE knode )
{
    PKT_public_key *pk = knode->pkt->pkt.public_key;
    PKT_signature *sig;
    KBNODE k;
    u32 kid[2];

    assert(    knode->pkt->pkttype == PKT_PUBLIC_KEY
	    || knode->pkt->pkttype == PKT_PUBLIC_SUBKEY );

    if( pk->version < 4 )
	return; /* this is only needed for version >=4 packets */

    /* find the selfsignature */
    if( knode->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
	k = find_kbnode( keyblock, PKT_PUBLIC_KEY );
	if( !k )
	   BUG(); /* keyblock without primary key!!! */
	keyid_from_pk( knode->pkt->pkt.public_key, kid );
    }
    else
	keyid_from_pk( pk, kid );
    for(k=keyblock; k; k = k->next ) {
	if( k->pkt->pkttype == PKT_SIGNATURE
	    && (sig=k->pkt->pkt.signature)->sig_class >= 0x10
	    && sig->sig_class <= 0x30
	    && sig->keyid[0] == kid[0]
	    && sig->keyid[1] == kid[1]
	    && sig->version > 3 ) {
	    /* okay this is (the first) self-signature which can be used
	     * FIXME: We should only use this if the signature is valid
	     *	      but this is time consuming - we must provide another
	     *	      way to handle this
	     */
	    const byte *p;
	    p = parse_sig_subpkt( sig->hashed_data, SIGSUBPKT_KEY_EXPIRE, NULL );
	    pk->expiredate = p? pk->timestamp + buffer_to_u32(p):0;
	    /* fixme: add usage etc. to pk */
	    break;
	}
    }
}


/****************
 * merge all selfsignatures with the keys.
 */
void
merge_keys_and_selfsig( KBNODE keyblock )
{
    PKT_public_key *pk = NULL;
    PKT_secret_key *sk = NULL;
    PKT_signature *sig;
    KBNODE k;
    u32 kid[2] = { 0, 0 };

    for(k=keyblock; k; k = k->next ) {
	if( k->pkt->pkttype == PKT_PUBLIC_KEY
	    || k->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
	    pk = k->pkt->pkt.public_key; sk = NULL;
	    if( pk->version < 4 )
		pk = NULL; /* not needed for old keys */
	    else if( k->pkt->pkttype == PKT_PUBLIC_KEY )
		keyid_from_pk( pk, kid );
	}
	else if( k->pkt->pkttype == PKT_SECRET_KEY
	    || k->pkt->pkttype == PKT_SECRET_SUBKEY ) {
	    pk = NULL; sk = k->pkt->pkt.secret_key;
	    if( sk->version < 4 )
		sk = NULL;
	    else if( k->pkt->pkttype == PKT_SECRET_KEY )
		keyid_from_sk( sk, kid );
	}
	else if( (pk || sk ) && k->pkt->pkttype == PKT_SIGNATURE
		 && (sig=k->pkt->pkt.signature)->sig_class >= 0x10
		 && sig->sig_class <= 0x30 && sig->version > 3
		 && sig->keyid[0] == kid[0] && sig->keyid[1] == kid[1] ) {
	    /* okay this is (the first) self-signature which can be used
	     * FIXME: We should only use this if the signature is valid
	     *	      but this is time consuming - we must provide another
	     *	      way to handle this
	     */
	    const byte *p;
	    p = parse_sig_subpkt( sig->hashed_data, SIGSUBPKT_KEY_EXPIRE, NULL );
	    if( pk ) {
		pk->expiredate = p? pk->timestamp + buffer_to_u32(p):0;
		/* fixme: add usage etc. */
		pk = NULL; /* use only the first self signature */
	    }
	    else {
		sk->expiredate = p? sk->timestamp + buffer_to_u32(p):0;
		sk = NULL; /* use only the first self signature */
	    }
	}
    }
}


static KBNODE
find_by_name( KBNODE keyblock, PKT_public_key *pk, const char *name,
	      int mode, byte *namehash, int *use_namehash )
{
    KBNODE k, kk;

    for(k=keyblock; k; k = k->next ) {
	if( k->pkt->pkttype == PKT_USER_ID
	    && !compare_name( k->pkt->pkt.user_id->name,
			      k->pkt->pkt.user_id->len, name, mode)) {
	    /* we found a matching name, look for the key */
	    for(kk=keyblock; kk; kk = kk->next ) {
		if( (	 kk->pkt->pkttype == PKT_PUBLIC_KEY
		      || kk->pkt->pkttype == PKT_PUBLIC_SUBKEY )
		    && ( !pk->pubkey_algo
			 || pk->pubkey_algo
			    == kk->pkt->pkt.public_key->pubkey_algo)
		    && ( !pk->pubkey_usage
			 || !check_pubkey_algo2(
			       kk->pkt->pkt.public_key->pubkey_algo,
						   pk->pubkey_usage ))
		  )
		    break;
	    }
	    if( kk ) {
		u32 aki[2];
		keyid_from_pk( kk->pkt->pkt.public_key, aki );
		cache_user_id( k->pkt->pkt.user_id, aki );
		rmd160_hash_buffer( namehash,
				    k->pkt->pkt.user_id->name,
				    k->pkt->pkt.user_id->len );
		*use_namehash = 1;
		return kk;
	    }
	    else if( is_RSA(pk->pubkey_algo) )
		log_error("RSA key cannot be used in this version\n");
	    else
		log_error("No key for userid\n");
	}
    }
    return NULL;
}


static KBNODE
find_by_keyid( KBNODE keyblock, PKT_public_key *pk, u32 *keyid, int mode )
{
    KBNODE k;

    if( DBG_CACHE )
	log_debug("lookup keyid=%08lx%08lx req_algo=%d mode=%d\n",
		   (ulong)keyid[0], (ulong)keyid[1], pk->pubkey_algo, mode );

    for(k=keyblock; k; k = k->next ) {
	if(    k->pkt->pkttype == PKT_PUBLIC_KEY
	    || k->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
	    u32 aki[2];
	    keyid_from_pk( k->pkt->pkt.public_key, aki );
	    if( DBG_CACHE )
		log_debug("         aki=%08lx%08lx algo=%d\n",
				(ulong)aki[0], (ulong)aki[1],
				 k->pkt->pkt.public_key->pubkey_algo	);

	    if( aki[1] == keyid[1]
		&& ( mode == 10 || aki[0] == keyid[0] )
		&& ( !pk->pubkey_algo
		     || pk->pubkey_algo
			== k->pkt->pkt.public_key->pubkey_algo) ){
		KBNODE kk;
		/* cache the userid */
		for(kk=keyblock; kk; kk = kk->next )
		    if( kk->pkt->pkttype == PKT_USER_ID )
			break;
		if( kk )
		    cache_user_id( kk->pkt->pkt.user_id, aki );
		else
		    log_error("No userid for key\n");
		return k; /* found */
	    }
	}
    }
    return NULL;
}


static KBNODE
find_first( KBNODE keyblock, PKT_public_key *pk )
{
    KBNODE k;

    for(k=keyblock; k; k = k->next ) {
	if(    k->pkt->pkttype == PKT_PUBLIC_KEY
	    || k->pkt->pkttype == PKT_PUBLIC_SUBKEY )
	{
	    if( !pk->pubkey_algo
		|| pk->pubkey_algo == k->pkt->pkt.public_key->pubkey_algo )
		return k;
	}
    }
    return NULL;
}


static KBNODE
find_by_fpr( KBNODE keyblock, PKT_public_key *pk, const char *name, int mode )
{
    KBNODE k;

    for(k=keyblock; k; k = k->next ) {
	if(    k->pkt->pkttype == PKT_PUBLIC_KEY
	    || k->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
	    byte afp[MAX_FINGERPRINT_LEN];
	    size_t an;

	    fingerprint_from_pk(k->pkt->pkt.public_key, afp, &an );

	    if( DBG_CACHE ) {
		u32 aki[2];
		keyid_from_pk( k->pkt->pkt.public_key, aki );
		log_debug("         aki=%08lx%08lx algo=%d mode=%d an=%u\n",
				(ulong)aki[0], (ulong)aki[1],
			k->pkt->pkt.public_key->pubkey_algo, mode, an );
	    }

	    if( an == mode
		&& !memcmp( afp, name, an)
		&& ( !pk->pubkey_algo
		     || pk->pubkey_algo == k->pkt->pkt.public_key->pubkey_algo) )
		return k;
	}
    }
    return NULL;
}


static void
finish_lookup( KBNODE keyblock, PKT_public_key *pk, KBNODE k, byte *namehash,
					       int use_namehash, int primary )
{
    assert(    k->pkt->pkttype == PKT_PUBLIC_KEY
	    || k->pkt->pkttype == PKT_PUBLIC_SUBKEY );
    assert( keyblock->pkt->pkttype == PKT_PUBLIC_KEY );
    if( primary && !pk->pubkey_usage ) {
	copy_public_key_new_namehash( pk, keyblock->pkt->pkt.public_key,
				      use_namehash? namehash:NULL);
	merge_one_pk_and_selfsig( keyblock, keyblock );
    }
    else {
	if( primary && pk->pubkey_usage
	    && check_pubkey_algo2( k->pkt->pkt.public_key->pubkey_algo,
		       pk->pubkey_usage ) == G10ERR_WR_PUBKEY_ALGO ) {
	    /* if the usage is not correct, try to use a subkey */
	    KBNODE save_k = k;

	    k = NULL;
	    /* kludge for pgp 5: which doesn't accept type 20:
	     * try to use a type 16 subkey instead */
	    if( pk->pubkey_usage == PUBKEY_USAGE_ENC ) {
		for( k = save_k; k; k = k->next ) {
		    if( k->pkt->pkttype == PKT_PUBLIC_SUBKEY
			&& k->pkt->pkt.public_key->pubkey_algo
			    == PUBKEY_ALGO_ELGAMAL_E
			&& !check_pubkey_algo2(
				k->pkt->pkt.public_key->pubkey_algo,
						 pk->pubkey_usage ) )
			break;
		}
	    }

	    if( !k ) {
		for(k = save_k ; k; k = k->next ) {
		    if( k->pkt->pkttype == PKT_PUBLIC_SUBKEY
			&& !check_pubkey_algo2(
				k->pkt->pkt.public_key->pubkey_algo,
						 pk->pubkey_usage ) )
			break;
		}
	    }
	    if( !k )
		k = save_k;
	    else
		log_info(_("using secondary key %08lX "
			   "instead of primary key %08lX\n"),
		      (ulong)keyid_from_pk( k->pkt->pkt.public_key, NULL),
		      (ulong)keyid_from_pk( save_k->pkt->pkt.public_key, NULL)
			);
	}

	copy_public_key_new_namehash( pk, k->pkt->pkt.public_key,
				      use_namehash? namehash:NULL);
	merge_one_pk_and_selfsig( keyblock, k );
    }
}

/****************
 * Lookup a key by scanning all keyresources
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
 * Caller must provide an empty PK, if the pubkey_algo is filled in, only
 * a key of this algo will be returned.
 * If ret_keyblock is not NULL, the complete keyblock is returned also
 * and the caller must release it.
 */
static int
lookup( GETKEY_CTX *retctx, PKT_public_key *pk, int mode, u32 *keyid,
	const char *name, KBNODE *ret_keyblock, int primary )
{
    struct getkey_ctx_s help_ctx;
    GETKEY_CTX ctx;
    int rc;

    if( !retctx )
	ctx = &help_ctx;
    else {
	ctx = m_alloc( sizeof *ctx );
	*retctx = ctx;
    }

    memset( ctx, 0, sizeof *ctx );
    ctx->mode = mode;
    if( keyid ) {
	ctx->keyid[0] = keyid[0];
	ctx->keyid[1] = keyid[1];
    }
    if( retctx ) {
	ctx->namebuf = name? m_strdup(name) : NULL;
	ctx->name = ctx->namebuf;
    }
    else
	ctx->name = name;
    ctx->primary = primary;
    rc = lookup_read( ctx, pk, ret_keyblock );
    if( !retctx )
	lookup_close( ctx );
    return rc;
}

static void
lookup_close( GETKEY_CTX ctx )
{
    enum_keyblocks( 2, &ctx->kbpos, NULL ); /* close */
    m_free( ctx->namebuf );
}

static int
lookup_read( GETKEY_CTX ctx, PKT_public_key *pk, KBNODE *ret_keyblock )
{
    int rc;
    KBNODE k;
    int oldmode = set_packet_list_mode(0);
    byte namehash[20];
    int use_namehash=0;

    /* try the quick functions */
    if( !ctx->count ) {
	k = NULL;
	switch( ctx->mode ) {
	  case 10:
	  case 11:
	    rc = locate_keyblock_by_keyid( &ctx->kbpos, ctx->keyid,
							ctx->mode==10, 0 );
	    if( !rc )
		rc = read_keyblock( &ctx->kbpos, &ctx->keyblock );
	    if( !rc )
		k = find_by_keyid( ctx->keyblock, pk, ctx->keyid, ctx->mode );
	    break;

	  case 16:
	  case 20:
	    rc = locate_keyblock_by_fpr( &ctx->kbpos, ctx->name, ctx->mode, 0 );
	    if( !rc )
		rc = read_keyblock( &ctx->kbpos, &ctx->keyblock );
	    if( !rc )
		k = find_by_fpr( ctx->keyblock, pk, ctx->name, ctx->mode );
	    break;

	  default: rc = G10ERR_UNSUPPORTED;
	}
	if( !rc ) {
	    if( !k ) {
		log_error("lookup: key has been located but was not found\n");
		rc = G10ERR_INV_KEYRING;
	    }
	    else
		finish_lookup( ctx->keyblock, pk, k, namehash, 0, ctx->primary );
	}
    }
    else
	rc = G10ERR_UNSUPPORTED;

    /* if this was not possible, loop over all keyblocks
     * fixme: If one of the resources in the quick functions above
     *	      works, but the key was not found, we will not find it
     *	      in the other resources */
    if( rc == G10ERR_UNSUPPORTED ) {
	if( !ctx->count )
	    rc = enum_keyblocks( 0, &ctx->kbpos, &ctx->keyblock );
	else
	    rc = 0;
	if( !rc ) {
	    while( !(rc = enum_keyblocks( 1, &ctx->kbpos, &ctx->keyblock )) ) {
		/* fixme: we don´t enum the complete keyblock, but
		 * use the first match and that continue with the next keyblock
		 */
		if( ctx->mode < 10 )
		    k = find_by_name( ctx->keyblock, pk, ctx->name, ctx->mode,
						    namehash, &use_namehash);
		else if( ctx->mode == 10 ||ctx-> mode == 11 )
		    k = find_by_keyid( ctx->keyblock, pk, ctx->keyid,
								ctx->mode );
		else if( ctx->mode == 15 )
		    k = find_first( ctx->keyblock, pk );
		else if( ctx->mode == 16 || ctx->mode == 20 )
		    k = find_by_fpr( ctx->keyblock, pk, ctx->name, ctx->mode );
		else
		    BUG();
		if( k ) {
		    finish_lookup( ctx->keyblock, pk, k, namehash,
						 use_namehash, ctx->primary );
		    break; /* found */
		}
		release_kbnode( ctx->keyblock );
		ctx->keyblock = NULL;
	    }
	}
	if( rc && rc != -1 )
	    log_error("enum_keyblocks failed: %s\n", g10_errstr(rc));
    }

    if( !rc ) {
	if( ret_keyblock ) {
	    *ret_keyblock = ctx->keyblock;
	    ctx->keyblock = NULL;
	}
    }
    else if( rc == -1 )
	rc = G10ERR_NO_PUBKEY;

    release_kbnode( ctx->keyblock );
    ctx->keyblock = NULL;
    set_packet_list_mode(oldmode);
    if( opt.debug & DBG_MEMSTAT_VALUE ) {
	static int initialized;

	if( !initialized ) {
	    initialized = 1;
	    atexit( print_stats );
	}

	assert( ctx->mode < DIM(lkup_stats) );
	lkup_stats[ctx->mode].any = 1;
	if( !rc )
	    lkup_stats[ctx->mode].okay_count++;
	else if ( rc == G10ERR_NO_PUBKEY )
	    lkup_stats[ctx->mode].nokey_count++;
	else
	    lkup_stats[ctx->mode].error_count++;
    }

    ctx->last_rc = rc;
    ctx->count++;
    return rc;
}


/****************
 * Ditto for secret keys
 */
static int
lookup_sk( PKT_secret_key *sk, int mode,  u32 *keyid, const char *name,
	   int primary )
{
    int rc;
    KBNODE keyblock = NULL;
    KBPOS kbpos;
    int oldmode = set_packet_list_mode(0);

    rc = enum_keyblocks( 5 /* open secret */, &kbpos, &keyblock );
    if( rc ) {
	if( rc == -1 )
	    rc = G10ERR_NO_SECKEY;
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
		    for(kk=keyblock; kk; kk = kk->next ) {
			if( (	 kk->pkt->pkttype == PKT_SECRET_KEY
			      || kk->pkt->pkttype == PKT_SECRET_SUBKEY )
			    && ( !sk->pubkey_algo
				 || sk->pubkey_algo
				    == kk->pkt->pkt.secret_key->pubkey_algo)
			    && ( !sk->pubkey_usage
				 || !check_pubkey_algo2(
				       kk->pkt->pkt.secret_key->pubkey_algo,
							   sk->pubkey_usage ))
			  )
			    break;
		    }
		    if( kk ) {
			u32 aki[2];
			keyid_from_sk( kk->pkt->pkt.secret_key, aki );
			cache_user_id( k->pkt->pkt.user_id, aki );
			k = kk;
			break;
		    }
		    else
			log_error("No key for userid (in sk)\n");
		}
	    }
	}
	else { /* keyid or fingerprint lookup */
	    if( DBG_CACHE && (mode== 10 || mode==11) ) {
		log_debug("lookup_sk keyid=%08lx%08lx req_algo=%d mode=%d\n",
				(ulong)keyid[0], (ulong)keyid[1],
				 sk->pubkey_algo, mode );
	    }
	    for(k=keyblock; k; k = k->next ) {
		if(    k->pkt->pkttype == PKT_SECRET_KEY
		    || k->pkt->pkttype == PKT_SECRET_SUBKEY ) {
		    if( mode == 10 || mode == 11 ) {
			u32 aki[2];
			keyid_from_sk( k->pkt->pkt.secret_key, aki );
			if( DBG_CACHE ) {
			    log_debug("             aki=%08lx%08lx algo=%d\n",
					    (ulong)aki[0], (ulong)aki[1],
				    k->pkt->pkt.secret_key->pubkey_algo    );
			}
			if( aki[1] == keyid[1]
			    && ( mode == 10 || aki[0] == keyid[0] )
			    && ( !sk->pubkey_algo
				 || sk->pubkey_algo
				    == k->pkt->pkt.secret_key->pubkey_algo) ){
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
			if( !sk->pubkey_algo
			    || sk->pubkey_algo
				  == k->pkt->pkt.secret_key->pubkey_algo )
			    break;
		    }
		    else if( mode == 16 || mode == 20 ) {
			size_t an;
			byte afp[MAX_FINGERPRINT_LEN];

			fingerprint_from_sk(k->pkt->pkt.secret_key, afp, &an );
			if( an == mode && !memcmp( afp, name, an)
			    && ( !sk->pubkey_algo
				 || sk->pubkey_algo
				    == k->pkt->pkt.secret_key->pubkey_algo) ) {
			    break;
			}
		    }
		    else
			BUG();
		} /* end compare secret keys */
	    }
	}
	if( k ) { /* found */
	    assert(    k->pkt->pkttype == PKT_SECRET_KEY
		    || k->pkt->pkttype == PKT_SECRET_SUBKEY );
	    assert( keyblock->pkt->pkttype == PKT_SECRET_KEY );
	    if( primary && !sk->pubkey_usage )
		copy_secret_key( sk, keyblock->pkt->pkt.secret_key );
	    else
		copy_secret_key( sk, k->pkt->pkt.secret_key );
	    break; /* enumeration */
	}
	release_kbnode( keyblock );
	keyblock = NULL;
    }
    if( rc == -1 )
	rc = G10ERR_NO_SECKEY;
    else if( rc )
	log_error("enum_keyblocks(read) failed: %s\n", g10_errstr(rc));

  leave:
    enum_keyblocks( 2, &kbpos, &keyblock ); /* close */
    release_kbnode( keyblock );
    set_packet_list_mode(oldmode);
    return rc;
}



/****************
 * Enumerate all primary secret keys.  Caller must use these procedure:
 *  1) create a void pointer and initialize it to NULL
 *  2) pass this void pointer by reference to this function
 *     and provide space for the secret key (pass a buffer for sk)
 *  3) call this function as long as it does not return -1
 *     to indicate EOF.
 *  4) Always call this function a last time with SK set to NULL,
 *     so that can free it's context.
 *
 *
 */
int
enum_secret_keys( void **context, PKT_secret_key *sk, int with_subkeys )
{
    int rc=0;
    PACKET pkt;
    int save_mode;
    struct {
	int eof;
	int sequence;
	const char *name;
	IOBUF iobuf;
    } *c = *context;


    if( !c ) { /* make a new context */
	c = m_alloc_clear( sizeof *c );
	*context = c;
	c->sequence = 0;
	c->name = enum_keyblock_resources( &c->sequence, 1 );
    }

    if( !sk ) { /* free the context */
	if( c->iobuf )
	    iobuf_close(c->iobuf);
	m_free( c );
	*context = NULL;
	return 0;
    }

    if( c->eof )
	return -1;

    /* FIXME: This assumes a plain keyring file */
    for( ; c->name; c->name = enum_keyblock_resources( &c->sequence, 1 ) ) {
	if( !c->iobuf ) {
	    if( !(c->iobuf = iobuf_open( c->name ) ) ) {
		log_error("enum_secret_keys: can't open '%s'\n", c->name );
		continue; /* try next file */
	    }
	}

	save_mode = set_packet_list_mode(0);
	init_packet(&pkt);
	while( (rc=parse_packet(c->iobuf, &pkt)) != -1 ) {
	    if( rc )
		; /* e.g. unknown packet */
	    else if( pkt.pkttype == PKT_SECRET_KEY
		     || ( with_subkeys && pkt.pkttype == PKT_SECRET_SUBKEY ) ) {
		copy_secret_key( sk, pkt.pkt.secret_key );
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
    /* try it two times; second pass reads from key resources */
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
    /* try it two times; second pass reads from key resources */
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


