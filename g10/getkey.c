/* getkey.c -  Get a key from the database
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
#include <assert.h>
#include <ctype.h>
#include "util.h"
#include "packet.h"
#include "memory.h"
#include "iobuf.h"
#include "keydb.h"
#include "options.h"
#include "main.h"
#include "trustdb.h"
#include "i18n.h"


#define MAX_UNK_CACHE_ENTRIES 1000   /* we use a linked list - so I guess
				      * this is a reasonable limit */
#define MAX_PK_CACHE_ENTRIES   200
#define MAX_UID_CACHE_ENTRIES  200

#if MAX_PK_CACHE_ENTRIES < 2
  #error We need the cache for key creation
#endif


/* A map of the all characters valid used for word_match()
 * Valid characters are in in this table converted to uppercase.
 * because the upper 128 bytes have special meaning, we assume
 * that they are all valid.
 * Note: We must use numerical values here in case that this program
 * will be converted to those little blue HAL9000s with their strange
 * EBCDIC character set (user ids are UTF-8).
 * wk 2000-04-13: Hmmm, does this really make sense, given the fact that
 * we can run gpg now on a S/390 running GNU/Linux, where the code
 * translation is done by the device drivers?
 */
static const byte word_match_chars[256] = {
  /* 00 */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  /* 08 */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  /* 10 */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  /* 18 */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  /* 20 */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  /* 28 */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  /* 30 */  0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
  /* 38 */  0x38, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  /* 40 */  0x00, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
  /* 48 */  0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
  /* 50 */  0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
  /* 58 */  0x58, 0x59, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00,
  /* 60 */  0x00, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
  /* 68 */  0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
  /* 70 */  0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
  /* 78 */  0x58, 0x59, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00,
  /* 80 */  0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
  /* 88 */  0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
  /* 90 */  0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
  /* 98 */  0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
  /* a0 */  0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
  /* a8 */  0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
  /* b0 */  0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
  /* b8 */  0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
  /* c0 */  0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
  /* c8 */  0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
  /* d0 */  0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
  /* d8 */  0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
  /* e0 */  0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
  /* e8 */  0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
  /* f0 */  0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
  /* f8 */  0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

typedef struct {
    int mode;
    u32 keyid[2];
    byte fprint[20];
    char *namebuf;
    const char *name;
} getkey_item_t;

struct getkey_ctx_s {
    int exact;
    KBNODE keyblock;
    KBPOS  kbpos;
    KBNODE found_key; /* pointer into some keyblock */
    int last_rc;
    int req_usage;
    int req_algo;
    ulong count;
    int not_allocated;
    int nitems;
    getkey_item_t items[1];
};

#if 0
static struct {
    int any;
    int okay_count;
    int nokey_count;
    int error_count;
} lkup_stats[21];
#endif

typedef struct keyid_list {
    struct keyid_list *next;
    u32 keyid[2];
} *keyid_list_t;


#if MAX_UNK_CACHE_ENTRIES
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
    keyid_list_t keyids;
    int len;
    char name[1];
} *user_id_db_t;
static user_id_db_t user_id_db;
static int uid_cache_entries;	/* number of entries in uid cache */



static char* prepare_word_match( const byte *name );
static int lookup( GETKEY_CTX ctx, KBNODE *ret_kb, int secmode );
static void merge_selfsigs( KBNODE keyblock );


#if 0
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
#endif


void
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
	if( opt.verbose > 1 )
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


/*
 * Return the user ID from the given keyblock.
 * We use the primary uid flag which has been set by the merge_selfsigs
 * function.  The returned value is only valid as long as then given
 * keyblock is not changed
 */
static const char *
get_primary_uid ( KBNODE keyblock, size_t *uidlen )
{
    KBNODE k;
    const char *s;

    for (k=keyblock; k; k=k->next ) {
        if ( k->pkt->pkttype == PKT_USER_ID
             && k->pkt->pkt.user_id->is_primary ) {
            *uidlen = k->pkt->pkt.user_id->len;
            return k->pkt->pkt.user_id->name;
        }
    } 
    /* fixme: returning translatable constants instead of a user ID is 
     * not good because they are probably not utf-8 encoded. */
    s = _("[User id not found]");
    *uidlen = strlen (s);
    return s;
}


static void
release_keyid_list ( keyid_list_t k )
{
    while (  k ) {
        keyid_list_t k2 = k->next;
        m_free (k);
        k = k2;
    }
}

/****************
 * Store the association of keyid and userid
 * Feed only public keys to this function.
 */
static void
cache_user_id( KBNODE keyblock )
{
    user_id_db_t r;
    const char *uid;
    size_t uidlen;
    keyid_list_t keyids = NULL;
    KBNODE k;

    for (k=keyblock; k; k = k->next ) {
        if ( k->pkt->pkttype == PKT_PUBLIC_KEY
             || k->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
            keyid_list_t a = m_alloc_clear ( sizeof *a );
            /* Hmmm: For a long list of keyids it might be an advantage
             * to append the keys */
            keyid_from_pk( k->pkt->pkt.public_key, a->keyid );
            /* first check for duplicates */
            for(r=user_id_db; r; r = r->next ) {
                keyid_list_t b = r->keyids;
                for ( b = r->keyids; b; b = b->next ) {
                    if( b->keyid[0] == a->keyid[0]
                        && b->keyid[1] == a->keyid[1] ) {
                        if( DBG_CACHE )
                            log_debug("cache_user_id: already in cache\n");
                        release_keyid_list ( keyids );
                        m_free ( a );
                        return;
                    }
                }
            }
            /* now put it into the cache */
            a->next = keyids;
            keyids = a;
        }
    }
    if ( !keyids )
        BUG (); /* No key no fun */


    uid = get_primary_uid ( keyblock, &uidlen );

    if( uid_cache_entries >= MAX_UID_CACHE_ENTRIES ) {
	/* fixme: use another algorithm to free some cache slots */
	r = user_id_db;
	user_id_db = r->next;
        release_keyid_list ( r->keyids );
	m_free(r);
	uid_cache_entries--;
    }
    r = m_alloc( sizeof *r + uidlen-1 );
    r->keyids = keyids;
    r->len = uidlen;
    memcpy(r->name, uid, r->len);
    r->next = user_id_db;
    user_id_db = r;
    uid_cache_entries++;
}


void
getkey_disable_caches()
{
  #if MAX_UNK_CACHE_ENTRIES
    {
	keyid_list_t kl, kl2;
	for( kl = unknown_keyids; kl; kl = kl2 ) {
	    kl2 = kl->next;
	    m_free(kl);
	}
	unknown_keyids = NULL;
	unk_cache_disabled = 1;
    }
  #endif
  #if MAX_PK_CACHE_ENTRIES
    {
	pk_cache_entry_t ce, ce2;

	for( ce = pk_cache; ce; ce = ce2 ) {
	    ce2 = ce->next;
	    free_public_key( ce->pk );
	    m_free( ce );
	}
	pk_cache_disabled=1;
	pk_cache_entries = 0;
	pk_cache = NULL;
    }
  #endif
    /* fixme: disable user id cache ? */
}


static void
pk_from_block ( GETKEY_CTX ctx,
                PKT_public_key *pk, KBNODE keyblock, const char *namehash )
{
    KBNODE a = ctx->found_key ? ctx->found_key : keyblock;

    assert ( a->pkt->pkttype == PKT_PUBLIC_KEY
             ||  a->pkt->pkttype == PKT_PUBLIC_SUBKEY );
     
    copy_public_key_new_namehash( pk, a->pkt->pkt.public_key, namehash);
}

static void
sk_from_block ( GETKEY_CTX ctx,
                PKT_secret_key *sk, KBNODE keyblock )
{
    KBNODE a = ctx->found_key ? ctx->found_key : keyblock;

    assert ( a->pkt->pkttype == PKT_SECRET_KEY
             ||  a->pkt->pkttype == PKT_SECRET_SUBKEY );
     
    copy_secret_key( sk, a->pkt->pkt.secret_key);
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
    {	struct getkey_ctx_s ctx;
        KBNODE kb = NULL;
	memset( &ctx, 0, sizeof ctx );
        ctx.exact = 1; /* use the key ID exactly as given */
	ctx.not_allocated = 1;
	ctx.nitems = 1;
	ctx.items[0].mode = 11;
	ctx.items[0].keyid[0] = keyid[0];
	ctx.items[0].keyid[1] = keyid[1];
        ctx.req_algo  = pk->req_algo;
        ctx.req_usage = pk->req_usage;
	rc = lookup( &ctx, &kb, 0 );
        if ( !rc ) {
            pk_from_block ( &ctx, pk, kb, NULL );
        }
	get_pubkey_end( &ctx );
        release_kbnode ( kb );
    }
    if( !rc )
	goto leave;

  #if MAX_UNK_CACHE_ENTRIES
    /* not found: store it for future reference */
    if( unk_cache_disabled )
	;
    else if( ++unk_cache_entries > MAX_UNK_CACHE_ENTRIES ) {
	unk_cache_disabled = 1;
	if( opt.verbose > 1 )
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


KBNODE
get_pubkeyblock( u32 *keyid )
{
    struct getkey_ctx_s ctx;
    int rc = 0;
    KBNODE keyblock = NULL;

    memset( &ctx, 0, sizeof ctx );
    /* co need to set exact here because we want the entire block */
    ctx.not_allocated = 1;
    ctx.nitems = 1;
    ctx.items[0].mode = 11;
    ctx.items[0].keyid[0] = keyid[0];
    ctx.items[0].keyid[1] = keyid[1];
    rc = lookup( &ctx, &keyblock, 0 );
    get_pubkey_end( &ctx );

    return rc ? NULL : keyblock;
}




/****************
 * Get a secret key and store it into sk
 */
int
get_seckey( PKT_secret_key *sk, u32 *keyid )
{
    int rc;
    struct getkey_ctx_s ctx;
    KBNODE kb = NULL;

    memset( &ctx, 0, sizeof ctx );
    ctx.exact = 1; /* use the key ID exactly as given */
    ctx.not_allocated = 1;
    ctx.nitems = 1;
    ctx.items[0].mode = 11;
    ctx.items[0].keyid[0] = keyid[0];
    ctx.items[0].keyid[1] = keyid[1];
    ctx.req_algo  = sk->req_algo;
    ctx.req_usage = sk->req_usage;
    rc = lookup( &ctx, &kb, 1 );
    if ( !rc ) {
        sk_from_block ( &ctx, sk, kb );
    }
    get_seckey_end( &ctx );
    release_kbnode ( kb );

    if( !rc ) {
	/* check the secret key (this may prompt for a passprase to
	 * unlock the secret key
	 */
	rc = check_secret_key( sk, 0 );
    }

    return rc;
}


/****************
 * Check whether the secret key is available.  This is just a fast
 * check and does not tell us whether the secret key is valid.  It
 * merely tells other whether there is some secret key.
 * Returns: 0 := key is available
 * G10ERR_NO_SECKEY := not availabe
 */
int
seckey_available( u32 *keyid )
{
#if 0
    int rc;
    struct getkey_ctx_s ctx;
    KBNODE kb = NULL;

    memset( &ctx, 0, sizeof ctx );
    ctx.exact = 1; /* use the key ID exactly as given */
    ctx.not_allocated = 1;
    ctx.nitems = 1;
    ctx.items[0].mode = 11;
    ctx.items[0].keyid[0] = keyid[0];
    ctx.items[0].keyid[1] = keyid[1];
    rc = lookup( &ctx, &kb, 1 );
    get_seckey_end( &ctx );
    release_kbnode ( kb );
    return rc;
#endif
    int rc;
    int found = 0;
    int oldmode = set_packet_list_mode (0);
    KBNODE keyblock = NULL; 
    KBPOS  kbpos;

    rc = enum_keyblocks ( 5, &kbpos, NULL );
    if ( !rc ) {
	while ( !(rc = enum_keyblocks (1, &kbpos, &keyblock)) ) {
            KBNODE k;

            for (k=keyblock; k; k = k->next ) {
                if ( k->pkt->pkttype == PKT_SECRET_KEY
                     || k->pkt->pkttype == PKT_SECRET_SUBKEY ) {
                    u32 aki[2];
                    keyid_from_sk (k->pkt->pkt.secret_key, aki );
                    if( aki[1] == keyid[1] && aki[0] == keyid[0] ) {
                        found = 1;
                        goto leave;
                    }
                }
            }
            release_kbnode (keyblock); keyblock = NULL;
	}
    }
    if( rc && rc != -1 )
	log_error ("enum_keyblocks failed: %s\n", g10_errstr(rc));
 leave:
    release_kbnode (keyblock); 
    enum_keyblocks ( 2, &kbpos, NULL );
    set_packet_list_mode (oldmode);
    return found? 0 : G10ERR_NO_SECKEY;
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
 *  6 = word match mode
 * 10 = it is a short KEYID (don't care about keyid[0])
 * 11 = it is a long  KEYID
 * 12 = it is a trustdb index (keyid is looked up)
 * 16 = it is a 16 byte fingerprint
 * 20 = it is a 20 byte fingerprint
 * 21 = Unified fingerprint :fpr:pk_algo:
 *      (We don't use pk_algo yet)
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
 * - If the username starts with a colon we assume it is a unified 
 *   key specfification. 
 * - If the username starts with a '.', we assume it is the ending
 *   part of an email address
 * - If the username starts with an '@', we assume it is a part of an
 *   email address
 * - If the userid start with an '=' an exact compare is done.
 * - If the userid starts with a '*' a case insensitive substring search is
 *   done (This is the default).
 * - If the userid starts with a '+' we will compare individual words
 *   and a match requires that all the words are in the userid.
 *   Words are delimited by white space or "()<>[]{}.@-+_,;/&!"
 *   (note that you can't search for these characters). Compare
 *   is not case sensitive.
 */

static int
classify_user_id2( const char *name, u32 *keyid, byte *fprint,
		  const char **retstr, size_t *retlen, int *force_exact )
{
    const char *	s;
    int 		mode = 0;
    int 		hexprefix = 0;
    int 		hexlength;
    
    *force_exact = 0;
    /* skip leading spaces.   FIXME: what is with leading spaces? */
    for(s = name; *s && isspace(*s); s++ )
	;

    switch (*s) {
	case 0:    /* empty string is an error */
	    return 0;

	case '.':  /* an email address, compare from end */
	    mode = 5;
	    s++;
	    break;

	case '<':  /* an email address */
	    mode = 3;
	    break;

	case '@':  /* part of an email address */
	    mode = 4;
	    s++;
	    break;

	case '=':  /* exact compare */
	    mode = 1;
	    s++;
	    break;

	case '*':  /* case insensitive substring search */
	    mode = 2;
	    s++;
	    break;

	case '+':  /* compare individual words */
	    mode = 6;
	    s++;
	    break;

	case '#':  /* local user id */
	    mode = 12;
	    s++;
	    if (keyid) {
		if (keyid_from_lid(strtoul(s, NULL, 10), keyid))
		    keyid[0] = keyid[1] = 0;
	    }
	    break;
        
        case ':': /*Unified fingerprint */
            {  
                const char *se, *si;
                int i;
                
                se = strchr( ++s,':');
                if ( !se )
                    return 0;
                for (i=0,si=s; si < se; si++, i++ ) {
                    if ( !strchr("01234567890abcdefABCDEF", *si ) )
                        return 0; /* invalid digit */
                }
                if (i != 32 && i != 40)
                    return 0; /* invalid length of fpr*/
		if (fprint) {
		    for (i=0,si=s; si < se; i++, si +=2) 
			fprint[i] = hextobyte(si);
                    for ( ; i < 20; i++)
                        fprint[i]= 0;
		}
                s = se + 1;
                mode = 21;
            } 
            break;
           
	default:
	    if (s[0] == '0' && s[1] == 'x') {
		hexprefix = 1;
		s += 2;
	    }

	    hexlength = strspn(s, "0123456789abcdefABCDEF");
            if (hexlength >= 8 && s[hexlength] =='!') {
                *force_exact = 1;
                hexlength++; /* just for the following check */
            }

	    /* check if a hexadecimal number is terminated by EOS or blank */
	    if (hexlength && s[hexlength] && !isspace(s[hexlength])) {
		if (hexprefix)	    /* a "0x" prefix without correct */
		    return 0;	    /* termination is an error */
		else		    /* The first chars looked like */
		    hexlength = 0;  /* a hex number, but really were not. */
	    }

            if (*force_exact)
                hexlength--;

	    if (hexlength == 8
                || (!hexprefix && hexlength == 9 && *s == '0')){
		/* short keyid */
		if (hexlength == 9)
		    s++;
		if (keyid) {
		    keyid[0] = 0;
		    keyid[1] = strtoul( s, NULL, 16 );
		}
		mode = 10;
	    }
	    else if (hexlength == 16
                     || (!hexprefix && hexlength == 17 && *s == '0')) {
		/* complete keyid */
		char buf[9];
		if (hexlength == 17)
		    s++;
		mem2str(buf, s, 9 );
		keyid[0] = strtoul( buf, NULL, 16 );
		keyid[1] = strtoul( s+8, NULL, 16 );
		mode = 11;
	    }
	    else if (hexlength == 32 || (!hexprefix && hexlength == 33
							    && *s == '0')) {
		/* md5 fingerprint */
		int i;
		if (hexlength == 33)
		    s++;
		if (fprint) {
		    memset(fprint+16, 4, 0);
		    for (i=0; i < 16; i++, s+=2) {
			int c = hextobyte(s);
			if (c == -1)
			    return 0;
			fprint[i] = c;
		    }
		}
		mode = 16;
	    }
	    else if (hexlength == 40 || (!hexprefix && hexlength == 41
							      && *s == '0')) {
		/* sha1/rmd160 fingerprint */
		int i;
		if (hexlength == 41)
		    s++;
		if (fprint) {
		    for (i=0; i < 20; i++, s+=2) {
			int c = hextobyte(s);
			if (c == -1)
			    return 0;
			fprint[i] = c;
		    }
		}
		mode = 20;
	    }
	    else {
		if (hexprefix)	/* This was a hex number with a prefix */
		    return 0;	/* and a wrong length */

                *force_exact = 0;
		mode = 2;   /* Default is case insensitive substring search */
	    }
    }

    if( retstr )
	*retstr = s;
    if( retlen )
	*retlen = strlen(s);

    return mode;
}

int
classify_user_id( const char *name, u32 *keyid, byte *fprint,
		  const char **retstr, size_t *retlen )
{
    int dummy;
    return classify_user_id2 (name, keyid, fprint, retstr, retlen, &dummy);
}

/****************
 * Try to get the pubkey by the userid. This function looks for the
 * first pubkey certificate which has the given name in a user_id.
 * if pk/sk has the pubkey algo set, the function will only return
 * a pubkey with that algo.
 * The caller should provide storage for either the pk or the sk.
 * If ret_kb is not NULL the function will return the keyblock there.
 */

static int
key_byname( GETKEY_CTX *retctx, STRLIST namelist,
	    PKT_public_key *pk, PKT_secret_key *sk, int secmode,
            KBNODE *ret_kb )
{
    int rc = 0;
    int n;
    STRLIST r;
    GETKEY_CTX ctx;
    KBNODE help_kb = NULL;
    int exact;
    
    if( retctx ) /* reset the returned context in case of error */
	*retctx = NULL;

    /* build the search context */
    /* Performance hint: Use a static buffer if there is only one name */
    /*			 and we don't have mode 6 */
    for(n=0, r=namelist; r; r = r->next )
	n++;
    ctx = m_alloc_clear(  sizeof *ctx + (n-1)*sizeof ctx->items );
    ctx->nitems = n;

    for(n=0, r=namelist; r; r = r->next, n++ ) {
	int mode = classify_user_id2 ( r->d,
                                       ctx->items[n].keyid,
                                       ctx->items[n].fprint,
                                       &ctx->items[n].name,
                                       NULL, &exact );

        if ( exact )
            ctx->exact = 1;
	ctx->items[n].mode = mode;
        if( !ctx->items[n].mode ) {
	    m_free( ctx );
	    return G10ERR_INV_USER_ID;
	}
	if( ctx->items[n].mode == 6 ) {
	    ctx->items[n].namebuf = prepare_word_match(ctx->items[n].name);
	    ctx->items[n].name = ctx->items[n].namebuf;
	}
    }



    if ( !ret_kb ) 
        ret_kb = &help_kb;

    if( secmode ) {
        if (sk) {
            ctx->req_algo  = sk->req_algo;
            ctx->req_usage = sk->req_usage;
        }
	rc = lookup( ctx, ret_kb, 1 );
        if ( !rc && sk ) {
            sk_from_block ( ctx, sk, *ret_kb );
        }
    }
    else {
        if (pk) {
            ctx->req_algo  = pk->req_algo;
            ctx->req_usage = pk->req_usage;
        }
	rc = lookup( ctx, ret_kb, 0 );
        if ( !rc && pk ) {
            pk_from_block ( ctx, pk, *ret_kb, NULL /* FIXME need to get the namehash*/ );
        }
    }

    release_kbnode ( help_kb );

    if( retctx ) /* caller wants the context */
	*retctx = ctx;
    else {
	/* Hmmm, why not get_pubkey-end here?? */
	enum_keyblocks( 2, &ctx->kbpos, NULL );
        memset (&ctx->kbpos, 0, sizeof ctx->kbpos);
	for(n=0; n < ctx->nitems; n++ )
	    m_free( ctx->items[n].namebuf );
	m_free( ctx );
    }

    return rc;
}

int
get_pubkey_byname( GETKEY_CTX *retctx, PKT_public_key *pk,
		   const char *name, KBNODE *ret_keyblock )
{
    int rc;
    STRLIST namelist = NULL;

    add_to_strlist( &namelist, name );
    rc = key_byname( retctx, namelist, pk, NULL, 0, ret_keyblock );
    free_strlist( namelist );
    return rc;
}

int
get_pubkey_bynames( GETKEY_CTX *retctx, PKT_public_key *pk,
		    STRLIST names, KBNODE *ret_keyblock )
{
    return key_byname( retctx, names, pk, NULL, 0, ret_keyblock );
}

int
get_pubkey_next( GETKEY_CTX ctx, PKT_public_key *pk, KBNODE *ret_keyblock )
{
    int rc;

    rc = lookup( ctx, ret_keyblock, 0 );
    if ( !rc && pk && ret_keyblock )
        pk_from_block ( ctx, pk, *ret_keyblock, NULL );
    
    return rc;
}


void
get_pubkey_end( GETKEY_CTX ctx )
{
    if( ctx ) {
	int n;

	enum_keyblocks( 2, &ctx->kbpos, NULL ); 
        memset (&ctx->kbpos, 0, sizeof ctx->kbpos);
	for(n=0; n < ctx->nitems; n++ )
	    m_free( ctx->items[n].namebuf );
	if( !ctx->not_allocated )
	    m_free( ctx );
    }
}




/****************
 * Search for a key with the given fingerprint.
 * FIXME:
 * We should replace this with the _byname function.  Thiscsan be done
 * by creating a userID conforming to the unified fingerprint style. 
 */
int
get_pubkey_byfprint( PKT_public_key *pk,
                     const byte *fprint, size_t fprint_len)
{
    int rc;

    if( fprint_len == 20 || fprint_len == 16 ) {
	struct getkey_ctx_s ctx;
        KBNODE kb = NULL;

	memset( &ctx, 0, sizeof ctx );
        ctx.exact = 1 ;
	ctx.not_allocated = 1;
	ctx.nitems = 1;
	ctx.items[0].mode = fprint_len;
	memcpy( ctx.items[0].fprint, fprint, fprint_len );
	rc = lookup( &ctx, &kb, 0 );
        if (!rc && pk )
            pk_from_block ( &ctx, pk, kb, NULL );
        release_kbnode ( kb );
	get_pubkey_end( &ctx );
    }
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

    if( fprint_len == 20 || fprint_len == 16 ) {
	struct getkey_ctx_s ctx;

	memset( &ctx, 0, sizeof ctx );
	ctx.not_allocated = 1;
	ctx.nitems = 1;
	ctx.items[0].mode = fprint_len;
	memcpy( ctx.items[0].fprint, fprint, fprint_len );
	rc = lookup( &ctx, ret_keyblock, 0 );
	get_pubkey_end( &ctx );
    }
    else
	rc = G10ERR_GENERAL; /* Oops */

    return rc;
}



/****************
 * Search for a key with the given lid and return the entire keyblock
 */
int
get_keyblock_bylid( KBNODE *ret_keyblock, ulong lid )
{
    int rc;
    struct getkey_ctx_s ctx;
    u32 kid[2];

    if( keyid_from_lid( lid, kid ) )
	kid[0] = kid[1] = 0;
    memset( &ctx, 0, sizeof ctx );
    ctx.exact = 1;
    ctx.not_allocated = 1;
    ctx.nitems = 1;
    ctx.items[0].mode = 12;
    ctx.items[0].keyid[0] = kid[0];
    ctx.items[0].keyid[1] = kid[1];
    rc = lookup( &ctx,  ret_keyblock, 0 );
    get_pubkey_end( &ctx );

    return rc;
}





/****************
 * Get a secret key by name and store it into sk
 * If NAME is NULL use the default key
 */
static int
get_seckey_byname2( GETKEY_CTX *retctx,
                   PKT_secret_key *sk, const char *name, int unprotect,
                   KBNODE *retblock )
{
    STRLIST namelist = NULL;
    int rc;

    if( !name && opt.def_secret_key && *opt.def_secret_key ) {
	add_to_strlist( &namelist, opt.def_secret_key );
	rc = key_byname( retctx, namelist, NULL, sk, 1, retblock );
    }
    else if( !name ) { /* use the first one as default key */
	struct getkey_ctx_s ctx;
        KBNODE kb = NULL;

        assert (!retctx ); /* do we need this at all */
        assert (!retblock);
	memset( &ctx, 0, sizeof ctx );
	ctx.not_allocated = 1;
	ctx.nitems = 1;
	ctx.items[0].mode = 15;
	rc = lookup( &ctx, &kb, 1 );
        if (!rc && sk )
            sk_from_block ( &ctx, sk, kb );
        release_kbnode ( kb );
	get_seckey_end( &ctx );
    }
    else {
	add_to_strlist( &namelist, name );
	rc = key_byname( retctx, namelist, NULL, sk, 1, retblock );
    }

    free_strlist( namelist );

    if( !rc && unprotect )
	rc = check_secret_key( sk, 0 );

    return rc;
}

int 
get_seckey_byname( PKT_secret_key *sk, const char *name, int unlock )
{
    return get_seckey_byname2 ( NULL, sk, name, unlock, NULL );
}


int
get_seckey_bynames( GETKEY_CTX *retctx, PKT_secret_key *sk,
		    STRLIST names, KBNODE *ret_keyblock )
{
    return key_byname( retctx, names, NULL, sk, 1, ret_keyblock );
}


int
get_seckey_next( GETKEY_CTX ctx, PKT_secret_key *sk, KBNODE *ret_keyblock )
{
    int rc;

    rc = lookup( ctx, ret_keyblock, 1 );
    if ( !rc && sk && ret_keyblock )
        sk_from_block ( ctx, sk, *ret_keyblock );

    return rc;
}


void
get_seckey_end( GETKEY_CTX ctx )
{
    get_pubkey_end( ctx );
}



/*******************************************************
 ************** compare functions **********************
 *******************************************************/

/****************
 * Do a word match (original user id starts with a '+').
 * The pattern is already tokenized to a more suitable format:
 * There are only the real words in it delimited by one space
 * and all converted to uppercase.
 *
 * Returns: 0 if all words match.
 *
 * Note: This algorithm is a straightforward one and not very
 *	 fast.	It works for UTF-8 strings.  The uidlen should
 *	 be removed but due to the fact that old versions of
 *	 pgp don't use UTF-8 we still use the length; this should
 *	 be fixed in parse-packet (and replace \0 by some special
 *	 UTF-8 encoding)
 */
static int
word_match( const byte *uid, size_t uidlen, const byte *pattern )
{
    size_t wlen, n;
    const byte *p;
    const byte *s;

    for( s=pattern; *s; ) {
	do {
	    /* skip leading delimiters */
	    while( uidlen && !word_match_chars[*uid] )
		uid++, uidlen--;
	    /* get length of the word */
	    n = uidlen; p = uid;
	    while( n && word_match_chars[*p] )
		p++, n--;
	    wlen = p - uid;
	    /* and compare against the current word from pattern */
	    for(n=0, p=uid; n < wlen && s[n] != ' ' && s[n] ; n++, p++ ) {
		if( word_match_chars[*p] != s[n] )
		    break;
	    }
	    if( n == wlen && (s[n] == ' ' || !s[n]) )
		break; /* found */
	    uid += wlen;
	    uidlen -= wlen;
	} while( uidlen );
	if( !uidlen )
	    return -1; /* not found */

	/* advance to next word in pattern */
	for(; *s != ' ' && *s ; s++ )
	    ;
	if( *s )
	    s++ ;
    }
    return 0; /* found */
}

/****************
 * prepare word word_match; that is parse the name and
 * build the pattern.
 * caller has to free the returned pattern
 */
static char*
prepare_word_match( const byte *name )
{
    byte *pattern, *p;
    int c;

    /* the original length is always enough for the pattern */
    p = pattern = m_alloc(strlen(name)+1);
    do {
	/* skip leading delimiters */
	while( *name && !word_match_chars[*name] )
	    name++;
	/* copy as long as we don't have a delimiter and convert
	 * to uppercase.
	 * fixme: how can we handle utf8 uppercasing */
	for( ; *name &&  (c=word_match_chars[*name]); name++ )
	    *p++ = c;
	*p++ = ' '; /* append pattern delimiter */
    } while( *name );
    p[-1] = 0; /* replace last pattern delimiter by EOS */

    return pattern;
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
    else if( mode == 6 )
	return word_match( uid, uidlen, name );
    else
	BUG();

    return -1; /* not found */
}




/************************************************
 ************* Merging stuff ********************
 ************************************************/

/****************
 * merge all selfsignatures with the keys.
 * FIXME: replace this at least for the public key parts
 *        by merge_selfsigs.
 *        It is still used in keyedit.c and
 *        at 2 or 3 other places - check whether it is really needed.
 *        It might be needed by the key edit and import stuff because
 *        the keylock is changed.
 */
void
merge_keys_and_selfsig( KBNODE keyblock )
{
    PKT_public_key *pk = NULL;
    PKT_secret_key *sk = NULL;
    PKT_signature *sig;
    KBNODE k;
    u32 kid[2] = { 0, 0 };
    u32 sigdate = 0;

    if (keyblock && keyblock->pkt->pkttype == PKT_PUBLIC_KEY ) {
        /* divert to our new function */
        merge_selfsigs (keyblock);
        return;
    }
    /* still need the old one because the new one can't handle secret keys */

    for(k=keyblock; k; k = k->next ) {
	if( k->pkt->pkttype == PKT_PUBLIC_KEY
	    || k->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
	    pk = k->pkt->pkt.public_key; sk = NULL;
	    if( pk->version < 4 )
		pk = NULL; /* not needed for old keys */
	    else if( k->pkt->pkttype == PKT_PUBLIC_KEY )
		keyid_from_pk( pk, kid );
	    else if( !pk->expiredate ) { /* and subkey */
		/* insert the expiration date here */
		/*FIXME!!! pk->expiredate = subkeys_expiretime( k, kid );*/
	    }
	    sigdate = 0;
	}
	else if( k->pkt->pkttype == PKT_SECRET_KEY
	    || k->pkt->pkttype == PKT_SECRET_SUBKEY ) {
	    pk = NULL; sk = k->pkt->pkt.secret_key;
	    if( sk->version < 4 )
		sk = NULL;
	    else if( k->pkt->pkttype == PKT_SECRET_KEY )
		keyid_from_sk( sk, kid );
	    sigdate = 0;
	}
	else if( (pk || sk ) && k->pkt->pkttype == PKT_SIGNATURE
		 && (sig=k->pkt->pkt.signature)->sig_class >= 0x10
		 && sig->sig_class <= 0x30 && sig->version > 3
		 && !(sig->sig_class == 0x18 || sig->sig_class == 0x28)
		 && sig->keyid[0] == kid[0] && sig->keyid[1] == kid[1] ) {
	    /* okay this is a self-signature which can be used.
	     * This is not used for subkey binding signature, becuase this
	     * is done above.
	     * FIXME: We should only use this if the signature is valid
	     *	      but this is time consuming - we must provide another
	     *	      way to handle this
	     */
	    const byte *p;
	    u32 ed;

	    p = parse_sig_subpkt( sig->hashed_data, SIGSUBPKT_KEY_EXPIRE, NULL );
	    if( pk ) {
		ed = p? pk->timestamp + buffer_to_u32(p):0;
		if( sig->timestamp > sigdate ) {
		    pk->expiredate = ed;
		    sigdate = sig->timestamp;
		}
	    }
	    else {
		ed = p? sk->timestamp + buffer_to_u32(p):0;
		if( sig->timestamp > sigdate ) {
		    sk->expiredate = ed;
		    sigdate = sig->timestamp;
		}
	    }
	}
    }
}


static void
fixup_uidnode ( KBNODE uidnode, KBNODE signode, u32 keycreated )
{
    PKT_user_id   *uid = uidnode->pkt->pkt.user_id;
    PKT_signature *sig = signode->pkt->pkt.signature;
    const byte *p;
    size_t n;

    uid->created = 0; /* not created == invalid */
    if ( IS_UID_REV ( sig ) ) {
        uid->is_revoked = 1;
        return; /* has been revoked */
    }

    uid->created = sig->timestamp; /* this one is okay */    
 
    /* store the key flags in the helper variable for later processing */
    uid->help_key_usage = 0;
    p = parse_sig_subpkt ( sig->hashed_data, SIGSUBPKT_KEY_FLAGS, &n );
    if ( p && n ) {
        /* first octet of the keyflags */   
        if ( (*p & 3) )
            uid->help_key_usage |= PUBKEY_USAGE_SIG;
        if ( (*p & 12) )    
            uid->help_key_usage |= PUBKEY_USAGE_ENC;
    }

    /* ditto or the key expiration */
    uid->help_key_expire = 0;
    p = parse_sig_subpkt ( sig->hashed_data, SIGSUBPKT_KEY_EXPIRE, NULL);
    if ( p ) { 
        uid->help_key_expire = keycreated + buffer_to_u32(p);
    }

    /* Set the primary user ID flag - we will later wipe out some
     * of them to only have one in out keyblock */
    uid->is_primary = 0;
    p = parse_sig_subpkt ( sig->hashed_data, SIGSUBPKT_PRIMARY_UID, NULL );
    if ( p && *p )
        uid->is_primary = 1;
    /* We could also query this from the unhashed area if it is not in
     * the hased area and then later try to decide which is the better
     * there should be no security problem with this.
     * For now we only look at the hashed one. 
     */
}

static void
merge_selfsigs_main( KBNODE keyblock, int *r_revoked )
{
    PKT_public_key *pk = NULL;
    KBNODE k;
    u32 kid[2];
    u32 sigdate = 0, uiddate=0, uiddate2;
    KBNODE signode, uidnode, uidnode2;
    u32 curtime = make_timestamp ();
    unsigned int key_usage = 0;
    u32 keytimestamp = 0;
    u32 key_expire = 0;
    int key_expire_seen = 0;

    *r_revoked = 0;
    if ( keyblock->pkt->pkttype != PKT_PUBLIC_KEY )
        BUG ();
    pk = keyblock->pkt->pkt.public_key;
    keytimestamp = pk->timestamp;

    keyid_from_pk( pk, kid );
    pk->main_keyid[0] = kid[0];
    pk->main_keyid[1] = kid[1];

    if ( pk->version < 4 ) {
        /* before v4 the key packet itself contains the expiration date
         * and there was noway to change it.  So we also use only the
         * one from the key packet */
        key_expire = pk->expiredate;
        key_expire_seen = 1;
    }

    /* first pass: find the latest direct key self-signature.
     * We assume that the newest one overrides all others
     */
    signode = NULL;
    sigdate = 0; /* helper to find the latest signature */
    for(k=keyblock; k && k->pkt->pkttype != PKT_PUBLIC_SUBKEY; k = k->next ) {
        if ( k->pkt->pkttype == PKT_SIGNATURE ) {
            PKT_signature *sig = k->pkt->pkt.signature;
            if ( sig->keyid[0] == kid[0] && sig->keyid[1]==kid[1] ) { 
           	if ( check_key_signature( keyblock, k, NULL ) )
                    ; /* signature did not verify */
                else if ( IS_KEY_REV (sig) ){
                    /* key has been revoked - there is no way to override
                     * such a revocation, so we theoretically can stop now.
                     * We should not cope with expiration times for revocations
                     * here because we have to assume that an attacker can
                     * generate all kinds of signatures.  However due to the
                     * fact that the key has been revoked it does not harm
                     * either and by continuing we gather some more info on 
                     * that key.
                     */ 
                    *r_revoked = 1;
                }
                else if ( IS_KEY_SIG (sig) && sig->timestamp >= sigdate ) {
                    const byte *p;
                    
                    p = parse_sig_subpkt( sig->hashed_data,
                                          SIGSUBPKT_SIG_EXPIRE, NULL );
                    if ( p && (sig->timestamp + buffer_to_u32(p)) >= curtime )
                        ; /* signature has expired - ignore it */
                    else {
                        sigdate = sig->timestamp;
                        signode = k;
                    }
                }
            }
        }
    }

    if ( signode ) {
        /* some information from a direct key signature take precedence
         * over the same information given in UID sigs.
         */
        PKT_signature *sig = signode->pkt->pkt.signature;
        const byte *p;
        size_t n;
        
        p = parse_sig_subpkt ( sig->hashed_data, SIGSUBPKT_KEY_FLAGS, &n );
        if ( p && n ) {
            /* first octet of the keyflags */   
            if ( (*p & 3) )
                key_usage |= PUBKEY_USAGE_SIG;
            if ( (*p & 12) )    
                key_usage |= PUBKEY_USAGE_ENC;
        }

        if ( pk->version > 3 ) {
            p = parse_sig_subpkt ( sig->hashed_data,
                                   SIGSUBPKT_KEY_EXPIRE, NULL);
            if ( p ) {
                key_expire = keytimestamp + buffer_to_u32(p);
                key_expire_seen = 1;
            }
        }
        /* mark that key as valid: one direct key signature should 
         * render a key as valid */
        pk->is_valid = 1;
    }


    /* second pass: look at the self-signature of all user IDs */
    signode = uidnode = NULL;
    sigdate = 0; /* helper to find the latest signature in one user ID */
    uiddate = 0; /* and over of all user IDs */
    for(k=keyblock; k && k->pkt->pkttype != PKT_PUBLIC_SUBKEY; k = k->next ) {
	if ( k->pkt->pkttype == PKT_USER_ID
             || k->pkt->pkttype == PKT_PHOTO_ID ) {
            if ( uidnode && signode ) 
                fixup_uidnode ( uidnode, signode, keytimestamp );
            uidnode = k;
            signode = NULL;
            if ( sigdate > uiddate )
                uiddate = sigdate;
            sigdate = 0;
      	}
        else if ( k->pkt->pkttype == PKT_SIGNATURE && uidnode ) {
            PKT_signature *sig = k->pkt->pkt.signature;
            if ( sig->keyid[0] == kid[0] && sig->keyid[1]==kid[1] ) { 
                if ( check_key_signature( keyblock, k, NULL ) )
                    ; /* signature did not verify */
                else if ( (IS_UID_SIG (sig) || IS_UID_REV (sig))
                          && sig->timestamp >= sigdate ) {
                    /* Note: we allow to invalidate cert revocations
                     * by a newer signature.  An attacker can't use this
                     * because a key should be revoced with a key revocation.
                     * The reason why we have to allow for that is that at
                     * one time an email address may become invalid but later
                     * the same email address may become valid again (hired,
                     * fired, hired again).
                     */                    
                    const byte *p;
                    
                    p = parse_sig_subpkt( sig->hashed_data,
                                          SIGSUBPKT_SIG_EXPIRE, NULL );
                    if ( p && (sig->timestamp + buffer_to_u32(p)) >= curtime )
                        ; /* signature/revocation has expired - ignore it */
                    else {
                        sigdate = sig->timestamp;
                        signode = k;
                    }
                }
            }
        }
    }
    if ( uidnode && signode ) {
        fixup_uidnode ( uidnode, signode, keytimestamp );
        pk->is_valid = 1;
    }
    if ( sigdate > uiddate )
        uiddate = sigdate;


    /* Now that we had a look at all user IDs we can now get some information
     * from those user IDs.
     */
    
    if ( !key_usage ) {
        /* find the latest user ID with key flags set */
        uiddate = 0; /* helper to find the latest user ID */
        for(k=keyblock; k && k->pkt->pkttype != PKT_PUBLIC_SUBKEY;
            k = k->next ) {
            if ( k->pkt->pkttype == PKT_USER_ID
                 || k->pkt->pkttype == PKT_PHOTO_ID ) {
                PKT_user_id *uid = k->pkt->pkt.user_id;
                if ( uid->help_key_usage && uid->created > uiddate ) {
                    key_usage = uid->help_key_usage;
                    uiddate = uid->created;
                }
            }
      	}
    }
    if ( !key_usage ) { /* no key flags at all: get it from the algo */
        key_usage = openpgp_pk_algo_usage ( pk->pubkey_algo );
    }
    else { /* check that the usage matches the usage as given by the algo */
        int x = openpgp_pk_algo_usage ( pk->pubkey_algo );
        if ( x ) /* mask it down to the actual allowed usage */
            key_usage &= x; 
    }
    pk->pubkey_usage = key_usage;

    if ( !key_expire_seen ) {
        /* find the latest valid user ID with a key expiration set 
         * Note, that this may be a different one from the above because
         * some user IDs may have no expiration date set */
        uiddate = 0; 
        for(k=keyblock; k && k->pkt->pkttype != PKT_PUBLIC_SUBKEY;
            k = k->next ) {
            if ( k->pkt->pkttype == PKT_USER_ID
                 || k->pkt->pkttype == PKT_PHOTO_ID ) {
                PKT_user_id *uid = k->pkt->pkt.user_id;
                if ( uid->help_key_expire && uid->created > uiddate ) {
                    key_expire = uid->help_key_expire;
                    uiddate = uid->created;
                }
            }
      	}
    }
   
    pk->has_expired = key_expire >= curtime? 0 : key_expire;
    if ( pk->version >= 4 ) 
        pk->expiredate = key_expire;
    /* Fixme: we should see how to get rid of the expiretime fields  but
     * this needs changes at other palces too. */

    /* and now find the real primary user ID and delete all others */
    uiddate = uiddate2 = 0;
    uidnode = uidnode2 = NULL;
    for(k=keyblock; k && k->pkt->pkttype != PKT_PUBLIC_SUBKEY; k = k->next ) {
        if ( k->pkt->pkttype == PKT_USER_ID
             || k->pkt->pkttype == PKT_PHOTO_ID ) {
            PKT_user_id *uid = k->pkt->pkt.user_id;
            if ( uid->is_primary && uid->created > uiddate ) {
                uiddate = uid->created;
                uidnode = k;
            }
            if ( !uid->is_primary && uid->created > uiddate2 ) {
                uiddate2 = uid->created;
                uidnode2 = k;
            }
        }
    }
    if ( uidnode ) {
        for(k=keyblock; k && k->pkt->pkttype != PKT_PUBLIC_SUBKEY;
            k = k->next ) {
            if ( k->pkt->pkttype == PKT_USER_ID
                 || k->pkt->pkttype == PKT_PHOTO_ID ) {
                PKT_user_id *uid = k->pkt->pkt.user_id;
                if ( k != uidnode ) 
                    uid->is_primary = 0;
            }
        }
    }
    else if( uidnode2 ) {
        /* none is flagged primary - use the latest user ID we have */
        uidnode2->pkt->pkt.user_id->is_primary = 1;
    }

}


static void
merge_selfsigs_subkey( KBNODE keyblock, KBNODE subnode )
{
    PKT_public_key *mainpk = NULL, *subpk = NULL;
    PKT_signature *sig;
    KBNODE k;
    u32 mainkid[2];
    u32 sigdate = 0;
    KBNODE signode;
    u32 curtime = make_timestamp ();
    unsigned int key_usage = 0;
    u32 keytimestamp = 0;
    u32 key_expire = 0;
    const byte *p;
    size_t n;

    if ( subnode->pkt->pkttype != PKT_PUBLIC_SUBKEY )
        BUG ();
    mainpk = keyblock->pkt->pkt.public_key;
    if ( mainpk->version < 4 )
        return; /* (actually this should never happen) */
    keyid_from_pk( mainpk, mainkid );
    subpk = subnode->pkt->pkt.public_key;
    keytimestamp = subpk->timestamp;

    subpk->is_valid = 0;
    subpk->main_keyid[0] = mainpk->main_keyid[0];
    subpk->main_keyid[1] = mainpk->main_keyid[1];
    if ( subpk->version < 4 )
        return; /* there are no v3 subkeys */

    /* find the latest key binding self-signature. */
    signode = NULL;
    sigdate = 0; /* helper to find the latest signature */
    for(k=subnode->next; k && k->pkt->pkttype != PKT_PUBLIC_SUBKEY;
                                                        k = k->next ) {
        if ( k->pkt->pkttype == PKT_SIGNATURE ) {
            sig = k->pkt->pkt.signature;
            if ( sig->keyid[0] == mainkid[0] && sig->keyid[1]==mainkid[1] ) { 
           	if ( check_key_signature( keyblock, k, NULL ) )
                    ; /* signature did not verify */
                else if ( IS_SUBKEY_REV (sig) ) {
                    subpk->is_revoked = 1;
                    /* although we could stop now, we continue to 
                     * figure out other information like the old expiration
                     * time */
                }
                else if ( IS_SUBKEY_SIG (sig) && sig->timestamp >= sigdate ) {
                    p = parse_sig_subpkt( sig->hashed_data,
                                          SIGSUBPKT_SIG_EXPIRE, NULL );
                    if ( p && (sig->timestamp + buffer_to_u32(p)) >= curtime )
                        ; /* signature has expired - ignore it */
                    else {
                        sigdate = sig->timestamp;
                        signode = k;
                    }
                }
            }
        }
    }

    if ( !signode ) {
        return;  /* no valid key binding */
    }

    subpk->is_valid = 1;
    sig = signode->pkt->pkt.signature;
        
    p = parse_sig_subpkt ( sig->hashed_data, SIGSUBPKT_KEY_FLAGS, &n );
    if ( p && n ) {
        /* first octet of the keyflags */   
        if ( (*p & 3) )
            key_usage |= PUBKEY_USAGE_SIG;
        if ( (*p & 12) )    
            key_usage |= PUBKEY_USAGE_ENC;
    }
    if ( !key_usage ) { /* no key flags at all: get it from the algo */
        key_usage = openpgp_pk_algo_usage ( subpk->pubkey_algo );
    }
    else { /* check that the usage matches the usage as given by the algo */
        int x = openpgp_pk_algo_usage ( subpk->pubkey_algo );
        if ( x ) /* mask it down to the actual allowed usage */
            key_usage &= x; 
    }
    subpk->pubkey_usage = key_usage;
    
    p = parse_sig_subpkt ( sig->hashed_data, SIGSUBPKT_KEY_EXPIRE, NULL);

    if ( p ) 
        key_expire = keytimestamp + buffer_to_u32(p);
    else
        key_expire = 0;
    subpk->has_expired = key_expire >= curtime? 0 : key_expire;
    subpk->expiredate = key_expire;
}



/* 
 * Merge information from the self-signatures with the key, so that
 * we can later use them more easy.
 * The function works by first applying the self signatures to the
 * primary key and the to each subkey.
 * Here are the rules we use to decide which inormation from which
 * self-signature is used:
 * We check all self signatures or validity and ignore all invalid signatures.
 * All signatures are then ordered by their creation date ....
 * For the primary key:
 *   FIXME the docs    
 */
static void
merge_selfsigs( KBNODE keyblock )
{
    KBNODE k;
    int revoked;
    PKT_public_key *main_pk;

    if ( keyblock->pkt->pkttype != PKT_PUBLIC_KEY )
        BUG ();

    merge_selfsigs_main ( keyblock, &revoked );
    main_pk = keyblock->pkt->pkt.public_key;
    if ( revoked ) {
        /* if the primary key has been revoked we better set the revoke
         * flag on that key and all subkeys */
        for(k=keyblock; k; k = k->next ) {
            if ( k->pkt->pkttype == PKT_PUBLIC_KEY
                || k->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
                PKT_public_key *pk = k->pkt->pkt.public_key;
                pk->is_revoked = 1;
                pk->main_keyid[0] = main_pk->main_keyid[0];
                pk->main_keyid[1] = main_pk->main_keyid[1];
            }
	}
        return;
    }

    /* now merge in the data from each of the subkeys */
    for(k=keyblock; k; k = k->next ) {
	if (  k->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
            merge_selfsigs_subkey ( keyblock, k );
        }
    }
}


/*
 * Merge the secret keys from secblock into the pubblock thereby
 * replacing the public (sub)keys with their secret counterparts Hmmm:
 * It might be better to get away from the concept of entire secret
 * keys at all and have a way to store just the real secret parts
 * from the key.
 */
static void
merge_public_with_secret ( KBNODE pubblock, KBNODE secblock )
{
    KBNODE pub;

    assert ( pubblock->pkt->pkttype == PKT_PUBLIC_KEY );
    assert ( secblock->pkt->pkttype == PKT_SECRET_KEY );
    
    for (pub=pubblock; pub; pub = pub->next ) {
        if ( pub->pkt->pkttype == PKT_PUBLIC_KEY ) {
             PKT_public_key *pk = pub->pkt->pkt.public_key;
             PKT_secret_key *sk = secblock->pkt->pkt.secret_key;
             assert ( pub == pubblock ); /* only in the first node */
             /* there is nothing to compare in this case, so just replace
              * some information */
             copy_public_parts_to_secret_key ( pk, sk );
             free_public_key ( pk );
             pub->pkt->pkttype = PKT_SECRET_KEY;
             pub->pkt->pkt.secret_key = copy_secret_key (NULL, sk);
        }
        else if ( pub->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
            KBNODE sec;
            PKT_public_key *pk = pub->pkt->pkt.public_key;

            /* this is more complicated: it may happen that the sequence
             * of the subkeys dosn't match, so we have to find the
             * appropriate secret key */
            for (sec=secblock->next; sec; sec = sec->next ) {
                if ( sec->pkt->pkttype == PKT_SECRET_SUBKEY ) {
                    PKT_secret_key *sk = sec->pkt->pkt.secret_key;
                    if ( !cmp_public_secret_key ( pk, sk ) ) {
                        copy_public_parts_to_secret_key ( pk, sk );
                        free_public_key ( pk );
                        pub->pkt->pkttype = PKT_SECRET_SUBKEY;
                        pub->pkt->pkt.secret_key = copy_secret_key (NULL, sk);
                        break;
                    }
                }
            }
            if ( !sec ) 
                BUG(); /* already checked in premerge */
        }
    }
}

/* This function checks that for every public subkey a corresponding
 * secret subkey is avalable and deletes the public subkey otherwise.
 * We need this function becuase we can'tdelete it later when we
 * actually merge the secret parts into the pubring.
 */
static void
premerge_public_with_secret ( KBNODE pubblock, KBNODE secblock )
{
    KBNODE last, pub;

    assert ( pubblock->pkt->pkttype == PKT_PUBLIC_KEY );
    assert ( secblock->pkt->pkttype == PKT_SECRET_KEY );
    
    for (pub=pubblock,last=NULL; pub; last = pub, pub = pub->next ) {
        if ( pub->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
            KBNODE sec;
            PKT_public_key *pk = pub->pkt->pkt.public_key;

            for (sec=secblock->next; sec; sec = sec->next ) {
                if ( sec->pkt->pkttype == PKT_SECRET_SUBKEY ) {
                    PKT_secret_key *sk = sec->pkt->pkt.secret_key;
                    if ( !cmp_public_secret_key ( pk, sk ) ) {
                        if ( sk->protect.s2k.mode == 1001 ) {
                            /* The secret parts are not available so
                               we can't use that key for signing etc.
                               Fix the pubkey usage */
                            pk->pubkey_usage &= ~PUBKEY_USAGE_SIG;
                        }
                        break;
                    }
                }
            }
            if ( !sec ) {
                KBNODE next, ll;

                log_info ( "no secret subkey "
                           "for public subkey %08lX - ignoring\n",  
                           (ulong)keyid_from_pk (pk,NULL) );
                /* we have to remove the subkey in this case */
                assert ( last );
                /* find the next subkey */
                for (next=pub->next,ll=pub;
                     next && pub->pkt->pkttype != PKT_PUBLIC_SUBKEY;
                     ll = next, next = next->next ) 
                    ;
                /* make new link */
                last->next = next;
                /* release this public subkey with all sigs */
                ll->next = NULL;
                release_kbnode( pub );
                /* let the loop continue */
                pub = last;
            }
        }
    }
}




/************************************************
 ************* Find stuff ***********************
 ************************************************/

static int 
find_by_name( KBNODE keyblock, const char *name,
	      int mode, byte *namehash )
{
    KBNODE k;

    for(k=keyblock; k; k = k->next ) {
	if( k->pkt->pkttype == PKT_USER_ID
	    && !compare_name( k->pkt->pkt.user_id->name,
			      k->pkt->pkt.user_id->len, name, mode)) {
	    /* we found a matching name, look for the key */
            if( k->pkt->pkt.user_id->photo ) {
                /* oops: this can never happen */
                rmd160_hash_buffer( namehash,
                                    k->pkt->pkt.user_id->photo,
                                    k->pkt->pkt.user_id->photolen );
            }
            else {
                rmd160_hash_buffer( namehash,
                                    k->pkt->pkt.user_id->name,
                                    k->pkt->pkt.user_id->len );
            }
            return 1; 
        }
    }
    
    return 0;
}



static KBNODE
find_by_keyid( KBNODE keyblock, u32 *keyid, int mode )
{
    KBNODE k;

    for(k=keyblock; k; k = k->next ) {
	if(    k->pkt->pkttype == PKT_PUBLIC_KEY
	    || k->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
	    u32 aki[2];
	    keyid_from_pk( k->pkt->pkt.public_key, aki );
	    if( aki[1] == keyid[1] && ( mode == 10 || aki[0] == keyid[0] ) ) {
                return k; /* found */
	    }
	}
    }
    return NULL;
}



static KBNODE
find_by_fpr( KBNODE keyblock,  const char *name, int mode )
{
    KBNODE k;

    for(k=keyblock; k; k = k->next ) {
	if(    k->pkt->pkttype == PKT_PUBLIC_KEY
	    || k->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
	    byte afp[MAX_FINGERPRINT_LEN];
	    size_t an;

	    fingerprint_from_pk(k->pkt->pkt.public_key, afp, &an );
            if ( mode == 21 ) {
                /* Unified fingerprint. The fingerprint is always 20 bytes*/
                while ( an < 20 )
                    afp[an++] = 0;
                if ( !memcmp( afp, name, 20 ) )
                    return k;
            }
	    else { 
                if( an == mode && !memcmp( afp, name, an) ) {
                    return k;
                }
            }
	}
    }
    return NULL;
}




/* See see whether the key fits
 * our requirements and in case we do not
 * request the primary key, we should select
 * a suitable subkey.
 * FIXME: Check against PGP 7 whether we still need a kludge
 *        to favor type 16 keys over type 20 keys when type 20
 *        has not been explitely requested.
 * Returns: True when a suitable key has been found.
 *
 * We have to distinguish four cases:  FIXME!
 *  1. No usage and no primary key requested
 *     Examples for this case are that we have a keyID to be used
 *     for decrytion or verification.
 *  2. No usage but primary key requested
 *     This is the case for all functions which work on an
 *     entire keyblock, e.g. for editing or listing
 *  3. Usage and primary key requested
 *     FXME
 *  4. Usage but no primary key requested
 *     FIXME
 * FIXME: Tell what is going to happen here and something about the rationale
 * Note: We don't use this function if no specific usage is requested;
 *       This way the getkey functions can be used for plain key listings.
 *
 * CTX ist the keyblock we are investigating, if FOUNDK is not NULL this
 * is the key we actually found by looking at the keyid or a fingerprint and
 * may eitehr point to the primary or one of the subkeys.
 */

static int
finish_lookup( GETKEY_CTX ctx,  KBNODE foundk )
{
    KBNODE keyblock = ctx->keyblock;
    KBNODE k;
  #define USAGE_MASK  (PUBKEY_USAGE_SIG|PUBKEY_USAGE_ENC)
    unsigned int req_usage = ( ctx->req_usage & USAGE_MASK );
    u32 latest_date;
    KBNODE latest_key;

    assert( !foundk || foundk->pkt->pkttype == PKT_PUBLIC_KEY
	            || foundk->pkt->pkttype == PKT_PUBLIC_SUBKEY );
    assert( keyblock->pkt->pkttype == PKT_PUBLIC_KEY );
   
    ctx->found_key = NULL;

    if (!ctx->exact)
        foundk = NULL;

    if ( DBG_CACHE )
        log_debug( "finish_lookup: checking key %08lX (%s)(req_usage=%x)\n",
                   (ulong)keyid_from_pk( keyblock->pkt->pkt.public_key, NULL),
                   foundk? "one":"all", req_usage);

    if (!req_usage) {
        latest_key = foundk? foundk:keyblock;
        goto found;
    }
    
    if (!req_usage) {
        ctx->found_key = foundk;
        cache_user_id( keyblock );
        return 1; /* found */
    }
    
    latest_date = 0;
    latest_key  = NULL;
    if ( !foundk || foundk->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
        KBNODE nextk;
        /* either start a loop or check just this one subkey */
        for (k=foundk?foundk:keyblock; k; k = nextk ) {
            PKT_public_key *pk;
            nextk = k->next;
            if ( k->pkt->pkttype != PKT_PUBLIC_SUBKEY )
                continue;
            if ( foundk )
                nextk = NULL;  /* what a hack */
            pk = k->pkt->pkt.public_key;
            if (DBG_CACHE)
                log_debug( "\tchecking subkey %08lX\n",
                           (ulong)keyid_from_pk( pk, NULL));
            if ( !pk->is_valid ) {
                if (DBG_CACHE)
                    log_debug( "\tsubkey not valid\n");
                continue;
            }
            if ( pk->is_revoked ) {
                if (DBG_CACHE)
                    log_debug( "\tsubkey has been revoked\n");
                continue;
            }
            if ( pk->has_expired ) {
                if (DBG_CACHE)
                    log_debug( "\tsubkey has expired\n");
                continue;
            }
            
            if ( !((pk->pubkey_usage&USAGE_MASK) & req_usage) ) {
                if (DBG_CACHE)
                    log_debug( "\tusage does not match: want=%x have=%x\n",
                               req_usage, pk->pubkey_usage );
                continue;
            }

            if (DBG_CACHE)
                log_debug( "\tsubkey looks fine\n");
            if ( pk->timestamp > latest_date ) {
                latest_date = pk->timestamp;
                latest_key  = k;
            }
        }
    }

    /* Okay now try the primary key unless we have want an exact 
     * key ID match on a subkey */
    if ( !latest_key && !(ctx->exact && foundk != keyblock) ) {
        PKT_public_key *pk;
        if (DBG_CACHE && !foundk )
            log_debug( "\tno suitable subkeys found - trying primary\n");
        pk = keyblock->pkt->pkt.public_key;
        if ( !pk->is_valid ) {
            if (DBG_CACHE)
                log_debug( "\tprimary key not valid\n");
        }
        else if ( pk->is_revoked ) {
            if (DBG_CACHE)
                log_debug( "\tprimary key has been revoked\n");
        }
        else if ( pk->has_expired ) {
            if (DBG_CACHE)
                log_debug( "\tprimary key has expired\n");
        }
        else  if ( !((pk->pubkey_usage&USAGE_MASK) & req_usage) ) {
            if (DBG_CACHE)
                log_debug( "\tprimary key usage does not match: "
                           "want=%x have=%x\n",
                           req_usage, pk->pubkey_usage );
        }
        else { /* okay */
            if (DBG_CACHE)
                log_debug( "\tprimary key may be used\n");
            latest_key = keyblock;
            latest_date = pk->timestamp;
        }
    }
    
    if ( !latest_key ) {
        if (DBG_CACHE)
            log_debug("\tno suitable key found -  giving up\n");
        return 0;
    }

 found:
    if (DBG_CACHE)
        log_debug( "\tusing key %08lX\n",
                (ulong)keyid_from_pk( latest_key->pkt->pkt.public_key, NULL) );

    ctx->found_key = latest_key;

    if (latest_key != keyblock && opt.verbose) {
        log_info(_("using secondary key %08lX "
                   "instead of primary key %08lX\n"),
                 (ulong)keyid_from_pk( latest_key->pkt->pkt.public_key, NULL),
                 (ulong)keyid_from_pk( keyblock->pkt->pkt.public_key, NULL) );
    }

    cache_user_id( keyblock );
    
    return 1; /* found */
}

 
static int
lookup( GETKEY_CTX ctx, KBNODE *ret_keyblock, int secmode )
{
    int rc;
    int oldmode = set_packet_list_mode(0);
    byte namehash[20];
    int use_namehash=0;
    KBNODE secblock = NULL; /* helper */
    int no_suitable_key = 0;

    if( !ctx->count ) /* first time */
	rc = enum_keyblocks( secmode? 5:0, &ctx->kbpos, NULL );
    else
	rc = 0;
    if( !rc ) {
	while( !(rc = enum_keyblocks( 1, &ctx->kbpos, &ctx->keyblock )) ) {
	    int n;
	    getkey_item_t *item;

            if ( secmode ) {
                /* find the correspondig public key and use this 
                 * this one for the selection process */
                u32 aki[2];
                KBNODE k = ctx->keyblock;
                
                if ( k->pkt->pkttype != PKT_SECRET_KEY )
                    BUG();
                keyid_from_sk( k->pkt->pkt.secret_key, aki );
	        k = get_pubkeyblock( aki );
	        if( !k ) {
	            log_info(_("key %08lX: secret key without public key "
                               "- skipped\n"),  (ulong)aki[1] );
                    goto skip;
                }
                secblock = ctx->keyblock;
                ctx->keyblock = k;
                premerge_public_with_secret ( ctx->keyblock, secblock );
            }


	    /* loop over all the user ids we want to look for */
	    item = ctx->items;
	    for(n=0; n < ctx->nitems; n++, item++ ) {
                KBNODE k = NULL;
                int found = 0;
    
		if( item->mode < 10 ) {
		    found = find_by_name( ctx->keyblock,
                                          item->name, item->mode,
                                          namehash );
                    use_namehash = found;
                }
		else if( item->mode >= 10 && item->mode <= 12 ) {
		    k = find_by_keyid( ctx->keyblock, 
				       item->keyid, item->mode );
                    found = !!k;
                }
		else if( item->mode == 15 ) {
		    found = 1;
                }
		else if( item->mode == 16 || item->mode == 20
                         || item->mode == 21 ) {
		    k = find_by_fpr( ctx->keyblock,
				     item->fprint, item->mode );
                    found = !!k;
                }
		else
		    BUG();
		if( found ) { 
                    /* this keyblock looks fine - do further investigation */
                    merge_selfsigs ( ctx->keyblock );
		    if ( finish_lookup( ctx, k ) ) {
                        no_suitable_key = 0;
                        if ( secmode ) {
                            merge_public_with_secret ( ctx->keyblock,
                                                       secblock);
                            release_kbnode (secblock);
                            secblock = NULL;
                        }
                        goto found;
                    }
                    else
                        no_suitable_key = 1;
		}
	    }
          skip:
            /* release resources and try the next keyblock */
            if ( secmode ) {
                release_kbnode( secblock );
                secblock = NULL;
            }
	    release_kbnode( ctx->keyblock );
	    ctx->keyblock = NULL;
	}
      found:
        ;
    }
    if( rc && rc != -1 )
	log_error("enum_keyblocks failed: %s\n", g10_errstr(rc));

    if( !rc ) {
        *ret_keyblock = ctx->keyblock; /* return the keyblock */
        ctx->keyblock = NULL;
    }
    else if (rc == -1 && no_suitable_key)
        rc = secmode ? G10ERR_UNU_SECKEY : G10ERR_UNU_PUBKEY;
    else if( rc == -1 )
	rc = secmode ? G10ERR_NO_SECKEY : G10ERR_NO_PUBKEY;

    if ( secmode ) {
        release_kbnode( secblock );
        secblock = NULL;
    }
    release_kbnode( ctx->keyblock );
    ctx->keyblock = NULL;
    set_packet_list_mode(oldmode);
  #if 0
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
	else if ( rc == G10ERR_NO_PUBKEY || rc == G10ERR_NO_SECKEY )
	    lkup_stats[ctx->mode].nokey_count++;
	else
	    lkup_stats[ctx->mode].error_count++;
    }
   #endif

    ctx->last_rc = rc;
    ctx->count++;
    return rc;
}




/****************
 * FIXME: Replace by the generic function 
 *        It does not work as it is right now - it is used at 
 *        2 places:  a) to get the key for an anonyous recipient
 *                   b) to get the ultimately trusted keys.
 *        The a) usage might have some problems.
 *
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
		log_error("enum_secret_keys: can't open `%s'\n", c->name );
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



/*********************************************
 ***********  user ID printing helpers *******
 *********************************************/

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
	for(r=user_id_db; r; r = r->next ) {
            keyid_list_t a;
            for (a=r->keyids; a; a= a->next ) {
                if( a->keyid[0] == keyid[0] && a->keyid[1] == keyid[1] ) {
                    p = m_alloc( r->len + 10 );
                    sprintf(p, "%08lX %.*s",
                            (ulong)keyid[1], r->len, r->name );
                    return p;
                }
            }
        }
    } while( ++pass < 2 && !get_pubkey( NULL, keyid ) );
    p = m_alloc( 15 );
    sprintf(p, "%08lX [?]", (ulong)keyid[1] );
    return p;
}


char*
get_user_id_string_native( u32 *keyid )
{
    char *p = get_user_id_string( keyid );
    char *p2 = utf8_to_native( p, strlen(p) );

    m_free(p);
    return p2;
}


char*
get_long_user_id_string( u32 *keyid )
{
    user_id_db_t r;
    char *p;
    int pass=0;
    /* try it two times; second pass reads from key resources */
    do {
	for(r=user_id_db; r; r = r->next ) {
            keyid_list_t a;
            for (a=r->keyids; a; a= a->next ) {
                if( a->keyid[0] == keyid[0] && a->keyid[1] == keyid[1] ) {
                    p = m_alloc( r->len + 20 );
                    sprintf(p, "%08lX%08lX %.*s",
                            (ulong)keyid[0], (ulong)keyid[1],
                            r->len, r->name );
                    return p;
                }
            }
        }
    } while( ++pass < 2 && !get_pubkey( NULL, keyid ) );
    p = m_alloc( 25 );
    sprintf(p, "%08lX%08lX [?]", (ulong)keyid[0], (ulong)keyid[1] );
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
	for(r=user_id_db; r; r = r->next ) {
            keyid_list_t a;
            for (a=r->keyids; a; a= a->next ) {
                if( a->keyid[0] == keyid[0] && a->keyid[1] == keyid[1] ) {
                    p = m_alloc( r->len );
                    memcpy(p, r->name, r->len );
                    *rn = r->len;
                    return p;
                }
            }
        }
    } while( ++pass < 2 && !get_pubkey( NULL, keyid ) );
    p = m_strdup( _("[User id not found]") );
    *rn = strlen(p);
    return p;
}


