/* getkey.c -  Get a key from the database
 *	Copyright (C) 1998, 1999, 2000 Free Software Foundation, Inc.
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
#define MAX_PK_CACHE_ENTRIES	50
#define MAX_UID_CACHE_ENTRIES	50

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
    /* make an array or a linked list from dome fields */
    int primary;
    KBNODE keyblock;
    KBPOS kbpos;
    int last_rc;
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



static char* prepare_word_match( const byte *name );
static int lookup_pk( GETKEY_CTX ctx, PKT_public_key *pk, KBNODE *ret_kb );
static int lookup_sk( GETKEY_CTX ctx, PKT_secret_key *sk, KBNODE *ret_kb );
static u32 subkeys_expiretime( KBNODE node, u32 *mainkid );


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
	memset( &ctx, 0, sizeof ctx );
	ctx.not_allocated = 1;
	ctx.nitems = 1;
	ctx.items[0].mode = 11;
	ctx.items[0].keyid[0] = keyid[0];
	ctx.items[0].keyid[1] = keyid[1];
	rc = lookup_pk( &ctx, pk, NULL );
	get_pubkey_end( &ctx );
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
    PKT_public_key *pk = m_alloc_clear( sizeof *pk );
    struct getkey_ctx_s ctx;
    int rc = 0;
    KBNODE keyblock = NULL;

    memset( &ctx, 0, sizeof ctx );
    ctx.not_allocated = 1;
    ctx.nitems = 1;
    ctx.items[0].mode = 11;
    ctx.items[0].keyid[0] = keyid[0];
    ctx.items[0].keyid[1] = keyid[1];
    rc = lookup_pk( &ctx, pk, &keyblock );
    free_public_key(pk);
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

    memset( &ctx, 0, sizeof ctx );
    ctx.not_allocated = 1;
    ctx.nitems = 1;
    ctx.items[0].mode = 11;
    ctx.items[0].keyid[0] = keyid[0];
    ctx.items[0].keyid[1] = keyid[1];
    rc = lookup_sk( &ctx, sk, NULL );
    get_seckey_end( &ctx );
    if( !rc ) {
	/* check the secret key (this may prompt for a passprase to
	 * unlock the secret key
	 */
	rc = check_secret_key( sk, 0 );
    }

    return rc;
}


/****************
 * Get the primary secret key and store it into sk
 * Note: This function does not unprotect the key!
 */
int
get_primary_seckey( PKT_secret_key *sk, u32 *keyid )
{
    struct getkey_ctx_s ctx;
    int rc;

    memset( &ctx, 0, sizeof ctx );
    ctx.not_allocated = 1;
    ctx.primary = 1;
    ctx.nitems = 1;
    ctx.items[0].mode = 11;
    ctx.items[0].keyid[0] = keyid[0];
    ctx.items[0].keyid[1] = keyid[1];
    rc = lookup_sk( &ctx, sk, NULL );
    get_seckey_end( &ctx );
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
    int rc;
    struct getkey_ctx_s ctx;
    PKT_secret_key *sk;

    sk = m_alloc_clear( sizeof *sk );
    memset( &ctx, 0, sizeof ctx );
    ctx.not_allocated = 1;
    ctx.nitems = 1;
    ctx.items[0].mode = 11;
    ctx.items[0].keyid[0] = keyid[0];
    ctx.items[0].keyid[1] = keyid[1];
    rc = lookup_sk( &ctx, sk, NULL );
    get_seckey_end( &ctx );
    free_secret_key( sk );
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
 *  6 = word match mode
 * 10 = it is a short KEYID (don't care about keyid[0])
 * 11 = it is a long  KEYID
 * 12 = it is a trustdb index (keyid is looked up)
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
 * - If the userid starts with a '+' we will compare individual words
 *   and a match requires that all the words are in the userid.
 *   Words are delimited by white space or "()<>[]{}.@-+_,;/&!"
 *   (note that you can't search for these characters). Compare
 *   is not case sensitive.
 */

int
classify_user_id( const char *name, u32 *keyid, byte *fprint,
		  const char **retstr, size_t *retlen )
{
    const char *	s;
    int 		mode = 0;
    int 		hexprefix = 0;
    int 		hexlength;

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

	default:
	    if (s[0] == '0' && s[1] == 'x') {
		hexprefix = 1;
		s += 2;
	    }

	    hexlength = strspn(s, "0123456789abcdefABCDEF");

	    /* check if a hexadecimal number is terminated by EOS or blank */
	    if (hexlength && s[hexlength] && !isspace(s[hexlength])) {
		if (hexprefix)	    /* a "0x" prefix without correct */
		    return 0;	    /* termination is an error */
		else		    /* The first chars looked like */
		    hexlength = 0;  /* a hex number, but really were not. */
	    }

	    if (hexlength == 8 || (!hexprefix && hexlength == 9 && *s == '0')){
		/* short keyid */
		if (hexlength == 9)
		    s++;
		if (keyid) {
		    keyid[0] = 0;
		    keyid[1] = strtoul( s, NULL, 16 );
		}
		mode = 10;
	    }
	    else if (hexlength == 16 || (!hexprefix && hexlength == 17
							  && *s == '0')) {
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

		mode = 2;   /* Default is case insensitive substring search */
	    }
    }

    if( retstr )
	*retstr = s;
    if( retlen )
	*retlen = strlen(s);

    return mode;
}



/****************
 * Try to get the pubkey by the userid. This function looks for the
 * first pubkey certificate which has the given name in a user_id.
 * if pk/sk has the pubkey algo set, the function will only return
 * a pubkey with that algo.
 * The caller must provide provide storage for either the pk or the sk.
 * If ret_kb is not NULL the funtion will return the keyblock there.
 */

static int
key_byname( GETKEY_CTX *retctx, STRLIST namelist,
	    PKT_public_key *pk, PKT_secret_key *sk, KBNODE *ret_kb )
{
    int rc = 0;
    int n;
    STRLIST r;
    GETKEY_CTX ctx;

    if( retctx ) /* reset the returned context in case of error */
	*retctx = NULL;
    assert( !pk ^ !sk );

    /* build the search context */
    /* Performance hint: Use a static buffer if there is only one name */
    /*			 and we don't have mode 6 */
    for(n=0, r=namelist; r; r = r->next )
	n++;
    ctx = m_alloc_clear( sizeof *ctx + (n-1)*sizeof ctx->items );
    ctx->nitems = n;

    for(n=0, r=namelist; r; r = r->next, n++ ) {
	ctx->items[n].mode = classify_user_id( r->d,
					      ctx->items[n].keyid,
					      ctx->items[n].fprint,
					      &ctx->items[n].name,
					      NULL );
	if( !ctx->items[n].mode ) {
	    m_free( ctx );
	    return G10ERR_INV_USER_ID;
	}
	if( ctx->items[n].mode == 6 ) {
	    ctx->items[n].namebuf = prepare_word_match(ctx->items[n].name);
	    ctx->items[n].name = ctx->items[n].namebuf;
	}
    }

    /* and call the lookup function */
    ctx->primary = 1; /* we want to look for the primary key only */
    if( sk )
	rc = lookup_sk( ctx, sk, ret_kb );
    else
	rc = lookup_pk( ctx, pk, ret_kb );

    if( retctx ) /* caller wants the context */
	*retctx = ctx;
    else {
	/* Hmmm, why not get_pubkey-end here?? */
	enum_keyblocks( 2, &ctx->kbpos, NULL ); /* close */
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

    if( !pk ) {
	/* Performance Hint: key_byname should not need a pk here */
	pk = m_alloc_clear( sizeof *pk );
	rc = key_byname( retctx, namelist, pk, NULL, ret_keyblock );
	free_public_key( pk );
    }
    else
	rc = key_byname( retctx, namelist, pk, NULL, ret_keyblock );

    free_strlist( namelist );
    return rc;
}

int
get_pubkey_bynames( GETKEY_CTX *retctx, PKT_public_key *pk,
		    STRLIST names, KBNODE *ret_keyblock )
{
    int rc;

    if( !pk ) {
	/* Performance Hint: key_byname should not need a pk here */
	pk = m_alloc_clear( sizeof *pk );
	rc = key_byname( retctx, names, pk, NULL, ret_keyblock );
	free_public_key( pk );
    }
    else
	rc = key_byname( retctx, names, pk, NULL, ret_keyblock );

    return rc;
}

int
get_pubkey_next( GETKEY_CTX ctx, PKT_public_key *pk, KBNODE *ret_keyblock )
{
    int rc;

    if( !pk ) {
	/* Performance Hint: lookup_read should not need a pk in this case */
	pk = m_alloc_clear( sizeof *pk );
	rc = lookup_pk( ctx, pk, ret_keyblock );
	free_public_key( pk );
    }
    else
	rc = lookup_pk( ctx, pk, ret_keyblock );
    return rc;
}

void
get_pubkey_end( GETKEY_CTX ctx )
{
    if( ctx ) {
	int n;

	enum_keyblocks( 2, &ctx->kbpos, NULL ); /* close */
	for(n=0; n < ctx->nitems; n++ )
	    m_free( ctx->items[n].namebuf );
	if( !ctx->not_allocated )
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

    if( fprint_len == 20 || fprint_len == 16 ) {
	struct getkey_ctx_s ctx;
	memset( &ctx, 0, sizeof ctx );
	ctx.not_allocated = 1;
	ctx.nitems = 1;
	ctx.items[0].mode = fprint_len;
	memcpy( ctx.items[0].fprint, fprint, fprint_len );
	rc = lookup_pk( &ctx, pk, NULL );
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
    PKT_public_key *pk = m_alloc_clear( sizeof *pk );

    if( fprint_len == 20 || fprint_len == 16 ) {
	struct getkey_ctx_s ctx;
	memset( &ctx, 0, sizeof ctx );
	ctx.not_allocated = 1;
	ctx.nitems = 1;
	ctx.items[0].mode = fprint_len;
	memcpy( ctx.items[0].fprint, fprint, fprint_len );
	rc = lookup_pk( &ctx, pk, ret_keyblock );
	get_pubkey_end( &ctx );
    }
    else
	rc = G10ERR_GENERAL; /* Oops */

    free_public_key( pk );
    return rc;
}



/****************
 * Search for a key with the given lid and return the complete keyblock
 */
int
get_keyblock_bylid( KBNODE *ret_keyblock, ulong lid )
{
    int rc;
    PKT_public_key *pk = m_alloc_clear( sizeof *pk );
    struct getkey_ctx_s ctx;
    u32 kid[2];

    if( keyid_from_lid( lid, kid ) )
	kid[0] = kid[1] = 0;
    memset( &ctx, 0, sizeof ctx );
    ctx.not_allocated = 1;
    ctx.nitems = 1;
    ctx.items[0].mode = 12;
    ctx.items[0].keyid[0] = kid[0];
    ctx.items[0].keyid[1] = kid[1];
    rc = lookup_pk( &ctx, pk, ret_keyblock );
    get_pubkey_end( &ctx );

    free_public_key( pk );
    return rc;
}





/****************
 * Get a secret key by name and store it into sk
 * If NAME is NULL use the default key
 */
int
get_seckey_byname( PKT_secret_key *sk, const char *name, int unprotect )
{
    STRLIST namelist = NULL;
    int rc;

    if( !name && opt.def_secret_key && *opt.def_secret_key ) {
	add_to_strlist( &namelist, opt.def_secret_key );
	rc = key_byname( NULL, namelist, NULL, sk, NULL );
    }
    else if( !name ) { /* use the first one as default key */
	struct getkey_ctx_s ctx;

	memset( &ctx, 0, sizeof ctx );
	ctx.not_allocated = 1;
	ctx.primary = 1;
	ctx.nitems = 1;
	ctx.items[0].mode = 15;
	rc = lookup_sk( &ctx, sk, NULL );
	get_seckey_end( &ctx );
    }
    else {
	add_to_strlist( &namelist, name );
	rc = key_byname( NULL, namelist, NULL, sk, NULL );
    }

    free_strlist( namelist );

    if( !rc && unprotect )
	rc = check_secret_key( sk, 0 );

    return rc;
}

int
get_seckey_bynames( GETKEY_CTX *retctx, PKT_secret_key *sk,
		    STRLIST names, KBNODE *ret_keyblock )
{
    int rc;

    if( !sk ) {
	/* Performance Hint: key_byname should not need a sk here */
	sk = m_alloc_secure_clear( sizeof *sk );
	rc = key_byname( retctx, names, NULL, sk, ret_keyblock );
	free_secret_key( sk );
    }
    else
	rc = key_byname( retctx, names, NULL, sk, ret_keyblock );

    return rc;
}


int
get_seckey_next( GETKEY_CTX ctx, PKT_secret_key *sk, KBNODE *ret_keyblock )
{
    int rc;

    if( !sk ) {
	/* Performance Hint: lookup_read should not need a pk in this case */
	sk = m_alloc_secure_clear( sizeof *sk );
	rc = lookup_sk( ctx, sk, ret_keyblock );
	free_secret_key( sk );
    }
    else
	rc = lookup_sk( ctx, sk, ret_keyblock );
    return rc;
}

void
get_seckey_end( GETKEY_CTX ctx )
{
    if( ctx ) {
	int n;

	enum_keyblocks( 2, &ctx->kbpos, NULL ); /* close */
	for(n=0; n < ctx->nitems; n++ )
	    m_free( ctx->items[n].namebuf );
	if( !ctx->not_allocated )
	    m_free( ctx );
    }
}



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



/****************
 * Assume that knode points to a public key packet  and keyblock is
 * the entire keyblock.  This function adds all relevant information from
 * a selfsignature to the public key.
 */

static void
merge_one_pk_and_selfsig( KBNODE keyblock, KBNODE knode,
			  PKT_public_key *orig_pk )
{
    PKT_public_key *pk = knode->pkt->pkt.public_key;
    PKT_signature *sig;
    KBNODE k;
    u32 kid[2];
    u32 sigdate = 0;

    assert(    knode->pkt->pkttype == PKT_PUBLIC_KEY
	    || knode->pkt->pkttype == PKT_PUBLIC_SUBKEY );

    if( pk->version < 4 )
	return; /* this is only needed for version >=4 packets */


    /* find the selfsignature */
    if( knode->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
	k = find_kbnode( keyblock, PKT_PUBLIC_KEY );
	if( !k )
	   BUG(); /* keyblock without primary key!!! */
	keyid_from_pk( k->pkt->pkt.public_key, kid );
    }
    else
	keyid_from_pk( pk, kid );

    for(k=knode->next; k; k = k->next ) {
	if( k->pkt->pkttype == PKT_SIGNATURE
	    && (sig=k->pkt->pkt.signature)->sig_class >= 0x10
	    && sig->sig_class <= 0x30
	    && sig->keyid[0] == kid[0]
	    && sig->keyid[1] == kid[1]
	    && sig->version > 3 ) {
	    /* okay this is a self-signature which can be used.
	     * We use the latest self-signature.
	     * FIXME: We should only use this if the signature is valid
	     *	      but this is time consuming - we must provide another
	     *	      way to handle this
	     */
	    const byte *p;
	    u32 ed;

	    p = parse_sig_subpkt( sig->hashed_data, SIGSUBPKT_KEY_EXPIRE, NULL );
	    ed = p? pk->timestamp + buffer_to_u32(p):0;
	    /* use the latest self signature */
	    if( sig->timestamp > sigdate ) {
		pk->expiredate = ed;
		orig_pk->expiredate = ed;
		sigdate = sig->timestamp;
	    }
	    /* fixme: add usage etc. to pk */
	}
	else if( k->pkt->pkttype == PKT_PUBLIC_SUBKEY )
	    break; /* stop here */
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
    u32 sigdate = 0;

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
		pk->expiredate = subkeys_expiretime( k, kid );
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
		if( k->pkt->pkt.user_id->photo )
		    rmd160_hash_buffer( namehash,
					k->pkt->pkt.user_id->photo,
					k->pkt->pkt.user_id->photolen );
		else
		    rmd160_hash_buffer( namehash,
					k->pkt->pkt.user_id->name,
					k->pkt->pkt.user_id->len );
		*use_namehash = 1;
		return kk;
	    }
	    else if( is_RSA(pk->pubkey_algo) )
		log_error(_("RSA key cannot be used in this version\n"));
	    else
		log_error(_("No key for user ID\n"));
	}
    }
    return NULL;
}

static KBNODE
find_by_name_sk( KBNODE keyblock, PKT_secret_key *sk, const char *name,
		 int mode )
{
    KBNODE k, kk;

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
		return kk;
	    }
	    else if( is_RSA(sk->pubkey_algo) )
		log_error(_("RSA key cannot be used in this version\n"));
	    else
		log_error(_("No key for user ID\n"));
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
		    log_error(_("No user ID for key\n"));
		return k; /* found */
	    }
	}
    }
    return NULL;
}

static KBNODE
find_by_keyid_sk( KBNODE keyblock, PKT_secret_key *sk, u32 *keyid, int mode )
{
    KBNODE k;

    if( DBG_CACHE )
	log_debug("lookup_sk keyid=%08lx%08lx req_algo=%d mode=%d\n",
		   (ulong)keyid[0], (ulong)keyid[1], sk->pubkey_algo, mode );

    for(k=keyblock; k; k = k->next ) {
	if(    k->pkt->pkttype == PKT_SECRET_KEY
	    || k->pkt->pkttype == PKT_SECRET_SUBKEY ) {
	    u32 aki[2];
	    keyid_from_sk( k->pkt->pkt.secret_key, aki );
	    if( DBG_CACHE )
		log_debug("         aki=%08lx%08lx algo=%d\n",
				(ulong)aki[0], (ulong)aki[1],
				 k->pkt->pkt.secret_key->pubkey_algo	);

	    if( aki[1] == keyid[1]
		&& ( mode == 10 || aki[0] == keyid[0] )
		&& ( !sk->pubkey_algo
		     || sk->pubkey_algo
			== k->pkt->pkt.secret_key->pubkey_algo) ){
		KBNODE kk;
		/* cache the userid */
		for(kk=keyblock; kk; kk = kk->next )
		    if( kk->pkt->pkttype == PKT_USER_ID )
			break;
		if( kk )
		    cache_user_id( kk->pkt->pkt.user_id, aki );
		else
		    log_error(_("No user ID for key\n"));
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
find_first_sk( KBNODE keyblock, PKT_secret_key *sk )
{
    KBNODE k;

    for(k=keyblock; k; k = k->next ) {
	if(    k->pkt->pkttype == PKT_SECRET_KEY
	    || k->pkt->pkttype == PKT_SECRET_SUBKEY )
	{
	    if( !sk->pubkey_algo
		|| sk->pubkey_algo == k->pkt->pkt.secret_key->pubkey_algo )
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
			k->pkt->pkt.public_key->pubkey_algo, mode,
							    (unsigned)an );
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

static KBNODE
find_by_fpr_sk( KBNODE keyblock, PKT_secret_key *sk,
				 const char *name, int mode )
{
    KBNODE k;

    for(k=keyblock; k; k = k->next ) {
	if(    k->pkt->pkttype == PKT_SECRET_KEY
	    || k->pkt->pkttype == PKT_SECRET_SUBKEY ) {
	    byte afp[MAX_FINGERPRINT_LEN];
	    size_t an;

	    fingerprint_from_sk(k->pkt->pkt.secret_key, afp, &an );

	    if( DBG_CACHE ) {
		u32 aki[2];
		keyid_from_sk( k->pkt->pkt.secret_key, aki );
		log_debug("         aki=%08lx%08lx algo=%d mode=%d an=%u\n",
				(ulong)aki[0], (ulong)aki[1],
			k->pkt->pkt.secret_key->pubkey_algo, mode,
							(unsigned)an );
	    }

	    if( an == mode
		&& !memcmp( afp, name, an)
		&& ( !sk->pubkey_algo
		     || sk->pubkey_algo == k->pkt->pkt.secret_key->pubkey_algo) )
		return k;
	}
    }
    return NULL;
}


/****************
 * Return the expiretime of a subkey.
 */
static u32
subkeys_expiretime( KBNODE node, u32 *mainkid )
{
    KBNODE k;
    PKT_signature *sig;
    u32 expires = 0, sigdate = 0;

    assert( node->pkt->pkttype == PKT_PUBLIC_SUBKEY );
    for(k=node->next; k; k = k->next ) {
	if( k->pkt->pkttype == PKT_SIGNATURE
	    && (sig=k->pkt->pkt.signature)->sig_class == 0x18
	    && sig->keyid[0] == mainkid[0]
	    && sig->keyid[1] == mainkid[1]
	    && sig->version > 3
	    && sig->timestamp > sigdate ) {
	    /* okay this is a key-binding which can be used.
	     * We use the latest self-signature.
	     * FIXME: We should only use this if the binding signature is valid
	     *	      but this is time consuming - we must provide another
	     *	      way to handle this
	     */
	    const byte *p;
	    u32 ed;

	    p = parse_sig_subpkt( sig->hashed_data, SIGSUBPKT_KEY_EXPIRE, NULL );
	    ed = p? node->pkt->pkt.public_key->timestamp + buffer_to_u32(p):0;
	    sigdate = sig->timestamp;
	    expires = ed;
	}
	else if( k->pkt->pkttype == PKT_PUBLIC_SUBKEY )
	    break; /* stop at the next subkey */
    }

    return expires;
}


/****************
 * Check whether the subkey has expired.  Node must point to the subkey
 */
static int
has_expired( KBNODE node, u32 *mainkid, u32 cur_time )
{
    u32 expires = subkeys_expiretime( node, mainkid );
    return expires && expires <= cur_time;
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
	merge_one_pk_and_selfsig( keyblock, keyblock, pk );
    }
    else {
	if( primary && pk->pubkey_usage == PUBKEY_USAGE_ENC
            && keyblock->pkt->pkt.public_key->version > 3
            && keyblock->pkt->pkt.public_key->pubkey_algo == PUBKEY_ALGO_RSA
            && k->pkt->pkttype == PKT_PUBLIC_KEY ) {
	    /* Ugly hack to support v4 RSA keys.  Here we assume that the
               primary key should be used only for signing and a subkey
               should be used for encryption.  So now look for a subkey.
            */
            KBNODE save_k = k;
	    u32 mainkid[2];
	    u32 cur_time = make_timestamp();

	    keyid_from_pk( keyblock->pkt->pkt.public_key, mainkid );

            for(k = save_k ; k; k = k->next ) {
                if( k->pkt->pkttype == PKT_PUBLIC_SUBKEY
                    && !check_pubkey_algo2(
                        k->pkt->pkt.public_key->pubkey_algo,
                        pk->pubkey_usage )
                    && !has_expired( k, mainkid, cur_time )
                    )
                    break;
            }
	    
	    if( !k )
		k = save_k; /* not found: better use the main key instead */
	    else
		log_info(_("using secondary key %08lX "
			   "instead of primary key %08lX\n"),
		      (ulong)keyid_from_pk( k->pkt->pkt.public_key, NULL),
		      (ulong)keyid_from_pk( save_k->pkt->pkt.public_key, NULL)
			);
	}
	else if( primary && pk->pubkey_usage
	    && check_pubkey_algo2( k->pkt->pkt.public_key->pubkey_algo,
		       pk->pubkey_usage ) == G10ERR_WR_PUBKEY_ALGO ) {
	    /* if the usage is not correct, try to use a subkey */
	    KBNODE save_k = k;
	    u32 mainkid[2];
	    u32 cur_time = make_timestamp();

	    keyid_from_pk( keyblock->pkt->pkt.public_key, mainkid );

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
						 pk->pubkey_usage )
			&& !has_expired(k, mainkid, cur_time) )
			break;
		}
	    }

	    if( !k ) {
		for(k = save_k ; k; k = k->next ) {
		    if( k->pkt->pkttype == PKT_PUBLIC_SUBKEY
			&& !check_pubkey_algo2(
				k->pkt->pkt.public_key->pubkey_algo,
						 pk->pubkey_usage )
			&& ( pk->pubkey_usage != PUBKEY_USAGE_ENC
			     || !has_expired( k, mainkid, cur_time ) )
		      )
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
	merge_one_pk_and_selfsig( keyblock, k, pk );
    }
}

static void
finish_lookup_sk( KBNODE keyblock, PKT_secret_key *sk, KBNODE k, int primary )
{
    assert(    k->pkt->pkttype == PKT_SECRET_KEY
	    || k->pkt->pkttype == PKT_SECRET_SUBKEY );
    assert( keyblock->pkt->pkttype == PKT_SECRET_KEY );
    if( primary && !sk->pubkey_usage ) {
	copy_secret_key( sk, keyblock->pkt->pkt.secret_key );
    }
    else {
	if( primary && sk->pubkey_usage
	    && check_pubkey_algo2( k->pkt->pkt.secret_key->pubkey_algo,
		       sk->pubkey_usage ) == G10ERR_WR_PUBKEY_ALGO ) {
	    /* if the usage is not correct, try to use a subkey */
	    KBNODE save_k = k;

	    k = NULL;
	    /* kludge for pgp 5: which doesn't accept type 20:
	     * try to use a type 16 subkey instead */
	    if( sk->pubkey_usage == PUBKEY_USAGE_ENC ) {
		for( k = save_k; k; k = k->next ) {
		    if( k->pkt->pkttype == PKT_SECRET_SUBKEY
			&& k->pkt->pkt.secret_key->pubkey_algo
			    == PUBKEY_ALGO_ELGAMAL_E
			&& !check_pubkey_algo2(
				k->pkt->pkt.secret_key->pubkey_algo,
						 sk->pubkey_usage ) )
			break;
		}
	    }

	    if( !k ) {
		for(k = save_k ; k; k = k->next ) {
		    if( k->pkt->pkttype == PKT_SECRET_SUBKEY
			&& !check_pubkey_algo2(
				k->pkt->pkt.secret_key->pubkey_algo,
						 sk->pubkey_usage ) )
			break;
		}
	    }
	    if( !k )
		k = save_k;
	    else
		log_info(_("using secondary key %08lX "
			   "instead of primary key %08lX\n"),
		      (ulong)keyid_from_sk( k->pkt->pkt.secret_key, NULL),
		      (ulong)keyid_from_sk( save_k->pkt->pkt.secret_key, NULL)
			);
	}

	copy_secret_key( sk, k->pkt->pkt.secret_key );
    }
}


static int
lookup_pk( GETKEY_CTX ctx, PKT_public_key *pk, KBNODE *ret_keyblock )
{
    int rc;
    KBNODE k;
    int oldmode = set_packet_list_mode(0);
    byte namehash[20];
    int use_namehash=0;

    if( !ctx->count ) /* first time */
	rc = enum_keyblocks( 0, &ctx->kbpos, &ctx->keyblock );
    else
	rc = 0;
    if( !rc ) {
	while( !(rc = enum_keyblocks( 1, &ctx->kbpos, &ctx->keyblock )) ) {
	    int n;
	    getkey_item_t *item;
	    /* fixme: we don't enum the complete keyblock, but
	     * use the first match and then continue with the next keyblock
	     */
	    /* loop over all the user ids we want to look for */
	    item = ctx->items;
	    for(n=0; n < ctx->nitems; n++, item++ ) {
		if( item->mode < 10 )
		    k = find_by_name( ctx->keyblock, pk,
				      item->name, item->mode,
				      namehash, &use_namehash );
		else if( item->mode >= 10 && item->mode <= 12 )
		    k = find_by_keyid( ctx->keyblock, pk,
				       item->keyid, item->mode );
		else if( item->mode == 15 )
		    k = find_first( ctx->keyblock, pk );
		else if( item->mode == 16 || item->mode == 20 )
		    k = find_by_fpr( ctx->keyblock, pk,
				     item->fprint, item->mode );
		else
		    BUG();
		if( k ) {
		    finish_lookup( ctx->keyblock, pk, k, namehash,
						 use_namehash, ctx->primary );
		    goto found;
		}
	    }
	    release_kbnode( ctx->keyblock );
	    ctx->keyblock = NULL;
	}
      found: ;
    }
    if( rc && rc != -1 )
	log_error("enum_keyblocks failed: %s\n", g10_errstr(rc));

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
	else if ( rc == G10ERR_NO_PUBKEY )
	    lkup_stats[ctx->mode].nokey_count++;
	else
	    lkup_stats[ctx->mode].error_count++;
    }
   #endif

    ctx->last_rc = rc;
    ctx->count++;
    return rc;
}



static int
lookup_sk( GETKEY_CTX ctx, PKT_secret_key *sk, KBNODE *ret_keyblock )
{
    int rc;
    KBNODE k;
    int oldmode = set_packet_list_mode(0);

    if( !ctx->count ) /* first time */
	rc = enum_keyblocks( 5, &ctx->kbpos, &ctx->keyblock );
    else
	rc = 0;
    if( !rc ) {
	while( !(rc = enum_keyblocks( 1, &ctx->kbpos, &ctx->keyblock )) ) {
	    int n;
	    getkey_item_t *item;
	    /* fixme: we don't enum the complete keyblock, but
	     * use the first match and then continue with the next keyblock
	     */
	    /* loop over all the user ids we want to look for */
	    item = ctx->items;
	    for(n=0; n < ctx->nitems; n++, item++ ) {
		if( item->mode < 10 )
		    k = find_by_name_sk( ctx->keyblock, sk,
					 item->name, item->mode );
		else if( item->mode >= 10 && item->mode <= 12 )
		    k = find_by_keyid_sk( ctx->keyblock, sk,
					  item->keyid, item->mode );
		else if( item->mode == 15 )
		    k = find_first_sk( ctx->keyblock, sk );
		else if( item->mode == 16 || item->mode == 20 )
		    k = find_by_fpr_sk( ctx->keyblock, sk,
					item->fprint, item->mode );
		else
		    BUG();
		if( k ) {
		    finish_lookup_sk( ctx->keyblock, sk, k, ctx->primary );
		    goto found;
		}
	    }
	    release_kbnode( ctx->keyblock );
	    ctx->keyblock = NULL;
	}
      found: ;
    }
    if( rc && rc != -1 )
	log_error("enum_keyblocks failed: %s\n", g10_errstr(rc));

    if( !rc ) {
	if( ret_keyblock ) {
	    *ret_keyblock = ctx->keyblock;
	    ctx->keyblock = NULL;
	}
    }
    else if( rc == -1 )
	rc = G10ERR_NO_SECKEY;

    release_kbnode( ctx->keyblock );
    ctx->keyblock = NULL;
    set_packet_list_mode(oldmode);

    ctx->last_rc = rc;
    ctx->count++;
    return rc;
}



/****************
 * fixme: replace by the generic function
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
	for(r=user_id_db; r; r = r->next )
	    if( r->keyid[0] == keyid[0] && r->keyid[1] == keyid[1] ) {
		p = m_alloc( r->len + 20 );
		sprintf(p, "%08lX%08lX %.*s",
			  (ulong)keyid[0], (ulong)keyid[1], r->len, r->name );
		return p;
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
	for(r=user_id_db; r; r = r->next )
	    if( r->keyid[0] == keyid[0] && r->keyid[1] == keyid[1] ) {
		p = m_alloc( r->len );
		memcpy(p, r->name, r->len );
		*rn = r->len;
		return p;
	    }
    } while( ++pass < 2 && !get_pubkey( NULL, keyid ) );
    p = m_strdup( _("[User id not found]") );
    *rn = strlen(p);
    return p;
}


