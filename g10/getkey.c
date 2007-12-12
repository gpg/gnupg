/* getkey.c -  Get a key from the database
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005,
 *               2006 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
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
#include "keyserver-internal.h"

#define MAX_PK_CACHE_ENTRIES   PK_UID_CACHE_SIZE
#define MAX_UID_CACHE_ENTRIES  PK_UID_CACHE_SIZE

#if MAX_PK_CACHE_ENTRIES < 2
#error We need the cache for key creation
#endif

struct getkey_ctx_s {
    int exact;
    KBNODE keyblock;
    KBPOS  kbpos;
    KBNODE found_key; /* pointer into some keyblock */
    int last_rc;
    int req_usage;
    int req_algo;
    KEYDB_HANDLE kr_handle;
    int not_allocated;
    int nitems;
    KEYDB_SEARCH_DESC items[1];
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

static void merge_selfsigs( KBNODE keyblock );
static int lookup( GETKEY_CTX ctx, KBNODE *ret_keyblock, int secmode );

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

    if( pk->dont_cache )
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
    ce = xmalloc( sizeof *ce );
    ce->next = pk_cache;
    pk_cache = ce;
    ce->pk = copy_public_key( NULL, pk );
    ce->keyid[0] = keyid[0];
    ce->keyid[1] = keyid[1];
#endif
}


/* Return a const utf-8 string with the text "[User ID not found]".
   This fucntion is required so that we don't need to switch gettext's
   encoding temporary. */
static const char *
user_id_not_found_utf8 (void)
{
  static char *text;

  if (!text)
    text = native_to_utf8 (_("[User ID not found]"));
  return text;
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
             && !k->pkt->pkt.user_id->attrib_data
             && k->pkt->pkt.user_id->is_primary ) {
            *uidlen = k->pkt->pkt.user_id->len;
            return k->pkt->pkt.user_id->name;
        }
    } 
    s = user_id_not_found_utf8 ();
    *uidlen = strlen (s);
    return s;
}


static void
release_keyid_list ( keyid_list_t k )
{
    while (  k ) {
        keyid_list_t k2 = k->next;
        xfree (k);
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
            keyid_list_t a = xmalloc_clear ( sizeof *a );
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
                        xfree ( a );
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
	xfree(r);
	uid_cache_entries--;
    }
    r = xmalloc( sizeof *r + uidlen-1 );
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
#if MAX_PK_CACHE_ENTRIES
    {
	pk_cache_entry_t ce, ce2;

	for( ce = pk_cache; ce; ce = ce2 ) {
	    ce2 = ce->next;
	    free_public_key( ce->pk );
	    xfree( ce );
	}
	pk_cache_disabled=1;
	pk_cache_entries = 0;
	pk_cache = NULL;
    }
#endif
    /* fixme: disable user id cache ? */
}


static void
pk_from_block ( GETKEY_CTX ctx, PKT_public_key *pk, KBNODE keyblock )
{
    KBNODE a = ctx->found_key ? ctx->found_key : keyblock;

    assert ( a->pkt->pkttype == PKT_PUBLIC_KEY
             ||  a->pkt->pkttype == PKT_PUBLIC_SUBKEY );
     
    copy_public_key ( pk, a->pkt->pkt.public_key );
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

#if MAX_PK_CACHE_ENTRIES
    if(pk)
      {
	/* Try to get it from the cache.  We don't do this when pk is
	   NULL as it does not guarantee that the user IDs are
	   cached. */
	pk_cache_entry_t ce;
	for( ce = pk_cache; ce; ce = ce->next )
	  {
	    if( ce->keyid[0] == keyid[0] && ce->keyid[1] == keyid[1] )
	      {
		copy_public_key( pk, ce->pk );
		return 0;
	      }
	  }
      }
#endif
    /* more init stuff */
    if( !pk ) {
	pk = xmalloc_clear( sizeof *pk );
	internal++;
    }


    /* do a lookup */
    {	struct getkey_ctx_s ctx;
        KBNODE kb = NULL;
	memset( &ctx, 0, sizeof ctx );
        ctx.exact = 1; /* use the key ID exactly as given */
	ctx.not_allocated = 1;
        ctx.kr_handle = keydb_new (0);
	ctx.nitems = 1;
	ctx.items[0].mode = KEYDB_SEARCH_MODE_LONG_KID;
	ctx.items[0].u.kid[0] = keyid[0];
	ctx.items[0].u.kid[1] = keyid[1];
        ctx.req_algo  = pk->req_algo;
        ctx.req_usage = pk->req_usage;
	rc = lookup( &ctx, &kb, 0 );
        if ( !rc ) {
            pk_from_block ( &ctx, pk, kb );
        }
	get_pubkey_end( &ctx );
        release_kbnode ( kb );
    }
    if( !rc )
	goto leave;

    rc = G10ERR_NO_PUBKEY;

  leave:
    if( !rc )
	cache_public_key( pk );
    if( internal )
	free_public_key(pk);
    return rc;
}


/* Get a public key and store it into the allocated pk.  This function
   differs from get_pubkey() in that it does not do a check of the key
   to avoid recursion.  It should be used only in very certain cases.
   It will only retrieve primary keys. */
int
get_pubkey_fast (PKT_public_key *pk, u32 *keyid)
{
  int rc = 0;
  KEYDB_HANDLE hd;
  KBNODE keyblock;
  u32 pkid[2];
  
  assert (pk);
#if MAX_PK_CACHE_ENTRIES
  { /* Try to get it from the cache */
    pk_cache_entry_t ce;

    for (ce = pk_cache; ce; ce = ce->next)
      {
        if (ce->keyid[0] == keyid[0] && ce->keyid[1] == keyid[1])
          {
            if (pk)
              copy_public_key (pk, ce->pk);
            return 0;
          }
      }
  }
#endif

  hd = keydb_new (0);
  rc = keydb_search_kid (hd, keyid);
  if (rc == -1)
    {
      keydb_release (hd);
      return G10ERR_NO_PUBKEY;
    }
  rc = keydb_get_keyblock (hd, &keyblock);
  keydb_release (hd);
  if (rc) 
    {
      log_error ("keydb_get_keyblock failed: %s\n", g10_errstr(rc));
      return G10ERR_NO_PUBKEY;
    }

  assert ( keyblock->pkt->pkttype == PKT_PUBLIC_KEY
           ||  keyblock->pkt->pkttype == PKT_PUBLIC_SUBKEY );

  keyid_from_pk(keyblock->pkt->pkt.public_key,pkid);
  if(keyid[0]==pkid[0] && keyid[1]==pkid[1])
    copy_public_key (pk, keyblock->pkt->pkt.public_key );
  else
    rc=G10ERR_NO_PUBKEY;

  release_kbnode (keyblock);

  /* Not caching key here since it won't have all of the fields
     properly set. */

  return rc;
}


KBNODE
get_pubkeyblock( u32 *keyid )
{
    struct getkey_ctx_s ctx;
    int rc = 0;
    KBNODE keyblock = NULL;

    memset( &ctx, 0, sizeof ctx );
    /* no need to set exact here because we want the entire block */
    ctx.not_allocated = 1;
    ctx.kr_handle = keydb_new (0);
    ctx.nitems = 1;
    ctx.items[0].mode = KEYDB_SEARCH_MODE_LONG_KID;
    ctx.items[0].u.kid[0] = keyid[0];
    ctx.items[0].u.kid[1] = keyid[1];
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
    ctx.kr_handle = keydb_new (1);
    ctx.nitems = 1;
    ctx.items[0].mode = KEYDB_SEARCH_MODE_LONG_KID;
    ctx.items[0].u.kid[0] = keyid[0];
    ctx.items[0].u.kid[1] = keyid[1];
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
    int rc;
    KEYDB_HANDLE hd = keydb_new (1);

    rc = keydb_search_kid (hd, keyid);
    if ( rc == -1 )
        rc = G10ERR_NO_SECKEY;
    keydb_release (hd);
    return rc;
}


/****************
 * Return the type of the user id:
 *
 * Please use the constants KEYDB_SERCH_MODE_xxx
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

int
classify_user_id( const char *name, KEYDB_SEARCH_DESC *desc )
{
    const char *s;
    int hexprefix = 0;
    int hexlength;
    int mode = 0;   
    KEYDB_SEARCH_DESC dummy_desc;

    if (!desc)
        desc = &dummy_desc;

    /* clear the structure so that the mode field is set to zero unless
     * we set it to the correct value right at the end of this function */
    memset (desc, 0, sizeof *desc);

    /* skip leading spaces.  Fixme: what is with trailing spaces? */
    for(s = name; *s && spacep (s); s++ )
	;

    switch (*s) {
	case 0:    /* empty string is an error */
	    return 0;

#if 0
	case '.':  /* an email address, compare from end */
	    mode = KEYDB_SEARCH_MODE_MAILEND;
	    s++;
            desc->u.name = s;
	    break;
#endif

	case '<':  /* an email address */
	    mode = KEYDB_SEARCH_MODE_MAIL;
            desc->u.name = s;
	    break;

	case '@':  /* part of an email address */
	    mode = KEYDB_SEARCH_MODE_MAILSUB;
	    s++;
            desc->u.name = s;
	    break;

	case '=':  /* exact compare */
	    mode = KEYDB_SEARCH_MODE_EXACT;
	    s++;
            desc->u.name = s;
	    break;

	case '*':  /* case insensitive substring search */
	    mode = KEYDB_SEARCH_MODE_SUBSTR;
	    s++;
            desc->u.name = s;
	    break;

#if 0
	case '+':  /* compare individual words */
	    mode = KEYDB_SEARCH_MODE_WORDS;
	    s++;
            desc->u.name = s;
	    break;
#endif

	case '#':  /* local user id */
            return 0; /* This is now obsolete and van't not be used anymore*/
        
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
                for (i=0,si=s; si < se; i++, si +=2) 
                    desc->u.fpr[i] = hextobyte(si);
                for ( ; i < 20; i++)
                    desc->u.fpr[i]= 0;
                s = se + 1;
                mode = KEYDB_SEARCH_MODE_FPR;
            } 
            break;
           
	default:
	    if (s[0] == '0' && s[1] == 'x') {
		hexprefix = 1;
		s += 2;
	    }

	    hexlength = strspn(s, "0123456789abcdefABCDEF");
            if (hexlength >= 8 && s[hexlength] =='!') {
		desc->exact = 1;
                hexlength++; /* just for the following check */
            }

	    /* check if a hexadecimal number is terminated by EOS or blank */
	    if (hexlength && s[hexlength] && !spacep(s+hexlength)) {
		if (hexprefix)	    /* a "0x" prefix without correct */
		    return 0;	    /* termination is an error */
		else		    /* The first chars looked like */
		    hexlength = 0;  /* a hex number, but really were not. */
	    }

            if (desc->exact)
                hexlength--;

	    if (hexlength == 8
                || (!hexprefix && hexlength == 9 && *s == '0')){
		/* short keyid */
		if (hexlength == 9)
		    s++;
                desc->u.kid[0] = 0;
                desc->u.kid[1] = strtoul( s, NULL, 16 );
		mode = KEYDB_SEARCH_MODE_SHORT_KID;
	    }
	    else if (hexlength == 16
                     || (!hexprefix && hexlength == 17 && *s == '0')) {
		/* complete keyid */
		char buf[9];
		if (hexlength == 17)
		    s++;
		mem2str(buf, s, 9 );
		desc->u.kid[0] = strtoul( buf, NULL, 16 );
		desc->u.kid[1] = strtoul( s+8, NULL, 16 );
		mode = KEYDB_SEARCH_MODE_LONG_KID;
	    }
	    else if (hexlength == 32 || (!hexprefix && hexlength == 33
							    && *s == '0')) {
		/* md5 fingerprint */
		int i;
		if (hexlength == 33)
		    s++;
                memset(desc->u.fpr+16, 0, 4); 
                for (i=0; i < 16; i++, s+=2) {
                    int c = hextobyte(s);
                    if (c == -1)
                        return 0;
                    desc->u.fpr[i] = c;
                }
		mode = KEYDB_SEARCH_MODE_FPR16;
	    }
	    else if (hexlength == 40 || (!hexprefix && hexlength == 41
							      && *s == '0')) {
		/* sha1/rmd160 fingerprint */
		int i;
		if (hexlength == 41)
		    s++;
                for (i=0; i < 20; i++, s+=2) {
                    int c = hextobyte(s);
                    if (c == -1)
                        return 0;
                    desc->u.fpr[i] = c;
                }
		mode = KEYDB_SEARCH_MODE_FPR20;
	    }
	    else {
		if (hexprefix)	/* This was a hex number with a prefix */
		    return 0;	/* and a wrong length */

		desc->exact = 0;
                desc->u.name = s;
		mode = KEYDB_SEARCH_MODE_SUBSTR;   /* default mode */
	    }
    }

    desc->mode = mode;
    return mode;
}


static int
skip_unusable(void *dummy,u32 *keyid,PKT_user_id *uid)
{
  int unusable=0;
  KBNODE keyblock;

  keyblock=get_pubkeyblock(keyid);
  if(!keyblock)
    {
      log_error("error checking usability status of %s\n",keystr(keyid));
      goto leave;
    }

  /* Is the user ID in question revoked/expired? */
  if(uid)
    {
      KBNODE node;

      for(node=keyblock;node;node=node->next)
	{
	  if(node->pkt->pkttype==PKT_USER_ID)
	    {
	      if(cmp_user_ids(uid,node->pkt->pkt.user_id)==0
		 && (node->pkt->pkt.user_id->is_revoked
		     || node->pkt->pkt.user_id->is_expired))
		{
		  unusable=1;
		  break;
		}
	    }
	}
    }

  if(!unusable)
    unusable=pk_is_disabled(keyblock->pkt->pkt.public_key);

 leave:
  release_kbnode(keyblock);
  return unusable;
}

/****************
 * Try to get the pubkey by the userid. This function looks for the
 * first pubkey certificate which has the given name in a user_id.  if
 * pk/sk has the pubkey algo set, the function will only return a
 * pubkey with that algo.  If namelist is NULL, the first key is
 * returned.  The caller should provide storage for either the pk or
 * the sk.  If ret_kb is not NULL the function will return the
 * keyblock there.
 */

static int
key_byname( GETKEY_CTX *retctx, STRLIST namelist,
	    PKT_public_key *pk, PKT_secret_key *sk,
	    int secmode, int include_unusable,
            KBNODE *ret_kb, KEYDB_HANDLE *ret_kdbhd )
{
    int rc = 0;
    int n;
    STRLIST r;
    GETKEY_CTX ctx;
    KBNODE help_kb = NULL;
    
    if( retctx ) {/* reset the returned context in case of error */
        assert (!ret_kdbhd);  /* not allowed because the handle is
                                 stored in the context */
	*retctx = NULL;
    }
    if (ret_kdbhd)
        *ret_kdbhd = NULL;

    if(!namelist)
      {
	ctx = xmalloc_clear (sizeof *ctx);
	ctx->nitems = 1;
	ctx->items[0].mode=KEYDB_SEARCH_MODE_FIRST;
	if(!include_unusable)
	  ctx->items[0].skipfnc=skip_unusable;
      }
    else
      {
	/* build the search context */
	for(n=0, r=namelist; r; r = r->next )
	  n++;

	ctx = xmalloc_clear (sizeof *ctx + (n-1)*sizeof ctx->items );
	ctx->nitems = n;

	for(n=0, r=namelist; r; r = r->next, n++ )
	  {
	    classify_user_id (r->d, &ctx->items[n]);
        
	    if (ctx->items[n].exact)
	      ctx->exact = 1;
	    if (!ctx->items[n].mode)
	      {
		xfree (ctx);
		return G10ERR_INV_USER_ID;
	      }
	    if(!include_unusable
	       && ctx->items[n].mode!=KEYDB_SEARCH_MODE_SHORT_KID
	       && ctx->items[n].mode!=KEYDB_SEARCH_MODE_LONG_KID
	       && ctx->items[n].mode!=KEYDB_SEARCH_MODE_FPR16
	       && ctx->items[n].mode!=KEYDB_SEARCH_MODE_FPR20
	       && ctx->items[n].mode!=KEYDB_SEARCH_MODE_FPR)
	      ctx->items[n].skipfnc=skip_unusable;
	  }
      }

    ctx->kr_handle = keydb_new (secmode);
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
            pk_from_block ( ctx, pk, *ret_kb );
        }
    }

    release_kbnode ( help_kb );

    if (retctx) /* caller wants the context */
	*retctx = ctx;
    else {
        if (ret_kdbhd) {
            *ret_kdbhd = ctx->kr_handle;
            ctx->kr_handle = NULL;
        }
        get_pubkey_end (ctx);
    }

    return rc;
}



/* Find a public key from NAME and return the keyblock or the key.  If
   ret_kdb is not NULL, the KEYDB handle used to locate this keyblock
   is returned and the caller is responsible for closing it.  If a key
   was not found and NAME is a valid RFC822 mailbox and PKA retrieval
   has been enabled, we try to import the pkea via the PKA
   mechanism. */
int
get_pubkey_byname (PKT_public_key *pk,
		   const char *name, KBNODE *ret_keyblock,
                   KEYDB_HANDLE *ret_kdbhd, int include_unusable )
{
  int rc;
  STRLIST namelist = NULL;

  add_to_strlist( &namelist, name );

  rc = key_byname( NULL, namelist, pk, NULL, 0,
                   include_unusable, ret_keyblock, ret_kdbhd);

  /* If the requested name resembles a valid mailbox and automatic
     retrieval has been enabled, we try to import the key. */

  if (rc == G10ERR_NO_PUBKEY && is_valid_mailbox(name))
    {
      struct akl *akl;

      for(akl=opt.auto_key_locate;akl;akl=akl->next)
	{
	  unsigned char *fpr=NULL;
	  size_t fpr_len;

	  switch(akl->type)
	    {
	    case AKL_CERT:
	      glo_ctrl.in_auto_key_retrieve++;
	      rc=keyserver_import_cert(name,&fpr,&fpr_len);
	      glo_ctrl.in_auto_key_retrieve--;

	      if(rc==0)
		log_info(_("automatically retrieved `%s' via %s\n"),
			 name,"DNS CERT");
	      break;

	    case AKL_PKA:
	      glo_ctrl.in_auto_key_retrieve++;
	      rc=keyserver_import_pka(name,&fpr,&fpr_len);
	      glo_ctrl.in_auto_key_retrieve--;

	      if(rc==0)
		log_info(_("automatically retrieved `%s' via %s\n"),
			 name,"PKA");
	      break;

	    case AKL_LDAP:
	      glo_ctrl.in_auto_key_retrieve++;
	      rc=keyserver_import_ldap(name,&fpr,&fpr_len);
	      glo_ctrl.in_auto_key_retrieve--;

	      if(rc==0)
		log_info(_("automatically retrieved `%s' via %s\n"),
			 name,"LDAP");
	      break;

	    case AKL_KEYSERVER:
	      /* Strictly speaking, we don't need to only use a valid
		 mailbox for the getname search, but it helps cut down
		 on the problem of searching for something like "john"
		 and getting a whole lot of keys back. */
	      if(opt.keyserver)
		{
		  glo_ctrl.in_auto_key_retrieve++;
		  rc=keyserver_import_name(name,&fpr,&fpr_len,opt.keyserver);
		  glo_ctrl.in_auto_key_retrieve--;

		  if(rc==0)
		    log_info(_("automatically retrieved `%s' via %s\n"),
			     name,opt.keyserver->uri);
		}
	      break;

	    case AKL_SPEC:
	      {
		struct keyserver_spec *keyserver;

		keyserver=keyserver_match(akl->spec);
		glo_ctrl.in_auto_key_retrieve++;
		rc=keyserver_import_name(name,&fpr,&fpr_len,keyserver);
		glo_ctrl.in_auto_key_retrieve--;

		if(rc==0)
		  log_info(_("automatically retrieved `%s' via %s\n"),
			   name,akl->spec->uri);
	      }
	      break;
	    }

	  /* Use the fingerprint of the key that we actually fetched.
	     This helps prevent problems where the key that we fetched
	     doesn't have the same name that we used to fetch it.  In
	     the case of CERT and PKA, this is an actual security
	     requirement as the URL might point to a key put in by an
	     attacker.  By forcing the use of the fingerprint, we
	     won't use the attacker's key here. */
	  if(rc==0 && fpr)
	    {
	      int i;
	      char fpr_string[MAX_FINGERPRINT_LEN*2+1];

	      assert(fpr_len<=MAX_FINGERPRINT_LEN);

	      free_strlist(namelist);
	      namelist=NULL;

	      for(i=0;i<fpr_len;i++)
		sprintf(fpr_string+2*i,"%02X",fpr[i]);

	      if(opt.verbose)
		log_info("auto-key-locate found fingerprint %s\n",fpr_string);

	      add_to_strlist( &namelist, fpr_string );

	      xfree(fpr);
	    }

	  rc = key_byname( NULL, namelist, pk, NULL, 0,
			   include_unusable, ret_keyblock, ret_kdbhd);
	  if(rc!=G10ERR_NO_PUBKEY)
	    break;
	}
    }

  free_strlist( namelist );
  return rc;
}

int
get_pubkey_bynames( GETKEY_CTX *retctx, PKT_public_key *pk,
		    STRLIST names, KBNODE *ret_keyblock )
{
    return key_byname( retctx, names, pk, NULL, 0, 1, ret_keyblock, NULL);
}

int
get_pubkey_next( GETKEY_CTX ctx, PKT_public_key *pk, KBNODE *ret_keyblock )
{
    int rc;

    rc = lookup( ctx, ret_keyblock, 0 );
    if ( !rc && pk && ret_keyblock )
        pk_from_block ( ctx, pk, *ret_keyblock );
    
    return rc;
}

void
get_pubkey_end( GETKEY_CTX ctx )
{
    if( ctx ) {
        memset (&ctx->kbpos, 0, sizeof ctx->kbpos);
        keydb_release (ctx->kr_handle);
	if( !ctx->not_allocated )
	    xfree( ctx );
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
        ctx.kr_handle = keydb_new (0);
	ctx.nitems = 1;
	ctx.items[0].mode = fprint_len==16? KEYDB_SEARCH_MODE_FPR16
                                          : KEYDB_SEARCH_MODE_FPR20;
	memcpy( ctx.items[0].u.fpr, fprint, fprint_len );
	rc = lookup( &ctx, &kb, 0 );
        if (!rc && pk )
            pk_from_block ( &ctx, pk, kb );
        release_kbnode ( kb );
	get_pubkey_end( &ctx );
    }
    else
	rc = G10ERR_GENERAL; /* Oops */
    return rc;
}


/* Get a public key and store it into the allocated pk.  This function
   differs from get_pubkey_byfprint() in that it does not do a check
   of the key to avoid recursion.  It should be used only in very
   certain cases.  PK may be NULL to check just for the existance of
   the key. */
int
get_pubkey_byfprint_fast (PKT_public_key *pk,
                          const byte *fprint, size_t fprint_len)
{
  int rc = 0;
  KEYDB_HANDLE hd;
  KBNODE keyblock;
  byte fprbuf[MAX_FINGERPRINT_LEN];
  int i;
  
  for (i=0; i < MAX_FINGERPRINT_LEN && i < fprint_len; i++)
    fprbuf[i] = fprint[i];
  while (i < MAX_FINGERPRINT_LEN) 
    fprbuf[i++] = 0;

  hd = keydb_new (0);
  rc = keydb_search_fpr (hd, fprbuf);
  if (rc == -1)
    {
      keydb_release (hd);
      return G10ERR_NO_PUBKEY;
    }
  rc = keydb_get_keyblock (hd, &keyblock);
  keydb_release (hd);
  if (rc) 
    {
      log_error ("keydb_get_keyblock failed: %s\n", g10_errstr(rc));
      return G10ERR_NO_PUBKEY;
    }
  
  assert ( keyblock->pkt->pkttype == PKT_PUBLIC_KEY
           ||  keyblock->pkt->pkttype == PKT_PUBLIC_SUBKEY );
  if (pk)
    copy_public_key (pk, keyblock->pkt->pkt.public_key );
  release_kbnode (keyblock);

  /* Not caching key here since it won't have all of the fields
     properly set. */

  return 0;
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
        ctx.kr_handle = keydb_new (0);
	ctx.nitems = 1;
	ctx.items[0].mode = fprint_len==16? KEYDB_SEARCH_MODE_FPR16
                                          : KEYDB_SEARCH_MODE_FPR20;
	memcpy( ctx.items[0].u.fpr, fprint, fprint_len );
	rc = lookup( &ctx, ret_keyblock, 0 );
	get_pubkey_end( &ctx );
    }
    else
	rc = G10ERR_GENERAL; /* Oops */

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
  int rc,include_unusable=1;

  /* If we have no name, try to use the default secret key.  If we
     have no default, we'll use the first usable one. */

  if( !name && opt.def_secret_key && *opt.def_secret_key )
    add_to_strlist( &namelist, opt.def_secret_key );
  else if(name)
    add_to_strlist( &namelist, name );
  else
    include_unusable=0;

  rc = key_byname( retctx, namelist, NULL, sk, 1, include_unusable,
		   retblock, NULL );

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
    return key_byname( retctx, names, NULL, sk, 1, 1, ret_keyblock, NULL );
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


/****************
 * Search for a key with the given fingerprint.
 * FIXME:
 * We should replace this with the _byname function.  Thiscsan be done
 * by creating a userID conforming to the unified fingerprint style. 
 */
int
get_seckey_byfprint( PKT_secret_key *sk,
                     const byte *fprint, size_t fprint_len)
{
    int rc;

    if( fprint_len == 20 || fprint_len == 16 ) {
	struct getkey_ctx_s ctx;
        KBNODE kb = NULL;

	memset( &ctx, 0, sizeof ctx );
        ctx.exact = 1 ;
	ctx.not_allocated = 1;
        ctx.kr_handle = keydb_new (1);
	ctx.nitems = 1;
	ctx.items[0].mode = fprint_len==16? KEYDB_SEARCH_MODE_FPR16
                                          : KEYDB_SEARCH_MODE_FPR20;
	memcpy( ctx.items[0].u.fpr, fprint, fprint_len );
	rc = lookup( &ctx, &kb, 1 );
        if (!rc && sk )
            sk_from_block ( &ctx, sk, kb );
        release_kbnode ( kb );
	get_seckey_end( &ctx );
    }
    else
	rc = G10ERR_GENERAL; /* Oops */
    return rc;
}


/* Search for a secret key with the given fingerprint and return the
   complete keyblock which may have more than only this key. */
int
get_seckeyblock_byfprint (KBNODE *ret_keyblock, const byte *fprint,
                          size_t fprint_len )
{
  int rc;
  struct getkey_ctx_s ctx;
  
  if (fprint_len != 20 && fprint_len == 16)
    return G10ERR_GENERAL; /* Oops */
    
  memset (&ctx, 0, sizeof ctx);
  ctx.not_allocated = 1;
  ctx.kr_handle = keydb_new (1);
  ctx.nitems = 1;
  ctx.items[0].mode = (fprint_len==16
                       ? KEYDB_SEARCH_MODE_FPR16
                       : KEYDB_SEARCH_MODE_FPR20);
  memcpy (ctx.items[0].u.fpr, fprint, fprint_len);
  rc = lookup (&ctx, ret_keyblock, 1);
  get_seckey_end (&ctx);
  
  return rc;
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

	    p = parse_sig_subpkt( sig->hashed, SIGSUBPKT_KEY_EXPIRE, NULL );
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

	if(pk && (pk->expiredate==0 ||
		  (pk->max_expiredate && pk->expiredate>pk->max_expiredate)))
	  pk->expiredate=pk->max_expiredate;

	if(sk && (sk->expiredate==0 ||
		  (sk->max_expiredate && sk->expiredate>sk->max_expiredate)))
	  sk->expiredate=sk->max_expiredate;
    }
}

static int
parse_key_usage(PKT_signature *sig)
{
  int key_usage=0;
  const byte *p;
  size_t n;
  byte flags;

  p=parse_sig_subpkt(sig->hashed,SIGSUBPKT_KEY_FLAGS,&n);
  if(p && n)
    {
      /* first octet of the keyflags */
      flags=*p;

      if(flags & 1)
	{
	  key_usage |= PUBKEY_USAGE_CERT;
	  flags&=~1;
	}

      if(flags & 2)
	{
	  key_usage |= PUBKEY_USAGE_SIG;
	  flags&=~2;
	}

      /* We do not distinguish between encrypting communications and
	 encrypting storage. */
      if(flags & (0x04|0x08))
	{
	  key_usage |= PUBKEY_USAGE_ENC;
	  flags&=~(0x04|0x08);
	}

      if(flags & 0x20)
	{
	  key_usage |= PUBKEY_USAGE_AUTH;
	  flags&=~0x20;
	}

      if(flags)
	key_usage |= PUBKEY_USAGE_UNKNOWN;
    }

  /* We set PUBKEY_USAGE_UNKNOWN to indicate that this key has a
     capability that we do not handle.  This serves to distinguish
     between a zero key usage which we handle as the default
     capabilities for that algorithm, and a usage that we do not
     handle. */

  return key_usage;
}

/*
 * Apply information from SIGNODE (which is the valid self-signature
 * associated with that UID) to the UIDNODE:
 * - wether the UID has been revoked
 * - assumed creation date of the UID
 * - temporary store the keyflags here
 * - temporary store the key expiration time here
 * - mark whether the primary user ID flag hat been set.
 * - store the preferences
 */
static void
fixup_uidnode ( KBNODE uidnode, KBNODE signode, u32 keycreated )
{
    PKT_user_id   *uid = uidnode->pkt->pkt.user_id;
    PKT_signature *sig = signode->pkt->pkt.signature;
    const byte *p, *sym, *hash, *zip;
    size_t n, nsym, nhash, nzip;

    sig->flags.chosen_selfsig = 1; /* we chose this one */
    uid->created = 0; /* not created == invalid */
    if ( IS_UID_REV ( sig ) )
      {
        uid->is_revoked = 1;
        return; /* has been revoked */
      }
    else
      uid->is_revoked=0;

    uid->expiredate = sig->expiredate;

    if(sig->flags.expired)
      {
	uid->is_expired = 1;
	return; /* has expired */
      }
    else
      uid->is_expired=0;

    uid->created = sig->timestamp; /* this one is okay */
    uid->selfsigversion = sig->version;
    /* If we got this far, it's not expired :) */
    uid->is_expired = 0;

    /* store the key flags in the helper variable for later processing */
    uid->help_key_usage=parse_key_usage(sig);

    /* ditto for the key expiration */
    p = parse_sig_subpkt (sig->hashed, SIGSUBPKT_KEY_EXPIRE, NULL);
    if( p && buffer_to_u32(p) )
      uid->help_key_expire = keycreated + buffer_to_u32(p);
    else
      uid->help_key_expire = 0;

    /* Set the primary user ID flag - we will later wipe out some
     * of them to only have one in our keyblock */
    uid->is_primary = 0;
    p = parse_sig_subpkt ( sig->hashed, SIGSUBPKT_PRIMARY_UID, NULL );
    if ( p && *p )
        uid->is_primary = 2;
    /* We could also query this from the unhashed area if it is not in
     * the hased area and then later try to decide which is the better
     * there should be no security problem with this.
     * For now we only look at the hashed one. 
     */

    /* Now build the preferences list.  These must come from the
       hashed section so nobody can modify the ciphers a key is
       willing to accept. */
    p = parse_sig_subpkt ( sig->hashed, SIGSUBPKT_PREF_SYM, &n );
    sym = p; nsym = p?n:0;
    p = parse_sig_subpkt ( sig->hashed, SIGSUBPKT_PREF_HASH, &n );
    hash = p; nhash = p?n:0;
    p = parse_sig_subpkt ( sig->hashed, SIGSUBPKT_PREF_COMPR, &n );
    zip = p; nzip = p?n:0;
    if (uid->prefs) 
        xfree (uid->prefs);
    n = nsym + nhash + nzip;
    if (!n)
        uid->prefs = NULL;
    else {
        uid->prefs = xmalloc (sizeof (*uid->prefs) * (n+1));
        n = 0;
        for (; nsym; nsym--, n++) {
            uid->prefs[n].type = PREFTYPE_SYM;
            uid->prefs[n].value = *sym++;
        }
        for (; nhash; nhash--, n++) {
            uid->prefs[n].type = PREFTYPE_HASH;
            uid->prefs[n].value = *hash++;
        }
        for (; nzip; nzip--, n++) {
            uid->prefs[n].type = PREFTYPE_ZIP;
            uid->prefs[n].value = *zip++;
        }
        uid->prefs[n].type = PREFTYPE_NONE; /* end of list marker */
        uid->prefs[n].value = 0;
    }

    /* see whether we have the MDC feature */
    uid->flags.mdc = 0;
    p = parse_sig_subpkt (sig->hashed, SIGSUBPKT_FEATURES, &n);
    if (p && n && (p[0] & 0x01))
        uid->flags.mdc = 1;

    /* and the keyserver modify flag */
    uid->flags.ks_modify = 1;
    p = parse_sig_subpkt (sig->hashed, SIGSUBPKT_KS_FLAGS, &n);
    if (p && n && (p[0] & 0x80))
        uid->flags.ks_modify = 0;
}

static void
sig_to_revoke_info(PKT_signature *sig,struct revoke_info *rinfo)
{
  rinfo->date = sig->timestamp;
  rinfo->algo = sig->pubkey_algo;
  rinfo->keyid[0] = sig->keyid[0];
  rinfo->keyid[1] = sig->keyid[1];
}

static void
merge_selfsigs_main(KBNODE keyblock, int *r_revoked, struct revoke_info *rinfo)
{
    PKT_public_key *pk = NULL;
    KBNODE k;
    u32 kid[2];
    u32 sigdate, uiddate, uiddate2;
    KBNODE signode, uidnode, uidnode2;
    u32 curtime = make_timestamp ();
    unsigned int key_usage = 0;
    u32 keytimestamp = 0;
    u32 key_expire = 0;
    int key_expire_seen = 0;
    byte sigversion = 0;

    *r_revoked = 0;
    memset(rinfo,0,sizeof(*rinfo));

    if ( keyblock->pkt->pkttype != PKT_PUBLIC_KEY )
        BUG ();
    pk = keyblock->pkt->pkt.public_key;
    keytimestamp = pk->timestamp;

    keyid_from_pk( pk, kid );
    pk->main_keyid[0] = kid[0];
    pk->main_keyid[1] = kid[1];

    if ( pk->version < 4 ) {
        /* before v4 the key packet itself contains the expiration
         * date and there was no way to change it, so we start with
         * the one from the key packet */
        key_expire = pk->max_expiredate;
        key_expire_seen = 1;
    }

    /* first pass: find the latest direct key self-signature.
     * We assume that the newest one overrides all others
     */

    /* In case this key was already merged */
    xfree(pk->revkey);
    pk->revkey=NULL;
    pk->numrevkeys=0;

    signode = NULL;
    sigdate = 0; /* helper to find the latest signature */
    for(k=keyblock; k && k->pkt->pkttype != PKT_USER_ID; k = k->next ) {
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
		    sig_to_revoke_info(sig,rinfo);
                }
                else if ( IS_KEY_SIG (sig) ) {
		  /* Add any revocation keys onto the pk.  This is
		     particularly interesting since we normally only
		     get data from the most recent 1F signature, but
		     you need multiple 1F sigs to properly handle
		     revocation keys (PGP does it this way, and a
		     revocation key could be sensitive and hence in a
		     different signature). */
		  if(sig->revkey) {
		    int i;

		    pk->revkey=
		      xrealloc(pk->revkey,sizeof(struct revocation_key)*
				(pk->numrevkeys+sig->numrevkeys));

		    for(i=0;i<sig->numrevkeys;i++)
		      memcpy(&pk->revkey[pk->numrevkeys++],
			     sig->revkey[i],
			     sizeof(struct revocation_key));
		  }

		  if( sig->timestamp >= sigdate ) {
		    if(sig->flags.expired)
                        ; /* signature has expired - ignore it */
                    else {
                        sigdate = sig->timestamp;
                        signode = k;
			if( sig->version > sigversion )
			  sigversion = sig->version;

		    }
		  }
                }
            }
        }
    }

    /* Remove dupes from the revocation keys */

    if(pk->revkey)
      {
	int i,j,x,changed=0;

	for(i=0;i<pk->numrevkeys;i++)
	  {
	    for(j=i+1;j<pk->numrevkeys;j++)
	      {
		if(memcmp(&pk->revkey[i],&pk->revkey[j],
			  sizeof(struct revocation_key))==0)
		  {
		    /* remove j */

		    for(x=j;x<pk->numrevkeys-1;x++)
		      pk->revkey[x]=pk->revkey[x+1];

		    pk->numrevkeys--;
		    j--;
		    changed=1;
		  }
	      }
	  }

	if(changed)
	  pk->revkey=xrealloc(pk->revkey,
			       pk->numrevkeys*sizeof(struct revocation_key));
      }

    if ( signode )
      {
        /* some information from a direct key signature take precedence
         * over the same information given in UID sigs.
         */
        PKT_signature *sig = signode->pkt->pkt.signature;
        const byte *p;

	key_usage=parse_key_usage(sig);

	p = parse_sig_subpkt (sig->hashed, SIGSUBPKT_KEY_EXPIRE, NULL);
	if( p && buffer_to_u32(p) )
	  {
	    key_expire = keytimestamp + buffer_to_u32(p);
	    key_expire_seen = 1;
	  }

        /* mark that key as valid: one direct key signature should 
         * render a key as valid */
        pk->is_valid = 1;
      }

    /* pass 1.5: look for key revocation signatures that were not made
       by the key (i.e. did a revocation key issue a revocation for
       us?).  Only bother to do this if there is a revocation key in
       the first place and we're not revoked already. */

    if(!*r_revoked && pk->revkey)
      for(k=keyblock; k && k->pkt->pkttype != PKT_USER_ID; k = k->next )
	{
	  if ( k->pkt->pkttype == PKT_SIGNATURE )
	    {
	      PKT_signature *sig = k->pkt->pkt.signature;

	      if(IS_KEY_REV(sig) &&
		 (sig->keyid[0]!=kid[0] || sig->keyid[1]!=kid[1]))
		{ 
		  int rc=check_revocation_keys(pk,sig);
		  if(rc==0)
		    {
		      *r_revoked=2;
		      sig_to_revoke_info(sig,rinfo);
		      /* don't continue checking since we can't be any
			 more revoked than this */
		      break;
		    }
		  else if(rc==G10ERR_NO_PUBKEY)
		    pk->maybe_revoked=1;

		  /* A failure here means the sig did not verify, was
		     not issued by a revocation key, or a revocation
		     key loop was broken.  If a revocation key isn't
		     findable, however, the key might be revoked and
		     we don't know it. */

		  /* TODO: In the future handle subkey and cert
                     revocations?  PGP doesn't, but it's in 2440. */
		}
	    }
	}

    /* second pass: look at the self-signature of all user IDs */
    signode = uidnode = NULL;
    sigdate = 0; /* helper to find the latest signature in one user ID */
    for(k=keyblock; k && k->pkt->pkttype != PKT_PUBLIC_SUBKEY; k = k->next ) {
	if ( k->pkt->pkttype == PKT_USER_ID ) {
            if ( uidnode && signode ) 
	      {
                fixup_uidnode ( uidnode, signode, keytimestamp );
		pk->is_valid=1;
	      }
            uidnode = k;
            signode = NULL;
            sigdate = 0;
      	}
        else if ( k->pkt->pkttype == PKT_SIGNATURE && uidnode ) {
            PKT_signature *sig = k->pkt->pkt.signature;
            if ( sig->keyid[0] == kid[0] && sig->keyid[1]==kid[1] ) { 
                if ( check_key_signature( keyblock, k, NULL ) )
                    ; /* signature did not verify */
                else if ( (IS_UID_SIG (sig) || IS_UID_REV (sig))
                          && sig->timestamp >= sigdate )
		  {
                    /* Note: we allow to invalidate cert revocations
                     * by a newer signature.  An attacker can't use this
                     * because a key should be revoced with a key revocation.
                     * The reason why we have to allow for that is that at
                     * one time an email address may become invalid but later
                     * the same email address may become valid again (hired,
                     * fired, hired again).
                     */

		    sigdate = sig->timestamp;
		    signode = k;
		    signode->pkt->pkt.signature->flags.chosen_selfsig=0;
		    if( sig->version > sigversion )
		      sigversion = sig->version;
		  }
            }
        }
    }
    if ( uidnode && signode ) {
        fixup_uidnode ( uidnode, signode, keytimestamp );
        pk->is_valid = 1;
    }

    /* If the key isn't valid yet, and we have
       --allow-non-selfsigned-uid set, then force it valid. */
    if(!pk->is_valid && opt.allow_non_selfsigned_uid)
      {
	if(opt.verbose)
	  log_info(_("Invalid key %s made valid by"
		     " --allow-non-selfsigned-uid\n"),keystr_from_pk(pk));
	pk->is_valid = 1;
      }

    /* The key STILL isn't valid, so try and find an ultimately
       trusted signature. */
    if(!pk->is_valid)
      {
	uidnode=NULL;

	for(k=keyblock; k && k->pkt->pkttype != PKT_PUBLIC_SUBKEY; k=k->next)
	  {
	    if ( k->pkt->pkttype == PKT_USER_ID )
	      uidnode = k;
	    else if ( k->pkt->pkttype == PKT_SIGNATURE && uidnode )
	      {
		PKT_signature *sig = k->pkt->pkt.signature;

		if(sig->keyid[0] != kid[0] || sig->keyid[1]!=kid[1])
		  {
		    PKT_public_key *ultimate_pk;

		    ultimate_pk=xmalloc_clear(sizeof(*ultimate_pk));

                    /* We don't want to use the full get_pubkey to
                       avoid infinite recursion in certain cases.
                       There is no reason to check that an ultimately
                       trusted key is still valid - if it has been
                       revoked or the user should also renmove the
                       ultimate trust flag.  */
		    if(get_pubkey_fast(ultimate_pk,sig->keyid)==0
		       && check_key_signature2(keyblock,k,ultimate_pk,
					       NULL,NULL,NULL,NULL)==0
		       && get_ownertrust(ultimate_pk)==TRUST_ULTIMATE)
		      {
			free_public_key(ultimate_pk);
			pk->is_valid=1;
			break;
		      }

		    free_public_key(ultimate_pk);
		  }
	      }
	  }
      }

    /* Record the highest selfsig version so we know if this is a v3
       key through and through, or a v3 key with a v4 selfsig
       somewhere.  This is useful in a few places to know if the key
       must be treated as PGP2-style or OpenPGP-style.  Note that a
       selfsig revocation with a higher version number will also raise
       this value.  This is okay since such a revocation must be
       issued by the user (i.e. it cannot be issued by someone else to
       modify the key behavior.) */

    pk->selfsigversion=sigversion;

    /* Now that we had a look at all user IDs we can now get some information
     * from those user IDs.
     */
    
    if ( !key_usage ) {
        /* find the latest user ID with key flags set */
        uiddate = 0; /* helper to find the latest user ID */
        for(k=keyblock; k && k->pkt->pkttype != PKT_PUBLIC_SUBKEY;
            k = k->next ) {
            if ( k->pkt->pkttype == PKT_USER_ID ) {
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

    /* Whatever happens, it's a primary key, so it can certify. */
    pk->pubkey_usage = key_usage|PUBKEY_USAGE_CERT;

    if ( !key_expire_seen ) {
        /* find the latest valid user ID with a key expiration set 
         * Note, that this may be a different one from the above because
         * some user IDs may have no expiration date set */
        uiddate = 0; 
        for(k=keyblock; k && k->pkt->pkttype != PKT_PUBLIC_SUBKEY;
            k = k->next ) {
            if ( k->pkt->pkttype == PKT_USER_ID ) {
                PKT_user_id *uid = k->pkt->pkt.user_id;
                if ( uid->help_key_expire && uid->created > uiddate ) {
                    key_expire = uid->help_key_expire;
                    uiddate = uid->created;
                }
            }
      	}
    }

    /* Currently only v3 keys have a maximum expiration date, but I'll
       bet v5 keys get this feature again. */
    if(key_expire==0 || (pk->max_expiredate && key_expire>pk->max_expiredate))
      key_expire=pk->max_expiredate;

    pk->has_expired = key_expire >= curtime? 0 : key_expire;
    pk->expiredate = key_expire;

    /* Fixme: we should see how to get rid of the expiretime fields  but
     * this needs changes at other places too. */

    /* and now find the real primary user ID and delete all others */
    uiddate = uiddate2 = 0;
    uidnode = uidnode2 = NULL;
    for(k=keyblock; k && k->pkt->pkttype != PKT_PUBLIC_SUBKEY; k = k->next ) {
        if ( k->pkt->pkttype == PKT_USER_ID &&
	     !k->pkt->pkt.user_id->attrib_data) {
            PKT_user_id *uid = k->pkt->pkt.user_id;
            if (uid->is_primary)
	      {
		if(uid->created > uiddate)
		  {
		    uiddate = uid->created;
		    uidnode = k;
		  }
		else if(uid->created==uiddate && uidnode)
		  {
		    /* The dates are equal, so we need to do a
		       different (and arbitrary) comparison.  This
		       should rarely, if ever, happen.  It's good to
		       try and guarantee that two different GnuPG
		       users with two different keyrings at least pick
		       the same primary. */
		    if(cmp_user_ids(uid,uidnode->pkt->pkt.user_id)>0)
		      uidnode=k;
		  }
	      }
	    else
	      {
		if(uid->created > uiddate2)
		  {
		    uiddate2 = uid->created;
		    uidnode2 = k;
		  }
		else if(uid->created==uiddate2 && uidnode2)
		  {
		    if(cmp_user_ids(uid,uidnode2->pkt->pkt.user_id)>0)
		      uidnode2=k;
		  }
	      }
        }
    }
    if ( uidnode ) {
        for(k=keyblock; k && k->pkt->pkttype != PKT_PUBLIC_SUBKEY;
            k = k->next ) {
            if ( k->pkt->pkttype == PKT_USER_ID &&
		 !k->pkt->pkt.user_id->attrib_data) {
                PKT_user_id *uid = k->pkt->pkt.user_id;
                if ( k != uidnode ) 
                    uid->is_primary = 0;
            }
        }
    }
    else if( uidnode2 ) {
        /* none is flagged primary - use the latest user ID we have,
	   and disambiguate with the arbitrary packet comparison. */
        uidnode2->pkt->pkt.user_id->is_primary = 1;
    }
    else
      {
	/* None of our uids were self-signed, so pick the one that
	   sorts first to be the primary.  This is the best we can do
	   here since there are no self sigs to date the uids. */

	uidnode = NULL;

	for(k=keyblock; k && k->pkt->pkttype != PKT_PUBLIC_SUBKEY;
	    k = k->next )
	  {
	    if(k->pkt->pkttype==PKT_USER_ID
	       && !k->pkt->pkt.user_id->attrib_data)
	      {
		if(!uidnode)
		  {
		    uidnode=k;
		    uidnode->pkt->pkt.user_id->is_primary=1;
		    continue;
		  }
		else
		  {
		    if(cmp_user_ids(k->pkt->pkt.user_id,
				    uidnode->pkt->pkt.user_id)>0)
		      {
			uidnode->pkt->pkt.user_id->is_primary=0;
			uidnode=k;
			uidnode->pkt->pkt.user_id->is_primary=1;
		      }
		    else
		      k->pkt->pkt.user_id->is_primary=0; /* just to be
							    safe */
		  }
	      }
	  }
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
		  /* Note that this means that the date on a
                     revocation sig does not matter - even if the
                     binding sig is dated after the revocation sig,
                     the subkey is still marked as revoked.  This
                     seems ok, as it is just as easy to make new
                     subkeys rather than re-sign old ones as the
                     problem is in the distribution.  Plus, PGP (7)
                     does this the same way.  */
                    subpk->is_revoked = 1;
		    sig_to_revoke_info(sig,&subpk->revoked);
                    /* although we could stop now, we continue to 
                     * figure out other information like the old expiration
                     * time */
                }
                else if ( IS_SUBKEY_SIG (sig) && sig->timestamp >= sigdate )
		  {
		    if(sig->flags.expired)
		      ; /* signature has expired - ignore it */
                    else
		      {
                        sigdate = sig->timestamp;
                        signode = k;
			signode->pkt->pkt.signature->flags.chosen_selfsig=0;
		      }
		  }
            }
        }
    }

    /* no valid key binding */
    if ( !signode )
      return;

    sig = signode->pkt->pkt.signature;
    sig->flags.chosen_selfsig=1; /* so we know which selfsig we chose later */

    key_usage=parse_key_usage(sig);
    if ( !key_usage )
      {
	/* no key flags at all: get it from the algo */
        key_usage = openpgp_pk_algo_usage ( subpk->pubkey_algo );
      }
    else
      {
	/* check that the usage matches the usage as given by the algo */
        int x = openpgp_pk_algo_usage ( subpk->pubkey_algo );
        if ( x ) /* mask it down to the actual allowed usage */
	  key_usage &= x; 
      }

    subpk->pubkey_usage = key_usage;
    
    p = parse_sig_subpkt (sig->hashed, SIGSUBPKT_KEY_EXPIRE, NULL);
    if ( p && buffer_to_u32(p) )
        key_expire = keytimestamp + buffer_to_u32(p);
    else
        key_expire = 0;
    subpk->has_expired = key_expire >= curtime? 0 : key_expire;
    subpk->expiredate = key_expire;

    /* Check that algo exists.  Elgamal sign+encrypt are only allowed
       with option --rfc2440. */
    if (RFC2440 && subpk->pubkey_algo == PUBKEY_ALGO_ELGAMAL)
      ;
    else if(check_pubkey_algo(subpk->pubkey_algo))
      return;

    subpk->is_valid = 1;

    /* Find the first 0x19 embedded signature on our self-sig. */
    if(subpk->backsig==0)
      {
	int seq=0;
	size_t n;

	/* We do this while() since there may be other embedded
	   signatures in the future.  We only want 0x19 here. */
	while((p=enum_sig_subpkt(sig->hashed,
				 SIGSUBPKT_SIGNATURE,&n,&seq,NULL)))
	  if(n>3 && ((p[0]==3 && p[2]==0x19) || (p[0]==4 && p[1]==0x19)))
	    break;

	if(p==NULL)
	  {
	    seq=0;
	    /* It is safe to have this in the unhashed area since the
	       0x19 is located on the selfsig for convenience, not
	       security. */
	    while((p=enum_sig_subpkt(sig->unhashed,SIGSUBPKT_SIGNATURE,
				     &n,&seq,NULL)))
	      if(n>3 && ((p[0]==3 && p[2]==0x19) || (p[0]==4 && p[1]==0x19)))
		break;
	  }

	if(p)
	  {
	    PKT_signature *backsig=xmalloc_clear(sizeof(PKT_signature));
	    IOBUF backsig_buf=iobuf_temp_with_content(p,n);
	    int save_mode=set_packet_list_mode(0);

	    if(parse_signature(backsig_buf,PKT_SIGNATURE,n,backsig)==0)
	      {
		if(check_backsig(mainpk,subpk,backsig)==0)
		  subpk->backsig=2;
		else
		  subpk->backsig=1;
	      }

	    set_packet_list_mode(save_mode);

	    iobuf_close(backsig_buf);
	    free_seckey_enc(backsig);
	  }
      }
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
    struct revoke_info rinfo;
    PKT_public_key *main_pk;
    prefitem_t *prefs;
    int mdc_feature;

    if ( keyblock->pkt->pkttype != PKT_PUBLIC_KEY ) {
        if (keyblock->pkt->pkttype == PKT_SECRET_KEY ) {
            log_error ("expected public key but found secret key "
                       "- must stop\n");
            /* we better exit here becuase a public key is expected at
               other places too.  FIXME: Figure this out earlier and
               don't get to here at all */
            g10_exit (1);
        }
        BUG ();
    }

    merge_selfsigs_main ( keyblock, &revoked, &rinfo );

    /* now merge in the data from each of the subkeys */
    for(k=keyblock; k; k = k->next ) {
	if (  k->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
            merge_selfsigs_subkey ( keyblock, k );
        }
    }

    main_pk = keyblock->pkt->pkt.public_key;
    if ( revoked || main_pk->has_expired || !main_pk->is_valid ) {
        /* if the primary key is revoked, expired, or invalid we
         * better set the appropriate flags on that key and all
         * subkeys */
        for(k=keyblock; k; k = k->next ) {
            if ( k->pkt->pkttype == PKT_PUBLIC_KEY
                || k->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
                PKT_public_key *pk = k->pkt->pkt.public_key;
		if(!main_pk->is_valid)
		  pk->is_valid = 0;
		if(revoked && !pk->is_revoked)
		  {
		    pk->is_revoked = revoked;
		    memcpy(&pk->revoked,&rinfo,sizeof(rinfo));
		  }
                if(main_pk->has_expired)
		  pk->has_expired = main_pk->has_expired;
            }
	}
	return;
    }

    /* set the preference list of all keys to those of the primary real
     * user ID.  Note: we use these preferences when we don't know by
     * which user ID the key has been selected.
     * fixme: we should keep atoms of commonly used preferences or
     * use reference counting to optimize the preference lists storage.
     * FIXME: it might be better to use the intersection of 
     * all preferences.
     * Do a similar thing for the MDC feature flag.
     */
    prefs = NULL;
    mdc_feature = 0;
    for (k=keyblock; k && k->pkt->pkttype != PKT_PUBLIC_SUBKEY; k = k->next) {
        if (k->pkt->pkttype == PKT_USER_ID
	    && !k->pkt->pkt.user_id->attrib_data
            && k->pkt->pkt.user_id->is_primary) {
            prefs = k->pkt->pkt.user_id->prefs;
            mdc_feature = k->pkt->pkt.user_id->flags.mdc;
            break;
        }
    }    
    for(k=keyblock; k; k = k->next ) {
        if ( k->pkt->pkttype == PKT_PUBLIC_KEY
             || k->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
            PKT_public_key *pk = k->pkt->pkt.public_key;
            if (pk->prefs)
                xfree (pk->prefs);
            pk->prefs = copy_prefs (prefs);
            pk->mdc_feature = mdc_feature;
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
 * secret subkey is available and deletes the public subkey otherwise.
 * We need this function because we can't delete it later when we
 * actually merge the secret parts into the pubring.
 * The function also plays some games with the node flags.
 */
static void
premerge_public_with_secret ( KBNODE pubblock, KBNODE secblock )
{
    KBNODE last, pub;

    assert ( pubblock->pkt->pkttype == PKT_PUBLIC_KEY );
    assert ( secblock->pkt->pkttype == PKT_SECRET_KEY );
    
    for (pub=pubblock,last=NULL; pub; last = pub, pub = pub->next ) {
        pub->flag &= ~3; /* reset bits 0 and 1 */
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
                            pk->pubkey_usage &= ~(PUBKEY_USAGE_SIG
                                                  |PUBKEY_USAGE_AUTH);
                        }
                        /* transfer flag bits 0 and 1 to the pubblock */
                        pub->flag |= (sec->flag &3);
                        break;
                    }
                }
            }
            if ( !sec ) {
                KBNODE next, ll;

                if (opt.verbose)
                  log_info (_("no secret subkey"
			      " for public subkey %s - ignoring\n"),  
			    keystr_from_pk (pk));
                /* we have to remove the subkey in this case */
                assert ( last );
                /* find the next subkey */
                for (next=pub->next,ll=pub;
                     next && next->pkt->pkttype != PKT_PUBLIC_SUBKEY;
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
    /* We need to copy the found bits (0 and 1) from the secret key to
       the public key.  This has already been done for the subkeys but
       got lost on the primary key - fix it here *. */
    pubblock->flag |= (secblock->flag & 3);
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
finish_lookup (GETKEY_CTX ctx)
{
    KBNODE keyblock = ctx->keyblock;
    KBNODE k;
    KBNODE foundk = NULL;
    PKT_user_id *foundu = NULL;
#define USAGE_MASK  (PUBKEY_USAGE_SIG|PUBKEY_USAGE_ENC|PUBKEY_USAGE_CERT)
    unsigned int req_usage = ( ctx->req_usage & USAGE_MASK );
    /* Request the primary if we're certifying another key, and also
       if signing data while --pgp6 or --pgp7 is on since pgp 6 and 7
       do not understand signatures made by a signing subkey.  PGP 8
       does. */
    int req_prim = (ctx->req_usage & PUBKEY_USAGE_CERT) ||
      ((PGP6 || PGP7) && (ctx->req_usage & PUBKEY_USAGE_SIG));
    u32 latest_date;
    KBNODE latest_key;
    u32 curtime = make_timestamp ();

    assert( keyblock->pkt->pkttype == PKT_PUBLIC_KEY );
   
    ctx->found_key = NULL;

    if (ctx->exact) {
        for (k=keyblock; k; k = k->next) {
            if ( (k->flag & 1) ) {
                assert ( k->pkt->pkttype == PKT_PUBLIC_KEY
                         || k->pkt->pkttype == PKT_PUBLIC_SUBKEY );
                foundk = k;
                break;
            }
        }
    }

    for (k=keyblock; k; k = k->next) {
        if ( (k->flag & 2) ) {
            assert (k->pkt->pkttype == PKT_USER_ID);
            foundu = k->pkt->pkt.user_id;
            break;
        }
    }

    if ( DBG_CACHE )
        log_debug( "finish_lookup: checking key %08lX (%s)(req_usage=%x)\n",
                   (ulong)keyid_from_pk( keyblock->pkt->pkt.public_key, NULL),
                   foundk? "one":"all", req_usage);

    if (!req_usage) {
        latest_key = foundk? foundk:keyblock;
        goto found;
    }
    
    if (!req_usage) {
        PKT_public_key *pk = foundk->pkt->pkt.public_key;
        if (pk->user_id)
            free_user_id (pk->user_id);
        pk->user_id = scopy_user_id (foundu);
        ctx->found_key = foundk;
        cache_user_id( keyblock );
        return 1; /* found */
    }
    
    latest_date = 0;
    latest_key  = NULL;
    /* do not look at subkeys if a certification key is requested */
    if ((!foundk || foundk->pkt->pkttype == PKT_PUBLIC_SUBKEY) && !req_prim) {
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
            if ( pk->timestamp > curtime && !opt.ignore_valid_from ) {
                if (DBG_CACHE)
                    log_debug( "\tsubkey not yet valid\n");
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

    /* Okay now try the primary key unless we want an exact 
     * key ID match on a subkey */
    if ((!latest_key && !(ctx->exact && foundk != keyblock)) || req_prim) {
        PKT_public_key *pk;
        if (DBG_CACHE && !foundk && !req_prim )
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

    if (latest_key) {
        PKT_public_key *pk = latest_key->pkt->pkt.public_key;
        if (pk->user_id)
            free_user_id (pk->user_id);
        pk->user_id = scopy_user_id (foundu);
    }    
        
    ctx->found_key = latest_key;

    if (latest_key != keyblock && opt.verbose)
      {
	char *tempkeystr=
	  xstrdup(keystr_from_pk(latest_key->pkt->pkt.public_key));
        log_info(_("using subkey %s instead of primary key %s\n"),
                 tempkeystr, keystr_from_pk(keyblock->pkt->pkt.public_key));
	xfree(tempkeystr);
      }

    cache_user_id( keyblock );
    
    return 1; /* found */
}


static int
lookup( GETKEY_CTX ctx, KBNODE *ret_keyblock, int secmode )
{
    int rc;
    KBNODE secblock = NULL; /* helper */
    int no_suitable_key = 0;
    
    rc = 0;
    while (!(rc = keydb_search (ctx->kr_handle, ctx->items, ctx->nitems))) {
        /* If we are searching for the first key we have to make sure
           that the next interation does not no an implicit reset.
           This can be triggered by an empty key ring. */
        if (ctx->nitems && ctx->items->mode == KEYDB_SEARCH_MODE_FIRST)
            ctx->items->mode = KEYDB_SEARCH_MODE_NEXT;

        rc = keydb_get_keyblock (ctx->kr_handle, &ctx->keyblock);
        if (rc) {
            log_error ("keydb_get_keyblock failed: %s\n", g10_errstr(rc));
            rc = 0;
            goto skip;
        }
                       
        if ( secmode ) {
            /* find the correspondig public key and use this 
             * this one for the selection process */
            u32 aki[2];
            KBNODE k = ctx->keyblock;
            
            if (k->pkt->pkttype != PKT_SECRET_KEY)
                BUG();

            keyid_from_sk (k->pkt->pkt.secret_key, aki);
            k = get_pubkeyblock (aki);
            if( !k )
	      {
                if (!opt.quiet)
		  log_info(_("key %s: secret key without public key"
			     " - skipped\n"), keystr(aki));
                goto skip;
	      }
            secblock = ctx->keyblock;
            ctx->keyblock = k;

            premerge_public_with_secret ( ctx->keyblock, secblock );
        }

        /* warning: node flag bits 0 and 1 should be preserved by
         * merge_selfsigs.  For secret keys, premerge did tranfer the
         * keys to the keyblock */
        merge_selfsigs ( ctx->keyblock );
        if ( finish_lookup (ctx) ) {
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
        
      skip:
        /* release resources and continue search */
        if ( secmode ) {
            release_kbnode( secblock );
            secblock = NULL;
        }
        release_kbnode( ctx->keyblock );
        ctx->keyblock = NULL;
    }

  found:
    if( rc && rc != -1 )
	log_error("keydb_search failed: %s\n", g10_errstr(rc));

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

    ctx->last_rc = rc;
    return rc;
}




/****************
 * FIXME: Replace by the generic function 
 *        It does not work as it is right now - it is used at 
 *        2 places:  a) to get the key for an anonyous recipient
 *                   b) to get the ultimately trusted keys.
 *        The a) usage might have some problems.
 *
 * set with_subkeys true to include subkeys
 * set with_spm true to include secret-parts-missing keys
 *
 * Enumerate all primary secret keys.  Caller must use these procedure:
 *  1) create a void pointer and initialize it to NULL
 *  2) pass this void pointer by reference to this function
 *     and provide space for the secret key (pass a buffer for sk)
 *  3) call this function as long as it does not return -1
 *     to indicate EOF.
 *  4) Always call this function a last time with SK set to NULL,
 *     so that can free it's context.
 */
int
enum_secret_keys( void **context, PKT_secret_key *sk,
		  int with_subkeys, int with_spm )
{
    int rc=0;
    struct {
	int eof;
        int first;
	KEYDB_HANDLE hd;
        KBNODE keyblock;
        KBNODE node;
    } *c = *context;


    if( !c ) { /* make a new context */
	c = xmalloc_clear( sizeof *c );
	*context = c;
	c->hd = keydb_new (1);
        c->first = 1;
        c->keyblock = NULL;
        c->node = NULL;
    }

    if( !sk ) { /* free the context */
        keydb_release (c->hd);
        release_kbnode (c->keyblock);
	xfree( c );
	*context = NULL;
	return 0;
    }

    if( c->eof )
	return -1;

    do {
        /* get the next secret key from the current keyblock */
        for (; c->node; c->node = c->node->next) {
            if ((c->node->pkt->pkttype == PKT_SECRET_KEY
                || (with_subkeys
                    && c->node->pkt->pkttype == PKT_SECRET_SUBKEY) )
		&& !(c->node->pkt->pkt.secret_key->protect.s2k.mode==1001
		     && !with_spm)) {
                copy_secret_key (sk, c->node->pkt->pkt.secret_key );
                c->node = c->node->next;
                return 0; /* found */
            }
        }
        release_kbnode (c->keyblock);
        c->keyblock = c->node = NULL;
        
        rc = c->first? keydb_search_first (c->hd) : keydb_search_next (c->hd);
        c->first = 0;
        if (rc) {
            keydb_release (c->hd); c->hd = NULL;
            c->eof = 1;
            return -1; /* eof */
        }
        
        rc = keydb_get_keyblock (c->hd, &c->keyblock);
        c->node = c->keyblock;
    } while (!rc);

    return rc; /* error */
}



/*********************************************
 ***********  user ID printing helpers *******
 *********************************************/

/****************
 * Return a string with a printable representation of the user_id.
 * this string must be freed by xfree.
 */
char*
get_user_id_string( u32 *keyid )
{
  user_id_db_t r;
  char *p;
  int pass=0;
  /* try it two times; second pass reads from key resources */
  do
    {
      for(r=user_id_db; r; r = r->next )
	{
	  keyid_list_t a;
	  for (a=r->keyids; a; a= a->next )
	    {
	      if( a->keyid[0] == keyid[0] && a->keyid[1] == keyid[1] )
		{
		  p = xmalloc( keystrlen() + 1 + r->len + 1 );
		  sprintf(p, "%s %.*s", keystr(keyid), r->len, r->name );
		  return p;
		}
	    }
        }
    } while( ++pass < 2 && !get_pubkey( NULL, keyid ) );
  p = xmalloc( keystrlen() + 5 );
  sprintf(p, "%s [?]", keystr(keyid));
  return p;
}


char*
get_user_id_string_native ( u32 *keyid )
{
  char *p = get_user_id_string( keyid );
  char *p2 = utf8_to_native( p, strlen(p), 0 );
  xfree(p);
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
                    p = xmalloc( r->len + 20 );
                    sprintf(p, "%08lX%08lX %.*s",
                            (ulong)keyid[0], (ulong)keyid[1],
                            r->len, r->name );
                    return p;
                }
            }
        }
    } while( ++pass < 2 && !get_pubkey( NULL, keyid ) );
    p = xmalloc( 25 );
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
                    p = xmalloc( r->len );
                    memcpy(p, r->name, r->len );
                    *rn = r->len;
                    return p;
                }
            }
        }
    } while( ++pass < 2 && !get_pubkey( NULL, keyid ) );
    p = xstrdup( user_id_not_found_utf8 () );
    *rn = strlen(p);
    return p;
}

char*
get_user_id_native( u32 *keyid )
{
  size_t rn;
  char *p = get_user_id( keyid, &rn );
  char *p2 = utf8_to_native( p, rn, 0 );
  xfree(p);
  return p2;
}

KEYDB_HANDLE
get_ctx_handle(GETKEY_CTX ctx)
{
  return ctx->kr_handle;
}

static void
free_akl(struct akl *akl)
{
  if(akl->spec)
    free_keyserver_spec(akl->spec);

  xfree(akl);
}

void
release_akl(void)
{
  while(opt.auto_key_locate)
    {
      struct akl *akl2=opt.auto_key_locate;
      opt.auto_key_locate=opt.auto_key_locate->next;
      free_akl(akl2);
    }
}

int
parse_auto_key_locate(char *options)
{
  char *tok;

  while((tok=optsep(&options)))
    {
      struct akl *akl,*check,*last=NULL;
      int dupe=0;

      if(tok[0]=='\0')
	continue;

      akl=xmalloc_clear(sizeof(*akl));

      if(ascii_strcasecmp(tok,"ldap")==0)
	akl->type=AKL_LDAP;
      else if(ascii_strcasecmp(tok,"keyserver")==0)
	akl->type=AKL_KEYSERVER;
#ifdef USE_DNS_CERT
      else if(ascii_strcasecmp(tok,"cert")==0)
	akl->type=AKL_CERT;
#endif
#ifdef USE_DNS_PKA
      else if(ascii_strcasecmp(tok,"pka")==0)
	akl->type=AKL_PKA;
#endif
      else if((akl->spec=parse_keyserver_uri(tok,1,NULL,0)))
	akl->type=AKL_SPEC;
      else
	{
	  free_akl(akl);
	  return 0;
	}

      /* We must maintain the order the user gave us */
      for(check=opt.auto_key_locate;check;last=check,check=check->next)
	{
	  /* Check for duplicates */
	  if(check->type==akl->type
	     && (akl->type!=AKL_SPEC
		 || (akl->type==AKL_SPEC
		     && strcmp(check->spec->uri,akl->spec->uri)==0)))
	    {
	      dupe=1;
	      free_akl(akl);
	      break;
	    }
	}

      if(!dupe)
	{
	  if(last)
	    last->next=akl;
	  else
	    opt.auto_key_locate=akl;
	}
    }

  return 1;
}
