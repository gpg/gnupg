/* keyring.c - keyring file handling
 * Copyright (C) 2001 Free Software Foundation, Inc.
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
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "util.h"
#include "keyring.h"
#include "packet.h"
#include "keydb.h" 
#include "options.h"
#include "i18n.h"

typedef struct keyring_name *KR_NAME;
struct keyring_name {
    struct keyring_name *next;
    int secret;
    DOTLOCK lockhd;
    int is_locked;
    char fname[1];
};
typedef struct keyring_name const * CONST_KR_NAME;

static KR_NAME kr_names;
static int active_handles;

struct keyring_handle {
    int secret; /* this is for a secret keyring */
    struct {
        CONST_KR_NAME kr;
        IOBUF iobuf;
        int eof;
        int error;
    } current;
    struct {
        CONST_KR_NAME kr; 
        off_t offset;
        size_t pk_no;
        size_t uid_no;
        unsigned int n_packets; /*used for delete and update*/
    } found;
    struct {
        char *name;
        char *pattern;
    } word_match;
};

static int do_copy (int mode, const char *fname, KBNODE root, int secret,
                    off_t start_offset, unsigned int n_packets );



/* 
 * Register a filename for plain keyring files
 */
void
keyring_register_filename (const char *fname, int secret)
{
    KR_NAME kr;

    if (active_handles)
        BUG (); /* We don't allow that */

    for (kr=kr_names; kr; kr = kr->next) {
        if ( !compare_filenames (kr->fname, fname) )
            return; /* already registered */
    }

    kr = m_alloc (sizeof *kr + strlen (fname));
    strcpy (kr->fname, fname);
    kr->secret = !!secret;
    kr->lockhd = NULL;
    kr->is_locked = 0;
    kr->next = kr_names;
    kr_names = kr;
}





KEYRING_HANDLE
keyring_new (int secret)
{
    KEYRING_HANDLE hd;

    hd = m_alloc_clear (sizeof *hd);
    hd->secret = !!secret;
    active_handles++;
    return hd;
}

void 
keyring_release (KEYRING_HANDLE hd)
{
    if (!hd)
        return;
    assert (active_handles > 0);
    active_handles--;
    m_free (hd->word_match.name);
    m_free (hd->word_match.pattern);
    iobuf_close (hd->current.iobuf);
    m_free (hd);
}

static CONST_KR_NAME
next_kr (CONST_KR_NAME start, int secret)
{
    start = start? start->next : kr_names;
    while ( start && start->secret != secret )
        start = start->next;
    return start;
}

const char *
keyring_get_resource_name (KEYRING_HANDLE hd)
{
    const char *fname;

    if (!hd)
        fname = NULL;
    else if (hd->found.kr)
        fname = hd->found.kr->fname;
    else if (hd->current.kr)
        fname = hd->current.kr->fname;
    else {
        CONST_KR_NAME kr = next_kr (NULL, hd->secret);
        fname = kr? kr->fname:NULL;
    }

    return fname;
}


/*
 * Lock the keyring with the given handle, or unlok if yes is false.
 * We ignore the handle and lock all registered files.
 */
int 
keyring_lock (KEYRING_HANDLE hd, int yes)
{
    KR_NAME kr;
    int rc = 0;

    if (yes) {
        /* first make sure the lock handles are created */
        for (kr=kr_names; kr; kr = kr->next) {
            if (!kr->lockhd) {
                kr->lockhd = create_dotlock( kr->fname );
                if (!kr->lockhd) {
                    log_info ("can't allocate lock for `%s'\n", kr->fname );
                    rc = G10ERR_GENERAL;
                }
            }
        }
        if (rc)
            return rc;
        
        /* and now set the locks */
        for (kr=kr_names; kr; kr = kr->next) {
            if (kr->is_locked)
                ;
            else if (make_dotlock (kr->lockhd, -1) ) {
                log_info ("can't lock `%s'\n", kr->fname );
                rc = G10ERR_GENERAL;
            }
            else 
                kr->is_locked = 1;
        }
    }

    if (rc || !yes) {
        for (kr=kr_names; kr; kr = kr->next) {
            if (!kr->is_locked)
                ;
            else if (release_dotlock (kr->lockhd))
                log_info ("can't unlock `%s'\n", kr->fname );
            else 
                kr->is_locked = 0;
        }
    } 

    return rc;
}



/*
 * Return the last found keyring.  Caller must free it.
 * The returned keyblock has the kbode flag bit 0 set for the node with
 * the public key used to locate the keyblock or flag bit 1 set for 
 * the user ID node.
 */
int
keyring_get_keyblock (KEYRING_HANDLE hd, KBNODE *ret_kb)
{
    PACKET *pkt;
    int rc;
    KBNODE keyblock = NULL, node;
    IOBUF a;
    int in_cert = 0;
    int pk_no = 0;
    int uid_no = 0;

    if (ret_kb)
        *ret_kb = NULL;

    if (!hd->found.kr)
        return -1; /* no successful search */

    a = iobuf_open (hd->found.kr->fname);
    if (!a) {
	log_error ("can't open `%s'\n", hd->found.kr->fname);
	return G10ERR_KEYRING_OPEN;
    }

    if (iobuf_seek (a, hd->found.offset) ) {
        log_error ("can't seek `%s'\n", hd->found.kr->fname);
	iobuf_close(a);
	return G10ERR_KEYRING_OPEN;
    }

    pkt = m_alloc (sizeof *pkt);
    init_packet (pkt);
    hd->found.n_packets = 0;;
    while ((rc=parse_packet (a, pkt)) != -1) {
        hd->found.n_packets++;
        if (rc == G10ERR_UNKNOWN_PACKET) {
	    free_packet (pkt);
	    init_packet (pkt);
	    continue;
	}
	if (rc) {  
            log_error ("keyring_get_keyblock: read error: %s\n",
                       g10_errstr(rc) );
            rc = G10ERR_INV_KEYRING;
            break;
        }
	if (pkt->pkttype == PKT_COMPRESSED) {
	    log_error ("skipped compressed packet in keyring\n");
	    free_packet(pkt);
	    init_packet(pkt);
	    continue;
        }

        if (in_cert && (pkt->pkttype == PKT_PUBLIC_KEY
                        || pkt->pkttype == PKT_SECRET_KEY)) {
            hd->found.n_packets--; /* fix counter */
            break; /* ready */
        }

        in_cert = 1;
        node = new_kbnode (pkt);
        if (!keyblock)
            keyblock = node;
        else
            add_kbnode (keyblock, node);
        
        if ( pkt->pkttype == PKT_PUBLIC_KEY
             || pkt->pkttype == PKT_PUBLIC_SUBKEY
             || pkt->pkttype == PKT_SECRET_KEY
             || pkt->pkttype == PKT_SECRET_SUBKEY) {
            if (++pk_no == hd->found.pk_no)
                node->flag |= 1;
        }
        else if ( pkt->pkttype == PKT_USER_ID) {
            if (++uid_no == hd->found.uid_no)
                node->flag |= 2;
        }

        pkt = m_alloc (sizeof *pkt);
        init_packet(pkt);
    }

    if (rc == -1 && keyblock)
	rc = 0; /* got the entire keyblock */

    if (rc || !ret_kb)
	release_kbnode (keyblock);
    else
	*ret_kb = keyblock;

    free_packet (pkt);
    m_free (pkt);
    iobuf_close(a);

    /* Make sure that future search operations fail immediately when
     * we know that we are working on a invalid keyring 
     */
    if (rc == G10ERR_INV_KEYRING)
        hd->current.error = rc;

    return rc;
}

int
keyring_update_keyblock (KEYRING_HANDLE hd, KBNODE kb)
{
    int rc;

    if (!hd->found.kr)
        return -1; /* no successful prior search */

    if (!hd->found.n_packets) {
        /* need to know the number of packets - do a dummy get_keyblock*/
        rc = keyring_get_keyblock (hd, NULL);
        if (rc) {
            log_error ("re-reading keyblock failed: %s\n", g10_errstr (rc));
            return rc;
        }
        if (!hd->found.n_packets)
            BUG ();
    }

    /* do the update */
    rc = do_copy (3, hd->found.kr->fname, kb, hd->secret,
                  hd->found.offset, hd->found.n_packets );
    if (!rc) {
        /* better reset the found info */
        hd->found.kr = NULL;
        hd->found.offset = 0;
    }
    return rc;
}

int
keyring_insert_keyblock (KEYRING_HANDLE hd, KBNODE kb)
{
    int rc;
    const char *fname;

    if (!hd)
        fname = NULL;
    else if (hd->found.kr)
        fname = hd->found.kr->fname;
    else if (hd->current.kr)
        fname = hd->current.kr->fname;
    else {
        CONST_KR_NAME kr = next_kr (NULL, hd->secret);
        fname = kr? kr->fname:NULL;
    }

    if (!fname)
        return G10ERR_GENERAL; 

    /* close this one otherwise we will lose the position for
     * a next search.  Fixme: it would be better to adjust the position
     * after the write opertions.
     */
    iobuf_close (hd->current.iobuf);
    hd->current.iobuf = NULL;

    /* do the insert */
    rc = do_copy (1, fname, kb, hd->secret, 0, 0 );
    return rc;
}

int
keyring_delete_keyblock (KEYRING_HANDLE hd)
{
    int rc;

    if (!hd->found.kr)
        return -1; /* no successful prior search */

    if (!hd->found.n_packets) {
        /* need to know the number of packets - do a dummy get_keyblock*/
        rc = keyring_get_keyblock (hd, NULL);
        if (rc) {
            log_error ("re-reading keyblock failed: %s\n", g10_errstr (rc));
            return rc;
        }
        if (!hd->found.n_packets)
            BUG ();
    }

    /* close this one otherwise we will lose the position for
     * a next search.  Fixme: it would be better to adjust the position
     * after the write opertions.
     */
    iobuf_close (hd->current.iobuf);
    hd->current.iobuf = NULL;

    /* do the delete */
    rc = do_copy (2, hd->found.kr->fname, NULL, hd->secret,
                  hd->found.offset, hd->found.n_packets );
    if (!rc) {
        /* better reset the found info */
        hd->found.kr = NULL;
        hd->found.offset = 0;
    }
    return rc;
}



/* 
 * Start the next search on this handle right at the beginning
 */
int 
keyring_search_reset (KEYRING_HANDLE hd)
{
    assert (hd);

    hd->current.kr = NULL;
    iobuf_close (hd->current.iobuf);
    hd->current.iobuf = NULL;
    hd->current.eof = 0;
    hd->current.error = 0;
    
    hd->found.kr = NULL;
    hd->found.offset = 0;
    return 0; 
}


static int
prepare_search (KEYRING_HANDLE hd)
{
    if (hd->current.error)  
        return hd->current.error; /* still in error state */

    if (hd->current.kr && !hd->current.eof) {
        if ( !hd->current.iobuf )
            return G10ERR_GENERAL; /* position invalid after a modify */
        return 0; /* okay */
    }

    if (!hd->current.kr && hd->current.eof)  
        return -1; /* still EOF */

    if (!hd->current.kr) { /* start search with first keyring */
        hd->current.kr = next_kr (NULL, hd->secret);
        if (!hd->current.kr) {
            hd->current.eof = 1;
            return -1; /* no keyring available */
        }
        assert (!hd->current.iobuf);
    }
    else { /* EOF on last keyring - switch to next one */
        iobuf_close (hd->current.iobuf); 
        hd->current.iobuf = NULL;
        hd->current.kr = next_kr (hd->current.kr, hd->secret);
        if (!hd->current.kr) {
            hd->current.eof = 1;
            return -1;
        }
    }

    hd->current.eof = 0;
    hd->current.iobuf = iobuf_open (hd->current.kr->fname);
    if (!hd->current.iobuf) {
        log_error ("can't open `%s'\n", hd->current.kr->fname );
        return (hd->current.error = G10ERR_OPEN_FILE);
    }

    return 0;
}


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
prepare_word_match (const byte *name)
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
compare_name (int mode, const char *name, const char *uid, size_t uidlen)
{
    int i;
    const char *s, *se;

    if (mode == KEYDB_SEARCH_MODE_EXACT) { 
	for (i=0; name[i] && uidlen; i++, uidlen--)
	    if (uid[i] != name[i])
		break;
	if (!uidlen && !name[i])
	    return 0; /* found */
    }
    else if (mode == KEYDB_SEARCH_MODE_SUBSTR) {
	if (ascii_memistr( uid, uidlen, name ))
	    return 0;
    }
    else if (   mode == KEYDB_SEARCH_MODE_MAIL 
             || mode == KEYDB_SEARCH_MODE_MAILSUB
             || mode == KEYDB_SEARCH_MODE_MAILEND) {
	for (i=0, s= uid; i < uidlen && *s != '<'; s++, i++)
	    ;
	if (i < uidlen)  {
	    /* skip opening delim and one char and look for the closing one*/
	    s++; i++;
	    for (se=s+1, i++; i < uidlen && *se != '>'; se++, i++)
		;
	    if (i < uidlen) {
		i = se - s;
		if (mode == KEYDB_SEARCH_MODE_MAIL) { 
		    if( strlen(name)-2 == i
                        && !ascii_memcasecmp( s, name+1, i) )
			return 0;
		}
		else if (mode == KEYDB_SEARCH_MODE_MAILSUB) {
		    if( ascii_memistr( s, i, name ) )
			return 0;
		}
		else { /* email from end */
		    /* nyi */
		}
	    }
	}
    }
    else if (mode == KEYDB_SEARCH_MODE_WORDS)
	return word_match (uid, uidlen, name);
    else
	BUG();

    return -1; /* not found */
}


/* 
 * Search through the keyring(s), starting at the current position,
 * for a keyblock which contains one of the keys described in the DESC array.
 */
int 
keyring_search (KEYRING_HANDLE hd, KEYDB_SEARCH_DESC *desc, size_t ndesc)
{
    int rc;
    PACKET pkt;
    int save_mode;
    off_t offset, main_offset;
    size_t n;
    int need_uid, need_words, need_keyid, need_fpr;
    int pk_no, uid_no;
    int initial_skip;
    PKT_user_id *uid = NULL;
    PKT_public_key *pk = NULL;
    PKT_secret_key *sk = NULL;

    /* figure out what information we need */
    need_uid = need_words = need_keyid = need_fpr = 0;
    for (n=0; n < ndesc; n++) {
        switch (desc[n].mode) {
          case KEYDB_SEARCH_MODE_EXACT: 
          case KEYDB_SEARCH_MODE_SUBSTR:
          case KEYDB_SEARCH_MODE_MAIL:
          case KEYDB_SEARCH_MODE_MAILSUB:
          case KEYDB_SEARCH_MODE_MAILEND:
            need_uid = 1;
            break;
          case KEYDB_SEARCH_MODE_WORDS: 
            need_uid = 1;
            need_words = 1;
            break;
          case KEYDB_SEARCH_MODE_SHORT_KID: 
          case KEYDB_SEARCH_MODE_LONG_KID:
            need_keyid = 1;
            break;
          case KEYDB_SEARCH_MODE_FPR16: 
          case KEYDB_SEARCH_MODE_FPR20:
          case KEYDB_SEARCH_MODE_FPR: 
            need_fpr = 1;
            break;
          case KEYDB_SEARCH_MODE_FIRST:
            /* always restart the search in this mode */
            keyring_search_reset (hd);
            break;
          default: break;
	}
    }

    rc = prepare_search (hd);
    if (rc)
        return rc;

#if 0
    if (need_words) {
        BUG();
        if ( !hd->word_match.name || strcmp (hd->word_match.name, name) ) {
            /* name changed */
            m_free (hd->word_match.name);
            m_free (hd->word_match.pattern);
            hd->word_match.name = m_strdup (name);
            hd->word_match.pattern = prepare_word_match (name);
        }
        name = hd->word_match.pattern;
    }
#endif

    init_packet(&pkt);
    save_mode = set_packet_list_mode(0);

    hd->found.kr = NULL;
    main_offset = 0;
    pk_no = uid_no = 0;
    initial_skip = 1; /* skip until we see the start of a keyblock */
    while (!(rc=search_packet (hd->current.iobuf, &pkt, &offset, need_uid))) {
        byte afp[MAX_FINGERPRINT_LEN];
        size_t an;
        u32 aki[2];

	if (pkt.pkttype == PKT_PUBLIC_KEY
            || pkt.pkttype == PKT_SECRET_KEY) {
            main_offset = offset;
            pk_no = uid_no = 0;
            initial_skip = 0;
        }
        if (initial_skip) {
            free_packet (&pkt);
            continue;
        }
	
        pk = NULL;
        sk = NULL;
        uid = NULL;
        if (   pkt.pkttype == PKT_PUBLIC_KEY
               || pkt.pkttype == PKT_PUBLIC_SUBKEY) {
            pk = pkt.pkt.public_key;
            ++pk_no;

            if (need_fpr) {
                fingerprint_from_pk (pk, afp, &an);
                while (an < 20) /* fill up to 20 bytes */
                    afp[an++] = 0;
            }
            if (need_keyid)
                keyid_from_pk (pk, aki);
        }
	else if (pkt.pkttype == PKT_USER_ID) {
            uid = pkt.pkt.user_id;
            ++uid_no;
        }
        else if (    pkt.pkttype == PKT_SECRET_KEY
                  || pkt.pkttype == PKT_SECRET_SUBKEY) {
            sk = pkt.pkt.secret_key;
            ++pk_no;

            if (need_fpr) {
                fingerprint_from_sk (sk, afp, &an);
                while (an < 20) /* fill up to 20 bytes */
                    afp[an++] = 0;
            }
            if (need_keyid)
                keyid_from_sk (sk, aki);
        }

        for (n=0; n < ndesc; n++) {
            switch (desc[n].mode) {
              case KEYDB_SEARCH_MODE_NONE: 
                BUG ();
                break;
              case KEYDB_SEARCH_MODE_TDBIDX: 
                BUG();
                break;
              case KEYDB_SEARCH_MODE_EXACT: 
              case KEYDB_SEARCH_MODE_SUBSTR:
              case KEYDB_SEARCH_MODE_MAIL:
              case KEYDB_SEARCH_MODE_MAILSUB:
              case KEYDB_SEARCH_MODE_MAILEND:
              case KEYDB_SEARCH_MODE_WORDS: 
                if ( uid && !compare_name (desc[n].mode,
                                           desc[n].u.name,
                                           uid->name, uid->len)) 
                    goto found;
                break;
                
              case KEYDB_SEARCH_MODE_SHORT_KID: 
                if ((pk||sk) && desc[n].u.kid[1] == aki[1])
                    goto found;
                break;
              case KEYDB_SEARCH_MODE_LONG_KID:
                if ((pk||sk) && desc[n].u.kid[0] == aki[0]
                       && desc[n].u.kid[1] == aki[1])
                    goto found;
                break;
              case KEYDB_SEARCH_MODE_FPR16:
                if ((pk||sk) && !memcmp (desc[n].u.fpr, afp, 16))
                    goto found;
                break;
              case KEYDB_SEARCH_MODE_FPR20:
              case KEYDB_SEARCH_MODE_FPR: 
                if ((pk||sk) && !memcmp (desc[n].u.fpr, afp, 20))
                    goto found;
                break;
              case KEYDB_SEARCH_MODE_FIRST: 
              case KEYDB_SEARCH_MODE_NEXT: 
                if (pk||sk)
                    goto found;
                break;
              default: 
                rc = G10ERR_INV_ARG;
                goto found;
            }
	}

	free_packet (&pkt);
    }
 found:
    if( !rc ) {
        hd->found.offset = main_offset;
	hd->found.kr = hd->current.kr;
        hd->found.pk_no = (pk||sk)? pk_no : 0;
        hd->found.uid_no = uid? uid_no : 0;
    }
    else if (rc == -1)
        hd->current.eof = 1;
    else 
        hd->current.error = rc;

    free_packet(&pkt);
    set_packet_list_mode(save_mode);
    return rc;
}



/****************
 * Perform insert/delete/update operation.
 * mode 1 = insert
 *	2 = delete
 *	3 = update
 */
static int
do_copy (int mode, const char *fname, KBNODE root, int secret,
         off_t start_offset, unsigned int n_packets )
{
    IOBUF fp, newfp;
    int rc=0;
    char *bakfname = NULL;
    char *tmpfname = NULL;

    /* open the source file */
    fp = iobuf_open (fname);
    if (mode == 1 && !fp && errno == ENOENT) { 
	/* insert mode but file does not exist: create a new file */
	KBNODE kbctx, node;

	newfp = iobuf_create (fname);
	if( !newfp ) {
	    log_error (_("%s: can't create: %s\n"),
                       fname, strerror(errno));
	    return G10ERR_OPEN_FILE;
	}
	if( !opt.quiet )
	    log_info(_("%s: keyring created\n"), fname );

	kbctx=NULL;
	while ( (node = walk_kbnode( root, &kbctx, 0 )) ) {
	    if( (rc = build_packet( newfp, node->pkt )) ) {
		log_error("build_packet(%d) failed: %s\n",
			    node->pkt->pkttype, g10_errstr(rc) );
		iobuf_cancel(newfp);
		return G10ERR_WRITE_FILE;
	    }
	}
	if( iobuf_close(newfp) ) {
	    log_error ("%s: close failed: %s\n", fname, strerror(errno));
	    return G10ERR_CLOSE_FILE;
	}
	if (chmod( fname, S_IRUSR | S_IWUSR )) {
	    log_error("%s: chmod failed: %s\n", fname, strerror(errno) );
	    return G10ERR_WRITE_FILE;
	}
	return 0; /* ready */
    }

    if( !fp ) {
	log_error ("%s: can't open: %s\n", fname, strerror(errno) );
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
    if( strlen (fname) > 4
	&& !strcmp (fname+strlen(fname)-4, EXTSEP_S "gpg") ) {
	bakfname = m_alloc( strlen (fname) + 1 );
	strcpy(bakfname, fname);
	strcpy(bakfname+strlen(fname)-4, EXTSEP_S "bak");
	tmpfname = m_alloc( strlen( fname ) + 1 );
	strcpy(tmpfname,fname);
	strcpy(tmpfname+strlen(fname)-4, EXTSEP_S "tmp");
    }
    else { /* file does not end with gpg; hmmm */
	bakfname = m_alloc( strlen( fname ) + 5 );
	strcpy(stpcpy(bakfname, fname), EXTSEP_S "bak");
	tmpfname = m_alloc( strlen( fname ) + 5 );
	strcpy(stpcpy(tmpfname, fname), EXTSEP_S "tmp");
    }
  #else
    bakfname = m_alloc( strlen( fname ) + 2 );
    strcpy(stpcpy(bakfname,fname),"~");
    tmpfname = m_alloc( strlen( fname ) + 5 );
    strcpy(stpcpy(tmpfname,fname), EXTSEP_S "tmp");
  #endif
    newfp = iobuf_create (tmpfname);
    if (!newfp) {
	log_error ("%s: can't create: %s\n", tmpfname, strerror(errno) );
	iobuf_close(fp);
	rc = G10ERR_OPEN_FILE;
	goto leave;
    }

    if( mode == 1 ) { /* insert */
	/* copy everything to the new file */
	rc = copy_all_packets (fp, newfp);
	if( rc != -1 ) {
	    log_error("%s: copy to `%s' failed: %s\n",
		      fname, tmpfname, g10_errstr(rc) );
	    iobuf_close(fp);
	    iobuf_cancel(newfp);
	    goto leave;
	}
	rc = 0;
    }

    if( mode == 2 || mode == 3 ) { /* delete or update */
	/* copy first part to the new file */
	rc = copy_some_packets( fp, newfp, start_offset );
	if( rc ) { /* should never get EOF here */
	    log_error ("%s: copy to `%s' failed: %s\n",
                       fname, tmpfname, g10_errstr(rc) );
	    iobuf_close(fp);
	    iobuf_cancel(newfp);
	    goto leave;
	}
	/* skip this keyblock */
	assert( n_packets );
	rc = skip_some_packets( fp, n_packets );
	if( rc ) {
	    log_error("%s: skipping %u packets failed: %s\n",
			    fname, n_packets, g10_errstr(rc));
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
	    log_error("%s: copy to `%s' failed: %s\n",
		      fname, tmpfname, g10_errstr(rc) );
	    iobuf_close(fp);
	    iobuf_cancel(newfp);
	    goto leave;
	}
	rc = 0;
    }

    /* close both files */
    if( iobuf_close(fp) ) {
	log_error("%s: close failed: %s\n", fname, strerror(errno) );
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
    if( secret && !opt.preserve_permissions ) {
	if( chmod( tmpfname, S_IRUSR | S_IWUSR ) ) {
	    log_error("%s: chmod failed: %s\n",
				    tmpfname, strerror(errno) );
	    rc = G10ERR_WRITE_FILE;
	    goto leave;
	}
    }
  #endif

    /* rename and make backup file */
    if( !secret ) {  /* but not for secret keyrings */
        iobuf_ioctl (NULL, 2, 0, (char *)bakfname );
        iobuf_ioctl (NULL, 2, 0, (char *)fname );
      #if defined(HAVE_DOSISH_SYSTEM) || defined(__riscos__)
	remove( bakfname );
      #endif
	if( rename( fname, bakfname ) ) {
	    log_error("%s: rename to `%s' failed: %s\n",
				    fname, bakfname, strerror(errno) );
	    rc = G10ERR_RENAME_FILE;
	    goto leave;
	}
    }
    iobuf_ioctl (NULL, 2, 0, (char*)tmpfname );
    iobuf_ioctl (NULL, 2, 0, (char*)fname );
  #if defined(HAVE_DOSISH_SYSTEM) || defined(__riscos__)
    remove( fname );
  #endif
    if( rename( tmpfname, fname ) ) {
	log_error("%s: rename to `%s' failed: %s\n",
			    tmpfname, fname,strerror(errno) );
	rc = G10ERR_RENAME_FILE;
	if( secret ) {
	    log_info(_(
		"WARNING: 2 files with confidential information exists.\n"));
	    log_info(_("%s is the unchanged one\n"), fname );
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





