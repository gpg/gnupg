/* tdbio.h - Trust database I/O functions
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

#ifndef G10_TDBIO_H
#define G10_TDBIO_H

#include "host2net.h"

#define TRUST_RECORD_LEN 40
#define SIGS_PER_RECORD 	((TRUST_RECORD_LEN-10)/5)
#define ITEMS_PER_HTBL_RECORD	((TRUST_RECORD_LEN-2)/4)
#define ITEMS_PER_HLST_RECORD	((TRUST_RECORD_LEN-6)/5)
#define ITEMS_PER_PREF_RECORD	(TRUST_RECORD_LEN-10)
#if ITEMS_PER_PREF_RECORD % 2
  #error ITEMS_PER_PREF_RECORD must be even
#endif
#define MAX_LIST_SIGS_DEPTH  20


#define RECTYPE_VER  1
#define RECTYPE_DIR  2
#define RECTYPE_KEY  3
#define RECTYPE_UID  4
#define RECTYPE_PREF 5
#define RECTYPE_SIG  6
#define RECTYPE_SDIR 8
#define RECTYPE_CACH 9
#define RECTYPE_HTBL 10
#define RECTYPE_HLST 11
#define RECTYPE_FREE 254


#define DIRF_CHECKED  1 /* has been checked - bits 1,2,3 are valid */
#define DIRF_VALID    2 /* This key is valid:  There is at least */
			/* one uid with a selfsignature or an revocation */
#define DIRF_EXPIRED  4 /* the complete key has expired */
#define DIRF_REVOKED  8 /* the complete key has been revoked */
#define DIRF_NEWKEYS 128 /* new keys are available: we can check the sigs */

#define KEYF_CHECKED  1 /* This key has been checked */
#define KEYF_VALID    2 /* This is a valid (sub)key */
#define KEYF_EXPIRED  4 /* this key is expired */
#define KEYF_REVOKED  8 /* this key has been revoked */

#define UIDF_CHECKED  1  /* user id has been checked - other bits are valid */
#define UIDF_VALID    2  /* this is a valid user id */
#define UIDF_REVOKED  8  /* this user id has been revoked */

#define SIGF_CHECKED  1 /* signature has been checked - bits 0..6 are valid */
#define SIGF_VALID    2 /* the signature is valid */
#define SIGF_EXPIRED  4 /* the key of this signature has expired */
#define SIGF_REVOKED  8 /* this signature has been revoked */
#define SIGF_IGNORED  64  /* this signature is ignored by the system */
#define SIGF_NOPUBKEY 128 /* there is no pubkey for this sig */

struct trust_record {
    int  rectype;
    int  mark;
    int  dirty; 		/* for now only used internal by functions */
    struct trust_record *next;	/* help pointer to build lists in memory */
    ulong recnum;
    union {
	struct {	     /* version record: */
	    byte version;    /* should be 2 */
	    byte  marginals;
	    byte  completes;
	    byte  cert_depth;
	    ulong created;   /* timestamp of trustdb creation  */
	    ulong mod_down;  /* timestamp of last modification downward */
	    ulong mod_up;    /* timestamp of last modification upward */
	    ulong keyhashtbl;
	    ulong firstfree;
	    ulong sdirhashtbl;
	} ver;
	struct {	    /* free record */
	    ulong next;
	} free;
	struct {	    /* directory record */
	    ulong lid;
	    ulong keylist;  /* List of keys (the first is the primary key)*/
	    ulong uidlist;  /* list of uid records */
	    ulong cacherec; /* the cache record */
	    byte ownertrust;
	    byte dirflags;
	    byte validity;   /* calculated trustlevel over all uids */
	    ulong valcheck;  /* timestamp of last validation check */
	    ulong checkat;   /* Check key when this time has been reached*/
	} dir;
	struct {	    /* primary public key record */
	    ulong lid;
	    ulong next;    /* next key */
	    byte keyflags;
	    byte pubkey_algo;
	    byte fingerprint_len;
	    byte fingerprint[20];
	} key;
	struct {	    /* user id reord */
	    ulong lid;	    /* point back to the directory record */
	    ulong next;    /* points to next user id record */
	    ulong prefrec;   /* recno of preference record */
	    ulong siglist;   /* list of valid signatures (w/o self-sig)*/
	    byte uidflags;
	    byte validity;  /* calculated trustlevel of this uid */
	    byte namehash[20]; /* ripemd hash of the username */
	} uid;
	struct {	    /* preference record */
	    ulong lid;	    /* point back to the directory record */
			    /* or 0 for a global pref record */
	    ulong next;    /* points to next pref record */
	    byte  data[ITEMS_PER_PREF_RECORD];
	} pref;
	struct {	    /* signature record */
	    ulong lid;
	    ulong next;   /* recnno of next record or NULL for last one */
	    struct {
		ulong lid;	 /* of pubkey record of signator (0=unused) */
		byte flag;	 /* SIGF_xxxxx */
	    } sig[SIGS_PER_RECORD];
	} sig;
	struct {
	    ulong lid;
	    u32  keyid[2];
	    byte pubkey_algo;
	    u32  hintlist;
	} sdir;
	struct {	    /* cache record */
	    ulong lid;
	    byte blockhash[20];
	    byte trustlevel;   /* calculated trustlevel */
	} cache;
	struct {
	    ulong item[ITEMS_PER_HTBL_RECORD];
	} htbl;
	struct {
	    ulong next;
	    ulong rnum[ITEMS_PER_HLST_RECORD]; /* of another record */
	} hlst;
    } r;
};
typedef struct trust_record TRUSTREC;

typedef struct {
    ulong     lid;	   /* localid */
    ulong     sigrec;
    ulong     sig_lid;	   /* returned signatures LID */
    unsigned  sig_flag;    /* returned signature record flag */
    struct {		   /* internal data */
	int init_done;
	int eof;
	TRUSTREC rec;
	ulong nextuid;
	int index;
    } ctl;
} SIGREC_CONTEXT;


/*-- tdbio.c --*/
int tdbio_set_dbname( const char *new_dbname, int create );
const char *tdbio_get_dbname(void);
void tdbio_dump_record( TRUSTREC *rec, FILE *fp );
int tdbio_read_record( ulong recnum, TRUSTREC *rec, int expected );
int tdbio_write_record( TRUSTREC *rec );
int tdbio_db_matches_options(void);
ulong tdbio_read_modify_stamp( int modify_down );
void tdbio_write_modify_stamp( int up, int down );
int tdbio_is_dirty(void);
int tdbio_sync(void);
int tdbio_begin_transaction(void);
int tdbio_end_transaction(void);
int tdbio_cancel_transaction(void);
int tdbio_delete_record( ulong recnum );
ulong tdbio_new_recnum(void);
int tdbio_search_dir_bypk( PKT_public_key *pk, TRUSTREC *rec );
int tdbio_search_dir_byfpr( const byte *fingerprint, size_t fingerlen,
					int pubkey_algo, TRUSTREC *rec );
int tdbio_search_dir(  u32 *keyid, int pubkey_algo, TRUSTREC *rec );
int tdbio_search_sdir( u32 *keyid, int pubkey_algo, TRUSTREC *rec );

void tdbio_invalid(void);

#endif /*G10_TDBIO_H*/
