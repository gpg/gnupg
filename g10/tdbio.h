/* tdbio.h - Trust database I/O functions
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

#ifndef G10_TDBIO_H
#define G10_TDBIO_H


#define TRUST_RECORD_LEN 40
#define SIGS_PER_RECORD 	((TRUST_RECORD_LEN-10)/5)
#define ITEMS_PER_HTBL_RECORD	((TRUST_RECORD_LEN-2)/4)
#define ITEMS_PER_HLST_RECORD	((TRUST_RECORD_LEN-6)/5)
#define MAX_LIST_SIGS_DEPTH  20


#define RECTYPE_VER  1
#define RECTYPE_DIR  2
#define RECTYPE_KEY  3
#define RECTYPE_UID  4
#define RECTYPE_PREF 5
#define RECTYPE_SIG  6
#define RECTYPE_CACH 9
#define RECTYPE_HTBL 10
#define RECTYPE_HLST 11



#define DIRF_CHECKED  1 /* everything has been checked, the other bits are
			   valid */
#define DIRF_MISKEY   2 /* some keys are missing, so they could not be checked*/
#define DIRF_ERROR    4 /* severe errors: the key is not valid for some reasons
			   but we mark it to avoid duplicate checks */
#define DIRF_REVOKED  8 /* the complete key has been revoked */

#define KEYF_REVOKED DIRF_REVOKED   /* this key has been revoked
				       (only useful on subkeys)*/
#define UIDF_REVOKED DIRF_REVOKED   /* this user id has been revoked */


struct trust_record {
    int  rectype;
    struct trust_record *next;	/* help pointer to build lists in memory */
    struct trust_record *help_pref;
    int  mark;
    ulong recnum;
    union {
	struct {	     /* version record: */
	    byte version;    /* should be 2 */
	    ulong created;   /* timestamp of trustdb creation  */
	    ulong modified;  /* timestamp of last modification */
	    ulong validated; /* timestamp of last validation   */
	    ulong keyhashtbl;
	} ver;
	struct {	    /* directory record */
	    ulong lid;
	    ulong keylist;  /* List of keys (the first is the primary key)*/
	    ulong uidlist;  /* list of uid records */
	    ulong cacherec; /* the cache record */
	    byte ownertrust;
	    byte dirflags;
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
	    byte namehash[20]; /* ripemd hash of the username */
	} uid;
	struct {	    /* preference reord */
	    ulong lid;	    /* point back to the directory record */
			    /* or 0 for a glocal pref record */
	    ulong next;    /* points to next pref record */
	} pref;
	struct {	    /* signature record */
	    ulong lid;
	    ulong next;   /* recnno of next record or NULL for last one */
	    struct {
		ulong lid;	 /* of pubkey record of signator (0=unused) */
		byte flag;	 /* SIGRF_xxxxx */
	    } sig[SIGS_PER_RECORD];
	} sig;
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
	    ulong rnum[ITEMS_PER_HLST_RECORD]; /* of a key record */
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
int tdbio_delete_record( ulong recnum );
ulong tdbio_new_recnum(void);
int tdbio_search_dir_bypk( PKT_public_key *pk, TRUSTREC *rec );
int tdbio_search_dir_byfpr( const byte *fingerprint, size_t fingerlen,
					int pubkey_algo, TRUSTREC *rec );
int tdbio_delete_uidrec( ulong dirlid, ulong uidlid );


#define buftoulong( p )  ((*(byte*)(p) << 24) | (*((byte*)(p)+1)<< 16) | \
		       (*((byte*)(p)+2) << 8) | (*((byte*)(p)+3)))
#define buftoushort( p )  ((*((byte*)(p)) << 8) | (*((byte*)(p)+1)))
#define ulongtobuf( p, a ) do { 			  \
			    ((byte*)p)[0] = a >> 24;	\
			    ((byte*)p)[1] = a >> 16;	\
			    ((byte*)p)[2] = a >>  8;	\
			    ((byte*)p)[3] = a	   ;	\
			} while(0)
#define ushorttobuf( p, a ) do {			   \
			    ((byte*)p)[0] = a >>  8;	\
			    ((byte*)p)[1] = a	   ;	\
			} while(0)
#define buftou32( p)	buftoulong( (p) )
#define u32tobuf( p, a) ulongtobuf( (p), (a) )



#endif /*G10_TDBIO_H*/
