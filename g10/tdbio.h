/* tdbio.h - Trust database I/O functions
 * Copyright (C) 1998, 1999, 2000, 2001, 2002 Free Software Foundation, Inc.
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
#define RECTYPE_HTBL 10
#define RECTYPE_HLST 11
#define RECTYPE_TRUST 12
#define RECTYPE_VALID 13
#define RECTYPE_FREE 254


struct trust_record {
    int  rectype;
    int  mark;
    int  dirty; 		/* for now only used internal by functions */
    struct trust_record *next;	/* help pointer to build lists in memory */
    ulong recnum;
    union {
	struct {	     /* version record: */
	    byte  version;   /* should be 3 */
	    byte  marginals;
	    byte  completes;
	    byte  cert_depth;
	    byte  trust_model;
	    ulong created;   /* timestamp of trustdb creation  */
	    ulong nextcheck; /* timestamp of next scheduled check */
	    ulong reserved;  
	    ulong reserved2;
	    ulong firstfree;
	    ulong reserved3;
            ulong trusthashtbl;
	} ver;
	struct {	    /* free record */
	    ulong next;
	} free;
	struct {
	    ulong item[ITEMS_PER_HTBL_RECORD];
	} htbl;
	struct {
	    ulong next;
	    ulong rnum[ITEMS_PER_HLST_RECORD]; /* of another record */
	} hlst;
      struct {
        byte fingerprint[20];
        byte ownertrust;
        byte depth;
        ulong validlist;
	byte min_ownertrust;
      } trust;
      struct {
        byte namehash[20];
        ulong next;  
        byte validity;
	byte full_count;
	byte marginal_count;
      } valid;
    } r;
};
typedef struct trust_record TRUSTREC;

/*-- tdbio.c --*/
int tdbio_update_version_record(void);
int tdbio_set_dbname( const char *new_dbname, int create );
const char *tdbio_get_dbname(void);
void tdbio_dump_record( TRUSTREC *rec, FILE *fp );
int tdbio_read_record( ulong recnum, TRUSTREC *rec, int expected );
int tdbio_write_record( TRUSTREC *rec );
int tdbio_db_matches_options(void);
byte tdbio_read_model(void);
ulong tdbio_read_nextcheck (void);
int tdbio_write_nextcheck (ulong stamp);
int tdbio_is_dirty(void);
int tdbio_sync(void);
int tdbio_begin_transaction(void);
int tdbio_end_transaction(void);
int tdbio_cancel_transaction(void);
int tdbio_delete_record( ulong recnum );
ulong tdbio_new_recnum(void);
int tdbio_search_trust_byfpr(const byte *fingerprint, TRUSTREC *rec );
int tdbio_search_trust_bypk(PKT_public_key *pk, TRUSTREC *rec );

void tdbio_invalid(void);

#endif /*G10_TDBIO_H*/
