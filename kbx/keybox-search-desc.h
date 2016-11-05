/* keybox-search-desc.h - Keybox serch description
 *	Copyright (C) 2001 Free Software Foundation, Inc.
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/*
   This file is a temporary kludge until we can come up with solution
   to share this description between keybox and the application
   specific keydb
*/

#ifndef KEYBOX_SEARCH_DESC_H
#define KEYBOX_SEARCH_DESC_H 1

typedef enum {
  KEYDB_SEARCH_MODE_NONE,
  KEYDB_SEARCH_MODE_EXACT,
  KEYDB_SEARCH_MODE_SUBSTR,
  KEYDB_SEARCH_MODE_MAIL,
  KEYDB_SEARCH_MODE_MAILSUB,
  KEYDB_SEARCH_MODE_MAILEND,
  KEYDB_SEARCH_MODE_WORDS,
  KEYDB_SEARCH_MODE_SHORT_KID,
  KEYDB_SEARCH_MODE_LONG_KID,
  KEYDB_SEARCH_MODE_FPR16,
  KEYDB_SEARCH_MODE_FPR20,
  KEYDB_SEARCH_MODE_FPR,
  KEYDB_SEARCH_MODE_ISSUER,
  KEYDB_SEARCH_MODE_ISSUER_SN,
  KEYDB_SEARCH_MODE_SN,
  KEYDB_SEARCH_MODE_SUBJECT,
  KEYDB_SEARCH_MODE_KEYGRIP,
  KEYDB_SEARCH_MODE_FIRST,
  KEYDB_SEARCH_MODE_NEXT
} KeydbSearchMode;


/* Forwward declaration.  See g10/packet.h.  */
struct gpg_pkt_user_id_s;
typedef struct gpg_pkt_user_id_s *gpg_pkt_user_id_t;

/* A search descriptor.  */
struct keydb_search_desc
{
  KeydbSearchMode mode;
  /* Callback used to filter results.  The first parameter is
     SKIPFUNCVALUE.  The second is the keyid.  The third is the
     1-based index of the UID packet that matched the search criteria
     (or 0, if none).

     Return non-zero if the result should be skipped.  */
  int (*skipfnc)(void *, u32 *, int);
  void *skipfncvalue;
  const unsigned char *sn;
  int snlen;  /* -1 := sn is a hex string */
  union {
    const char *name;
    unsigned char fpr[24];
    u32 kid[2]; /* Note that this is in native endianness.  */
    unsigned char grip[20];
  } u;
  int exact;    /* Use exactly this key ('!' suffix in gpg).  */
};


struct keydb_search_desc;
typedef struct keydb_search_desc KEYDB_SEARCH_DESC;
typedef struct keydb_search_desc KEYBOX_SEARCH_DESC;



#endif /*KEYBOX_SEARCH_DESC_H*/
