/* kbx.h  -  The GnuPG Keybox
 *	Copyright (C) 2000 Free Software Foundation, Inc.
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

#ifndef GPG_KBX_H
#define GPG_KBX_H 1

#include "keydb.h"

/*-- kbxblob.c */
struct kbxblob;
typedef struct kbxblob *KBXBLOB;

int kbx_new_blob ( KBXBLOB *r_blob,  char *image, size_t imagelen );
int kbx_create_blob ( KBXBLOB *r_blob,	KBNODE keyblock );
void kbx_release_blob ( KBXBLOB blob );
const char *kbx_get_blob_image ( KBXBLOB blob, size_t *n );

int kbx_dump_blob ( FILE *fp, KBXBLOB blob  );
int kbx_blob_has_fpr ( KBXBLOB blob, const byte *fpr );
int kbx_blob_has_kid ( KBXBLOB blob, const byte *keyidbuf, size_t keyidlen );
int kbx_blob_has_uid ( KBXBLOB blob,
		       int (*cmp)(const byte *, size_t, void *), void *opaque );

/*-- kbxio.c --*/
int kbx_read_blob ( KBXBLOB *r_blob, FILE *a );

/*-- kbxfile.c --*/
int kbxfile_search_by_fpr( const char *filename, const byte *fpr );
int kbxfile_search_by_kid ( const char *filename, u32 *kid, int mode );
int kbxfile_search_by_uid ( const char *filename, const char *name );
void print_kbxfile( const char *filename );


#endif /*GPG_KBX_H*/
