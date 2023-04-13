/* free-packet.c - cleanup stuff for packets
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003,
 *               2005, 2010  Free Software Foundation, Inc.
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gpg.h"
#include "../common/util.h"
#include "packet.h"
#include "../common/iobuf.h"
#include "options.h"


/* Run time check to see whether mpi_copy does not copy the flags
 * properly.   This was fixed in version 1.8.6.  */
static int
is_mpi_copy_broken (void)
{
  static char result;

  if (!result)
    {
      result = !gcry_check_version ("1.8.6");
      result |= 0x80;
    }
  return (result & 1);
}


/* This is mpi_copy with a fix for opaque MPIs which store a NULL
   pointer.  This will also be fixed in Libggcrypt 1.7.0.  */
static gcry_mpi_t
my_mpi_copy (gcry_mpi_t a)
{
  if (a
      && gcry_mpi_get_flag (a, GCRYMPI_FLAG_OPAQUE)
      && !gcry_mpi_get_opaque (a, NULL))
    return NULL;

  if (is_mpi_copy_broken ())
    {
      int flag_user2 = a? gcry_mpi_get_flag (a, GCRYMPI_FLAG_USER2) : 0;
      gcry_mpi_t b;

      b = gcry_mpi_copy (a);
      if (b && flag_user2)
        gcry_mpi_set_flag (b, GCRYMPI_FLAG_USER2);
      return b;
    }

  return gcry_mpi_copy (a);
}


void
free_symkey_enc( PKT_symkey_enc *enc )
{
    xfree(enc);
}

void
free_pubkey_enc( PKT_pubkey_enc *enc )
{
    int n, i;
    n = pubkey_get_nenc( enc->pubkey_algo );
    if( !n )
	mpi_release(enc->data[0]);
    for(i=0; i < n; i++ )
	mpi_release( enc->data[i] );
    xfree(enc);
}

void
free_seckey_enc( PKT_signature *sig )
{
  int n, i;

  n = pubkey_get_nsig( sig->pubkey_algo );
  if( !n )
    mpi_release(sig->data[0]);
  for(i=0; i < n; i++ )
    mpi_release( sig->data[i] );

  xfree(sig->revkey);
  xfree(sig->hashed);
  xfree(sig->unhashed);

  xfree (sig->signers_uid);

  xfree(sig);
}


void
release_public_key_parts (PKT_public_key *pk)
{
  int n, i;

  if (pk->seckey_info)
    n = pubkey_get_nskey (pk->pubkey_algo);
  else
    n = pubkey_get_npkey (pk->pubkey_algo);
  if (!n)
    mpi_release (pk->pkey[0]);
  for (i=0; i < n; i++ )
    {
      mpi_release (pk->pkey[i]);
      pk->pkey[i] = NULL;
    }
  if (pk->seckey_info)
    {
      xfree (pk->seckey_info);
      pk->seckey_info = NULL;
    }
  if (pk->prefs)
    {
      xfree (pk->prefs);
      pk->prefs = NULL;
    }
  free_user_id (pk->user_id);
  pk->user_id = NULL;
  if (pk->revkey)
    {
      xfree(pk->revkey);
      pk->revkey=NULL;
      pk->numrevkeys=0;
    }
  if (pk->serialno)
    {
      xfree (pk->serialno);
      pk->serialno = NULL;
    }
  if (pk->updateurl)
    {
      xfree (pk->updateurl);
      pk->updateurl = NULL;
    }
}


/* Free an allocated public key structure including all parts.
   Passing NULL is allowed.  */
void
free_public_key (PKT_public_key *pk)
{
  if (pk)
    {
      release_public_key_parts (pk);
      xfree(pk);
    }
}


static subpktarea_t *
cp_subpktarea (subpktarea_t *s )
{
    subpktarea_t *d;

    if( !s )
	return NULL;
    d = xmalloc (sizeof (*d) + s->size - 1 );
    d->size = s->size;
    d->len = s->len;
    memcpy (d->data, s->data, s->len);
    return d;
}

/*
 * Return a copy of the preferences
 */
prefitem_t *
copy_prefs (const prefitem_t *prefs)
{
    size_t n;
    prefitem_t *new;

    if (!prefs)
        return NULL;

    for (n=0; prefs[n].type; n++)
        ;
    new = xmalloc ( sizeof (*new) * (n+1));
    for (n=0; prefs[n].type; n++) {
        new[n].type = prefs[n].type;
        new[n].value = prefs[n].value;
    }
    new[n].type = PREFTYPE_NONE;
    new[n].value = 0;

    return new;
}


/* Copy the public key S to D.  If D is NULL allocate a new public key
 * structure.  Only the basic stuff is copied; not any ancillary
 * data.  */
PKT_public_key *
copy_public_key_basics (PKT_public_key *d, PKT_public_key *s)
{
  int n, i;

  if (!d)
    d = xmalloc (sizeof *d);
  memcpy (d, s, sizeof *d);
  d->seckey_info = NULL;
  d->user_id = NULL;
  d->prefs = NULL;

  n = pubkey_get_npkey (s->pubkey_algo);
  i = 0;
  if (!n)
    d->pkey[i++] = my_mpi_copy (s->pkey[0]);
  else
    {
      for (; i < n; i++ )
        d->pkey[i] = my_mpi_copy (s->pkey[i]);
    }
  for (; i < PUBKEY_MAX_NSKEY; i++)
    d->pkey[i] = NULL;

  d->revkey = NULL;
  d->serialno = NULL;
  d->updateurl = NULL;

  return d;
}


/* Copy the public key S to D.  If D is NULL allocate a new public key
   structure.  If S has seckret key infos, only the public stuff is
   copied.  */
PKT_public_key *
copy_public_key (PKT_public_key *d, PKT_public_key *s)
{
  d = copy_public_key_basics (d, s);
  d->user_id = scopy_user_id (s->user_id);
  d->prefs = copy_prefs (s->prefs);

  if (!s->revkey && s->numrevkeys)
    BUG();
  if (s->numrevkeys)
    {
      d->revkey = xmalloc(sizeof(struct revocation_key)*s->numrevkeys);
      memcpy(d->revkey,s->revkey,sizeof(struct revocation_key)*s->numrevkeys);
    }

  if (s->serialno)
    d->serialno = xstrdup (s->serialno);
  if (s->updateurl)
    d->updateurl = xstrdup (s->updateurl);

  return d;
}



PKT_signature *
copy_signature( PKT_signature *d, PKT_signature *s )
{
    int n, i;

    if( !d )
	d = xmalloc(sizeof *d);
    memcpy( d, s, sizeof *d );
    n = pubkey_get_nsig( s->pubkey_algo );
    if( !n )
	d->data[0] = my_mpi_copy(s->data[0]);
    else {
	for(i=0; i < n; i++ )
	    d->data[i] = my_mpi_copy( s->data[i] );
    }
    d->hashed = cp_subpktarea (s->hashed);
    d->unhashed = cp_subpktarea (s->unhashed);
    if (s->signers_uid)
      d->signers_uid = xstrdup (s->signers_uid);
    if(s->numrevkeys)
      {
	d->revkey=NULL;
	d->numrevkeys=0;
	parse_revkeys(d);
      }
    return d;
}


/*
 * shallow copy of the user ID
 */
PKT_user_id *
scopy_user_id (PKT_user_id *s)
{
    if (s)
        s->ref++;
    return s;
}



void
free_comment( PKT_comment *rem )
{
    xfree(rem);
}

void
free_attributes(PKT_user_id *uid)
{
  if (!uid)
    return;

  xfree(uid->attribs);
  xfree(uid->attrib_data);

  uid->attribs=NULL;
  uid->attrib_data=NULL;
  uid->attrib_len=0;
}

void
free_user_id (PKT_user_id *uid)
{
  if (!uid)
    return;

  log_assert (uid->ref > 0);
  if (--uid->ref)
    return;

  free_attributes(uid);
  xfree (uid->prefs);
  xfree (uid->namehash);
  xfree (uid->updateurl);
  xfree (uid->mbox);
  xfree (uid);
}

void
free_compressed( PKT_compressed *zd )
{
  if (!zd)
    return;

  if (zd->buf)
    {
      /* We need to skip some bytes.  Because don't have any
       * information about the length, so we assume this is the last
       * packet */
      while (iobuf_read( zd->buf, NULL, 1<<30 ) != -1)
        ;
    }
  xfree(zd);
}

void
free_encrypted( PKT_encrypted *ed )
{
  if (!ed)
    return;

  if (ed->buf)
    {
      /* We need to skip some bytes. */
      if (ed->is_partial)
        {
          while (iobuf_read( ed->buf, NULL, 1<<30 ) != -1)
            ;
	}
      else
        {
          while (ed->len)
            {
              /* Skip the packet. */
              int n = iobuf_read( ed->buf, NULL, ed->len );
              if (n == -1)
                ed->len = 0;
              else
                ed->len -= n;
            }
	}
    }
  xfree (ed);
}


void
free_plaintext( PKT_plaintext *pt )
{
  if (!pt)
    return;

  if (pt->buf)
    { /* We need to skip some bytes.  */
      if (pt->is_partial)
        {
          while (iobuf_read( pt->buf, NULL, 1<<30 ) != -1)
            ;
        }
      else
        {
          while( pt->len )
            { /* Skip the packet.  */
              int n = iobuf_read( pt->buf, NULL, pt->len );
              if (n == -1)
                pt->len = 0;
              else
                pt->len -= n;
            }
	}
    }
  xfree (pt);
}


/****************
 * Free the packet in PKT.
 */
void
free_packet (PACKET *pkt, parse_packet_ctx_t parsectx)
{
  if (!pkt || !pkt->pkt.generic)
    {
      if (parsectx && parsectx->last_pkt.pkt.generic)
        {
          if (parsectx->free_last_pkt)
            {
              free_packet (&parsectx->last_pkt, NULL);
              parsectx->free_last_pkt = 0;
            }
          parsectx->last_pkt.pkttype = 0;
          parsectx->last_pkt.pkt.generic = NULL;
        }
      return;
    }

  if (DBG_MEMORY)
    log_debug ("free_packet() type=%d\n", pkt->pkttype);

  /* If we have a parser context holding PKT then do not free the
   * packet but set a flag that the packet in the parser context is
   * now a deep copy.  */
  if (parsectx && !parsectx->free_last_pkt
      && parsectx->last_pkt.pkttype == pkt->pkttype
      && parsectx->last_pkt.pkt.generic == pkt->pkt.generic)
    {
      parsectx->last_pkt = *pkt;
      parsectx->free_last_pkt = 1;
      pkt->pkt.generic = NULL;
      return;
    }

  switch (pkt->pkttype)
    {
    case PKT_SIGNATURE:
      free_seckey_enc (pkt->pkt.signature);
      break;
    case PKT_PUBKEY_ENC:
      free_pubkey_enc (pkt->pkt.pubkey_enc);
      break;
    case PKT_SYMKEY_ENC:
      free_symkey_enc (pkt->pkt.symkey_enc);
      break;
    case PKT_PUBLIC_KEY:
    case PKT_PUBLIC_SUBKEY:
    case PKT_SECRET_KEY:
    case PKT_SECRET_SUBKEY:
      free_public_key (pkt->pkt.public_key);
      break;
    case PKT_COMMENT:
      free_comment (pkt->pkt.comment);
      break;
    case PKT_USER_ID:
      free_user_id (pkt->pkt.user_id);
      break;
    case PKT_COMPRESSED:
      free_compressed (pkt->pkt.compressed);
      break;
    case PKT_ENCRYPTED:
    case PKT_ENCRYPTED_MDC:
    case PKT_ENCRYPTED_AEAD:
      free_encrypted (pkt->pkt.encrypted);
      break;
    case PKT_PLAINTEXT:
      free_plaintext (pkt->pkt.plaintext);
      break;
    default:
      xfree (pkt->pkt.generic);
      break;
    }

  pkt->pkt.generic = NULL;
}


/****************
 * returns 0 if they match.
 */
int
cmp_public_keys( PKT_public_key *a, PKT_public_key *b )
{
    int n, i;

    if( a->timestamp != b->timestamp )
	return -1;
    if( a->version < 4 && a->expiredate != b->expiredate )
	return -1;
    if( a->pubkey_algo != b->pubkey_algo )
	return -1;

    n = pubkey_get_npkey( b->pubkey_algo );
    if( !n ) { /* unknown algorithm, rest is in opaque MPI */
	if( mpi_cmp( a->pkey[0], b->pkey[0] ) )
	    return -1; /* can't compare due to unknown algorithm */
    } else {
	for(i=0; i < n; i++ ) {
	    if( mpi_cmp( a->pkey[i], b->pkey[i] ) )
		return -1;
	}
    }

    return 0;
}



int
cmp_signatures( PKT_signature *a, PKT_signature *b )
{
    int n, i;

    if( a->keyid[0] != b->keyid[0] )
	return -1;
    if( a->keyid[1] != b->keyid[1] )
	return -1;
    if( a->pubkey_algo != b->pubkey_algo )
	return -1;

    n = pubkey_get_nsig( a->pubkey_algo );
    if( !n )
	return -1; /* can't compare due to unknown algorithm */
    for(i=0; i < n; i++ ) {
	if( mpi_cmp( a->data[i] , b->data[i] ) )
	    return -1;
    }
    return 0;
}


/****************
 * Returns: true if the user ids do not match
 */
int
cmp_user_ids( PKT_user_id *a, PKT_user_id *b )
{
    int res=1;

    if( a == b )
        return 0;

    if( a->attrib_data && b->attrib_data )
      {
	res = a->attrib_len - b->attrib_len;
	if( !res )
	  res = memcmp( a->attrib_data, b->attrib_data, a->attrib_len );
      }
    else if( !a->attrib_data && !b->attrib_data )
      {
	res = a->len - b->len;
	if( !res )
	  res = memcmp( a->name, b->name, a->len );
      }

    return res;
}
