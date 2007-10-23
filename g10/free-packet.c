/* free-packet.c - cleanup stuff for packets
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003,
 *               2005  Free Software Foundation, Inc.
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

#include "packet.h"
#include "iobuf.h"
#include "mpi.h"
#include "util.h"
#include "cipher.h"
#include "memory.h"
#include "options.h"

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
	mpi_free(enc->data[0]);
    for(i=0; i < n; i++ )
	mpi_free( enc->data[i] );
    xfree(enc);
}

void
free_seckey_enc( PKT_signature *sig )
{
  int n, i;

  n = pubkey_get_nsig( sig->pubkey_algo );
  if( !n )
    mpi_free(sig->data[0]);
  for(i=0; i < n; i++ )
    mpi_free( sig->data[i] );

  xfree(sig->revkey);
  xfree(sig->hashed);
  xfree(sig->unhashed);

  if (sig->pka_info)
    {
      xfree (sig->pka_info->uri);
      xfree (sig->pka_info);
    }

  xfree(sig);
}


void
release_public_key_parts( PKT_public_key *pk )
{
    int n, i;
    n = pubkey_get_npkey( pk->pubkey_algo );
    if( !n )
	mpi_free(pk->pkey[0]);
    for(i=0; i < n; i++ ) {
	mpi_free( pk->pkey[i] );
	pk->pkey[i] = NULL;
    }
    if (pk->prefs) {
        xfree (pk->prefs);
        pk->prefs = NULL;
    }
    if (pk->user_id) {
        free_user_id (pk->user_id);
        pk->user_id = NULL;
    }
    if (pk->revkey) {
        xfree(pk->revkey);
	pk->revkey=NULL;
	pk->numrevkeys=0;
    }
}


void
free_public_key( PKT_public_key *pk )
{
    release_public_key_parts( pk );
    xfree(pk);
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


PKT_public_key *
copy_public_key ( PKT_public_key *d, PKT_public_key *s)
{
    int n, i;

    if( !d )
	d = xmalloc(sizeof *d);
    memcpy( d, s, sizeof *d );
    d->user_id = scopy_user_id (s->user_id);
    d->prefs = copy_prefs (s->prefs);
    n = pubkey_get_npkey( s->pubkey_algo );
    if( !n )
	d->pkey[0] = mpi_copy(s->pkey[0]);
    else {
	for(i=0; i < n; i++ )
	    d->pkey[i] = mpi_copy( s->pkey[i] );
    }
    if( !s->revkey && s->numrevkeys )
        BUG();
    if( s->numrevkeys ) {
        d->revkey = xmalloc(sizeof(struct revocation_key)*s->numrevkeys);
        memcpy(d->revkey,s->revkey,sizeof(struct revocation_key)*s->numrevkeys);
    }
    else
        d->revkey = NULL;
    return d;
}

/****************
 * Replace all common parts of a sk by the one from the public key.
 * This is a hack and a better solution will be to just store the real secret
 * parts somewhere and don't duplicate all the other stuff.
 */
void
copy_public_parts_to_secret_key( PKT_public_key *pk, PKT_secret_key *sk )
{
    sk->expiredate  = pk->expiredate;     
    sk->pubkey_algo = pk->pubkey_algo;    
    sk->pubkey_usage= pk->pubkey_usage;
    sk->req_usage   = pk->req_usage;
    sk->req_algo    = pk->req_algo;
    sk->has_expired = pk->has_expired;    
    sk->is_revoked  = pk->is_revoked;     
    sk->is_valid    = pk->is_valid;    
    sk->main_keyid[0]= pk->main_keyid[0];
    sk->main_keyid[1]= pk->main_keyid[1];
    sk->keyid[0]    = pk->keyid[0];
    sk->keyid[1]    = pk->keyid[1];
}


static pka_info_t *
cp_pka_info (const pka_info_t *s)
{
  pka_info_t *d = xmalloc (sizeof *s + strlen (s->email));
  
  d->valid = s->valid;
  d->checked = s->checked;
  d->uri = s->uri? xstrdup (s->uri):NULL;
  memcpy (d->fpr, s->fpr, sizeof s->fpr);
  strcpy (d->email, s->email);
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
	d->data[0] = mpi_copy(s->data[0]);
    else {
	for(i=0; i < n; i++ )
	    d->data[i] = mpi_copy( s->data[i] );
    }
    d->pka_info = s->pka_info? cp_pka_info (s->pka_info) : NULL;
    d->hashed = cp_subpktarea (s->hashed);
    d->unhashed = cp_subpktarea (s->unhashed);
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
release_secret_key_parts( PKT_secret_key *sk )
{
    int n, i;

    n = pubkey_get_nskey( sk->pubkey_algo );
    if( !n )
	mpi_free(sk->skey[0]);
    for(i=0; i < n; i++ ) {
	mpi_free( sk->skey[i] );
	sk->skey[i] = NULL;
    }
}

void
free_secret_key( PKT_secret_key *sk )
{
    release_secret_key_parts( sk );
    xfree(sk);
}

PKT_secret_key *
copy_secret_key( PKT_secret_key *d, PKT_secret_key *s )
{
    int n, i;

    if( !d )
	d = xmalloc_secure(sizeof *d);
    else
        release_secret_key_parts (d);
    memcpy( d, s, sizeof *d );
    n = pubkey_get_nskey( s->pubkey_algo );
    if( !n )
  	d->skey[0] = mpi_copy(s->skey[0]);
    else {
	for(i=0; i < n; i++ )
  	    d->skey[i] = mpi_copy( s->skey[i] );
    }

    return d;
}

void
free_comment( PKT_comment *rem )
{
    xfree(rem);
}

void
free_attributes(PKT_user_id *uid)
{
  xfree(uid->attribs);
  xfree(uid->attrib_data);

  uid->attribs=NULL;
  uid->attrib_data=NULL;
  uid->attrib_len=0;
}

void
free_user_id (PKT_user_id *uid)
{
    assert (uid->ref > 0);
    if (--uid->ref)
        return;

    free_attributes(uid);
    xfree (uid->prefs);
    xfree (uid->namehash);
    xfree (uid);
}

void
free_compressed( PKT_compressed *zd )
{
    if( zd->buf ) { /* have to skip some bytes */
	/* don't have any information about the length, so
	 * we assume this is the last packet */
	while( iobuf_read( zd->buf, NULL, 1<<30 ) != -1 )
	    ;
    }
    xfree(zd);
}

void
free_encrypted( PKT_encrypted *ed )
{
    if( ed->buf ) { /* have to skip some bytes */
	if( ed->is_partial ) {
	    while( iobuf_read( ed->buf, NULL, 1<<30 ) != -1 )
		;
	}
	else {
	   while( ed->len ) { /* skip the packet */
	       int n = iobuf_read( ed->buf, NULL, ed->len );
	       if( n == -1 )
		   ed->len = 0;
	       else
		   ed->len -= n;
	   }
	}
    }
    xfree(ed);
}


void
free_plaintext( PKT_plaintext *pt )
{
    if( pt->buf ) { /* have to skip some bytes */
	if( pt->is_partial ) {
	    while( iobuf_read( pt->buf, NULL, 1<<30 ) != -1 )
		;
	}
	else {
	   while( pt->len ) { /* skip the packet */
	       int n = iobuf_read( pt->buf, NULL, pt->len );
	       if( n == -1 )
		   pt->len = 0;
	       else
		   pt->len -= n;
	   }
	}
    }
    xfree(pt);
}

/****************
 * Free the packet in pkt.
 */
void
free_packet( PACKET *pkt )
{
    if( !pkt || !pkt->pkt.generic )
	return;

    if( DBG_MEMORY )
	log_debug("free_packet() type=%d\n", pkt->pkttype );

    switch( pkt->pkttype ) {
      case PKT_SIGNATURE:
	free_seckey_enc( pkt->pkt.signature );
	break;
      case PKT_PUBKEY_ENC:
	free_pubkey_enc( pkt->pkt.pubkey_enc );
	break;
      case PKT_SYMKEY_ENC:
	free_symkey_enc( pkt->pkt.symkey_enc );
	break;
      case PKT_PUBLIC_KEY:
      case PKT_PUBLIC_SUBKEY:
	free_public_key( pkt->pkt.public_key );
	break;
      case PKT_SECRET_KEY:
      case PKT_SECRET_SUBKEY:
	free_secret_key( pkt->pkt.secret_key );
	break;
      case PKT_COMMENT:
	free_comment( pkt->pkt.comment );
	break;
      case PKT_USER_ID:
	free_user_id( pkt->pkt.user_id );
	break;
      case PKT_COMPRESSED:
	free_compressed( pkt->pkt.compressed);
	break;
      case PKT_ENCRYPTED:
      case PKT_ENCRYPTED_MDC:
	free_encrypted( pkt->pkt.encrypted );
	break;
      case PKT_PLAINTEXT:
	free_plaintext( pkt->pkt.plaintext );
	break;
      default:
	xfree( pkt->pkt.generic );
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
    if( !n )
	return -1; /* can't compare due to unknown algorithm */
    for(i=0; i < n; i++ ) {
	if( mpi_cmp( a->pkey[i], b->pkey[i] ) )
	    return -1;
    }

    return 0;
}

/****************
 * Returns 0 if they match.
 * We only compare the public parts.
 */
int
cmp_secret_keys( PKT_secret_key *a, PKT_secret_key *b )
{
    int n, i;

    if( a->timestamp != b->timestamp )
	return -1;
    if( a->version < 4 && a->expiredate != b->expiredate )
	return -1;
    if( a->pubkey_algo != b->pubkey_algo )
	return -1;

    n = pubkey_get_npkey( b->pubkey_algo );
    if( !n )
	return -1; /* can't compare due to unknown algorithm */
    for(i=0; i < n; i++ ) {
	if( mpi_cmp( a->skey[i], b->skey[i] ) )
	    return -1;
    }

    return 0;
}

/****************
 * Returns 0 if they match.
 */
int
cmp_public_secret_key( PKT_public_key *pk, PKT_secret_key *sk )
{
    int n, i;

    if( pk->timestamp != sk->timestamp )
	return -1;
    if( pk->version < 4 && pk->expiredate != sk->expiredate )
	return -1;
    if( pk->pubkey_algo != sk->pubkey_algo )
	return -1;

    n = pubkey_get_npkey( pk->pubkey_algo );
    if( !n )
	return -1; /* can't compare due to unknown algorithm */
    for(i=0; i < n; i++ ) {
	if( mpi_cmp( pk->pkey[i] , sk->skey[i] ) )
	    return -1;
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
