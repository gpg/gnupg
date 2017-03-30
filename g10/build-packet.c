/* build-packet.c - assemble packets and write them
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005,
 *               2006, 2010, 2011  Free Software Foundation, Inc.
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
#include <ctype.h>

#include "gpg.h"
#include "../common/util.h"
#include "packet.h"
#include "../common/status.h"
#include "../common/iobuf.h"
#include "../common/i18n.h"
#include "options.h"
#include "../common/host2net.h"

static gpg_error_t do_ring_trust (iobuf_t out, PKT_ring_trust *rt);
static int do_user_id( IOBUF out, int ctb, PKT_user_id *uid );
static int do_key (iobuf_t out, int ctb, PKT_public_key *pk);
static int do_symkey_enc( IOBUF out, int ctb, PKT_symkey_enc *enc );
static int do_pubkey_enc( IOBUF out, int ctb, PKT_pubkey_enc *enc );
static u32 calc_plaintext( PKT_plaintext *pt );
static int do_plaintext( IOBUF out, int ctb, PKT_plaintext *pt );
static int do_encrypted( IOBUF out, int ctb, PKT_encrypted *ed );
static int do_encrypted_mdc( IOBUF out, int ctb, PKT_encrypted *ed );
static int do_compressed( IOBUF out, int ctb, PKT_compressed *cd );
static int do_signature( IOBUF out, int ctb, PKT_signature *sig );
static int do_onepass_sig( IOBUF out, int ctb, PKT_onepass_sig *ops );

static int calc_header_length( u32 len, int new_ctb );
static int write_16(IOBUF inp, u16 a);
static int write_32(IOBUF inp, u32 a);
static int write_header( IOBUF out, int ctb, u32 len );
static int write_sign_packet_header( IOBUF out, int ctb, u32 len );
static int write_header2( IOBUF out, int ctb, u32 len, int hdrlen );
static int write_new_header( IOBUF out, int ctb, u32 len, int hdrlen );

/* Returns 1 if CTB is a new format ctb and 0 if CTB is an old format
   ctb.  */
static int
ctb_new_format_p (int ctb)
{
  /* Bit 7 must always be set.  */
  log_assert ((ctb & (1 << 7)));
  /* Bit 6 indicates whether the packet is a new format packet.  */
  return (ctb & (1 << 6));
}

/* Extract the packet type from a CTB.  */
static int
ctb_pkttype (int ctb)
{
  if (ctb_new_format_p (ctb))
    /* Bits 0 through 5 are the packet type.  */
    return (ctb & ((1 << 6) - 1));
  else
    /* Bits 2 through 5 are the packet type.  */
    return (ctb & ((1 << 6) - 1)) >> 2;
}


/* Build a packet and write it to the stream OUT.
 * Returns: 0 on success or on an error code.  */
int
build_packet (IOBUF out, PACKET *pkt)
{
  int rc = 0;
  int new_ctb = 0;
  int ctb, pkttype;

  if (DBG_PACKET)
    log_debug ("build_packet() type=%d\n", pkt->pkttype);
  log_assert (pkt->pkt.generic);

  switch ((pkttype = pkt->pkttype))
    {
    case PKT_PUBLIC_KEY:
      if (pkt->pkt.public_key->seckey_info)
        pkttype = PKT_SECRET_KEY;
      break;
    case PKT_PUBLIC_SUBKEY:
      if (pkt->pkt.public_key->seckey_info)
        pkttype = PKT_SECRET_SUBKEY;
      break;
    case PKT_PLAINTEXT:
      new_ctb = pkt->pkt.plaintext->new_ctb;
      break;
    case PKT_ENCRYPTED:
    case PKT_ENCRYPTED_MDC:
      new_ctb = pkt->pkt.encrypted->new_ctb;
      break;
    case PKT_COMPRESSED:
      new_ctb = pkt->pkt.compressed->new_ctb;
      break;
    case PKT_USER_ID:
      if (pkt->pkt.user_id->attrib_data)
        pkttype = PKT_ATTRIBUTE;
      break;
    default:
      break;
    }

  if (new_ctb || pkttype > 15) /* new format */
    ctb = (0xc0 | (pkttype & 0x3f));
  else
    ctb = (0x80 | ((pkttype & 15)<<2));
  switch (pkttype)
    {
    case PKT_ATTRIBUTE:
    case PKT_USER_ID:
      rc = do_user_id (out, ctb, pkt->pkt.user_id);
      break;
    case PKT_OLD_COMMENT:
    case PKT_COMMENT:
      /* Ignore these.  Theoretically, this will never be called as we
       * have no way to output comment packets any longer, but just in
       * case there is some code path that would end up outputting a
       * comment that was written before comments were dropped (in the
       * public key?) this is a no-op. 	*/
      break;
    case PKT_PUBLIC_SUBKEY:
    case PKT_PUBLIC_KEY:
    case PKT_SECRET_SUBKEY:
    case PKT_SECRET_KEY:
      rc = do_key (out, ctb, pkt->pkt.public_key);
      break;
    case PKT_SYMKEY_ENC:
      rc = do_symkey_enc (out, ctb, pkt->pkt.symkey_enc);
      break;
    case PKT_PUBKEY_ENC:
      rc = do_pubkey_enc (out, ctb, pkt->pkt.pubkey_enc);
      break;
    case PKT_PLAINTEXT:
      rc = do_plaintext (out, ctb, pkt->pkt.plaintext);
      break;
    case PKT_ENCRYPTED:
      rc = do_encrypted (out, ctb, pkt->pkt.encrypted);
      break;
    case PKT_ENCRYPTED_MDC:
      rc = do_encrypted_mdc (out, ctb, pkt->pkt.encrypted);
      break;
    case PKT_COMPRESSED:
      rc = do_compressed (out, ctb, pkt->pkt.compressed);
      break;
    case PKT_SIGNATURE:
      rc = do_signature (out, ctb, pkt->pkt.signature);
      break;
    case PKT_ONEPASS_SIG:
      rc = do_onepass_sig (out, ctb, pkt->pkt.onepass_sig);
      break;
    case PKT_RING_TRUST:
      /* Ignore it (only written by build_packet_and_meta)  */
      break;
    case PKT_MDC:
      /* We write it directly, so we should never see it here. */
    default:
      log_bug ("invalid packet type in build_packet()\n");
      break;
    }

  return rc;
}


/* Build a packet and write it to the stream OUT.  This variant also
 * writes the meta data using ring tyrust packets.  Returns: 0 on
 * success or on aerror code.  */
gpg_error_t
build_packet_and_meta (iobuf_t out, PACKET *pkt)
{
  gpg_error_t err;
  PKT_ring_trust rt = {0};

  err = build_packet (out, pkt);
  if (err)
    ;
  else if (pkt->pkttype == PKT_SIGNATURE)
    {
      PKT_signature *sig = pkt->pkt.signature;

      rt.subtype = RING_TRUST_SIG;
      /* Note: trustval is not yet used.  */
      if (sig->flags.checked)
        {
          rt.sigcache = 1;
          if (sig->flags.valid)
            rt.sigcache |= 2;
        }
      err = do_ring_trust (out, &rt);
    }
  else if (pkt->pkttype == PKT_USER_ID
           || pkt->pkttype == PKT_ATTRIBUTE)
    {
      PKT_user_id *uid = pkt->pkt.user_id;

      rt.subtype = RING_TRUST_UID;
      rt.keysrc = uid->keysrc;
      rt.keyupdate = uid->keyupdate;
      rt.url = uid->updateurl;
      err = do_ring_trust (out, &rt);
      rt.url = NULL;
    }
  else if (pkt->pkttype == PKT_PUBLIC_KEY
           || pkt->pkttype == PKT_SECRET_KEY)
    {
      PKT_public_key *pk = pkt->pkt.public_key;

      rt.subtype = RING_TRUST_KEY;
      rt.keysrc = pk->keysrc;
      rt.keyupdate = pk->keyupdate;
      rt.url = pk->updateurl;
      err = do_ring_trust (out, &rt);
      rt.url = NULL;

    }

  return err;
}


/*
 * Write the mpi A to OUT.
 */
gpg_error_t
gpg_mpi_write (iobuf_t out, gcry_mpi_t a)
{
  int rc;

  if (gcry_mpi_get_flag (a, GCRYMPI_FLAG_OPAQUE))
    {
      unsigned int nbits;
      const unsigned char *p;
      unsigned char lenhdr[2];

      /* gcry_log_debugmpi ("a", a); */
      p = gcry_mpi_get_opaque (a, &nbits);
      if (p)
        {
          /* Strip leading zero bits.  */
          for (; nbits >= 8 && !*p; p++, nbits -= 8)
            ;
          if (nbits >= 8 && !(*p & 0x80))
            if (--nbits >= 7 && !(*p & 0x40))
              if (--nbits >= 6 && !(*p & 0x20))
                if (--nbits >= 5 && !(*p & 0x10))
                  if (--nbits >= 4 && !(*p & 0x08))
                    if (--nbits >= 3 && !(*p & 0x04))
                      if (--nbits >= 2 && !(*p & 0x02))
                        if (--nbits >= 1 && !(*p & 0x01))
                          --nbits;
        }
      /* gcry_log_debug ("   [%u bit]\n", nbits); */
      /* gcry_log_debughex (" ", p, (nbits+7)/8); */
      lenhdr[0] = nbits >> 8;
      lenhdr[1] = nbits;
      rc = iobuf_write (out, lenhdr, 2);
      if (!rc && p)
        rc = iobuf_write (out, p, (nbits+7)/8);
    }
  else
    {
      char buffer[(MAX_EXTERN_MPI_BITS+7)/8+2]; /* 2 is for the mpi length. */
      size_t nbytes;

      nbytes = DIM(buffer);
      rc = gcry_mpi_print (GCRYMPI_FMT_PGP, buffer, nbytes, &nbytes, a );
      if( !rc )
        rc = iobuf_write( out, buffer, nbytes );
      else if (gpg_err_code(rc) == GPG_ERR_TOO_SHORT )
        {
          log_info ("mpi too large (%u bits)\n", gcry_mpi_get_nbits (a));
          /* The buffer was too small. We better tell the user about the MPI. */
          rc = gpg_error (GPG_ERR_TOO_LARGE);
        }
    }

  return rc;
}


/*
 * Write an opaque MPI to the output stream without length info.
 */
gpg_error_t
gpg_mpi_write_nohdr (iobuf_t out, gcry_mpi_t a)
{
  int rc;

  if (gcry_mpi_get_flag (a, GCRYMPI_FLAG_OPAQUE))
    {
      unsigned int nbits;
      const void *p;

      p = gcry_mpi_get_opaque (a, &nbits);
      rc = p ? iobuf_write (out, p, (nbits+7)/8) : 0;
    }
  else
    rc = gpg_error (GPG_ERR_BAD_MPI);

  return rc;
}


/* Calculate the length of a packet described by PKT.  */
u32
calc_packet_length( PACKET *pkt )
{
  u32 n = 0;
  int new_ctb = 0;

  log_assert (pkt->pkt.generic);
  switch (pkt->pkttype)
    {
    case PKT_PLAINTEXT:
      n = calc_plaintext (pkt->pkt.plaintext);
      new_ctb = pkt->pkt.plaintext->new_ctb;
      break;
    case PKT_ATTRIBUTE:
    case PKT_USER_ID:
    case PKT_COMMENT:
    case PKT_PUBLIC_KEY:
    case PKT_SECRET_KEY:
    case PKT_SYMKEY_ENC:
    case PKT_PUBKEY_ENC:
    case PKT_ENCRYPTED:
    case PKT_SIGNATURE:
    case PKT_ONEPASS_SIG:
    case PKT_RING_TRUST:
    case PKT_COMPRESSED:
    default:
      log_bug ("invalid packet type in calc_packet_length()");
      break;
    }

  n += calc_header_length (n, new_ctb);
  return n;
}


static gpg_error_t
write_fake_data (IOBUF out, gcry_mpi_t a)
{
  unsigned int n;
  void *p;

  if (!a)
    return 0;
  if (!gcry_mpi_get_flag (a, GCRYMPI_FLAG_OPAQUE))
    return 0; /* e.g. due to generating a key with wrong usage.  */
  p = gcry_mpi_get_opaque ( a, &n);
  if (!p)
    return 0; /* For example due to a read error in
                 parse-packet.c:read_rest.  */
  return iobuf_write (out, p, (n+7)/8 );
}


/* Write a ring trust meta packet.  */
static gpg_error_t
do_ring_trust (iobuf_t out, PKT_ring_trust *rt)
{
  unsigned int namelen = 0;
  unsigned int pktlen = 6;

  if (rt->subtype == RING_TRUST_KEY || rt->subtype == RING_TRUST_UID)
    {
      if (rt->url)
        namelen = strlen (rt->url);
      pktlen += 1 + 4 + 1 + namelen;
    }

  write_header (out, (0x80 | ((PKT_RING_TRUST & 15)<<2)), pktlen);
  iobuf_put (out, rt->trustval);
  iobuf_put (out, rt->sigcache);
  iobuf_write (out, "gpg", 3);
  iobuf_put (out, rt->subtype);
  if (rt->subtype == RING_TRUST_KEY || rt->subtype == RING_TRUST_UID)
    {
      iobuf_put (out, rt->keysrc);
      write_32 (out, rt->keyupdate);
      iobuf_put (out, namelen);
      if (namelen)
        iobuf_write (out, rt->url, namelen);
    }

  return 0;
}


/* Serialize the user id (RFC 4880, Section 5.11) or the user
 * attribute UID (Section 5.12) and write it to OUT.
 *
 * CTB is the serialization's CTB.  It specifies the header format and
 * the packet's type.  The header length must not be set.  */
static int
do_user_id( IOBUF out, int ctb, PKT_user_id *uid )
{
  int rc;
  int hdrlen;

  log_assert (ctb_pkttype (ctb) == PKT_USER_ID
              || ctb_pkttype (ctb) == PKT_ATTRIBUTE);

  /* We need to take special care of a user ID with a length of 0:
   * Without forcing HDRLEN to 2 in this case an indeterminate length
   * packet would be written which is not allowed.  Note that we are
   * always called with a CTB indicating an old packet header format,
   * so that forcing a 2 octet header works.  */
  if (uid->attrib_data)
    {
      hdrlen = uid->attrib_len? 0 : 2;
      write_header2 (out, ctb, uid->attrib_len, hdrlen);
      rc = iobuf_write( out, uid->attrib_data, uid->attrib_len );
    }
  else
    {
      hdrlen = uid->len? 0 : 2;
      write_header2 (out, ctb, uid->len, hdrlen);
      rc = iobuf_write( out, uid->name, uid->len );
    }
  return rc;
}


/* Serialize the key (RFC 4880, Section 5.5) described by PK and write
 * it to OUT.
 *
 * This function serializes both primary keys and subkeys with or
 * without a secret part.
 *
 * CTB is the serialization's CTB.  It specifies the header format and
 * the packet's type.  The header length must not be set.
 *
 * PK->VERSION specifies the serialization format.  A value of 0 means
 * to use the default version.  Currently, only version 4 packets are
 * supported.
 */
static int
do_key (iobuf_t out, int ctb, PKT_public_key *pk)
{
  gpg_error_t err = 0;
  /* The length of the body is stored in the packet's header, which
     occurs before the body.  Unfortunately, we don't know the length
     of the packet's body until we've written all of the data!  To
     work around this, we first write the data into this temporary
     buffer, then generate the header, and finally copy the contents
     of this buffer to OUT.  */
  iobuf_t a = iobuf_temp();
  int i, nskey, npkey;

  log_assert (pk->version == 0 || pk->version == 4);
  log_assert (ctb_pkttype (ctb) == PKT_PUBLIC_KEY
              || ctb_pkttype (ctb) == PKT_PUBLIC_SUBKEY
              || ctb_pkttype (ctb) == PKT_SECRET_KEY
              || ctb_pkttype (ctb) == PKT_SECRET_SUBKEY);

  /* Write the version number - if none is specified, use 4 */
  if ( !pk->version )
    iobuf_put ( a, 4 );
  else
    iobuf_put ( a, pk->version );
  write_32 (a, pk->timestamp );

  iobuf_put (a, pk->pubkey_algo );

  /* Get number of secret and public parameters.  They are held in one
     array: the public ones followed by the secret ones.  */
  nskey = pubkey_get_nskey (pk->pubkey_algo);
  npkey = pubkey_get_npkey (pk->pubkey_algo);

  /* If we don't have any public parameters - which is for example the
     case if we don't know the algorithm used - the parameters are
     stored as one blob in a faked (opaque) MPI. */
  if (!npkey)
    {
      write_fake_data (a, pk->pkey[0]);
      goto leave;
    }
  log_assert (npkey < nskey);

  for (i=0; i < npkey; i++ )
    {
      if (   (pk->pubkey_algo == PUBKEY_ALGO_ECDSA && (i == 0))
          || (pk->pubkey_algo == PUBKEY_ALGO_EDDSA && (i == 0))
          || (pk->pubkey_algo == PUBKEY_ALGO_ECDH  && (i == 0 || i == 2)))
        err = gpg_mpi_write_nohdr (a, pk->pkey[i]);
      else
        err = gpg_mpi_write (a, pk->pkey[i]);
      if (err)
        goto leave;
    }


  if (pk->seckey_info)
    {
      /* This is a secret key packet.  */
      struct seckey_info *ski = pk->seckey_info;

      /* Build the header for protected (encrypted) secret parameters.  */
      if (ski->is_protected)
        {
          /* OpenPGP protection according to rfc2440. */
          iobuf_put (a, ski->sha1chk? 0xfe : 0xff);
          iobuf_put (a, ski->algo);
          if (ski->s2k.mode >= 1000)
            {
              /* These modes are not possible in OpenPGP, we use them
                 to implement our extensions, 101 can be viewed as a
                 private/experimental extension (this is not specified
                 in rfc2440 but the same scheme is used for all other
                 algorithm identifiers). */
              iobuf_put (a, 101);
              iobuf_put (a, ski->s2k.hash_algo);
              iobuf_write (a, "GNU", 3 );
              iobuf_put (a, ski->s2k.mode - 1000);
            }
          else
            {
              iobuf_put (a, ski->s2k.mode);
              iobuf_put (a, ski->s2k.hash_algo);
            }

          if (ski->s2k.mode == 1 || ski->s2k.mode == 3)
            iobuf_write (a, ski->s2k.salt, 8);

          if (ski->s2k.mode == 3)
            iobuf_put (a, ski->s2k.count);

          /* For our special modes 1001, 1002 we do not need an IV. */
          if (ski->s2k.mode != 1001 && ski->s2k.mode != 1002)
            iobuf_write (a, ski->iv, ski->ivlen);

        }
      else /* Not protected. */
        iobuf_put (a, 0 );

      if (ski->s2k.mode == 1001)
        ; /* GnuPG extension - don't write a secret key at all. */
      else if (ski->s2k.mode == 1002)
        {
          /* GnuPG extension - divert to OpenPGP smartcard. */
          /* Length of the serial number or 0 for no serial number. */
          iobuf_put (a, ski->ivlen );
          /* The serial number gets stored in the IV field.  */
          iobuf_write (a, ski->iv, ski->ivlen);
        }
      else if (ski->is_protected)
        {
          /* The secret key is protected - write it out as it is.  */
          byte *p;
          unsigned int ndatabits;

          log_assert (gcry_mpi_get_flag (pk->pkey[npkey], GCRYMPI_FLAG_OPAQUE));
          p = gcry_mpi_get_opaque (pk->pkey[npkey], &ndatabits);
          if (p)
            iobuf_write (a, p, (ndatabits+7)/8 );
        }
      else
        {
          /* Non-protected key. */
          for ( ; i < nskey; i++ )
            if ( (err = gpg_mpi_write (a, pk->pkey[i])))
              goto leave;
          write_16 (a, ski->csum );
        }
    }

 leave:
  if (!err)
    {
      /* Build the header of the packet - which we must do after
         writing all the other stuff, so that we know the length of
         the packet */
      write_header2 (out, ctb, iobuf_get_temp_length(a), 0);
       /* And finally write it out to the real stream. */
      err = iobuf_write_temp (out, a);
    }

  iobuf_close (a); /* Close the temporary buffer */
  return err;
}


/* Serialize the symmetric-key encrypted session key packet (RFC 4880,
 * 5.3) described by ENC and write it to OUT.
 *
 * CTB is the serialization's CTB.  It specifies the header format and
 * the packet's type.  The header length must not be set.  */
static int
do_symkey_enc( IOBUF out, int ctb, PKT_symkey_enc *enc )
{
  int rc = 0;
  IOBUF a = iobuf_temp();

  log_assert (ctb_pkttype (ctb) == PKT_SYMKEY_ENC);

  /* The only acceptable version.  */
  log_assert( enc->version == 4 );

  /* RFC 4880, Section 3.7.  */
  switch (enc->s2k.mode)
    {
    case 0: /* Simple S2K.  */
    case 1: /* Salted S2K.  */
    case 3: /* Iterated and salted S2K.  */
      break; /* Reasonable values.  */

    default:
      log_bug ("do_symkey_enc: s2k=%d\n", enc->s2k.mode);
    }
    iobuf_put( a, enc->version );
    iobuf_put( a, enc->cipher_algo );
    iobuf_put( a, enc->s2k.mode );
    iobuf_put( a, enc->s2k.hash_algo );
    if( enc->s2k.mode == 1 || enc->s2k.mode == 3 ) {
	iobuf_write(a, enc->s2k.salt, 8 );
	if( enc->s2k.mode == 3 )
	    iobuf_put(a, enc->s2k.count);
    }
    if( enc->seskeylen )
	iobuf_write(a, enc->seskey, enc->seskeylen );

    write_header(out, ctb, iobuf_get_temp_length(a) );
    rc = iobuf_write_temp( out, a );

    iobuf_close(a);
    return rc;
}


/* Serialize the public-key encrypted session key packet (RFC 4880,
   5.1) described by ENC and write it to OUT.

   CTB is the serialization's CTB.  It specifies the header format and
   the packet's type.  The header length must not be set.  */
static int
do_pubkey_enc( IOBUF out, int ctb, PKT_pubkey_enc *enc )
{
  int rc = 0;
  int n, i;
  IOBUF a = iobuf_temp();

  log_assert (ctb_pkttype (ctb) == PKT_PUBKEY_ENC);

  iobuf_put (a, 3); /* Version.  */

  if ( enc->throw_keyid )
    {
      write_32(a, 0 );  /* Don't tell Eve who can decrypt the message.  */
      write_32(a, 0 );
    }
  else
    {
      write_32(a, enc->keyid[0] );
      write_32(a, enc->keyid[1] );
    }
  iobuf_put(a,enc->pubkey_algo );
  n = pubkey_get_nenc( enc->pubkey_algo );
  if ( !n )
    write_fake_data( a, enc->data[0] );

  for (i=0; i < n && !rc ; i++ )
    {
      if (enc->pubkey_algo == PUBKEY_ALGO_ECDH && i == 1)
        rc = gpg_mpi_write_nohdr (a, enc->data[i]);
      else
        rc = gpg_mpi_write (a, enc->data[i]);
    }

  if (!rc)
    {
      write_header (out, ctb, iobuf_get_temp_length(a) );
      rc = iobuf_write_temp (out, a);
    }
  iobuf_close(a);
  return rc;
}


/* Calculate the length of the serialized plaintext packet PT (RFC
   4480, Section 5.9).  */
static u32
calc_plaintext( PKT_plaintext *pt )
{
  /* Truncate namelen to the maximum 255 characters.  Note this means
     that a function that calls build_packet with an illegal literal
     packet will get it back legalized. */

  if(pt->namelen>255)
    pt->namelen=255;

  return pt->len? (1 + 1 + pt->namelen + 4 + pt->len) : 0;
}

/* Serialize the plaintext packet (RFC 4880, 5.9) described by PT and
   write it to OUT.

   The body of the message is stored in PT->BUF.  The amount of data
   to write is PT->LEN.  (PT->BUF should be configured to return EOF
   after this much data has been read.)  If PT->LEN is 0 and CTB
   indicates that this is a new format packet, then partial block mode
   is assumed to have been enabled on OUT.  On success, partial block
   mode is disabled.

   If PT->BUF is NULL, the caller must write out the data.  In
   this case, if PT->LEN was 0, then partial body length mode was
   enabled and the caller must disable it by calling
   iobuf_set_partial_body_length_mode (out, 0).  */
static int
do_plaintext( IOBUF out, int ctb, PKT_plaintext *pt )
{
    int rc = 0;
    size_t nbytes;

    log_assert (ctb_pkttype (ctb) == PKT_PLAINTEXT);

    write_header(out, ctb, calc_plaintext( pt ) );
    log_assert (pt->mode == 'b' || pt->mode == 't' || pt->mode == 'u'
                || pt->mode == 'm'
                || pt->mode == 'l' || pt->mode == '1');
    iobuf_put(out, pt->mode );
    iobuf_put(out, pt->namelen );
    iobuf_write (out, pt->name, pt->namelen);
    rc = write_32(out, pt->timestamp );
    if (rc)
      return rc;

    if (pt->buf)
      {
        nbytes = iobuf_copy (out, pt->buf);
        if(ctb_new_format_p (ctb) && !pt->len)
          /* Turn off partial body length mode.  */
          iobuf_set_partial_body_length_mode (out, 0);
        if( pt->len && nbytes != pt->len )
          log_error("do_plaintext(): wrote %lu bytes but expected %lu bytes\n",
                    (ulong)nbytes, (ulong)pt->len );
      }

    return rc;
}



/* Serialize the symmetrically encrypted data packet (RFC 4880,
   Section 5.7) described by ED and write it to OUT.

   Note: this only writes the packets header!  The call must then
   follow up and write the initial random data and the body to OUT.
   (If you use the encryption iobuf filter (cipher_filter), then this
   is done automatically.)  */
static int
do_encrypted( IOBUF out, int ctb, PKT_encrypted *ed )
{
    int rc = 0;
    u32 n;

    log_assert (! ed->mdc_method);
    log_assert (ctb_pkttype (ctb) == PKT_ENCRYPTED);

    n = ed->len ? (ed->len + ed->extralen) : 0;
    write_header(out, ctb, n );

    /* This is all. The caller has to write the real data */

    return rc;
}

/* Serialize the symmetrically encrypted integrity protected data
   packet (RFC 4880, Section 5.13) described by ED and write it to
   OUT.

   Note: this only writes the packet's header!  The caller must then
   follow up and write the initial random data, the body and the MDC
   packet to OUT.  (If you use the encryption iobuf filter
   (cipher_filter), then this is done automatically.)  */
static int
do_encrypted_mdc( IOBUF out, int ctb, PKT_encrypted *ed )
{
    int rc = 0;
    u32 n;

    log_assert (ed->mdc_method);
    log_assert (ctb_pkttype (ctb) == PKT_ENCRYPTED_MDC);

    /* Take version number and the following MDC packet in account. */
    n = ed->len ? (ed->len + ed->extralen + 1 + 22) : 0;
    write_header(out, ctb, n );
    iobuf_put(out, 1 );  /* version */

    /* This is all. The caller has to write the real data */

    return rc;
}


/* Serialize the compressed packet (RFC 4880, Section 5.6) described
   by CD and write it to OUT.

   Note: this only writes the packet's header!  The caller must then
   follow up and write the body to OUT.  */
static int
do_compressed( IOBUF out, int ctb, PKT_compressed *cd )
{
    int rc = 0;

    log_assert (ctb_pkttype (ctb) == PKT_COMPRESSED);

    /* We must use the old convention and don't use blockmode for the
       sake of PGP 2 compatibility.  However if the new_ctb flag was
       set, CTB is already formatted as new style and write_header2
       does create a partial length encoding using new the new
       style. */
    write_header2(out, ctb, 0, 0);
    iobuf_put(out, cd->algorithm );

    /* This is all. The caller has to write the real data */

    return rc;
}


/****************
 * Delete all subpackets of type REQTYPE and return a bool whether a packet
 * was deleted.
 */
int
delete_sig_subpkt (subpktarea_t *area, sigsubpkttype_t reqtype )
{
    int buflen;
    sigsubpkttype_t type;
    byte *buffer, *bufstart;
    size_t n;
    size_t unused = 0;
    int okay = 0;

    if( !area )
	return 0;
    buflen = area->len;
    buffer = area->data;
    for(;;) {
	if( !buflen ) {
            okay = 1;
            break;
        }
	bufstart = buffer;
	n = *buffer++; buflen--;
	if( n == 255 ) {
	    if( buflen < 4 )
		break;
	    n = buf32_to_size_t (buffer);
	    buffer += 4;
	    buflen -= 4;
	}
	else if( n >= 192 ) {
	    if( buflen < 2 )
		break;
	    n = (( n - 192 ) << 8) + *buffer + 192;
	    buffer++;
	    buflen--;
	}
	if( buflen < n )
	    break;

	type = *buffer & 0x7f;
	if( type == reqtype ) {
	    buffer++;
            buflen--;
	    n--;
	    if( n > buflen )
		break;
            buffer += n; /* point to next subpkt */
            buflen -= n;
            memmove (bufstart, buffer, buflen); /* shift */
            unused +=  buffer - bufstart;
            buffer = bufstart;
	}
        else {
            buffer += n; buflen -=n;
        }
    }

    if (!okay)
        log_error ("delete_subpkt: buffer shorter than subpacket\n");
    log_assert (unused <= area->len);
    area->len -= unused;
    return !!unused;
}


/****************
 * Create or update a signature subpacket for SIG of TYPE.  This
 * functions knows where to put the data (hashed or unhashed).  The
 * function may move data from the unhashed part to the hashed one.
 * Note: All pointers into sig->[un]hashed (e.g. returned by
 * parse_sig_subpkt) are not valid after a call to this function.  The
 * data to put into the subpaket should be in a buffer with a length
 * of buflen.
 */
void
build_sig_subpkt (PKT_signature *sig, sigsubpkttype_t type,
		  const byte *buffer, size_t buflen )
{
    byte *p;
    int critical, hashed;
    subpktarea_t *oldarea, *newarea;
    size_t nlen, n, n0;

    critical = (type & SIGSUBPKT_FLAG_CRITICAL);
    type &= ~SIGSUBPKT_FLAG_CRITICAL;

    /* Sanity check buffer sizes */
    if(parse_one_sig_subpkt(buffer,buflen,type)<0)
      BUG();

    switch(type)
      {
      case SIGSUBPKT_NOTATION:
      case SIGSUBPKT_POLICY:
      case SIGSUBPKT_REV_KEY:
      case SIGSUBPKT_SIGNATURE:
	/* we do allow multiple subpackets */
	break;

      default:
	/* we don't allow multiple subpackets */
	delete_sig_subpkt(sig->hashed,type);
	delete_sig_subpkt(sig->unhashed,type);
	break;
      }

    /* Any special magic that needs to be done for this type so the
       packet doesn't need to be reparsed? */
    switch(type)
      {
      case SIGSUBPKT_NOTATION:
	sig->flags.notation=1;
	break;

      case SIGSUBPKT_POLICY:
	sig->flags.policy_url=1;
	break;

      case SIGSUBPKT_PREF_KS:
	sig->flags.pref_ks=1;
	break;

      case SIGSUBPKT_EXPORTABLE:
	if(buffer[0])
	  sig->flags.exportable=1;
	else
	  sig->flags.exportable=0;
	break;

      case SIGSUBPKT_REVOCABLE:
	if(buffer[0])
	  sig->flags.revocable=1;
	else
	  sig->flags.revocable=0;
	break;

      case SIGSUBPKT_TRUST:
	sig->trust_depth=buffer[0];
	sig->trust_value=buffer[1];
	break;

      case SIGSUBPKT_REGEXP:
	sig->trust_regexp=buffer;
	break;

	/* This should never happen since we don't currently allow
	   creating such a subpacket, but just in case... */
      case SIGSUBPKT_SIG_EXPIRE:
	if(buf32_to_u32(buffer)+sig->timestamp<=make_timestamp())
	  sig->flags.expired=1;
	else
	  sig->flags.expired=0;
	break;

      default:
	break;
      }

    if( (buflen+1) >= 8384 )
	nlen = 5; /* write 5 byte length header */
    else if( (buflen+1) >= 192 )
	nlen = 2; /* write 2 byte length header */
    else
	nlen = 1; /* just a 1 byte length header */

    switch( type )
      {
	/* The issuer being unhashed is a historical oddity.  It
	   should work equally as well hashed.  Of course, if even an
	   unhashed issuer is tampered with, it makes it awfully hard
	   to verify the sig... */
      case SIGSUBPKT_ISSUER:
      case SIGSUBPKT_SIGNATURE:
        hashed = 0;
        break;
      default:
        hashed = 1;
        break;
      }

    if( critical )
	type |= SIGSUBPKT_FLAG_CRITICAL;

    oldarea = hashed? sig->hashed : sig->unhashed;

    /* Calculate new size of the area and allocate */
    n0 = oldarea? oldarea->len : 0;
    n = n0 + nlen + 1 + buflen; /* length, type, buffer */
    if (oldarea && n <= oldarea->size) { /* fits into the unused space */
        newarea = oldarea;
        /*log_debug ("updating area for type %d\n", type );*/
    }
    else if (oldarea) {
        newarea = xrealloc (oldarea, sizeof (*newarea) + n - 1);
        newarea->size = n;
        /*log_debug ("reallocating area for type %d\n", type );*/
    }
    else {
        newarea = xmalloc (sizeof (*newarea) + n - 1);
        newarea->size = n;
        /*log_debug ("allocating area for type %d\n", type );*/
    }
    newarea->len = n;

    p = newarea->data + n0;
    if (nlen == 5) {
	*p++ = 255;
	*p++ = (buflen+1) >> 24;
	*p++ = (buflen+1) >> 16;
	*p++ = (buflen+1) >>  8;
	*p++ = (buflen+1);
	*p++ = type;
	memcpy (p, buffer, buflen);
    }
    else if (nlen == 2) {
	*p++ = (buflen+1-192) / 256 + 192;
	*p++ = (buflen+1-192) % 256;
	*p++ = type;
	memcpy (p, buffer, buflen);
    }
    else {
	*p++ = buflen+1;
	*p++ = type;
	memcpy (p, buffer, buflen);
    }

    if (hashed)
	sig->hashed = newarea;
    else
	sig->unhashed = newarea;
}

/*
 * Put all the required stuff from SIG into subpackets of sig.
 * PKSK is the signing key.
 * Hmmm, should we delete those subpackets which are in a wrong area?
 */
void
build_sig_subpkt_from_sig (PKT_signature *sig, PKT_public_key *pksk)
{
    u32  u;
    byte buf[1+MAX_FINGERPRINT_LEN];
    size_t fprlen;

    /* For v4 keys we need to write the ISSUER subpacket.  We do not
     * want that for a future v5 format.  */
    if (pksk->version < 5)
      {
        u = sig->keyid[0];
        buf[0] = (u >> 24) & 0xff;
        buf[1] = (u >> 16) & 0xff;
        buf[2] = (u >>  8) & 0xff;
        buf[3] = u & 0xff;
        u = sig->keyid[1];
        buf[4] = (u >> 24) & 0xff;
        buf[5] = (u >> 16) & 0xff;
        buf[6] = (u >>  8) & 0xff;
        buf[7] = u & 0xff;
        build_sig_subpkt (sig, SIGSUBPKT_ISSUER, buf, 8);
      }

    /* Write the new ISSUER_FPR subpacket.  */
    fingerprint_from_pk (pksk, buf+1, &fprlen);
    if (fprlen == 20)
      {
        buf[0] = pksk->version;
        build_sig_subpkt (sig, SIGSUBPKT_ISSUER_FPR, buf, 21);
      }

    /* Write the timestamp.  */
    u = sig->timestamp;
    buf[0] = (u >> 24) & 0xff;
    buf[1] = (u >> 16) & 0xff;
    buf[2] = (u >>  8) & 0xff;
    buf[3] = u & 0xff;
    build_sig_subpkt( sig, SIGSUBPKT_SIG_CREATED, buf, 4 );

    if(sig->expiredate)
      {
	if(sig->expiredate>sig->timestamp)
	  u=sig->expiredate-sig->timestamp;
	else
	  u=1; /* A 1-second expiration time is the shortest one
		  OpenPGP has */

	buf[0] = (u >> 24) & 0xff;
	buf[1] = (u >> 16) & 0xff;
	buf[2] = (u >>  8) & 0xff;
	buf[3] = u & 0xff;

	/* Mark this CRITICAL, so if any implementation doesn't
           understand sigs that can expire, it'll just disregard this
           sig altogether. */

	build_sig_subpkt( sig, SIGSUBPKT_SIG_EXPIRE | SIGSUBPKT_FLAG_CRITICAL,
			  buf, 4 );
      }
}

void
build_attribute_subpkt(PKT_user_id *uid,byte type,
		       const void *buf,u32 buflen,
		       const void *header,u32 headerlen)
{
  byte *attrib;
  int idx;

  if(1+headerlen+buflen>8383)
    idx=5;
  else if(1+headerlen+buflen>191)
    idx=2;
  else
    idx=1;

  /* realloc uid->attrib_data to the right size */

  uid->attrib_data=xrealloc(uid->attrib_data,
			     uid->attrib_len+idx+1+headerlen+buflen);

  attrib=&uid->attrib_data[uid->attrib_len];

  if(idx==5)
    {
      attrib[0]=255;
      attrib[1]=(1+headerlen+buflen) >> 24;
      attrib[2]=(1+headerlen+buflen) >> 16;
      attrib[3]=(1+headerlen+buflen) >> 8;
      attrib[4]=1+headerlen+buflen;
    }
  else if(idx==2)
    {
      attrib[0]=(1+headerlen+buflen-192) / 256 + 192;
      attrib[1]=(1+headerlen+buflen-192) % 256;
    }
  else
    attrib[0]=1+headerlen+buflen; /* Good luck finding a JPEG this small! */

  attrib[idx++]=type;

  /* Tack on our data at the end */

  if(headerlen>0)
    memcpy(&attrib[idx],header,headerlen);
  memcpy(&attrib[idx+headerlen],buf,buflen);
  uid->attrib_len+=idx+headerlen+buflen;
}

/* Returns a human-readable string corresponding to the notation.
   This ignores notation->value.  The caller must free the result.  */
static char *
notation_value_to_human_readable_string (struct notation *notation)
{
  if(notation->bdat)
    /* Binary data.  */
    {
      size_t len = notation->blen;
      int i;
      char preview[20];

      for (i = 0; i < len && i < sizeof (preview) - 1; i ++)
        if (isprint (notation->bdat[i]))
          preview[i] = notation->bdat[i];
        else
          preview[i] = '?';
      preview[i] = 0;

      return xasprintf (_("[ not human readable (%zu bytes: %s%s) ]"),
                        len, preview, i < len ? "..." : "");
    }
  else
    /* The value is human-readable.  */
    return xstrdup (notation->value);
}

/* Turn the notation described by the string STRING into a notation.

   STRING has the form:

     - -name - Delete the notation.
     - name@domain.name=value - Normal notation
     - !name@domain.name=value - Notation with critical bit set.

   The caller must free the result using free_notation().  */
struct notation *
string_to_notation(const char *string,int is_utf8)
{
  const char *s;
  int saw_at=0;
  struct notation *notation;

  notation=xmalloc_clear(sizeof(*notation));

  if(*string=='-')
    {
      notation->flags.ignore=1;
      string++;
    }

  if(*string=='!')
    {
      notation->flags.critical=1;
      string++;
    }

  /* If and when the IETF assigns some official name tags, we'll have
     to add them here. */

  for( s=string ; *s != '='; s++ )
    {
      if( *s=='@')
	saw_at++;

      /* -notationname is legal without an = sign */
      if(!*s && notation->flags.ignore)
	break;

      if( !*s || !isascii (*s) || (!isgraph(*s) && !isspace(*s)) )
	{
	  log_error(_("a notation name must have only printable characters"
		      " or spaces, and end with an '='\n") );
	  goto fail;
	}
    }

  notation->name=xmalloc((s-string)+1);
  strncpy(notation->name,string,s-string);
  notation->name[s-string]='\0';

  if(!saw_at && !opt.expert)
    {
      log_error(_("a user notation name must contain the '@' character\n"));
      goto fail;
    }

  if (saw_at > 1)
    {
      log_error(_("a notation name must not contain more than"
		  " one '@' character\n"));
      goto fail;
    }

  if(*s)
    {
      const char *i=s+1;
      int highbit=0;

      /* we only support printable text - therefore we enforce the use
	 of only printable characters (an empty value is valid) */
      for(s++; *s ; s++ )
	{
	  if ( !isascii (*s) )
	    highbit=1;
	  else if (iscntrl(*s))
	    {
	      log_error(_("a notation value must not use any"
			  " control characters\n"));
	      goto fail;
	    }
	}

      if(!highbit || is_utf8)
	notation->value=xstrdup(i);
      else
	notation->value=native_to_utf8(i);
    }

  return notation;

 fail:
  free_notation(notation);
  return NULL;
}

/* Like string_to_notation, but store opaque data rather than human
   readable data.  */
struct notation *
blob_to_notation(const char *name, const char *data, size_t len)
{
  const char *s;
  int saw_at=0;
  struct notation *notation;

  notation=xmalloc_clear(sizeof(*notation));

  if(*name=='-')
    {
      notation->flags.ignore=1;
      name++;
    }

  if(*name=='!')
    {
      notation->flags.critical=1;
      name++;
    }

  /* If and when the IETF assigns some official name tags, we'll have
     to add them here. */

  for( s=name ; *s; s++ )
    {
      if( *s=='@')
	saw_at++;

      /* -notationname is legal without an = sign */
      if(!*s && notation->flags.ignore)
	break;

      if (*s == '=')
        {
          log_error(_("a notation name may not contain an '=' character\n"));
          goto fail;
        }

      if (!isascii (*s) || (!isgraph(*s) && !isspace(*s)))
	{
	  log_error(_("a notation name must have only printable characters"
		      " or spaces\n") );
	  goto fail;
	}
    }

  notation->name=xstrdup (name);

  if(!saw_at && !opt.expert)
    {
      log_error(_("a user notation name must contain the '@' character\n"));
      goto fail;
    }

  if (saw_at > 1)
    {
      log_error(_("a notation name must not contain more than"
		  " one '@' character\n"));
      goto fail;
    }

  notation->bdat = xmalloc (len);
  memcpy (notation->bdat, data, len);
  notation->blen = len;

  notation->value = notation_value_to_human_readable_string (notation);

  return notation;

 fail:
  free_notation(notation);
  return NULL;
}

struct notation *
sig_to_notation(PKT_signature *sig)
{
  const byte *p;
  size_t len;
  int seq = 0;
  int crit;
  notation_t list = NULL;

  /* See RFC 4880, 5.2.3.16 for the format of notation data.  In
     short, a notation has:

       - 4 bytes of flags
       - 2 byte name length (n1)
       - 2 byte value length (n2)
       - n1 bytes of name data
       - n2 bytes of value data
   */
  while((p=enum_sig_subpkt(sig->hashed,SIGSUBPKT_NOTATION,&len,&seq,&crit)))
    {
      int n1,n2;
      struct notation *n=NULL;

      if(len<8)
	{
	  log_info(_("WARNING: invalid notation data found\n"));
	  continue;
	}

      /* name length.  */
      n1=(p[4]<<8)|p[5];
      /* value length.  */
      n2=(p[6]<<8)|p[7];

      if(8+n1+n2!=len)
	{
	  log_info(_("WARNING: invalid notation data found\n"));
	  continue;
	}

      n=xmalloc_clear(sizeof(*n));
      n->name=xmalloc(n1+1);

      memcpy(n->name,&p[8],n1);
      n->name[n1]='\0';

      if(p[0]&0x80)
        /* The value is human-readable.  */
	{
	  n->value=xmalloc(n2+1);
	  memcpy(n->value,&p[8+n1],n2);
	  n->value[n2]='\0';
          n->flags.human = 1;
	}
      else
        /* Binary data.  */
	{
	  n->bdat=xmalloc(n2);
	  n->blen=n2;
	  memcpy(n->bdat,&p[8+n1],n2);

          n->value = notation_value_to_human_readable_string (n);
	}

      n->flags.critical=crit;

      n->next=list;
      list=n;
    }

  return list;
}

/* Release the resources associated with the *list* of notations.  To
   release a single notation, make sure that notation->next is
   NULL.  */
void
free_notation(struct notation *notation)
{
  while(notation)
    {
      struct notation *n=notation;

      xfree(n->name);
      xfree(n->value);
      xfree(n->altvalue);
      xfree(n->bdat);
      notation=n->next;
      xfree(n);
    }
}

/* Serialize the signature packet (RFC 4880, Section 5.2) described by
   SIG and write it to OUT.  */
static int
do_signature( IOBUF out, int ctb, PKT_signature *sig )
{
  int rc = 0;
  int n, i;
  IOBUF a = iobuf_temp();

  log_assert (ctb_pkttype (ctb) == PKT_SIGNATURE);

  if ( !sig->version || sig->version == 3)
    {
      iobuf_put( a, 3 );

      /* Version 3 packets don't support subpackets.  */
      log_assert (! sig->hashed);
      log_assert (! sig->unhashed);
    }
  else
    iobuf_put( a, sig->version );
  if ( sig->version < 4 )
    iobuf_put (a, 5 ); /* Constant */
  iobuf_put (a, sig->sig_class );
  if ( sig->version < 4 )
    {
      write_32(a, sig->timestamp );
      write_32(a, sig->keyid[0] );
      write_32(a, sig->keyid[1] );
    }
  iobuf_put(a, sig->pubkey_algo );
  iobuf_put(a, sig->digest_algo );
  if ( sig->version >= 4 )
    {
      size_t nn;
      /* Timestamp and keyid must have been packed into the subpackets
	 prior to the call of this function, because these subpackets
	 are hashed. */
      nn = sig->hashed? sig->hashed->len : 0;
      write_16(a, nn);
      if (nn)
        iobuf_write( a, sig->hashed->data, nn );
      nn = sig->unhashed? sig->unhashed->len : 0;
      write_16(a, nn);
      if (nn)
        iobuf_write( a, sig->unhashed->data, nn );
    }
  iobuf_put(a, sig->digest_start[0] );
  iobuf_put(a, sig->digest_start[1] );
  n = pubkey_get_nsig( sig->pubkey_algo );
  if ( !n )
    write_fake_data( a, sig->data[0] );
  for (i=0; i < n && !rc ; i++ )
    rc = gpg_mpi_write (a, sig->data[i] );

  if (!rc)
    {
      if ( is_RSA(sig->pubkey_algo) && sig->version < 4 )
        write_sign_packet_header(out, ctb, iobuf_get_temp_length(a) );
      else
        write_header(out, ctb, iobuf_get_temp_length(a) );
      rc = iobuf_write_temp( out, a );
    }

  iobuf_close(a);
  return rc;
}


/* Serialize the one-pass signature packet (RFC 4880, Section 5.4)
   described by OPS and write it to OUT.  */
static int
do_onepass_sig( IOBUF out, int ctb, PKT_onepass_sig *ops )
{
    log_assert (ctb_pkttype (ctb) == PKT_ONEPASS_SIG);

    write_header(out, ctb, 4 + 8 + 1);

    iobuf_put (out, 3);  /* Version.  */
    iobuf_put(out, ops->sig_class );
    iobuf_put(out, ops->digest_algo );
    iobuf_put(out, ops->pubkey_algo );
    write_32(out, ops->keyid[0] );
    write_32(out, ops->keyid[1] );
    iobuf_put(out, ops->last );

    return 0;
}


/* Write a 16-bit quantity to OUT in big endian order.  */
static int
write_16(IOBUF out, u16 a)
{
    iobuf_put(out, a>>8);
    if( iobuf_put(out,a) )
	return -1;
    return 0;
}

/* Write a 32-bit quantity to OUT in big endian order.  */
static int
write_32(IOBUF out, u32 a)
{
    iobuf_put(out, a>> 24);
    iobuf_put(out, a>> 16);
    iobuf_put(out, a>> 8);
    return iobuf_put(out, a);
}


/****************
 * calculate the length of a header.
 *
 * LEN is the length of the packet's body.  NEW_CTB is whether we are
 * using a new or old format packet.
 *
 * This function does not handle indeterminate lengths or partial body
 * lengths.  (If you pass LEN as 0, then this function assumes you
 * really mean an empty body.)
 */
static int
calc_header_length( u32 len, int new_ctb )
{
    if( new_ctb ) {
	if( len < 192 )
	    return 2;
	if( len < 8384 )
	    return 3;
	else
	    return 6;
    }
    if( len < 256 )
	return 2;
    if( len < 65536 )
	return 3;

    return 5;
}

/****************
 * Write the CTB and the packet length
 */
static int
write_header( IOBUF out, int ctb, u32 len )
{
    return write_header2( out, ctb, len, 0 );
}


static int
write_sign_packet_header (IOBUF out, int ctb, u32 len)
{
  (void)ctb;

  /* Work around a bug in the pgp read function for signature packets,
     which are not correctly coded and silently assume at some point 2
     byte length headers.*/
  iobuf_put (out, 0x89 );
  iobuf_put (out, len >> 8 );
  return iobuf_put (out, len) == -1 ? -1:0;
}

/****************
 * Write a packet header to OUT.
 *
 * CTB is the ctb.  It determines whether a new or old format packet
 * header should be written.  The length field is adjusted, but the
 * CTB is otherwise written out as is.
 *
 * LEN is the length of the packet's body.
 *
 * If HDRLEN is set, then we don't necessarily use the most efficient
 * encoding to store LEN, but the specified length.  (If this is not
 * possible, this is a bug.)  In this case, LEN=0 means a 0 length
 * packet.  Note: setting HDRLEN is only supported for old format
 * packets!
 *
 * If HDRLEN is not set, then the shortest encoding is used.  In this
 * case, LEN=0 means the body has an indeterminate length and a
 * partial body length header (if a new format packet) or an
 * indeterminate length header (if an old format packet) is written
 * out.  Further, if using partial body lengths, this enables partial
 * body length mode on OUT.
 */
static int
write_header2( IOBUF out, int ctb, u32 len, int hdrlen )
{
  if (ctb_new_format_p (ctb))
    return write_new_header( out, ctb, len, hdrlen );

  /* An old format packet.  Refer to RFC 4880, Section 4.2.1 to
     understand how lengths are encoded in this case.  */

  /* The length encoding is stored in the two least significant bits.
     Make sure they are cleared.  */
  log_assert ((ctb & 3) == 0);

  log_assert (hdrlen == 0 || hdrlen == 2 || hdrlen == 3 || hdrlen == 5);

  if (hdrlen)
    /* Header length is given.  */
    {
      if( hdrlen == 2 && len < 256 )
        /* 00 => 1 byte length.  */
	;
      else if( hdrlen == 3 && len < 65536 )
        /* 01 => 2 byte length.  If len < 256, this is not the most
           compact encoding, but it is a correct encoding.  */
	ctb |= 1;
      else if (hdrlen == 5)
        /* 10 => 4 byte length.  If len < 65536, this is not the most
           compact encoding, but it is a correct encoding.  */
	ctb |= 2;
      else
        log_bug ("Can't encode length=%d in a %d byte header!\n",
                 len, hdrlen);
    }
  else
    {
      if( !len )
        /* 11 => Indeterminate length.  */
	ctb |= 3;
      else if( len < 256 )
        /* 00 => 1 byte length.  */
	;
      else if( len < 65536 )
        /* 01 => 2 byte length.  */
	ctb |= 1;
      else
        /* 10 => 4 byte length.  */
	ctb |= 2;
    }

  if( iobuf_put(out, ctb ) )
    return -1;

  if( len || hdrlen )
    {
      if( ctb & 2 )
	{
	  if(iobuf_put(out, len >> 24 ))
	    return -1;
	  if(iobuf_put(out, len >> 16 ))
	    return -1;
	}

      if( ctb & 3 )
	if(iobuf_put(out, len >> 8 ))
	  return -1;

      if( iobuf_put(out, len ) )
	return -1;
    }

  return 0;
}


/* Write a new format header to OUT.

   CTB is the ctb.

   LEN is the length of the packet's body.  If LEN is 0, then enables
   partial body length mode (i.e., the body is of an indeterminant
   length) on OUT.  Note: this function cannot be used to generate a
   header for a zero length packet.

   HDRLEN is the length of the packet's header.  If HDRLEN is 0, the
   shortest encoding is chosen based on the length of the packet's
   body.  Currently, values other than 0 are not supported.

   Returns 0 on success.  */
static int
write_new_header( IOBUF out, int ctb, u32 len, int hdrlen )
{
    if( hdrlen )
	log_bug("can't cope with hdrlen yet\n");

    if( iobuf_put(out, ctb ) )
	return -1;
    if( !len ) {
	iobuf_set_partial_body_length_mode(out, 512 );
    }
    else {
	if( len < 192 ) {
	    if( iobuf_put(out, len ) )
		return -1;
	}
	else if( len < 8384 ) {
	    len -= 192;
	    if( iobuf_put( out, (len / 256) + 192) )
		return -1;
	    if( iobuf_put( out, (len % 256) )  )
		return -1;
	}
	else {
	    if( iobuf_put( out, 0xff ) )
		return -1;
	    if( iobuf_put( out, (len >> 24)&0xff ) )
		return -1;
	    if( iobuf_put( out, (len >> 16)&0xff ) )
		return -1;
	    if( iobuf_put( out, (len >> 8)&0xff )  )
		return -1;
	    if( iobuf_put( out, len & 0xff ) )
		return -1;
	}
    }
    return 0;
}
