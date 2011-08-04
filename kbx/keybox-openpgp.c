/* keybox-openpgp.c - OpenPGP key parsing
 *	Copyright (C) 2001, 2003 Free Software Foundation, Inc.
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

/* This is a simple OpenPGP parser suitable for all OpenPGP key
   material.  It just provides the functionality required to build and
   parse an KBX OpenPGP key blob.  Thus it is not a complete parser.
   However it is self-contained and optimized for fast in-memory
   parsing.  Note that we don't support old ElGamal v3 keys
   anymore. */

#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "keybox-defs.h"

#include <gcrypt.h>


enum packet_types
  {
    PKT_NONE	           =0,
    PKT_PUBKEY_ENC	   =1, /* public key encrypted packet */
    PKT_SIGNATURE	   =2, /* secret key encrypted packet */
    PKT_SYMKEY_ENC	   =3, /* session key packet (OpenPGP)*/
    PKT_ONEPASS_SIG        =4, /* one pass sig packet (OpenPGP)*/
    PKT_SECRET_KEY	   =5, /* secret key */
    PKT_PUBLIC_KEY	   =6, /* public key */
    PKT_SECRET_SUBKEY      =7, /* secret subkey (OpenPGP) */
    PKT_COMPRESSED	   =8, /* compressed data packet */
    PKT_ENCRYPTED	   =9, /* conventional encrypted data */
    PKT_MARKER	          =10, /* marker packet (OpenPGP) */
    PKT_PLAINTEXT	  =11, /* plaintext data with filename and mode */
    PKT_RING_TRUST	  =12, /* keyring trust packet */
    PKT_USER_ID	          =13, /* user id packet */
    PKT_PUBLIC_SUBKEY     =14, /* public subkey (OpenPGP) */
    PKT_OLD_COMMENT       =16, /* comment packet from an OpenPGP draft */
    PKT_ATTRIBUTE         =17, /* PGP's attribute packet */
    PKT_ENCRYPTED_MDC     =18, /* integrity protected encrypted data */
    PKT_MDC 	          =19, /* manipulation detection code packet */
    PKT_COMMENT	          =61, /* new comment packet (private) */
    PKT_GPG_CONTROL       =63  /* internal control packet */
  };



/* Assume a valid OpenPGP packet at the address pointed to by BUFBTR
   which is of amaximum length as stored at BUFLEN.  Return the header
   information of that packet and advance the pointer stored at BUFPTR
   to the next packet; also adjust the length stored at BUFLEN to
   match the remaining bytes. If there are no more packets, store NULL
   at BUFPTR.  Return an non-zero error code on failure or the
   follwing data on success:

   R_DATAPKT = Pointer to the begin of the packet data.
   R_DATALEN = Length of this data.  This has already been checked to fit
               into the buffer.
   R_PKTTYPE = The packet type.
   R_NTOTAL  = The total number of bytes of this packet

   Note that these values are only updated on success.
*/
static gpg_error_t
next_packet (unsigned char const **bufptr, size_t *buflen,
             unsigned char const **r_data, size_t *r_datalen, int *r_pkttype,
             size_t *r_ntotal)
{
  const unsigned char *buf = *bufptr;
  size_t len = *buflen;
  int c, ctb, pkttype;
  unsigned long pktlen;

  if (!len)
    return gpg_error (GPG_ERR_NO_DATA);

  ctb = *buf++; len--;
  if ( !(ctb & 0x80) )
    return gpg_error (GPG_ERR_INV_PACKET); /* Invalid CTB. */

  pktlen = 0;
  if ((ctb & 0x40))  /* New style (OpenPGP) CTB.  */
    {
      pkttype = (ctb & 0x3f);
      if (!len)
        return gpg_error (GPG_ERR_INV_PACKET); /* No 1st length byte. */
      c = *buf++; len--;
      if (pkttype == PKT_COMPRESSED)
        return gpg_error (GPG_ERR_UNEXPECTED); /* ... packet in a keyblock. */
      if ( c < 192 )
        pktlen = c;
      else if ( c < 224 )
        {
          pktlen = (c - 192) * 256;
          if (!len)
            return gpg_error (GPG_ERR_INV_PACKET); /* No 2nd length byte. */
          c = *buf++; len--;
          pktlen += c + 192;
        }
      else if (c == 255)
        {
          if (len <4 )
            return gpg_error (GPG_ERR_INV_PACKET); /* No length bytes. */
          pktlen  = (*buf++) << 24;
          pktlen |= (*buf++) << 16;
          pktlen |= (*buf++) << 8;
          pktlen |= (*buf++);
          len -= 4;
      }
      else /* Partial length encoding is not allowed for key packets. */
        return gpg_error (GPG_ERR_UNEXPECTED);
    }
  else /* Old style CTB.  */
    {
      int lenbytes;

      pktlen = 0;
      pkttype = (ctb>>2)&0xf;
      lenbytes = ((ctb&3)==3)? 0 : (1<<(ctb & 3));
      if (!lenbytes) /* Not allowed in key packets.  */
        return gpg_error (GPG_ERR_UNEXPECTED);
      if (len < lenbytes)
        return gpg_error (GPG_ERR_INV_PACKET); /* Not enough length bytes.  */
      for (; lenbytes; lenbytes--)
        {
          pktlen <<= 8;
          pktlen |= *buf++; len--;
	}
    }

  /* Do some basic sanity check.  */
  switch (pkttype)
    {
    case PKT_SIGNATURE:
    case PKT_SECRET_KEY:
    case PKT_PUBLIC_KEY:
    case PKT_SECRET_SUBKEY:
    case PKT_MARKER:
    case PKT_RING_TRUST:
    case PKT_USER_ID:
    case PKT_PUBLIC_SUBKEY:
    case PKT_OLD_COMMENT:
    case PKT_ATTRIBUTE:
    case PKT_COMMENT:
    case PKT_GPG_CONTROL:
      break; /* Okay these are allowed packets. */
    default:
      return gpg_error (GPG_ERR_UNEXPECTED);
    }

  if (pktlen == 0xffffffff)
      return gpg_error (GPG_ERR_INV_PACKET);

  if (pktlen > len)
    return gpg_error (GPG_ERR_INV_PACKET); /* Packet length header too long. */

  *r_data = buf;
  *r_datalen = pktlen;
  *r_pkttype = pkttype;
  *r_ntotal = (buf - *bufptr) + pktlen;

  *bufptr = buf + pktlen;
  *buflen = len - pktlen;
  if (!*buflen)
    *bufptr = NULL;

  return 0;
}


/* Parse a key packet and store the ionformation in KI. */
static gpg_error_t
parse_key (const unsigned char *data, size_t datalen,
           struct _keybox_openpgp_key_info *ki)
{
  gpg_error_t err;
  const unsigned char *data_start = data;
  int i, version, algorithm;
  size_t n;
  /*unsigned long timestamp;*/
  int npkey;
  unsigned char hashbuffer[768];
  const unsigned char *mpi_n = NULL;
  size_t mpi_n_len = 0, mpi_e_len = 0;
  gcry_md_hd_t md;

  if (datalen < 5)
    return gpg_error (GPG_ERR_INV_PACKET);
  version = *data++; datalen--;
  if (version < 2 || version > 4 )
    return gpg_error (GPG_ERR_INV_PACKET); /* Invalid version. */

  /*timestamp = ((data[0]<<24)|(data[1]<<16)|(data[2]<<8)|(data[3]));*/
  data +=4; datalen -=4;

  if (version < 4)
    {
      if (datalen < 2)
        return gpg_error (GPG_ERR_INV_PACKET);
      data += 2; datalen -= 2;
    }

  if (!datalen)
    return gpg_error (GPG_ERR_INV_PACKET);
  algorithm = *data++; datalen--;

  switch (algorithm)
    {
    case 1:
    case 2:
    case 3: /* RSA */
      npkey = 2;
      break;
    case 16:
    case 20: /* Elgamal */
      npkey = 3;
      break;
    case 17: /* DSA */
      npkey = 4;
      break;
    default: /* Unknown algorithm. */
      return gpg_error (GPG_ERR_UNKNOWN_ALGORITHM);
    }

  for (i=0; i < npkey; i++ )
    {
      unsigned int nbits, nbytes;

      if (datalen < 2)
        return gpg_error (GPG_ERR_INV_PACKET);
      nbits = ((data[0]<<8)|(data[1]));
      data += 2; datalen -=2;
      nbytes = (nbits+7) / 8;
      if (datalen < nbytes)
        return gpg_error (GPG_ERR_INV_PACKET);
      /* For use by v3 fingerprint calculation we need to know the RSA
         modulus and exponent. */
      if (i==0)
        {
          mpi_n = data;
          mpi_n_len = nbytes;
        }
      else if (i==1)
        mpi_e_len = nbytes;

      data += nbytes; datalen -= nbytes;
    }
  n = data - data_start;

  if (version < 4)
    {
      /* We do not support any other algorithm than RSA in v3
         packets. */
      if (algorithm < 1 || algorithm > 3)
        return gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);

      err = gcry_md_open (&md, GCRY_MD_MD5, 0);
      if (err)
        return err; /* Oops */
      gcry_md_write (md, mpi_n, mpi_n_len);
      gcry_md_write (md, mpi_n+mpi_n_len+2, mpi_e_len);
      memcpy (ki->fpr, gcry_md_read (md, 0), 16);
      gcry_md_close (md);
      ki->fprlen = 16;

      if (mpi_n_len < 8)
        {
          /* Moduli less than 64 bit are out of the specs scope.  Zero
             them out becuase this is what gpg does too. */
          memset (ki->keyid, 0, 8);
        }
      else
        memcpy (ki->keyid, mpi_n + mpi_n_len - 8, 8);
    }
  else
    {
      /* Its a pitty that we need to prefix the buffer with the tag
         and a length header: We can't simply pass it to the fast
         hashing fucntion for that reason.  It might be a good idea to
         have a scatter-gather enabled hash function. What we do here
         is to use a static buffer if this one is large enough and
         only use the regular hash fucntions if this buffer is not
         large enough. */
      if ( 3 + n < sizeof hashbuffer )
        {
          hashbuffer[0] = 0x99;     /* CTB */
          hashbuffer[1] = (n >> 8); /* 2 byte length header. */
          hashbuffer[2] = n;
          memcpy (hashbuffer + 3, data_start, n);
          gcry_md_hash_buffer (GCRY_MD_SHA1, ki->fpr, hashbuffer, 3 + n);
        }
      else
        {
          err = gcry_md_open (&md, GCRY_MD_SHA1, 0);
          if (err)
            return err; /* Oops */
          gcry_md_putc (md, 0x99 );     /* CTB */
          gcry_md_putc (md, (n >> 8) ); /* 2 byte length header. */
          gcry_md_putc (md, n );
          gcry_md_write (md, data_start, n);
          memcpy (ki->fpr, gcry_md_read (md, 0), 20);
          gcry_md_close (md);
        }
      ki->fprlen = 20;
      memcpy (ki->keyid, ki->fpr+12, 8);
    }

  return 0;
}



/* The caller must pass the address of an INFO structure which will
   get filled on success with information pertaining to the OpenPGP
   keyblock IMAGE of length IMAGELEN.  Note that a caller does only
   need to release this INFO structure when the function returns
   success.  If NPARSED is not NULL the actual number of bytes parsed
   will be stored at this address.  */
gpg_error_t
_keybox_parse_openpgp (const unsigned char *image, size_t imagelen,
                       size_t *nparsed,
                       keybox_openpgp_info_t info)
{
  gpg_error_t err = 0;
  const unsigned char *image_start, *data;
  size_t n, datalen;
  int pkttype;
  int first = 1;
  struct _keybox_openpgp_key_info *k, **ktail = NULL;
  struct _keybox_openpgp_uid_info *u, **utail = NULL;

  memset (info, 0, sizeof *info);
  if (nparsed)
    *nparsed = 0;

  image_start = image;
  while (image)
    {
      err = next_packet (&image, &imagelen, &data, &datalen, &pkttype, &n);
      if (err)
        break;

      if (first)
        {
          if (pkttype == PKT_PUBLIC_KEY)
            ;
          else if (pkttype == PKT_SECRET_KEY)
            info->is_secret = 1;
          else
            {
              err = gpg_error (GPG_ERR_UNEXPECTED);
              break;
            }
          first = 0;
        }
      else if (pkttype == PKT_PUBLIC_KEY || pkttype == PKT_SECRET_KEY)
        break; /* Next keyblock encountered - ready. */

      if (nparsed)
        *nparsed += n;

      if (pkttype == PKT_SIGNATURE)
        {
          /* For now we only count the total number of signatures. */
          info->nsigs++;
        }
      else if (pkttype == PKT_USER_ID)
        {
          info->nuids++;
          if (info->nuids == 1)
            {
              info->uids.off = data - image_start;
              info->uids.len = datalen;
              utail = &info->uids.next;
            }
          else
            {
              u = xtrycalloc (1, sizeof *u);
              if (!u)
                {
                  err = gpg_error_from_syserror ();
                  break;
                }
              u->off = data - image_start;
              u->len = datalen;
              *utail = u;
              utail = &u->next;
            }
        }
      else if (pkttype == PKT_PUBLIC_KEY || pkttype == PKT_SECRET_KEY)
        {
          err = parse_key (data, datalen, &info->primary);
          if (err)
            break;
        }
      else if( pkttype == PKT_PUBLIC_SUBKEY && datalen && *data == '#' )
        {
          /* Early versions of GnuPG used old PGP comment packets;
           * luckily all those comments are prefixed by a hash
           * sign - ignore these packets. */
        }
      else if (pkttype == PKT_PUBLIC_SUBKEY || pkttype == PKT_SECRET_SUBKEY)
        {
          info->nsubkeys++;
          if (info->nsubkeys == 1)
            {
              err = parse_key (data, datalen, &info->subkeys);
              if (err)
                {
                  info->nsubkeys--;
                  if (gpg_err_code (err) != GPG_ERR_UNKNOWN_ALGORITHM)
                    break;
                  /* We ignore subkeys with unknown algorithms. */
                }
              else
                ktail = &info->subkeys.next;
            }
          else
            {
              k = xtrycalloc (1, sizeof *k);
              if (!k)
                {
                  err = gpg_error_from_syserror ();
                  break;
                }
              err = parse_key (data, datalen, k);
              if (err)
                {
                  xfree (k);
                  info->nsubkeys--;
                  if (gpg_err_code (err) != GPG_ERR_UNKNOWN_ALGORITHM)
                    break;
                  /* We ignore subkeys with unknown algorithms. */
                }
              else
                {
                  *ktail = k;
                  ktail = &k->next;
                }
            }
        }
    }

  if (err)
    {
      _keybox_destroy_openpgp_info (info);
      if (!first
          && (gpg_err_code (err) == GPG_ERR_UNSUPPORTED_ALGORITHM
              || gpg_err_code (err) == GPG_ERR_UNKNOWN_ALGORITHM))
        {
          /* We are able to skip to the end of this keyblock. */
          while (image)
            {
              if (next_packet (&image, &imagelen,
                               &data, &datalen, &pkttype, &n) )
                break; /* Another error - stop here. */

              if (pkttype == PKT_PUBLIC_KEY || pkttype == PKT_SECRET_KEY)
                break; /* Next keyblock encountered - ready. */

              if (nparsed)
                *nparsed += n;
            }
        }
    }

  return err;
}


/* Release any malloced data in INFO but not INFO itself! */
void
_keybox_destroy_openpgp_info (keybox_openpgp_info_t info)
{
  struct _keybox_openpgp_key_info *k, *k2;
  struct _keybox_openpgp_uid_info *u, *u2;

  assert (!info->primary.next);
  for (k=info->subkeys.next; k; k = k2)
    {
      k2 = k->next;
      xfree (k);
    }

  for (u=info->uids.next; u; u = u2)
    {
      u2 = u->next;
      xfree (u);
    }
}
