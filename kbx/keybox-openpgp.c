/* keybox-openpgp.c - OpenPGP key parsing
 * Copyright (C) 2001, 2003, 2011 Free Software Foundation, Inc.
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

#include "../common/openpgpdefs.h"
#include "../common/host2net.h"

struct keyparm_s
{
  const char *mpi;
  int len;   /* int to avoid a cast in gcry_sexp_build.  */
};


/* Assume a valid OpenPGP packet at the address pointed to by BUFBTR
   which has a maximum length as stored at BUFLEN.  Return the header
   information of that packet and advance the pointer stored at BUFPTR
   to the next packet; also adjust the length stored at BUFLEN to
   match the remaining bytes. If there are no more packets, store NULL
   at BUFPTR.  Return an non-zero error code on failure or the
   following data on success:

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
          pktlen = buf32_to_ulong (buf);
          buf += 4;
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

  if (pkttype == 63 && pktlen == 0xFFFFFFFF)
    /* Sometimes the decompressing layer enters an error state in
       which it simply outputs 0xff for every byte read.  If we have a
       stream of 0xff bytes, then it will be detected as a new format
       packet with type 63 and a 4-byte encoded length that is 4G-1.
       Since packets with type 63 are private and we use them as a
       control packet, which won't be 4 GB, we reject such packets as
       invalid.  */
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


/* Take a list of key parameters KP for the OpenPGP ALGO and compute
 * the keygrip which will be stored at GRIP.  GRIP needs to be a
 * buffer of 20 bytes.  */
static gpg_error_t
keygrip_from_keyparm (int algo, struct keyparm_s *kp, unsigned char *grip)
{
  gpg_error_t err;
  gcry_sexp_t s_pkey = NULL;

  switch (algo)
    {
    case PUBKEY_ALGO_DSA:
      err = gcry_sexp_build (&s_pkey, NULL,
                             "(public-key(dsa(p%b)(q%b)(g%b)(y%b)))",
                             kp[0].len, kp[0].mpi,
                             kp[1].len, kp[1].mpi,
                             kp[2].len, kp[2].mpi,
                             kp[3].len, kp[3].mpi);
      break;

    case PUBKEY_ALGO_ELGAMAL:
    case PUBKEY_ALGO_ELGAMAL_E:
      err = gcry_sexp_build (&s_pkey, NULL,
                             "(public-key(elg(p%b)(g%b)(y%b)))",
                             kp[0].len, kp[0].mpi,
                             kp[1].len, kp[1].mpi,
                             kp[2].len, kp[2].mpi);
      break;

    case PUBKEY_ALGO_RSA:
    case PUBKEY_ALGO_RSA_S:
    case PUBKEY_ALGO_RSA_E:
      err = gcry_sexp_build (&s_pkey, NULL,
                             "(public-key(rsa(n%b)(e%b)))",
                             kp[0].len, kp[0].mpi,
                             kp[1].len, kp[1].mpi);
      break;

    case PUBKEY_ALGO_EDDSA:
    case PUBKEY_ALGO_ECDSA:
    case PUBKEY_ALGO_ECDH:
      {
        char *curve = openpgp_oidbuf_to_str (kp[0].mpi, kp[0].len);
        if (!curve)
          err = gpg_error_from_syserror ();
        else
          {
            err = gcry_sexp_build
              (&s_pkey, NULL,
               (algo == PUBKEY_ALGO_EDDSA)?
               "(public-key(ecc(curve%s)(flags eddsa)(q%b)))":
               (algo == PUBKEY_ALGO_ECDH
                && openpgp_oidbuf_is_cv25519 (kp[0].mpi, kp[0].len))?
               "(public-key(ecc(curve%s)(flags djb-tweak)(q%b)))":
               "(public-key(ecc(curve%s)(q%b)))",
               curve, kp[1].len, kp[1].mpi);
            xfree (curve);
          }
      }
      break;

    default:
      err = gpg_error (GPG_ERR_PUBKEY_ALGO);
      break;
    }

  if (!err && !gcry_pk_get_keygrip (s_pkey, grip))
    {
      /* Some Linux distributions remove certain curves from Libgcrypt
       * but not from GnuPG and thus the keygrip can't be computed.
       * Emit a better error message for this case.  */
      if (!gcry_pk_get_curve (s_pkey, 0, NULL))
        err = gpg_error (GPG_ERR_UNKNOWN_CURVE);
      else
        {
          log_info ("kbx: error computing keygrip\n");
          err = gpg_error (GPG_ERR_GENERAL);
        }
    }

  gcry_sexp_release (s_pkey);

  if (err)
    memset (grip, 0, 20);
  return err;
}


/* Parse a key packet and store the information in KI. */
static gpg_error_t
parse_key (const unsigned char *data, size_t datalen,
           struct _keybox_openpgp_key_info *ki)
{
  gpg_error_t err;
  const unsigned char *data_start = data;
  int i, version, algorithm;
  size_t n;
  int npkey;
  unsigned char hashbuffer[768];
  gcry_md_hd_t md;
  int is_ecc = 0;
  struct keyparm_s keyparm[OPENPGP_MAX_NPKEY];
  unsigned char *helpmpibuf[OPENPGP_MAX_NPKEY] = { NULL };

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
      data +=2; datalen -= 2;
    }

  if (!datalen)
    return gpg_error (GPG_ERR_INV_PACKET);
  algorithm = *data++; datalen--;

  switch (algorithm)
    {
    case PUBKEY_ALGO_RSA:
    case PUBKEY_ALGO_RSA_E:
    case PUBKEY_ALGO_RSA_S:
      npkey = 2;
      break;
    case PUBKEY_ALGO_ELGAMAL_E:
    case PUBKEY_ALGO_ELGAMAL:
      npkey = 3;
      break;
    case PUBKEY_ALGO_DSA:
      npkey = 4;
      break;
    case PUBKEY_ALGO_ECDH:
      npkey = 3;
      is_ecc = 1;
      break;
    case PUBKEY_ALGO_ECDSA:
    case PUBKEY_ALGO_EDDSA:
      npkey = 2;
      is_ecc = 1;
      break;
    default: /* Unknown algorithm. */
      return gpg_error (GPG_ERR_UNKNOWN_ALGORITHM);
    }

  ki->algo = algorithm;

  for (i=0; i < npkey; i++ )
    {
      unsigned int nbits, nbytes;

      if (datalen < 2)
        return gpg_error (GPG_ERR_INV_PACKET);

      if (is_ecc && (i == 0 || i == 2))
        {
          nbytes = data[0];
          if (nbytes < 2 || nbytes > 254)
            return gpg_error (GPG_ERR_INV_PACKET);
          nbytes++; /* The size byte itself.  */
          if (datalen < nbytes)
            return gpg_error (GPG_ERR_INV_PACKET);

          keyparm[i].mpi = data;
          keyparm[i].len = nbytes;
        }
      else
        {
          nbits = ((data[0]<<8)|(data[1]));
          data += 2;
          datalen -= 2;
          nbytes = (nbits+7) / 8;
          if (datalen < nbytes)
            return gpg_error (GPG_ERR_INV_PACKET);

          keyparm[i].mpi = data;
          keyparm[i].len = nbytes;
        }

      data += nbytes; datalen -= nbytes;
    }
  n = data - data_start;


  /* Note: Starting here we need to jump to leave on error. */

  /* Make sure the MPIs are unsigned.  */
  for (i=0; i < npkey; i++)
    {
      if (!keyparm[i].len || (keyparm[i].mpi[0] & 0x80))
        {
          helpmpibuf[i] = xtrymalloc (1+keyparm[i].len);
          if (!helpmpibuf[i])
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          helpmpibuf[i][0] = 0;
          memcpy (helpmpibuf[i]+1, keyparm[i].mpi, keyparm[i].len);
          keyparm[i].mpi = helpmpibuf[i];
          keyparm[i].len++;
        }
    }

  err = keygrip_from_keyparm (algorithm, keyparm, ki->grip);
  if (err)
    goto leave;

  if (version < 4)
    {
      /* We do not support any other algorithm than RSA in v3
         packets. */
      if (algorithm < 1 || algorithm > 3)
        return gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);

      err = gcry_md_open (&md, GCRY_MD_MD5, 0);
      if (err)
        return err; /* Oops */
      gcry_md_write (md, keyparm[0].mpi, keyparm[0].len);
      gcry_md_write (md, keyparm[1].mpi, keyparm[1].len);
      memcpy (ki->fpr, gcry_md_read (md, 0), 16);
      gcry_md_close (md);
      ki->fprlen = 16;

      if (keyparm[0].len < 8)
        {
          /* Moduli less than 64 bit are out of the specs scope.  Zero
             them out because this is what gpg does too. */
          memset (ki->keyid, 0, 8);
        }
      else
        memcpy (ki->keyid, keyparm[0].mpi + keyparm[0].len - 8, 8);
    }
  else
    {
      /* Its a pity that we need to prefix the buffer with the tag
         and a length header: We can't simply pass it to the fast
         hashing function for that reason.  It might be a good idea to
         have a scatter-gather enabled hash function. What we do here
         is to use a static buffer if this one is large enough and
         only use the regular hash functions if this buffer is not
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

 leave:
  for (i=0; i < npkey; i++)
    xfree (helpmpibuf[i]);

  return err;
}



/* The caller must pass the address of an INFO structure which will
   get filled on success with information pertaining to the OpenPGP
   keyblock IMAGE of length IMAGELEN.  Note that a caller does only
   need to release this INFO structure if the function returns
   success.  If NPARSED is not NULL the actual number of bytes parsed
   will be stored at this address.  */
gpg_error_t
_keybox_parse_openpgp (const unsigned char *image, size_t imagelen,
                       size_t *nparsed, keybox_openpgp_info_t info)
{
  gpg_error_t err = 0;
  const unsigned char *image_start, *data;
  size_t n, datalen;
  int pkttype;
  int first = 1;
  int read_error = 0;
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
        {
          read_error = 1;
          break;
        }

      if (first)
        {
          if (pkttype == PKT_PUBLIC_KEY)
            ;
          else if (pkttype == PKT_SECRET_KEY)
            info->is_secret = 1;
          else
            {
              err = gpg_error (GPG_ERR_UNEXPECTED);
              if (nparsed)
                *nparsed += n;
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
                  /* We ignore subkeys with unknown algorithms. */
                  if (gpg_err_code (err) == GPG_ERR_UNKNOWN_ALGORITHM
                      || gpg_err_code (err) == GPG_ERR_UNSUPPORTED_ALGORITHM)
                    err = 0;
                  if (err)
                    break;
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
                  /* We ignore subkeys with unknown algorithms. */
                  if (gpg_err_code (err) == GPG_ERR_UNKNOWN_ALGORITHM
                      || gpg_err_code (err) == GPG_ERR_UNSUPPORTED_ALGORITHM)
                    err = 0;
                  if (err)
                    break;
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
      if (!read_error)
        {
          /* Packet parsing worked, thus we should be able to skip the
             rest of the keyblock.  */
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
