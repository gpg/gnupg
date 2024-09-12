/* parse-packet.c  - read packets
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
 *               2007, 2009, 2010 Free Software Foundation, Inc.
 * Copyright (C) 2014 Werner Koch
 * Copyright (C) 2015 g10 Code GmbH
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
#include "filter.h"
#include "photoid.h"
#include "options.h"
#include "main.h"
#include "../common/i18n.h"
#include "../common/host2net.h"
#include "../common/mbox-util.h"


static int mpi_print_mode;
static int list_mode;
static estream_t listfp;

/* A linked list of known notation names.  Note that the FLAG is used
 * to store the length of the name to speed up the check.  */
static strlist_t known_notations_list;


static int parse (parse_packet_ctx_t ctx, PACKET *pkt, int onlykeypkts,
		  off_t * retpos, int *skip, IOBUF out, int do_skip
#if DEBUG_PARSE_PACKET
		  , const char *dbg_w, const char *dbg_f, int dbg_l
#endif
  );
static int copy_packet (IOBUF inp, IOBUF out, int pkttype,
			unsigned long pktlen, int partial);
static void skip_packet (IOBUF inp, int pkttype,
			 unsigned long pktlen, int partial);
static void *read_rest (IOBUF inp, size_t pktlen);
static int parse_marker (IOBUF inp, int pkttype, unsigned long pktlen);
static int parse_symkeyenc (IOBUF inp, int pkttype, unsigned long pktlen,
			    PACKET * packet);
static int parse_pubkeyenc (IOBUF inp, int pkttype, unsigned long pktlen,
			    PACKET * packet);
static int parse_onepass_sig (IOBUF inp, int pkttype, unsigned long pktlen,
			      PKT_onepass_sig * ops);
static int parse_key (IOBUF inp, int pkttype, unsigned long pktlen,
		      byte * hdr, int hdrlen, PACKET * packet);
static int parse_user_id (IOBUF inp, int pkttype, unsigned long pktlen,
			  PACKET * packet);
static int parse_attribute (IOBUF inp, int pkttype, unsigned long pktlen,
			    PACKET * packet);
static int parse_comment (IOBUF inp, int pkttype, unsigned long pktlen,
			  PACKET * packet);
static gpg_error_t parse_ring_trust (parse_packet_ctx_t ctx,
                                     unsigned long pktlen);
static int parse_plaintext (IOBUF inp, int pkttype, unsigned long pktlen,
			    PACKET * packet, int new_ctb, int partial);
static int parse_compressed (IOBUF inp, int pkttype, unsigned long pktlen,
			     PACKET * packet, int new_ctb);
static int parse_encrypted (IOBUF inp, int pkttype, unsigned long pktlen,
			    PACKET * packet, int new_ctb, int partial);
static gpg_error_t parse_encrypted_aead (IOBUF inp, int pkttype,
                                         unsigned long pktlen, PACKET *packet,
                                         int partial);
static int parse_mdc (IOBUF inp, int pkttype, unsigned long pktlen,
		      PACKET * packet, int new_ctb);
static int parse_gpg_control (IOBUF inp, int pkttype, unsigned long pktlen,
			      PACKET * packet, int partial);

/* Read a 16-bit value in MSB order (big endian) from an iobuf.  */
static unsigned short
read_16 (IOBUF inp)
{
  unsigned short a;
  a = (unsigned short)iobuf_get_noeof (inp) << 8;
  a |= iobuf_get_noeof (inp);
  return a;
}


/* Read a 32-bit value in MSB order (big endian) from an iobuf.  */
static unsigned long
read_32 (IOBUF inp)
{
  unsigned long a;
  a = (unsigned long)iobuf_get_noeof (inp) << 24;
  a |= iobuf_get_noeof (inp) << 16;
  a |= iobuf_get_noeof (inp) << 8;
  a |= iobuf_get_noeof (inp);
  return a;
}


/* Read an external representation of an MPI and return the MPI.  The
   external format is a 16-bit unsigned value stored in network byte
   order giving the number of bits for the following integer.  The
   integer is stored MSB first and is left padded with zero bits to
   align on a byte boundary.

   The caller must set *RET_NREAD to the maximum number of bytes to
   read from the pipeline INP.  This function sets *RET_NREAD to be
   the number of bytes actually read from the pipeline.

   If SECURE is true, the integer is stored in secure memory
   (allocated using gcry_xmalloc_secure).  */
static gcry_mpi_t
mpi_read (iobuf_t inp, unsigned int *ret_nread, int secure)
{
  int c, c1, c2, i;
  unsigned int nmax = *ret_nread;
  unsigned int nbits, nbytes;
  size_t nread = 0;
  gcry_mpi_t a = NULL;
  byte *buf = NULL;
  byte *p;

  if (!nmax)
    goto overflow;

  if ((c = c1 = iobuf_get (inp)) == -1)
    goto leave;
  if (++nread == nmax)
    goto overflow;
  nbits = c << 8;
  if ((c = c2 = iobuf_get (inp)) == -1)
    goto leave;
  ++nread;
  nbits |= c;
  if (nbits > MAX_EXTERN_MPI_BITS)
    {
      log_error ("mpi too large (%u bits)\n", nbits);
      goto leave;
    }

  nbytes = (nbits + 7) / 8;
  buf = secure ? gcry_xmalloc_secure (nbytes + 2) : gcry_xmalloc (nbytes + 2);
  p = buf;
  p[0] = c1;
  p[1] = c2;
  for (i = 0; i < nbytes; i++)
    {
      if (nread == nmax)
	goto overflow;

      c = iobuf_get (inp);
      if (c == -1)
	goto leave;

      p[i + 2] = c;
      nread ++;
    }

  if (gcry_mpi_scan (&a, GCRYMPI_FMT_PGP, buf, nread, &nread))
    a = NULL;

  *ret_nread = nread;
  gcry_free(buf);
  return a;

 overflow:
  log_error ("mpi larger than indicated length (%u bits)\n", 8*nmax);
 leave:
  *ret_nread = nread;
  gcry_free(buf);
  return a;
}


/* Read an external representation (which is possibly an SOS) and
   return the MPI.  The external format is a 16-bit unsigned value
   stored in network byte order giving information for the following
   octets.

   The caller must set *RET_NREAD to the maximum number of bytes to
   read from the pipeline INP.  This function sets *RET_NREAD to be
   the number of bytes actually read from the pipeline.

   If SECURE is true, the integer is stored in secure memory
   (allocated using gcry_xmalloc_secure).  */
static gcry_mpi_t
mpi_read_detect_0_removal (iobuf_t inp, unsigned int *ret_nread, int secure,
                           u16 *r_csum_tweak)
{
  int c, c1, c2, i;
  unsigned int nmax = *ret_nread;
  unsigned int nbits, nbits1, nbytes;
  size_t nread = 0;
  gcry_mpi_t a = NULL;
  byte *buf = NULL;
  byte *p;

  if (!nmax)
    goto overflow;

  if ((c = c1 = iobuf_get (inp)) == -1)
    goto leave;
  if (++nread == nmax)
    goto overflow;
  nbits = c << 8;
  if ((c = c2 = iobuf_get (inp)) == -1)
    goto leave;
  ++nread;
  nbits |= c;
  if (nbits > MAX_EXTERN_MPI_BITS)
    {
      log_error ("mpi too large (%u bits)\n", nbits);
      goto leave;
    }

  nbytes = (nbits + 7) / 8;
  buf = secure ? gcry_xmalloc_secure (nbytes + 2) : gcry_xmalloc (nbytes + 2);
  p = buf;
  p[0] = c1;
  p[1] = c2;
  for (i = 0; i < nbytes; i++)
    {
      if (nread == nmax)
        goto overflow;

      c = iobuf_get (inp);
      if (c == -1)
        goto leave;

      p[i + 2] = c;

      nread ++;
    }

  if (gcry_mpi_scan (&a, GCRYMPI_FMT_PGP, buf, nread, &nread))
    a = NULL;

  /* Possibly, it has leading zeros.  */
  if (a)
    {
      nbits1 = gcry_mpi_get_nbits (a);
      if (nbits > nbits1)
        {
          *r_csum_tweak -= (nbits >> 8);
          *r_csum_tweak -= (nbits & 0xff);
          *r_csum_tweak += (nbits1 >> 8);
          *r_csum_tweak += (nbits1 & 0xff);
        }
    }

  *ret_nread = nread;
  gcry_free(buf);
  return a;

 overflow:
  log_error ("mpi larger than indicated length (%u bits)\n", 8*nmax);
 leave:
  *ret_nread = nread;
  gcry_free(buf);
  return a;
}


/* Register STRING as a known critical notation name.  */
void
register_known_notation (const char *string)
{
  strlist_t sl;

  if (!known_notations_list)
    {
      sl = add_to_strlist (&known_notations_list,
                           "preferred-email-encoding@pgp.com");
      sl->flags = 32;
      sl = add_to_strlist (&known_notations_list, "pka-address@gnupg.org");
      sl->flags = 21;
    }
  if (!string)
    return; /* Only initialized the default known notations.  */

  /* In --set-notation we use an exclamation mark to indicate a
   * critical notation.  As a convenience skip this here.  */
  if (*string == '!')
    string++;

  if (!*string || strlist_find (known_notations_list, string))
    return; /* Empty string or already registered.  */

  sl = add_to_strlist (&known_notations_list, string);
  sl->flags = strlen (string);
}


int
set_packet_list_mode (int mode)
{
  int old = list_mode;
  list_mode = mode;

  /* We use stdout only if invoked by the --list-packets command
     but switch to stderr in all other cases.  This breaks the
     previous behaviour but that seems to be more of a bug than
     intentional.  I don't believe that any application makes use of
     this long standing annoying way of printing to stdout except when
     doing a --list-packets. If this assumption fails, it will be easy
     to add an option for the listing stream.  Note that we initialize
     it only once; mainly because there is code which switches
     opt.list_mode back to 1 and we want to have all output to the
     same stream.  The MPI_PRINT_MODE will be enabled if the
     corresponding debug flag is set or if we are in --list-packets
     and --verbose is given.

     Using stderr is not actually very clean because it bypasses the
     logging code but it is a special thing anyway.  I am not sure
     whether using log_stream() would be better.  Perhaps we should
     enable the list mode only with a special option. */
  if (!listfp)
    {
      if (opt.list_packets)
        {
          listfp = es_stdout;
          if (opt.verbose)
            mpi_print_mode = 1;
        }
      else
        listfp = es_stderr;

      if (DBG_MPI)
        mpi_print_mode = 1;
    }
  return old;
}


/* If OPT.VERBOSE is set, print a warning that the algorithm ALGO is
   not suitable for signing and encryption.  */
static void
unknown_pubkey_warning (int algo)
{
  static byte unknown_pubkey_algos[256];

  /* First check whether the algorithm is usable but not suitable for
     encryption/signing.  */
  if (pubkey_get_npkey (algo))
    {
      if (opt.verbose && !glo_ctrl.silence_parse_warnings)
        {
          if (!pubkey_get_nsig (algo))
            log_info ("public key algorithm %s not suitable for %s\n",
                      openpgp_pk_algo_name (algo), "signing");
          if (!pubkey_get_nenc (algo))
            log_info ("public key algorithm %s not suitable for %s\n",
                      openpgp_pk_algo_name (algo), "encryption");
        }
    }
  else
    {
      algo &= 0xff;
      if (!unknown_pubkey_algos[algo])
        {
          if (opt.verbose && !glo_ctrl.silence_parse_warnings)
            log_info (_("can't handle public key algorithm %d\n"), algo);
          unknown_pubkey_algos[algo] = 1;
        }
    }
}


#if DEBUG_PARSE_PACKET
int
dbg_parse_packet (parse_packet_ctx_t ctx, PACKET *pkt,
                  const char *dbg_f, int dbg_l)
{
  int skip, rc;

  do
    {
      rc = parse (ctx, pkt, 0, NULL, &skip, NULL, 0, "parse", dbg_f, dbg_l);
    }
  while (skip && ! rc);
  return rc;
}
#else /*!DEBUG_PARSE_PACKET*/
int
parse_packet (parse_packet_ctx_t ctx, PACKET *pkt)
{
  int skip, rc;

  do
    {
      rc = parse (ctx, pkt, 0, NULL, &skip, NULL, 0);
    }
  while (skip && ! rc);
  return rc;
}
#endif /*!DEBUG_PARSE_PACKET*/


/*
 * Like parse packet, but only return secret or public (sub)key
 * packets.
 */
#if DEBUG_PARSE_PACKET
int
dbg_search_packet (parse_packet_ctx_t ctx, PACKET *pkt,
                   off_t * retpos, int with_uid,
		   const char *dbg_f, int dbg_l)
{
  int skip, rc;

  do
    {
      rc = parse (ctx, pkt, with_uid ? 2 : 1, retpos, &skip, NULL, 0, "search",
                  dbg_f, dbg_l);
    }
  while (skip && ! rc);
  return rc;
}
#else /*!DEBUG_PARSE_PACKET*/
int
search_packet (parse_packet_ctx_t ctx, PACKET *pkt,
               off_t * retpos, int with_uid)
{
  int skip, rc;

  do
    {
      rc = parse (ctx, pkt, with_uid ? 2 : 1, retpos, &skip, NULL, 0);
    }
  while (skip && ! rc);
  return rc;
}
#endif /*!DEBUG_PARSE_PACKET*/


/*
 * Copy all packets from INP to OUT, thereby removing unused spaces.
 */
#if DEBUG_PARSE_PACKET
int
dbg_copy_all_packets (iobuf_t inp, iobuf_t out, const char *dbg_f, int dbg_l)
{
  PACKET pkt;
  struct parse_packet_ctx_s parsectx;
  int skip, rc = 0;

  if (! out)
    log_bug ("copy_all_packets: OUT may not be NULL.\n");

  init_parse_packet (&parsectx, inp);

  do
    {
      init_packet (&pkt);
    }
  while (!
	 (rc =
	  parse (&parsectx, &pkt, 0, NULL, &skip, out, 0, "copy",
                 dbg_f, dbg_l)));

  deinit_parse_packet (&parsectx);

  return rc;
}
#else /*!DEBUG_PARSE_PACKET*/
int
copy_all_packets (iobuf_t inp, iobuf_t out)
{
  PACKET pkt;
  struct parse_packet_ctx_s parsectx;
  int skip, rc = 0;

  if (! out)
    log_bug ("copy_all_packets: OUT may not be NULL.\n");

  init_parse_packet (&parsectx, inp);

  do
    {
      init_packet (&pkt);
    }
  while (!(rc = parse (&parsectx, &pkt, 0, NULL, &skip, out, 0)));

  deinit_parse_packet (&parsectx);

  return rc;
}
#endif /*!DEBUG_PARSE_PACKET*/


/*
 * Copy some packets from INP to OUT, thereby removing unused spaces.
 * Stop at offset STOPoff (i.e. don't copy packets at this or later
 * offsets)
 */
#if DEBUG_PARSE_PACKET
int
dbg_copy_some_packets (iobuf_t inp, iobuf_t out, off_t stopoff,
		       const char *dbg_f, int dbg_l)
{
  int rc = 0;
  PACKET pkt;
  int skip;
  struct parse_packet_ctx_s parsectx;

  init_parse_packet (&parsectx, inp);

  do
    {
      if (iobuf_tell (inp) >= stopoff)
        {
          deinit_parse_packet (&parsectx);
          return 0;
        }
      init_packet (&pkt);
    }
  while (!(rc = parse (&parsectx, &pkt, 0, NULL, &skip, out, 0,
		       "some", dbg_f, dbg_l)));

  deinit_parse_packet (&parsectx);

  return rc;
}
#else /*!DEBUG_PARSE_PACKET*/
int
copy_some_packets (iobuf_t inp, iobuf_t out, off_t stopoff)
{
  int rc = 0;
  PACKET pkt;
  struct parse_packet_ctx_s parsectx;
  int skip;

  init_parse_packet (&parsectx, inp);

  do
    {
      if (iobuf_tell (inp) >= stopoff)
        {
          deinit_parse_packet (&parsectx);
          return 0;
        }
      init_packet (&pkt);
    }
  while (!(rc = parse (&parsectx, &pkt, 0, NULL, &skip, out, 0)));

  deinit_parse_packet (&parsectx);

  return rc;
}
#endif /*!DEBUG_PARSE_PACKET*/


/*
 * Skip over N packets
 */
#if DEBUG_PARSE_PACKET
int
dbg_skip_some_packets (iobuf_t inp, unsigned n, const char *dbg_f, int dbg_l)
{
  int rc = 0;
  int skip;
  PACKET pkt;
  struct parse_packet_ctx_s parsectx;

  init_parse_packet (&parsectx, inp);

  for (; n && !rc; n--)
    {
      init_packet (&pkt);
      rc = parse (&parsectx, &pkt, 0, NULL, &skip, NULL, 1, "skip",
                  dbg_f, dbg_l);
    }

  deinit_parse_packet (&parsectx);

  return rc;
}
#else /*!DEBUG_PARSE_PACKET*/
int
skip_some_packets (iobuf_t inp, unsigned int n)
{
  int rc = 0;
  int skip;
  PACKET pkt;
  struct parse_packet_ctx_s parsectx;

  init_parse_packet (&parsectx, inp);

  for (; n && !rc; n--)
    {
      init_packet (&pkt);
      rc = parse (&parsectx, &pkt, 0, NULL, &skip, NULL, 1);
    }

  deinit_parse_packet (&parsectx);

  return rc;
}
#endif /*!DEBUG_PARSE_PACKET*/


/* Parse a packet and save it in *PKT.

   If OUT is not NULL and the packet is valid (its type is not 0),
   then the header, the initial length field and the packet's contents
   are written to OUT.  In this case, the packet is not saved in *PKT.

   ONLYKEYPKTS is a simple packet filter.  If ONLYKEYPKTS is set to 1,
   then only public subkey packets, public key packets, private subkey
   packets and private key packets are parsed.  The rest are skipped
   (i.e., the header and the contents are read from the pipeline and
   discarded).  If ONLYKEYPKTS is set to 2, then in addition to the
   above 4 types of packets, user id packets are also accepted.

   DO_SKIP is a more coarse grained filter.  Unless ONLYKEYPKTS is set
   to 2 and the packet is a user id packet, all packets are skipped.

   Finally, if a packet is invalid (it's type is 0), it is skipped.

   If a packet is skipped and SKIP is not NULL, then *SKIP is set to
   1.

   Note: ONLYKEYPKTS and DO_SKIP are only respected if OUT is NULL,
   i.e., the packets are not simply being copied.

   If RETPOS is not NULL, then the position of CTX->INP (as returned by
   iobuf_tell) is saved there before any data is read from CTX->INP.
  */
static int
parse (parse_packet_ctx_t ctx, PACKET *pkt, int onlykeypkts, off_t * retpos,
       int *skip, IOBUF out, int do_skip
#if DEBUG_PARSE_PACKET
       , const char *dbg_w, const char *dbg_f, int dbg_l
#endif
       )
{
  int rc = 0;
  iobuf_t inp;
  int c, ctb, pkttype, lenbytes;
  unsigned long pktlen;
  byte hdr[8];
  int hdrlen;
  int new_ctb = 0, partial = 0;
  int with_uid = (onlykeypkts == 2);
  off_t pos;

  *skip = 0;
  inp = ctx->inp;

 again:
  log_assert (!pkt->pkt.generic);
  if (retpos || list_mode)
    {
      pos = iobuf_tell (inp);
      if (retpos)
        *retpos = pos;
    }
  else
    pos = 0; /* (silence compiler warning) */

  /* The first byte of a packet is the so-called tag.  The highest bit
     must be set.  */
  if ((ctb = iobuf_get (inp)) == -1)
    {
      rc = -1;
      goto leave;
    }
  hdrlen = 0;
  hdr[hdrlen++] = ctb;

  if (!(ctb & 0x80))
    {
      log_error ("%s: invalid packet (ctb=%02x)\n", iobuf_where (inp), ctb);
      rc = gpg_error (GPG_ERR_INV_PACKET);
      goto leave;
    }

  /* Immediately following the header is the length.  There are two
     formats: the old format and the new format.  If bit 6 (where the
     least significant bit is bit 0) is set in the tag, then we are
     dealing with a new format packet.  Otherwise, it is an old format
     packet.  */
  pktlen = 0;
  new_ctb = !!(ctb & 0x40);
  if (new_ctb)
    {
      /* Get the packet's type.  This is encoded in the 6 least
	 significant bits of the tag.  */
      pkttype = ctb & 0x3f;

      /* Extract the packet's length.  New format packets have 4 ways
	 to encode the packet length.  The value of the first byte
	 determines the encoding and partially determines the length.
	 See section 4.2.2 of RFC 4880 for details.  */
      if ((c = iobuf_get (inp)) == -1)
	{
	  log_error ("%s: 1st length byte missing\n", iobuf_where (inp));
	  rc = gpg_error (GPG_ERR_INV_PACKET);
	  goto leave;
	}


      hdr[hdrlen++] = c;
      if (c < 192)
        pktlen = c;
      else if (c < 224)
        {
          pktlen = (c - 192) * 256;
          if ((c = iobuf_get (inp)) == -1)
            {
              log_error ("%s: 2nd length byte missing\n",
                         iobuf_where (inp));
              rc = gpg_error (GPG_ERR_INV_PACKET);
              goto leave;
            }
          hdr[hdrlen++] = c;
          pktlen += c + 192;
        }
      else if (c == 255)
        {
	  int i;
	  char value[4];

	  for (i = 0; i < 4; i ++)
            {
              if ((c = iobuf_get (inp)) == -1)
                {
                  log_error ("%s: 4 byte length invalid\n", iobuf_where (inp));
                  rc = gpg_error (GPG_ERR_INV_PACKET);
                  goto leave;
                }
              value[i] = hdr[hdrlen++] = c;
            }

	  pktlen = buf32_to_ulong (value);
        }
      else /* Partial body length.  */
        {
          switch (pkttype)
            {
            case PKT_PLAINTEXT:
            case PKT_ENCRYPTED:
            case PKT_ENCRYPTED_MDC:
            case PKT_ENCRYPTED_AEAD:
            case PKT_COMPRESSED:
              iobuf_set_partial_body_length_mode (inp, c & 0xff);
              pktlen = 0;	/* To indicate partial length.  */
              partial = 1;
              break;

            default:
              log_error ("%s: partial length invalid for"
                         " packet type %d\n", iobuf_where (inp), pkttype);
              rc = gpg_error (GPG_ERR_INV_PACKET);
              goto leave;
            }
        }

    }
  else
    /* This is an old format packet.  */
    {
      /* Extract the packet's type.  This is encoded in bits 2-5.  */
      pkttype = (ctb >> 2) & 0xf;

      /* The type of length encoding is encoded in bits 0-1 of the
	 tag.  */
      lenbytes = ((ctb & 3) == 3) ? 0 : (1 << (ctb & 3));
      if (!lenbytes)
	{
	  pktlen = 0;	/* Don't know the value.  */
	  /* This isn't really partial, but we can treat it the same
	     in a "read until the end" sort of way.  */
	  partial = 1;
	  if (pkttype != PKT_ENCRYPTED && pkttype != PKT_PLAINTEXT
	      && pkttype != PKT_COMPRESSED)
	    {
	      log_error ("%s: indeterminate length for invalid"
			 " packet type %d\n", iobuf_where (inp), pkttype);
	      rc = gpg_error (GPG_ERR_INV_PACKET);
	      goto leave;
	    }
	}
      else
	{
	  for (; lenbytes; lenbytes--)
	    {
	      pktlen <<= 8;
	      c = iobuf_get (inp);
	      if (c == -1)
		{
		  log_error ("%s: length invalid\n", iobuf_where (inp));
		  rc = gpg_error (GPG_ERR_INV_PACKET);
		  goto leave;
		}
	      pktlen |= hdr[hdrlen++] = c;
	    }
	}
    }

  /* Sometimes the decompressing layer enters an error state in which
     it simply outputs 0xff for every byte read.  If we have a stream
     of 0xff bytes, then it will be detected as a new format packet
     with type 63 and a 4-byte encoded length that is 4G-1.  Since
     packets with type 63 are private and we use them as a control
     packet, which won't be 4 GB, we reject such packets as
     invalid.  */
  if (pkttype == 63 && pktlen == 0xFFFFFFFF)
    {
      /* With some probability this is caused by a problem in the
       * the uncompressing layer - in some error cases it just loops
       * and spits out 0xff bytes. */
      log_error ("%s: garbled packet detected\n", iobuf_where (inp));
      g10_exit (2);
    }

  if (out && pkttype)
    {
      /* This type of copying won't work if the packet uses a partial
	 body length.  (In other words, this only works if HDR is
	 actually the length.)  Currently, no callers require this
	 functionality so we just log this as an error.  */
      if (partial)
	{
	  log_error ("parse: Can't copy partial packet.  Aborting.\n");
	  rc = gpg_error (GPG_ERR_INV_PACKET);
	  goto leave;
	}

      rc = iobuf_write (out, hdr, hdrlen);
      if (!rc)
	rc = copy_packet (inp, out, pkttype, pktlen, partial);
      goto leave;
    }

  if (with_uid && pkttype == PKT_USER_ID)
    /* If ONLYKEYPKTS is set to 2, then we never skip user id packets,
       even if DO_SKIP is set.  */
    ;
  else if (do_skip
	   /* type==0 is not allowed.  This is an invalid packet.  */
	   || !pkttype
	   /* When ONLYKEYPKTS is set, we don't skip keys.  */
	   || (onlykeypkts && pkttype != PKT_PUBLIC_SUBKEY
	       && pkttype != PKT_PUBLIC_KEY
	       && pkttype != PKT_SECRET_SUBKEY && pkttype != PKT_SECRET_KEY))
    {
      iobuf_skip_rest (inp, pktlen, partial);
      *skip = 1;
      rc = 0;
      goto leave;
    }

  if (DBG_PACKET)
    {
#if DEBUG_PARSE_PACKET
      log_debug ("parse_packet(iob=%d): type=%d length=%lu%s (%s.%s.%d)\n",
		 iobuf_id (inp), pkttype, pktlen, new_ctb ? " (new_ctb)" : "",
		 dbg_w, dbg_f, dbg_l);
#else
      log_debug ("parse_packet(iob=%d): type=%d length=%lu%s\n",
		 iobuf_id (inp), pkttype, pktlen,
		 new_ctb ? " (new_ctb)" : "");
#endif
    }

  if (list_mode)
    es_fprintf (listfp, "# off=%lu ctb=%02x tag=%d hlen=%d plen=%lu%s%s\n",
                (unsigned long)pos, ctb, pkttype, hdrlen, pktlen,
                partial? (new_ctb ? " partial" : " indeterminate") :"",
                new_ctb? " new-ctb":"");

  /* Count it.  */
  ctx->n_parsed_packets++;

  pkt->pkttype = pkttype;
  rc = GPG_ERR_UNKNOWN_PACKET;	/* default error */
  switch (pkttype)
    {
    case PKT_PUBLIC_KEY:
    case PKT_PUBLIC_SUBKEY:
    case PKT_SECRET_KEY:
    case PKT_SECRET_SUBKEY:
      pkt->pkt.public_key = xmalloc_clear (sizeof *pkt->pkt.public_key);
      rc = parse_key (inp, pkttype, pktlen, hdr, hdrlen, pkt);
      break;
    case PKT_SYMKEY_ENC:
      rc = parse_symkeyenc (inp, pkttype, pktlen, pkt);
      break;
    case PKT_PUBKEY_ENC:
      rc = parse_pubkeyenc (inp, pkttype, pktlen, pkt);
      break;
    case PKT_SIGNATURE:
      pkt->pkt.signature = xmalloc_clear (sizeof *pkt->pkt.signature);
      rc = parse_signature (inp, pkttype, pktlen, pkt->pkt.signature);
      break;
    case PKT_ONEPASS_SIG:
      pkt->pkt.onepass_sig = xmalloc_clear (sizeof *pkt->pkt.onepass_sig);
      rc = parse_onepass_sig (inp, pkttype, pktlen, pkt->pkt.onepass_sig);
      break;
    case PKT_USER_ID:
      rc = parse_user_id (inp, pkttype, pktlen, pkt);
      break;
    case PKT_ATTRIBUTE:
      pkt->pkttype = pkttype = PKT_USER_ID;	/* we store it in the userID */
      rc = parse_attribute (inp, pkttype, pktlen, pkt);
      break;
    case PKT_OLD_COMMENT:
    case PKT_COMMENT:
      rc = parse_comment (inp, pkttype, pktlen, pkt);
      break;
    case PKT_RING_TRUST:
      {
        rc = parse_ring_trust (ctx, pktlen);
        if (!rc)
          goto again; /* Directly read the next packet.  */
      }
      break;
    case PKT_PLAINTEXT:
      rc = parse_plaintext (inp, pkttype, pktlen, pkt, new_ctb, partial);
      break;
    case PKT_COMPRESSED:
      rc = parse_compressed (inp, pkttype, pktlen, pkt, new_ctb);
      break;
    case PKT_ENCRYPTED:
    case PKT_ENCRYPTED_MDC:
      rc = parse_encrypted (inp, pkttype, pktlen, pkt, new_ctb, partial);
      break;
    case PKT_MDC:
      rc = parse_mdc (inp, pkttype, pktlen, pkt, new_ctb);
      break;
    case PKT_ENCRYPTED_AEAD:
      rc = parse_encrypted_aead (inp, pkttype, pktlen, pkt, partial);
      break;
    case PKT_GPG_CONTROL:
      rc = parse_gpg_control (inp, pkttype, pktlen, pkt, partial);
      break;
    case PKT_MARKER:
      rc = parse_marker (inp, pkttype, pktlen);
      break;
    default:
      /* Unknown packet.  Skip it.  */
      skip_packet (inp, pkttype, pktlen, partial);
      break;
    }

  /* Store a shallow copy of certain packets in the context.  */
  free_packet (NULL, ctx);
  if (!rc && (pkttype == PKT_PUBLIC_KEY
              || pkttype == PKT_SECRET_KEY
              || pkttype == PKT_USER_ID
              || pkttype == PKT_ATTRIBUTE
              || pkttype == PKT_SIGNATURE))
    {
      ctx->last_pkt = *pkt;
    }

 leave:
  /* FIXME: We leak in case of an error (see the xmalloc's above).  */
  if (!rc && iobuf_error (inp))
    rc = GPG_ERR_INV_KEYRING;

  /* FIXME: We use only the error code for now to avoid problems with
     callers which have not been checked to always use gpg_err_code()
     when comparing error codes.  */
  return rc == -1? -1 : gpg_err_code (rc);
}


static void
dump_hex_line (int c, int *i)
{
  if (*i && !(*i % 8))
    {
      if (*i && !(*i % 24))
	es_fprintf (listfp, "\n%4d:", *i);
      else
	es_putc (' ', listfp);
    }
  if (c == -1)
    es_fprintf (listfp, " EOF");
  else
    es_fprintf (listfp, " %02x", c);
  ++*i;
}


/* Copy the contents of a packet from the pipeline IN to the pipeline
   OUT.

   The header and length have already been read from INP and the
   decoded values are given as PKGTYPE and PKTLEN.

   If the packet is a partial body length packet (RFC 4880, Section
   4.2.2.4), then iobuf_set_partial_block_modeiobuf_set_partial_block_mode
   should already have been called on INP and PARTIAL should be set.

   If PARTIAL is set or PKTLEN is 0 and PKTTYPE is PKT_COMPRESSED,
   copy until the first EOF is encountered on INP.

   Returns 0 on success and an error code if an error occurs.  */
static int
copy_packet (IOBUF inp, IOBUF out, int pkttype,
	     unsigned long pktlen, int partial)
{
  int rc;
  int n;
  char buf[100];

  if (partial)
    {
      while ((n = iobuf_read (inp, buf, sizeof (buf))) != -1)
	if ((rc = iobuf_write (out, buf, n)))
	  return rc;		/* write error */
    }
  else if (!pktlen && pkttype == PKT_COMPRESSED)
    {
      log_debug ("copy_packet: compressed!\n");
      /* compressed packet, copy till EOF */
      while ((n = iobuf_read (inp, buf, sizeof (buf))) != -1)
	if ((rc = iobuf_write (out, buf, n)))
	  return rc;		/* write error */
    }
  else
    {
      for (; pktlen; pktlen -= n)
	{
	  n = pktlen > sizeof (buf) ? sizeof (buf) : pktlen;
	  n = iobuf_read (inp, buf, n);
	  if (n == -1)
	    return gpg_error (GPG_ERR_EOF);
	  if ((rc = iobuf_write (out, buf, n)))
	    return rc;		/* write error */
	}
    }
  return 0;
}


/* Skip an unknown packet.  PKTTYPE is the packet's type, PKTLEN is
   the length of the packet's content and PARTIAL is whether partial
   body length encoding in used (in this case PKTLEN is ignored).  */
static void
skip_packet (IOBUF inp, int pkttype, unsigned long pktlen, int partial)
{
  if (list_mode)
    {
      es_fprintf (listfp, ":unknown packet: type %2d, length %lu\n",
                  pkttype, pktlen);
      if (pkttype)
	{
	  int c, i = 0;
	  es_fputs ("dump:", listfp);
	  if (partial)
	    {
	      while ((c = iobuf_get (inp)) != -1)
		dump_hex_line (c, &i);
	    }
	  else
	    {
	      for (; pktlen; pktlen--)
		{
		  dump_hex_line ((c = iobuf_get (inp)), &i);
		  if (c == -1)
		    break;
		}
	    }
	  es_putc ('\n', listfp);
	  return;
	}
    }
  iobuf_skip_rest (inp, pktlen, partial);
}


/* Read PKTLEN bytes from INP and return them in a newly allocated
 * buffer.  In case of an error (including reading fewer than PKTLEN
 * bytes from INP before EOF is returned), NULL is returned and an
 * error message is logged.  */
static void *
read_rest (IOBUF inp, size_t pktlen)
{
  int c;
  byte *buf, *p;

  buf = xtrymalloc (pktlen);
  if (!buf)
    {
      gpg_error_t err = gpg_error_from_syserror ();
      log_error ("error reading rest of packet: %s\n", gpg_strerror (err));
      return NULL;
    }
  for (p = buf; pktlen; pktlen--)
    {
      c = iobuf_get (inp);
      if (c == -1)
        {
          log_error ("premature eof while reading rest of packet\n");
          xfree (buf);
          return NULL;
        }
      *p++ = c;
    }

  return buf;
}


/* Read a special size+body from INP.  On success store an opaque MPI
   with it at R_DATA.  On error return an error code and store NULL at
   R_DATA.  Even in the error case store the number of read bytes at
   R_NREAD.  The caller shall pass the remaining size of the packet in
   PKTLEN.  */
static gpg_error_t
read_size_body (iobuf_t inp, int pktlen, size_t *r_nread,
                gcry_mpi_t *r_data)
{
  char buffer[256];
  char *tmpbuf;
  int i, c, nbytes;

  *r_nread = 0;
  *r_data = NULL;

  if (!pktlen)
    return gpg_error (GPG_ERR_INV_PACKET);
  c = iobuf_readbyte (inp);
  if (c < 0)
    return gpg_error (GPG_ERR_INV_PACKET);
  pktlen--;
  ++*r_nread;
  nbytes = c;
  if (nbytes < 2 || nbytes > 254)
    return gpg_error (GPG_ERR_INV_PACKET);
  if (nbytes > pktlen)
    return gpg_error (GPG_ERR_INV_PACKET);

  buffer[0] = nbytes;

  for (i = 0; i < nbytes; i++)
    {
      c = iobuf_get (inp);
      if (c < 0)
        return gpg_error (GPG_ERR_INV_PACKET);
      ++*r_nread;
      buffer[1+i] = c;
    }

  tmpbuf = xtrymalloc (1 + nbytes);
  if (!tmpbuf)
    return gpg_error_from_syserror ();
  memcpy (tmpbuf, buffer, 1 + nbytes);
  *r_data = gcry_mpi_set_opaque (NULL, tmpbuf, 8 * (1 + nbytes));
  if (!*r_data)
    {
      xfree (tmpbuf);
      return gpg_error_from_syserror ();
    }
  return 0;
}


/* Parse a marker packet.  */
static int
parse_marker (IOBUF inp, int pkttype, unsigned long pktlen)
{
  (void) pkttype;

  if (pktlen != 3)
    goto fail;

  if (iobuf_get (inp) != 'P')
    {
      pktlen--;
      goto fail;
    }

  if (iobuf_get (inp) != 'G')
    {
      pktlen--;
      goto fail;
    }

  if (iobuf_get (inp) != 'P')
    {
      pktlen--;
      goto fail;
    }

  if (list_mode)
    es_fputs (":marker packet: PGP\n", listfp);

  return 0;

 fail:
  log_error ("invalid marker packet\n");
  if (list_mode)
    es_fputs (":marker packet: [invalid]\n", listfp);
  iobuf_skip_rest (inp, pktlen, 0);
  return GPG_ERR_INV_PACKET;
}


static int
parse_symkeyenc (IOBUF inp, int pkttype, unsigned long pktlen,
		 PACKET * packet)
{
  PKT_symkey_enc *k;
  int rc = 0;
  int i, version, s2kmode, cipher_algo, aead_algo, hash_algo, seskeylen, minlen;

  if (pktlen < 4)
    goto too_short;
  version = iobuf_get_noeof (inp);
  pktlen--;
  if (version == 4)
    ;
  else if (version == 5)
    ;
  else
    {
      log_error ("packet(%d) with unknown version %d\n", pkttype, version);
      if (list_mode)
        es_fprintf (listfp, ":symkey enc packet: [unknown version]\n");
      rc = gpg_error (GPG_ERR_INV_PACKET);
      goto leave;
    }
  if (pktlen > 200)
    {				/* (we encode the seskeylen in a byte) */
      log_error ("packet(%d) too large\n", pkttype);
      if (list_mode)
        es_fprintf (listfp, ":symkey enc packet: [too large]\n");
      rc = gpg_error (GPG_ERR_INV_PACKET);
      goto leave;
    }
  cipher_algo = iobuf_get_noeof (inp);
  pktlen--;
  if (version == 5)
    {
      aead_algo = iobuf_get_noeof (inp);
      pktlen--;
    }
  else
    aead_algo = 0;
  if (pktlen < 2)
    goto too_short;
  s2kmode = iobuf_get_noeof (inp);
  pktlen--;
  hash_algo = iobuf_get_noeof (inp);
  pktlen--;
  switch (s2kmode)
    {
    case 0: /* Simple S2K.  */
      minlen = 0;
      break;
    case 1: /* Salted S2K.  */
      minlen = 8;
      break;
    case 3: /* Iterated+salted S2K.  */
      minlen = 9;
      break;
    default:
      log_error ("unknown S2K mode %d\n", s2kmode);
      if (list_mode)
        es_fprintf (listfp, ":symkey enc packet: [unknown S2K mode]\n");
      goto leave;
    }
  if (minlen > pktlen)
    {
      log_error ("packet with S2K %d too short\n", s2kmode);
      if (list_mode)
        es_fprintf (listfp, ":symkey enc packet: [too short]\n");
      rc = gpg_error (GPG_ERR_INV_PACKET);
      goto leave;
    }
  seskeylen = pktlen - minlen;
  k = packet->pkt.symkey_enc = xmalloc_clear (sizeof *packet->pkt.symkey_enc
					      + seskeylen - 1);
  k->version = version;
  k->cipher_algo = cipher_algo;
  k->aead_algo = aead_algo;
  k->s2k.mode = s2kmode;
  k->s2k.hash_algo = hash_algo;
  if (s2kmode == 1 || s2kmode == 3)
    {
      for (i = 0; i < 8 && pktlen; i++, pktlen--)
	k->s2k.salt[i] = iobuf_get_noeof (inp);
    }
  if (s2kmode == 3)
    {
      k->s2k.count = iobuf_get_noeof (inp);
      pktlen--;
    }
  k->seskeylen = seskeylen;
  if (k->seskeylen)
    {
      for (i = 0; i < seskeylen && pktlen; i++, pktlen--)
	k->seskey[i] = iobuf_get_noeof (inp);

      /* What we're watching out for here is a session key decryptor
         with no salt.  The RFC says that using salt for this is a
         MUST. */
      if (s2kmode != 1 && s2kmode != 3)
	log_info (_("WARNING: potentially insecure symmetrically"
		    " encrypted session key\n"));
    }
  log_assert (!pktlen);

  if (list_mode)
    {
      es_fprintf (listfp,
                  ":symkey enc packet: version %d, cipher %d, aead %d,"
                  "s2k %d, hash %d",
                  version, cipher_algo, aead_algo, s2kmode, hash_algo);
      if (seskeylen)
        {
          /* To compute the size of the session key we need to know
           * the size of the AEAD nonce which we may not know.  Thus
           * we show only the size of the entire encrypted session
           * key.  */
          if (aead_algo)
            es_fprintf (listfp, ", encrypted seskey %d bytes", seskeylen);
          else
            es_fprintf (listfp, ", seskey %d bits", (seskeylen - 1) * 8);
        }
      es_fprintf (listfp, "\n");
      if (s2kmode == 1 || s2kmode == 3)
	{
	  es_fprintf (listfp, "\tsalt ");
          es_write_hexstring (listfp, k->s2k.salt, 8, 0, NULL);
	  if (s2kmode == 3)
	    es_fprintf (listfp, ", count %lu (%lu)",
                        S2K_DECODE_COUNT ((ulong) k->s2k.count),
                        (ulong) k->s2k.count);
	  es_fprintf (listfp, "\n");
	}
    }

 leave:
  iobuf_skip_rest (inp, pktlen, 0);
  return rc;

 too_short:
  log_error ("packet(%d) too short\n", pkttype);
  if (list_mode)
    es_fprintf (listfp, ":symkey enc packet: [too short]\n");
  rc = gpg_error (GPG_ERR_INV_PACKET);
  goto leave;
}


static int
parse_pubkeyenc (IOBUF inp, int pkttype, unsigned long pktlen,
		 PACKET * packet)
{
  int rc = 0;
  int i, ndata;
  PKT_pubkey_enc *k;

  k = packet->pkt.pubkey_enc = xmalloc_clear (sizeof *packet->pkt.pubkey_enc);
  if (pktlen < 12)
    {
      log_error ("packet(%d) too short\n", pkttype);
      if (list_mode)
        es_fputs (":pubkey enc packet: [too short]\n", listfp);
      rc = gpg_error (GPG_ERR_INV_PACKET);
      goto leave;
    }
  k->version = iobuf_get_noeof (inp);
  pktlen--;
  if (k->version != 2 && k->version != 3)
    {
      log_error ("packet(%d) with unknown version %d\n", pkttype, k->version);
      if (list_mode)
        es_fputs (":pubkey enc packet: [unknown version]\n", listfp);
      rc = gpg_error (GPG_ERR_INV_PACKET);
      goto leave;
    }
  k->keyid[0] = read_32 (inp);
  pktlen -= 4;
  k->keyid[1] = read_32 (inp);
  pktlen -= 4;
  k->pubkey_algo = iobuf_get_noeof (inp);
  pktlen--;
  k->throw_keyid = 0;  /* Only used as flag for build_packet.  */
  if (list_mode)
    es_fprintf (listfp,
                ":pubkey enc packet: version %d, algo %d, keyid %08lX%08lX\n",
                k->version, k->pubkey_algo, (ulong) k->keyid[0],
                (ulong) k->keyid[1]);

  ndata = pubkey_get_nenc (k->pubkey_algo);
  if (!ndata)
    {
      if (list_mode)
	es_fprintf (listfp, "\tunsupported algorithm %d\n", k->pubkey_algo);
      unknown_pubkey_warning (k->pubkey_algo);
      k->data[0] = NULL; /* No need to store the encrypted data.  */
    }
  else
    {
      for (i = 0; i < ndata; i++)
        {
          if (k->pubkey_algo == PUBKEY_ALGO_ECDH && i == 1)
            {
              size_t n;
	      rc = read_size_body (inp, pktlen, &n, k->data+i);
              pktlen -= n;
            }
          else
            {
	      int n = pktlen;
              k->data[i] = mpi_read (inp, &n, 0);
              pktlen -= n;
              if (!k->data[i])
                rc = gpg_error (GPG_ERR_INV_PACKET);
            }
          if (rc)
            goto leave;
          if (list_mode)
            {
              es_fprintf (listfp, "\tdata: ");
              mpi_print (listfp, k->data[i], mpi_print_mode);
              es_putc ('\n', listfp);
            }
        }
    }

 leave:
  iobuf_skip_rest (inp, pktlen, 0);
  return rc;
}


/* Dump a subpacket to LISTFP.  BUFFER contains the subpacket in
   question and points to the type field in the subpacket header (not
   the start of the header).  TYPE is the subpacket's type with the
   critical bit cleared.  CRITICAL is the value of the CRITICAL bit.
   BUFLEN is the length of the buffer and LENGTH is the length of the
   subpacket according to the subpacket's header.  */
static void
dump_sig_subpkt (int hashed, int type, int critical,
		 const byte * buffer, size_t buflen, size_t length)
{
  const char *p = NULL;
  int i;

  /* The CERT has warning out with explains how to use GNUPG to detect
   * the ARRs - we print our old message here when it is a faked ARR
   * and add an additional notice.  */
  if (type == SIGSUBPKT_ARR && !hashed)
    {
      es_fprintf (listfp,
                  "\tsubpkt %d len %u (additional recipient request)\n"
                  "WARNING: PGP versions > 5.0 and < 6.5.8 will automagically "
                  "encrypt to this key and thereby reveal the plaintext to "
                  "the owner of this ARR key. Detailed info follows:\n",
                  type, (unsigned) length);
    }

  buffer++;
  length--;

  es_fprintf (listfp, "\t%s%ssubpkt %d len %u (",	/*) */
              critical ? "critical " : "",
              hashed ? "hashed " : "", type, (unsigned) length);
  if (length > buflen)
    {
      es_fprintf (listfp, "too short: buffer is only %u)\n", (unsigned) buflen);
      return;
    }
  switch (type)
    {
    case SIGSUBPKT_SIG_CREATED:
      if (length >= 4)
	es_fprintf (listfp, "sig created %s",
                    strtimestamp (buf32_to_u32 (buffer)));
      break;
    case SIGSUBPKT_SIG_EXPIRE:
      if (length >= 4)
	{
	  if (buf32_to_u32 (buffer))
	    es_fprintf (listfp, "sig expires after %s",
                        strtimevalue (buf32_to_u32 (buffer)));
	  else
	    es_fprintf (listfp, "sig does not expire");
	}
      break;
    case SIGSUBPKT_EXPORTABLE:
      if (length)
	es_fprintf (listfp, "%sexportable", *buffer ? "" : "not ");
      break;
    case SIGSUBPKT_TRUST:
      if (length != 2)
	p = "[invalid trust subpacket]";
      else
	es_fprintf (listfp, "trust signature of depth %d, value %d", buffer[0],
                    buffer[1]);
      break;
    case SIGSUBPKT_REGEXP:
      if (!length)
	p = "[invalid regexp subpacket]";
      else
        {
          es_fprintf (listfp, "regular expression: \"");
          es_write_sanitized (listfp, buffer, length, "\"", NULL);
          p = "\"";
        }
      break;
    case SIGSUBPKT_REVOCABLE:
      if (length)
	es_fprintf (listfp, "%srevocable", *buffer ? "" : "not ");
      break;
    case SIGSUBPKT_KEY_EXPIRE:
      if (length >= 4)
	{
	  if (buf32_to_u32 (buffer))
	    es_fprintf (listfp, "key expires after %s",
                        strtimevalue (buf32_to_u32 (buffer)));
	  else
	    es_fprintf (listfp, "key does not expire");
	}
      break;
    case SIGSUBPKT_PREF_SYM:
      es_fputs ("pref-sym-algos:", listfp);
      for (i = 0; i < length; i++)
	es_fprintf (listfp, " %d", buffer[i]);
      break;
    case SIGSUBPKT_PREF_AEAD:
      es_fputs ("pref-aead-algos:", listfp);
      for (i = 0; i < length; i++)
        es_fprintf (listfp, " %d", buffer[i]);
      break;
    case SIGSUBPKT_REV_KEY:
      es_fputs ("revocation key: ", listfp);
      if (length < 22)
	p = "[too short]";
      else
	{
	  es_fprintf (listfp, "c=%02x a=%d f=", buffer[0], buffer[1]);
	  for (i = 2; i < length; i++)
	    es_fprintf (listfp, "%02X", buffer[i]);
	}
      break;
    case SIGSUBPKT_ISSUER:
      if (length >= 8)
	es_fprintf (listfp, "issuer key ID %08lX%08lX",
                    (ulong) buf32_to_u32 (buffer),
                    (ulong) buf32_to_u32 (buffer + 4));
      break;
    case SIGSUBPKT_ISSUER_FPR:
      if (length >= 21)
        {
          char *tmp;
          es_fprintf (listfp, "issuer fpr v%d ", buffer[0]);
          tmp = bin2hex (buffer+1, length-1, NULL);
          if (tmp)
            {
              es_fputs (tmp, listfp);
              xfree (tmp);
            }
        }
      break;
    case SIGSUBPKT_NOTATION:
      {
	es_fputs ("notation: ", listfp);
	if (length < 8)
	  p = "[too short]";
	else
	  {
	    const byte *s = buffer;
	    size_t n1, n2;

	    n1 = (s[4] << 8) | s[5];
	    n2 = (s[6] << 8) | s[7];
	    s += 8;
	    if (8 + n1 + n2 != length)
	      p = "[error]";
	    else
	      {
		es_write_sanitized (listfp, s, n1, ")", NULL);
		es_putc ('=', listfp);

		if (*buffer & 0x80)
		  es_write_sanitized (listfp, s + n1, n2, ")", NULL);
		else
		  p = "[not human readable]";
	      }
	  }
      }
      break;
    case SIGSUBPKT_PREF_HASH:
      es_fputs ("pref-hash-algos:", listfp);
      for (i = 0; i < length; i++)
	es_fprintf (listfp, " %d", buffer[i]);
      break;
    case SIGSUBPKT_PREF_COMPR:
      es_fputs ("pref-zip-algos:", listfp);
      for (i = 0; i < length; i++)
	es_fprintf (listfp, " %d", buffer[i]);
      break;
    case SIGSUBPKT_KS_FLAGS:
      es_fputs ("keyserver preferences:", listfp);
      for (i = 0; i < length; i++)
	es_fprintf (listfp, " %02X", buffer[i]);
      break;
    case SIGSUBPKT_PREF_KS:
      es_fputs ("preferred keyserver: ", listfp);
      es_write_sanitized (listfp, buffer, length, ")", NULL);
      break;
    case SIGSUBPKT_PRIMARY_UID:
      p = "primary user ID";
      break;
    case SIGSUBPKT_POLICY:
      es_fputs ("policy: ", listfp);
      es_write_sanitized (listfp, buffer, length, ")", NULL);
      break;
    case SIGSUBPKT_KEY_FLAGS:
      es_fputs ("key flags:", listfp);
      for (i = 0; i < length; i++)
	es_fprintf (listfp, " %02X", buffer[i]);
      break;
    case SIGSUBPKT_SIGNERS_UID:
      p = "signer's user ID";
      break;
    case SIGSUBPKT_REVOC_REASON:
      if (length)
	{
	  es_fprintf (listfp, "revocation reason 0x%02x (", *buffer);
	  es_write_sanitized (listfp, buffer + 1, length - 1, ")", NULL);
	  p = ")";
	}
      break;
    case SIGSUBPKT_ARR:
      es_fputs ("Big Brother's key (ignored): ", listfp);
      if (length < 22)
	p = "[too short]";
      else
	{
	  es_fprintf (listfp, "c=%02x a=%d f=", buffer[0], buffer[1]);
          if (length > 2)
            es_write_hexstring (listfp, buffer+2, length-2, 0, NULL);
	}
      break;
    case SIGSUBPKT_FEATURES:
      es_fputs ("features:", listfp);
      for (i = 0; i < length; i++)
	es_fprintf (listfp, " %02x", buffer[i]);
      break;
    case SIGSUBPKT_SIGNATURE:
      es_fputs ("signature: ", listfp);
      if (length < 17)
	p = "[too short]";
      else
	es_fprintf (listfp, "v%d, class 0x%02X, algo %d, digest algo %d",
                    buffer[0],
                    buffer[0] == 3 ? buffer[2] : buffer[1],
                    buffer[0] == 3 ? buffer[15] : buffer[2],
                    buffer[0] == 3 ? buffer[16] : buffer[3]);
      break;

    case SIGSUBPKT_KEY_BLOCK:
      es_fputs ("key-block: ", listfp);
      if (length && buffer[0])
        p = "[unknown reserved octet]";
      else if (length < 50)  /* 50 is an arbitrary min. length.  */
        p = "[invalid subpacket]";
      else
        {
          /* estream_t fp; */
          /* fp = es_fopen ("a.key-block", "wb"); */
          /* log_assert (fp); */
          /* es_fwrite ( buffer+1, length-1, 1, fp); */
          /* es_fclose (fp); */
          es_fprintf (listfp, "[%u octets]", (unsigned int)length-1);
        }
      break;

    default:
      if (type >= 100 && type <= 110)
	p = "experimental / private subpacket";
      else
	p = "?";
      break;
    }

  es_fprintf (listfp, "%s)\n", p ? p : "");
}


/*
 * Returns: >= 0 use this offset into buffer
 *	    -1 explicitly reject returning this type
 *	    -2 subpacket too short
 */
int
parse_one_sig_subpkt (const byte * buffer, size_t n, int type)
{
  switch (type)
    {
    case SIGSUBPKT_REV_KEY:
      if (n < 22)
	break;
      return 0;
    case SIGSUBPKT_SIG_CREATED:
    case SIGSUBPKT_SIG_EXPIRE:
    case SIGSUBPKT_KEY_EXPIRE:
      if (n < 4)
	break;
      return 0;
    case SIGSUBPKT_KEY_FLAGS:
    case SIGSUBPKT_KS_FLAGS:
    case SIGSUBPKT_PREF_SYM:
    case SIGSUBPKT_PREF_AEAD:
    case SIGSUBPKT_PREF_HASH:
    case SIGSUBPKT_PREF_COMPR:
    case SIGSUBPKT_POLICY:
    case SIGSUBPKT_PREF_KS:
    case SIGSUBPKT_FEATURES:
    case SIGSUBPKT_REGEXP:
      return 0;
    case SIGSUBPKT_SIGNATURE:
    case SIGSUBPKT_EXPORTABLE:
    case SIGSUBPKT_REVOCABLE:
    case SIGSUBPKT_REVOC_REASON:
      if (!n)
	break;
      return 0;
    case SIGSUBPKT_ISSUER:	/* issuer key ID */
      if (n < 8)
	break;
      return 0;
    case SIGSUBPKT_ISSUER_FPR:	/* issuer key ID */
      if (n < 21)
	break;
      return 0;
    case SIGSUBPKT_NOTATION:
      /* minimum length needed, and the subpacket must be well-formed
         where the name length and value length all fit inside the
         packet. */
      if (n < 8
	  || 8 + ((buffer[4] << 8) | buffer[5]) +
	  ((buffer[6] << 8) | buffer[7]) != n)
	break;
      return 0;
    case SIGSUBPKT_PRIMARY_UID:
      if (n != 1)
	break;
      return 0;
    case SIGSUBPKT_TRUST:
      if (n != 2)
	break;
      return 0;
    case SIGSUBPKT_KEY_BLOCK:
      if (n && buffer[0])
        return -1; /* Unknown version - ignore.  */
      if (n < 50)
	break;  /* Definitely too short to carry a key block.  */
      return 0;
    default:
      return 0;
    }
  return -2;
}


/* Return true if we understand the critical notation.  */
static int
can_handle_critical_notation (const byte *name, size_t len)
{
  strlist_t sl;

  register_known_notation (NULL); /* Make sure it is initialized.  */

  for (sl = known_notations_list; sl; sl = sl->next)
    if (sl->flags == len && !memcmp (sl->d, name, len))
      return 1; /* Known */

  if (opt.verbose && !glo_ctrl.silence_parse_warnings)
    {
      log_info(_("Unknown critical signature notation: ") );
      print_utf8_buffer (log_get_stream(), name, len);
      log_printf ("\n");
    }

  return 0; /* Unknown.  */
}


static int
can_handle_critical (const byte * buffer, size_t n, int type)
{
  switch (type)
    {
    case SIGSUBPKT_NOTATION:
      if (n >= 8)
	{
	  size_t notation_len = ((buffer[4] << 8) | buffer[5]);
	  if (n - 8 >= notation_len)
	    return can_handle_critical_notation (buffer + 8, notation_len);
	}
      return 0;
    case SIGSUBPKT_SIGNATURE:
    case SIGSUBPKT_SIG_CREATED:
    case SIGSUBPKT_SIG_EXPIRE:
    case SIGSUBPKT_KEY_EXPIRE:
    case SIGSUBPKT_EXPORTABLE:
    case SIGSUBPKT_REVOCABLE:
    case SIGSUBPKT_REV_KEY:
    case SIGSUBPKT_ISSUER:	/* issuer key ID */
    case SIGSUBPKT_ISSUER_FPR:	/* issuer fingerprint */
    case SIGSUBPKT_PREF_SYM:
    case SIGSUBPKT_PREF_HASH:
    case SIGSUBPKT_PREF_COMPR:
    case SIGSUBPKT_KEY_FLAGS:
    case SIGSUBPKT_PRIMARY_UID:
    case SIGSUBPKT_FEATURES:
    case SIGSUBPKT_TRUST:
    case SIGSUBPKT_REGEXP:
      /* Is it enough to show the policy or keyserver? */
    case SIGSUBPKT_POLICY:
    case SIGSUBPKT_PREF_KS:
    case SIGSUBPKT_REVOC_REASON: /* At least we know about it.  */
      return 1;

    case SIGSUBPKT_KEY_BLOCK:
      if (n && !buffer[0])
        return 1;
      else
        return 0;

    default:
      return 0;
    }
}


const byte *
enum_sig_subpkt (const subpktarea_t * pktbuf, sigsubpkttype_t reqtype,
		 size_t * ret_n, int *start, int *critical)
{
  const byte *buffer;
  int buflen;
  int type;
  int critical_dummy;
  int offset;
  size_t n;
  int seq = 0;
  int reqseq = start ? *start : 0;

  if (!critical)
    critical = &critical_dummy;

  if (!pktbuf || reqseq == -1)
    {
      static char dummy[] = "x";
      /* Return a value different from NULL to indicate that
       * there is no critical bit we do not understand.  */
      return reqtype ==	SIGSUBPKT_TEST_CRITICAL ? dummy : NULL;
    }
  buffer = pktbuf->data;
  buflen = pktbuf->len;
  while (buflen)
    {
      n = *buffer++;
      buflen--;
      if (n == 255) /* 4 byte length header.  */
	{
	  if (buflen < 4)
	    goto too_short;
	  n = buf32_to_size_t (buffer);
	  buffer += 4;
	  buflen -= 4;
	}
      else if (n >= 192) /* 4 byte special encoded length header.  */
	{
	  if (buflen < 2)
	    goto too_short;
	  n = ((n - 192) << 8) + *buffer + 192;
	  buffer++;
	  buflen--;
	}
      if (buflen < n)
	goto too_short;
      if (!buflen)
        goto no_type_byte;
      type = *buffer;
      if (type & 0x80)
	{
	  type &= 0x7f;
	  *critical = 1;
	}
      else
	*critical = 0;
      if (!(++seq > reqseq))
	;
      else if (reqtype == SIGSUBPKT_TEST_CRITICAL)
	{
	  if (*critical)
	    {
	      if (n - 1 > buflen + 1)
		goto too_short;
	      if (!can_handle_critical (buffer + 1, n - 1, type))
		{
		  if (opt.verbose && !glo_ctrl.silence_parse_warnings)
		    log_info (_("subpacket of type %d has "
				"critical bit set\n"), type);
		  if (start)
		    *start = seq;
		  return NULL;	/* This is an error.  */
		}
	    }
	}
      else if (reqtype < 0) /* List packets.  */
	dump_sig_subpkt (reqtype == SIGSUBPKT_LIST_HASHED,
			 type, *critical, buffer, buflen, n);
      else if (type == reqtype) /* Found.  */
	{
	  buffer++;
	  n--;
	  if (n > buflen)
	    goto too_short;
	  if (ret_n)
	    *ret_n = n;
	  offset = parse_one_sig_subpkt (buffer, n, type);
	  switch (offset)
	    {
	    case -2:
	      log_error ("subpacket of type %d too short\n", type);
	      return NULL;
	    case -1:
	      return NULL;
	    default:
	      break;
	    }
	  if (start)
	    *start = seq;
	  return buffer + offset;
	}
      buffer += n;
      buflen -= n;
    }
  if (reqtype == SIGSUBPKT_TEST_CRITICAL)
    /* Returning NULL means we found a subpacket with the critical bit
       set that we don't grok.  We've iterated over all the subpackets
       and haven't found such a packet so we need to return a non-NULL
       value.  */
    return buffer;

  /* Critical bit we don't understand. */
  if (start)
    *start = -1;
  return NULL;	/* End of packets; not found.  */

 too_short:
  if (opt.verbose && !glo_ctrl.silence_parse_warnings)
    log_info ("buffer shorter than subpacket\n");
  if (start)
    *start = -1;
  return NULL;

 no_type_byte:
  if (opt.verbose && !glo_ctrl.silence_parse_warnings)
    log_info ("type octet missing in subpacket\n");
  if (start)
    *start = -1;
  return NULL;
}


const byte *
parse_sig_subpkt (const subpktarea_t * buffer, sigsubpkttype_t reqtype,
		  size_t * ret_n)
{
  return enum_sig_subpkt (buffer, reqtype, ret_n, NULL, NULL);
}


const byte *
parse_sig_subpkt2 (PKT_signature * sig, sigsubpkttype_t reqtype)
{
  const byte *p;

  p = parse_sig_subpkt (sig->hashed, reqtype, NULL);
  if (!p)
    p = parse_sig_subpkt (sig->unhashed, reqtype, NULL);
  return p;
}


/* Find all revocation keys.  Look in hashed area only.  */
void
parse_revkeys (PKT_signature * sig)
{
  const byte *revkey;
  int seq = 0;
  size_t len;

  if (sig->sig_class != 0x1F)
    return;

  while ((revkey = enum_sig_subpkt (sig->hashed, SIGSUBPKT_REV_KEY,
				    &len, &seq, NULL)))
    {
      if (/* The only valid length is 22 bytes.  See RFC 4880
	     5.2.3.15.  */
	  len == 22
	  /* 0x80 bit must be set on the class.  */
          && (revkey[0] & 0x80))
	{
	  sig->revkey = xrealloc (sig->revkey,
				  sizeof (struct revocation_key) *
				  (sig->numrevkeys + 1));

	  /* Copy the individual fields.  */
	  sig->revkey[sig->numrevkeys].class = revkey[0];
	  sig->revkey[sig->numrevkeys].algid = revkey[1];
	  memcpy (sig->revkey[sig->numrevkeys].fpr, &revkey[2], 20);

	  sig->numrevkeys++;
	}
    }
}


int
parse_signature (IOBUF inp, int pkttype, unsigned long pktlen,
		 PKT_signature * sig)
{
  int md5_len = 0;
  unsigned n;
  int is_v4 = 0;
  int rc = 0;
  int i, ndata;

  if (pktlen < 16)
    {
      log_error ("packet(%d) too short\n", pkttype);
      if (list_mode)
        es_fputs (":signature packet: [too short]\n", listfp);
      goto leave;
    }
  sig->version = iobuf_get_noeof (inp);
  pktlen--;
  if (sig->version == 4)
    is_v4 = 1;
  else if (sig->version != 2 && sig->version != 3)
    {
      log_error ("packet(%d) with unknown version %d\n",
		 pkttype, sig->version);
      if (list_mode)
        es_fputs (":signature packet: [unknown version]\n", listfp);
      rc = gpg_error (GPG_ERR_INV_PACKET);
      goto leave;
    }

  if (!is_v4)
    {
      if (pktlen == 0)
	goto underflow;
      md5_len = iobuf_get_noeof (inp);
      pktlen--;
    }
  if (pktlen == 0)
    goto underflow;
  sig->sig_class = iobuf_get_noeof (inp);
  pktlen--;
  if (!is_v4)
    {
      if (pktlen < 12)
	goto underflow;
      sig->timestamp = read_32 (inp);
      pktlen -= 4;
      sig->keyid[0] = read_32 (inp);
      pktlen -= 4;
      sig->keyid[1] = read_32 (inp);
      pktlen -= 4;
    }
  if (pktlen < 2)
    goto underflow;
  sig->pubkey_algo = iobuf_get_noeof (inp);
  pktlen--;
  sig->digest_algo = iobuf_get_noeof (inp);
  pktlen--;
  sig->flags.exportable = 1;
  sig->flags.revocable = 1;
  if (is_v4) /* Read subpackets.  */
    {
      if (pktlen < 2)
	goto underflow;
      n = read_16 (inp);
      pktlen -= 2;  /* Length of hashed data. */
      if (pktlen < n)
	goto underflow;
      if (n > 10000)
	{
	  log_error ("signature packet: hashed data too long\n");
          if (list_mode)
            es_fputs (":signature packet: [hashed data too long]\n", listfp);
	  rc = GPG_ERR_INV_PACKET;
	  goto leave;
	}
      if (n)
	{
	  sig->hashed = xmalloc (sizeof (*sig->hashed) + n - 1);
	  sig->hashed->size = n;
	  sig->hashed->len = n;
	  if (iobuf_read (inp, sig->hashed->data, n) != n)
	    {
	      log_error ("premature eof while reading "
			 "hashed signature data\n");
              if (list_mode)
                es_fputs (":signature packet: [premature eof]\n", listfp);
	      rc = -1;
	      goto leave;
	    }
	  pktlen -= n;
	}
      if (pktlen < 2)
	goto underflow;
      n = read_16 (inp);
      pktlen -= 2;  /* Length of unhashed data.  */
      if (pktlen < n)
	goto underflow;
      if (n > 10000)
	{
	  log_error ("signature packet: unhashed data too long\n");
          if (list_mode)
            es_fputs (":signature packet: [unhashed data too long]\n", listfp);
	  rc = GPG_ERR_INV_PACKET;
	  goto leave;
	}
      if (n)
	{
	  sig->unhashed = xmalloc (sizeof (*sig->unhashed) + n - 1);
	  sig->unhashed->size = n;
	  sig->unhashed->len = n;
	  if (iobuf_read (inp, sig->unhashed->data, n) != n)
	    {
	      log_error ("premature eof while reading "
			 "unhashed signature data\n");
              if (list_mode)
                es_fputs (":signature packet: [premature eof]\n", listfp);
	      rc = -1;
	      goto leave;
	    }
	  pktlen -= n;
	}
    }

  if (pktlen < 2)
    goto underflow;
  sig->digest_start[0] = iobuf_get_noeof (inp);
  pktlen--;
  sig->digest_start[1] = iobuf_get_noeof (inp);
  pktlen--;

  if (is_v4 && sig->pubkey_algo)  /* Extract required information.  */
    {
      const byte *p;
      size_t len;

      /* Set sig->flags.unknown_critical if there is a critical bit
       * set for packets which we do not understand.  */
      if (!parse_sig_subpkt (sig->hashed, SIGSUBPKT_TEST_CRITICAL, NULL)
	  || !parse_sig_subpkt (sig->unhashed, SIGSUBPKT_TEST_CRITICAL, NULL))
	sig->flags.unknown_critical = 1;

      p = parse_sig_subpkt (sig->hashed, SIGSUBPKT_SIG_CREATED, NULL);
      if (p)
	sig->timestamp = buf32_to_u32 (p);
      else if (!(sig->pubkey_algo >= 100 && sig->pubkey_algo <= 110)
	       && opt.verbose && !glo_ctrl.silence_parse_warnings)
	log_info ("signature packet without timestamp\n");

      /* Set the key id.  We first try the issuer fingerprint and if
       * this is not found fallback to the issuer.  Note that
       * only the issuer packet is also searched in the unhashed area.  */
      p = parse_sig_subpkt (sig->hashed, SIGSUBPKT_ISSUER_FPR, &len);
      if (p && len == 21 && p[0] == 4)
        {
          sig->keyid[0] = buf32_to_u32 (p + 1 + 12);
	  sig->keyid[1] = buf32_to_u32 (p + 1 + 16);
	}
      else if (p && len == 33 && p[0] == 5)
        {
          sig->keyid[0] = buf32_to_u32 (p + 1 );
	  sig->keyid[1] = buf32_to_u32 (p + 1 + 4);
	}
      else if ((p = parse_sig_subpkt2 (sig, SIGSUBPKT_ISSUER)))
	{
	  sig->keyid[0] = buf32_to_u32 (p);
	  sig->keyid[1] = buf32_to_u32 (p + 4);
	}
      else if (!(sig->pubkey_algo >= 100 && sig->pubkey_algo <= 110)
	       && opt.verbose && !glo_ctrl.silence_parse_warnings)
	log_info ("signature packet without keyid\n");

      p = parse_sig_subpkt (sig->hashed, SIGSUBPKT_SIG_EXPIRE, NULL);
      if (p && buf32_to_u32 (p))
	sig->expiredate = sig->timestamp + buf32_to_u32 (p);
      if (sig->expiredate && sig->expiredate <= make_timestamp ())
	sig->flags.expired = 1;

      p = parse_sig_subpkt (sig->hashed, SIGSUBPKT_POLICY, NULL);
      if (p)
	sig->flags.policy_url = 1;

      p = parse_sig_subpkt (sig->hashed, SIGSUBPKT_PREF_KS, NULL);
      if (p)
	sig->flags.pref_ks = 1;

      p = parse_sig_subpkt (sig->hashed, SIGSUBPKT_SIGNERS_UID, &len);
      if (p && len)
        {
          char *mbox;

          sig->signers_uid = try_make_printable_string (p, len, 0);
          if (!sig->signers_uid)
            {
              rc = gpg_error_from_syserror ();
              goto leave;
            }
          mbox = mailbox_from_userid (sig->signers_uid);
          if (mbox)
            {
              xfree (sig->signers_uid);
              sig->signers_uid = mbox;
            }
        }

      p = parse_sig_subpkt (sig->hashed, SIGSUBPKT_NOTATION, NULL);
      if (p)
	sig->flags.notation = 1;

      p = parse_sig_subpkt (sig->hashed, SIGSUBPKT_KEY_BLOCK, NULL);
      if (p)
        sig->flags.key_block = 1;

      p = parse_sig_subpkt (sig->hashed, SIGSUBPKT_REVOCABLE, NULL);
      if (p && *p == 0)
	sig->flags.revocable = 0;

      p = parse_sig_subpkt (sig->hashed, SIGSUBPKT_TRUST, &len);
      if (p && len == 2)
	{
	  sig->trust_depth = p[0];
	  sig->trust_value = p[1];

	  /* Only look for a regexp if there is also a trust
	     subpacket. */
	  sig->trust_regexp =
	    parse_sig_subpkt (sig->hashed, SIGSUBPKT_REGEXP, &len);

	  /* If the regular expression is of 0 length, there is no
	     regular expression. */
	  if (len == 0)
	    sig->trust_regexp = NULL;
	}

      /* We accept the exportable subpacket from either the hashed or
         unhashed areas as older versions of gpg put it in the
         unhashed area.  In theory, anyway, we should never see this
         packet off of a local keyring. */

      p = parse_sig_subpkt2 (sig, SIGSUBPKT_EXPORTABLE);
      if (p && *p == 0)
	sig->flags.exportable = 0;

      /* Find all revocation keys.  */
      if (sig->sig_class == 0x1F)
	parse_revkeys (sig);
    }

  if (list_mode)
    {
      es_fprintf (listfp, ":signature packet: algo %d, keyid %08lX%08lX\n"
                  "\tversion %d, created %lu, md5len %d, sigclass 0x%02x\n"
                  "\tdigest algo %d, begin of digest %02x %02x\n",
                  sig->pubkey_algo,
                  (ulong) sig->keyid[0], (ulong) sig->keyid[1],
                  sig->version, (ulong) sig->timestamp, md5_len, sig->sig_class,
                  sig->digest_algo, sig->digest_start[0], sig->digest_start[1]);
      if (is_v4)
	{
	  parse_sig_subpkt (sig->hashed, SIGSUBPKT_LIST_HASHED, NULL);
	  parse_sig_subpkt (sig->unhashed, SIGSUBPKT_LIST_UNHASHED, NULL);
	}
    }

  ndata = pubkey_get_nsig (sig->pubkey_algo);
  if (!ndata)
    {
      if (list_mode)
	es_fprintf (listfp, "\tunknown algorithm %d\n", sig->pubkey_algo);
      unknown_pubkey_warning (sig->pubkey_algo);

      /* We store the plain material in data[0], so that we are able
       * to write it back with build_packet().  */
      if (pktlen > (5 * MAX_EXTERN_MPI_BITS / 8))
	{
	  /* We include a limit to avoid too trivial DoS attacks by
	     having gpg allocate too much memory.  */
	  log_error ("signature packet: too much data\n");
	  rc = GPG_ERR_INV_PACKET;
	}
      else
	{
          void *tmpp;

          tmpp = read_rest (inp, pktlen);
	  sig->data[0] = gcry_mpi_set_opaque (NULL, tmpp, tmpp? pktlen * 8 : 0);
	  pktlen = 0;
	}
    }
  else
    {
      for (i = 0; i < ndata; i++)
	{
	  n = pktlen;
	  sig->data[i] = mpi_read (inp, &n, 0);
	  pktlen -= n;
	  if (list_mode)
	    {
	      es_fprintf (listfp, "\tdata: ");
	      mpi_print (listfp, sig->data[i], mpi_print_mode);
	      es_putc ('\n', listfp);
	    }
	  if (!sig->data[i])
	    rc = GPG_ERR_INV_PACKET;
	}
    }

 leave:
  iobuf_skip_rest (inp, pktlen, 0);
  return rc;

 underflow:
  log_error ("packet(%d) too short\n", pkttype);
  if (list_mode)
    es_fputs (":signature packet: [too short]\n", listfp);

  iobuf_skip_rest (inp, pktlen, 0);

  return GPG_ERR_INV_PACKET;
}


static int
parse_onepass_sig (IOBUF inp, int pkttype, unsigned long pktlen,
		   PKT_onepass_sig * ops)
{
  int version;
  int rc = 0;

  if (pktlen < 13)
    {
      log_error ("packet(%d) too short\n", pkttype);
      if (list_mode)
        es_fputs (":onepass_sig packet: [too short]\n", listfp);
      rc = gpg_error (GPG_ERR_INV_PACKET);
      goto leave;
    }
  version = iobuf_get_noeof (inp);
  pktlen--;
  if (version != 3)
    {
      log_error ("onepass_sig with unknown version %d\n", version);
      if (list_mode)
        es_fputs (":onepass_sig packet: [unknown version]\n", listfp);
      rc = gpg_error (GPG_ERR_INV_PACKET);
      goto leave;
    }
  ops->sig_class = iobuf_get_noeof (inp);
  pktlen--;
  ops->digest_algo = iobuf_get_noeof (inp);
  pktlen--;
  ops->pubkey_algo = iobuf_get_noeof (inp);
  pktlen--;
  ops->keyid[0] = read_32 (inp);
  pktlen -= 4;
  ops->keyid[1] = read_32 (inp);
  pktlen -= 4;
  ops->last = iobuf_get_noeof (inp);
  pktlen--;
  if (list_mode)
    es_fprintf (listfp,
                ":onepass_sig packet: keyid %08lX%08lX\n"
                "\tversion %d, sigclass 0x%02x, digest %d, pubkey %d, "
                "last=%d\n",
                (ulong) ops->keyid[0], (ulong) ops->keyid[1],
                version, ops->sig_class,
                ops->digest_algo, ops->pubkey_algo, ops->last);


 leave:
  iobuf_skip_rest (inp, pktlen, 0);
  return rc;
}


static int
parse_key (IOBUF inp, int pkttype, unsigned long pktlen,
	   byte * hdr, int hdrlen, PACKET * pkt)
{
  gpg_error_t err = 0;
  int i, version, algorithm;
  unsigned long timestamp, expiredate, max_expiredate;
  int npkey, nskey;
  u32 keyid[2];
  PKT_public_key *pk;

  (void) hdr;

  pk = pkt->pkt.public_key; /* PK has been cleared. */

  version = iobuf_get_noeof (inp);
  pktlen--;
  if (pkttype == PKT_PUBLIC_SUBKEY && version == '#')
    {
      /* Early versions of G10 used the old PGP comments packets;
       * luckily all those comments are started by a hash.  */
      if (list_mode)
	{
	  es_fprintf (listfp, ":rfc1991 comment packet: \"");
	  for (; pktlen; pktlen--)
	    {
	      int c;
	      c = iobuf_get (inp);
              if (c == -1)
                break; /* Ooops: shorter than indicated.  */
	      if (c >= ' ' && c <= 'z')
		es_putc (c, listfp);
	      else
		es_fprintf (listfp, "\\x%02x", c);
	    }
	  es_fprintf (listfp, "\"\n");
	}
      iobuf_skip_rest (inp, pktlen, 0);
      return 0;
    }
  else if (version == 4)
    {
      /* The only supported version.  Use an older gpg
         version (i.e. gpg 1.4) to parse v3 packets.  */
    }
  else if (version == 2 || version == 3)
    {
      /* Not anymore supported since 2.1.  Use an older gpg version
       * (i.e. gpg 1.4) to parse v3 packets.  */
      if (opt.verbose > 1 && !glo_ctrl.silence_parse_warnings)
        log_info ("packet(%d) with obsolete version %d\n", pkttype, version);
      if (list_mode)
        es_fprintf (listfp, ":key packet: [obsolete version %d]\n", version);
      pk->version = version;
      err = gpg_error (GPG_ERR_LEGACY_KEY);
      goto leave;
    }
  else
    {
      if (version == 5)
        log_info ("packet(%d) with unsupported version %d\n", pkttype, version);
      else
        log_error ("packet(%d) with unsupported version %d\n", pkttype,version);
      if (list_mode)
        es_fputs (":key packet: [unknown version]\n", listfp);
      err = gpg_error (GPG_ERR_UNKNOWN_VERSION);
      goto leave;
    }

  if (pktlen < 11)
    {
      log_error ("packet(%d) too short\n", pkttype);
      if (list_mode)
        es_fputs (":key packet: [too short]\n", listfp);
      err = gpg_error (GPG_ERR_INV_PACKET);
      goto leave;
    }
  else if (pktlen > MAX_KEY_PACKET_LENGTH)
    {
      log_error ("packet(%d) too large\n", pkttype);
      if (list_mode)
        es_fputs (":key packet: [too larget]\n", listfp);
      err = gpg_error (GPG_ERR_INV_PACKET);
      goto leave;
    }

  timestamp = read_32 (inp);
  pktlen -= 4;
  expiredate = 0;		/* have to get it from the selfsignature */
  max_expiredate = 0;
  algorithm = iobuf_get_noeof (inp);
  pktlen--;
  if (list_mode)
    es_fprintf (listfp, ":%s key packet:\n"
                "\tversion %d, algo %d, created %lu, expires %lu\n",
                pkttype == PKT_PUBLIC_KEY ? "public" :
                pkttype == PKT_SECRET_KEY ? "secret" :
                pkttype == PKT_PUBLIC_SUBKEY ? "public sub" :
                pkttype == PKT_SECRET_SUBKEY ? "secret sub" : "??",
                version, algorithm, timestamp, expiredate);

  pk->timestamp = timestamp;
  pk->expiredate = expiredate;
  pk->max_expiredate = max_expiredate;
  pk->hdrbytes = hdrlen;
  pk->version = version;
  pk->flags.primary = (pkttype == PKT_PUBLIC_KEY || pkttype == PKT_SECRET_KEY);
  pk->pubkey_algo = algorithm;

  nskey = pubkey_get_nskey (algorithm);
  npkey = pubkey_get_npkey (algorithm);
  if (!npkey)
    {
      if (list_mode)
	es_fprintf (listfp, "\tunknown algorithm %d\n", algorithm);
      unknown_pubkey_warning (algorithm);
    }

  if (!npkey)
    {
      /* Unknown algorithm - put data into an opaque MPI.  */
      void *tmpp = read_rest (inp, pktlen);
      /* Current gcry_mpi_cmp does not handle a (NULL,n>0) nicely and
       * thus we avoid to create such an MPI.  */
      pk->pkey[0] = gcry_mpi_set_opaque (NULL, tmpp, tmpp? pktlen * 8 : 0);
      pktlen = 0;
      goto leave;
    }
  else
    {
      for (i = 0; i < npkey; i++)
        {
          if (    (algorithm == PUBKEY_ALGO_ECDSA && (i == 0))
               || (algorithm == PUBKEY_ALGO_EDDSA && (i == 0))
               || (algorithm == PUBKEY_ALGO_ECDH  && (i == 0 || i == 2)))
            {
              /* Read the OID (i==1) or the KDF params (i==2).  */
              size_t n;
	      err = read_size_body (inp, pktlen, &n, pk->pkey+i);
              pktlen -= n;
            }
          else
            {
              unsigned int n = pktlen;
              pk->pkey[i] = mpi_read (inp, &n, 0);
              pktlen -= n;
              if (!pk->pkey[i])
                err = gpg_error (GPG_ERR_INV_PACKET);
            }
          if (err)
            goto leave;
          if (list_mode)
            {
              es_fprintf (listfp, "\tpkey[%d]: ", i);
              mpi_print (listfp, pk->pkey[i], mpi_print_mode);
              if ((algorithm == PUBKEY_ALGO_ECDSA
                   || algorithm == PUBKEY_ALGO_EDDSA
                   || algorithm == PUBKEY_ALGO_ECDH) && i==0)
                {
                  char *curve = openpgp_oid_to_str (pk->pkey[0]);
                  const char *name = openpgp_oid_to_curve (curve, 0);
                  es_fprintf (listfp, " %s (%s)", name?name:"", curve);
                  xfree (curve);
                }
              es_putc ('\n', listfp);
            }
        }
    }
  if (list_mode)
    keyid_from_pk (pk, keyid);

  if (pkttype == PKT_SECRET_KEY || pkttype == PKT_SECRET_SUBKEY)
    {
      struct seckey_info *ski;
      byte temp[16];
      size_t snlen = 0;

      if (pktlen < 1)
        {
          err = gpg_error (GPG_ERR_INV_PACKET);
          goto leave;
        }

      pk->seckey_info = ski = xtrycalloc (1, sizeof *ski);
      if (!pk->seckey_info)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }

      ski->algo = iobuf_get_noeof (inp);
      pktlen--;
      if (ski->algo)
	{
	  ski->is_protected = 1;
	  ski->s2k.count = 0;
	  if (ski->algo == 254 || ski->algo == 255)
	    {
	      if (pktlen < 3)
		{
		  err = gpg_error (GPG_ERR_INV_PACKET);
		  goto leave;
		}
	      ski->sha1chk = (ski->algo == 254);
	      ski->algo = iobuf_get_noeof (inp);
	      pktlen--;
	      /* Note that a ski->algo > 110 is illegal, but I'm not
	         erroring on it here as otherwise there would be no
	         way to delete such a key.  */
	      ski->s2k.mode = iobuf_get_noeof (inp);
	      pktlen--;
	      ski->s2k.hash_algo = iobuf_get_noeof (inp);
	      pktlen--;
	      /* Check for the special GNU extension.  */
	      if (ski->s2k.mode == 101)
		{
		  for (i = 0; i < 4 && pktlen; i++, pktlen--)
		    temp[i] = iobuf_get_noeof (inp);
		  if (i < 4 || memcmp (temp, "GNU", 3))
		    {
		      if (list_mode)
			es_fprintf (listfp, "\tunknown S2K %d\n",
                                    ski->s2k.mode);
		      err = gpg_error (GPG_ERR_INV_PACKET);
		      goto leave;
		    }
		  /* Here we know that it is a GNU extension.  What
		   * follows is the GNU protection mode: All values
		   * have special meanings and they are mapped to MODE
		   * with a base of 1000.  */
		  ski->s2k.mode = 1000 + temp[3];
		}

              /* Read the salt.  */
	      switch (ski->s2k.mode)
		{
		case 1:
		case 3:
		  for (i = 0; i < 8 && pktlen; i++, pktlen--)
		    temp[i] = iobuf_get_noeof (inp);
                  if (i < 8)
                    {
		      err = gpg_error (GPG_ERR_INV_PACKET);
		      goto leave;
                    }
		  memcpy (ski->s2k.salt, temp, 8);
		  break;
		}

              /* Check the mode.  */
	      switch (ski->s2k.mode)
		{
		case 0:
		  if (list_mode)
		    es_fprintf (listfp, "\tsimple S2K");
		  break;
		case 1:
		  if (list_mode)
		    es_fprintf (listfp, "\tsalted S2K");
		  break;
		case 3:
		  if (list_mode)
		    es_fprintf (listfp, "\titer+salt S2K");
		  break;
		case 1001:
		  if (list_mode)
		    es_fprintf (listfp, "\tgnu-dummy S2K");
		  break;
		case 1002:
		  if (list_mode)
		    es_fprintf (listfp, "\tgnu-divert-to-card S2K");
		  break;
		default:
		  if (list_mode)
		    es_fprintf (listfp, "\tunknown %sS2K %d\n",
                                ski->s2k.mode < 1000 ? "" : "GNU ",
                                ski->s2k.mode);
		  err = gpg_error (GPG_ERR_INV_PACKET);
		  goto leave;
		}

              /* Print some info.  */
	      if (list_mode)
		{
		  es_fprintf (listfp, ", algo: %d,%s hash: %d",
                              ski->algo,
                              ski->sha1chk ? " SHA1 protection,"
                              : " simple checksum,", ski->s2k.hash_algo);
		  if (ski->s2k.mode == 1 || ski->s2k.mode == 3)
		    {
		      es_fprintf (listfp, ", salt: ");
                      es_write_hexstring (listfp, ski->s2k.salt, 8, 0, NULL);
		    }
		  es_putc ('\n', listfp);
		}

              /* Read remaining protection parameters.  */
	      if (ski->s2k.mode == 3)
		{
		  if (pktlen < 1)
		    {
		      err = gpg_error (GPG_ERR_INV_PACKET);
		      goto leave;
		    }
		  ski->s2k.count = iobuf_get_noeof (inp);
		  pktlen--;
		  if (list_mode)
		    es_fprintf (listfp, "\tprotect count: %lu (%lu)\n",
                                (ulong)S2K_DECODE_COUNT ((ulong)ski->s2k.count),
                                (ulong) ski->s2k.count);
		}
	      else if (ski->s2k.mode == 1002)
		{
		  /* Read the serial number. */
		  if (pktlen < 1)
		    {
		      err = gpg_error (GPG_ERR_INV_PACKET);
		      goto leave;
		    }
		  snlen = iobuf_get (inp);
		  pktlen--;
		  if (pktlen < snlen || snlen == (size_t)(-1))
		    {
		      err = gpg_error (GPG_ERR_INV_PACKET);
		      goto leave;
		    }
		}
	    }
	  else /* Old version; no S2K, so we set mode to 0, hash MD5.  */
	    {
              /* Note that a ski->algo > 110 is illegal, but I'm not
                 erroring on it here as otherwise there would be no
                 way to delete such a key.  */
	      ski->s2k.mode = 0;
	      ski->s2k.hash_algo = DIGEST_ALGO_MD5;
	      if (list_mode)
		es_fprintf (listfp, "\tprotect algo: %d  (hash algo: %d)\n",
                            ski->algo, ski->s2k.hash_algo);
	    }

	  /* It is really ugly that we don't know the size
	   * of the IV here in cases we are not aware of the algorithm.
	   * so a
	   *   ski->ivlen = cipher_get_blocksize (ski->algo);
	   * won't work.  The only solution I see is to hardwire it.
	   * NOTE: if you change the ivlen above 16, don't forget to
	   * enlarge temp.  */
	  ski->ivlen = openpgp_cipher_blocklen (ski->algo);
	  log_assert (ski->ivlen <= sizeof (temp));

	  if (ski->s2k.mode == 1001)
	    ski->ivlen = 0;
	  else if (ski->s2k.mode == 1002)
	    ski->ivlen = snlen < 16 ? snlen : 16;

	  if (pktlen < ski->ivlen)
	    {
              err = gpg_error (GPG_ERR_INV_PACKET);
	      goto leave;
	    }
	  for (i = 0; i < ski->ivlen; i++, pktlen--)
	    temp[i] = iobuf_get_noeof (inp);
	  if (list_mode)
	    {
	      es_fprintf (listfp,
                          ski->s2k.mode == 1002 ? "\tserial-number: "
                          : "\tprotect IV: ");
	      for (i = 0; i < ski->ivlen; i++)
		es_fprintf (listfp, " %02x", temp[i]);
	      es_putc ('\n', listfp);
	    }
	  memcpy (ski->iv, temp, ski->ivlen);
	}

      /* It does not make sense to read it into secure memory.
       * If the user is so careless, not to protect his secret key,
       * we can assume, that he operates an open system :=(.
       * So we put the key into secure memory when we unprotect it. */
      if (ski->s2k.mode == 1001 || ski->s2k.mode == 1002)
	{
	  /* Better set some dummy stuff here.  */
	  pk->pkey[npkey] = gcry_mpi_set_opaque (NULL,
						 xstrdup ("dummydata"),
						 10 * 8);
	  pktlen = 0;
	}
      else if (ski->is_protected)
	{
          void *tmpp;

	  if (pktlen < 2) /* At least two bytes for the length.  */
	    {
              err = gpg_error (GPG_ERR_INV_PACKET);
	      goto leave;
	    }

	  /* Ugly: The length is encrypted too, so we read all stuff
	   * up to the end of the packet into the first SKEY
	   * element.  */

          tmpp = read_rest (inp, pktlen);
	  pk->pkey[npkey] = gcry_mpi_set_opaque (NULL,
						 tmpp, tmpp? pktlen * 8 : 0);
          /* Mark that MPI as protected - we need this information for
             importing a key.  The OPAQUE flag can't be used because
             we also store public EdDSA values in opaque MPIs.  */
          if (pk->pkey[npkey])
            gcry_mpi_set_flag (pk->pkey[npkey], GCRYMPI_FLAG_USER1);
	  pktlen = 0;
	  if (list_mode)
            es_fprintf (listfp, "\tskey[%d]: [v4 protected]\n", npkey);
	}
      else
	{
          u16 csum_tweak = 0;

          /* Not encrypted.  */
	  for (i = npkey; i < nskey; i++)
	    {
              unsigned int n;

              if (pktlen < 2) /* At least two bytes for the length.  */
                {
                  err = gpg_error (GPG_ERR_INV_PACKET);
                  goto leave;
                }
              n = pktlen;
              if (algorithm == PUBKEY_ALGO_EDDSA)
                pk->pkey[i] = mpi_read_detect_0_removal (inp, &n, 0,
                                                         &csum_tweak);
              else
                pk->pkey[i] = mpi_read (inp, &n, 0);
              pktlen -= n;
              if (list_mode)
                {
                  es_fprintf (listfp, "\tskey[%d]: ", i);
                  mpi_print (listfp, pk->pkey[i], mpi_print_mode);
                  es_putc ('\n', listfp);
                }

	      if (!pk->pkey[i])
		err = gpg_error (GPG_ERR_INV_PACKET);
	    }
	  if (err)
	    goto leave;

	  if (pktlen < 2)
	    {
              err = gpg_error (GPG_ERR_INV_PACKET);
	      goto leave;
	    }
	  ski->csum = read_16 (inp);
          ski->csum += csum_tweak;
	  pktlen -= 2;
	  if (list_mode)
            es_fprintf (listfp, "\tchecksum: %04hx\n", ski->csum);
	}
    }

  /* Note that KEYID below has been initialized above in list_mode.  */
  if (list_mode)
    es_fprintf (listfp, "\tkeyid: %08lX%08lX\n",
                (ulong) keyid[0], (ulong) keyid[1]);

 leave:
  iobuf_skip_rest (inp, pktlen, 0);
  return err;
}


/* Attribute subpackets have the same format as v4 signature
   subpackets.  This is not part of OpenPGP, but is done in several
   versions of PGP nevertheless.  */
int
parse_attribute_subpkts (PKT_user_id * uid)
{
  size_t n;
  int count = 0;
  struct user_attribute *attribs = NULL;
  const byte *buffer = uid->attrib_data;
  int buflen = uid->attrib_len;
  byte type;

  xfree (uid->attribs);

  while (buflen)
    {
      n = *buffer++;
      buflen--;
      if (n == 255)  /* 4 byte length header.  */
	{
	  if (buflen < 4)
	    goto too_short;
	  n = buf32_to_size_t (buffer);
	  buffer += 4;
	  buflen -= 4;
	}
      else if (n >= 192)  /* 2 byte special encoded length header.  */
	{
	  if (buflen < 2)
	    goto too_short;
	  n = ((n - 192) << 8) + *buffer + 192;
	  buffer++;
	  buflen--;
	}
      if (buflen < n)
	goto too_short;

      if (!n)
        {
          /* Too short to encode the subpacket type.  */
          if (opt.verbose)
            log_info ("attribute subpacket too short\n");
          break;
        }

      attribs = xrealloc (attribs,
                          (count + 1) * sizeof (struct user_attribute));
      memset (&attribs[count], 0, sizeof (struct user_attribute));

      type = *buffer;
      buffer++;
      buflen--;
      n--;

      attribs[count].type = type;
      attribs[count].data = buffer;
      attribs[count].len = n;
      buffer += n;
      buflen -= n;
      count++;
    }

  uid->attribs = attribs;
  uid->numattribs = count;
  return count;

 too_short:
  if (opt.verbose && !glo_ctrl.silence_parse_warnings)
    log_info ("buffer shorter than attribute subpacket\n");
  uid->attribs = attribs;
  uid->numattribs = count;
  return count;
}


static int
parse_user_id (IOBUF inp, int pkttype, unsigned long pktlen, PACKET * packet)
{
  byte *p;

  /* Cap the size of a user ID at 2k: a value absurdly large enough
     that there is no sane user ID string (which is printable text
     as of RFC2440bis) that won't fit in it, but yet small enough to
     avoid allocation problems.  A large pktlen may not be
     allocatable, and a very large pktlen could actually cause our
     allocation to wrap around in xmalloc to a small number. */

  if (pktlen > MAX_UID_PACKET_LENGTH)
    {
      log_error ("packet(%d) too large\n", pkttype);
      if (list_mode)
        es_fprintf (listfp, ":user ID packet: [too large]\n");
      iobuf_skip_rest (inp, pktlen, 0);
      return GPG_ERR_INV_PACKET;
    }

  packet->pkt.user_id = xmalloc_clear (sizeof *packet->pkt.user_id + pktlen);
  packet->pkt.user_id->len = pktlen;
  packet->pkt.user_id->ref = 1;

  p = packet->pkt.user_id->name;
  for (; pktlen; pktlen--, p++)
    *p = iobuf_get_noeof (inp);
  *p = 0;

  if (list_mode)
    {
      int n = packet->pkt.user_id->len;
      es_fprintf (listfp, ":user ID packet: \"");
      /* fixme: Hey why don't we replace this with es_write_sanitized?? */
      for (p = packet->pkt.user_id->name; n; p++, n--)
	{
	  if (*p >= ' ' && *p <= 'z')
	    es_putc (*p, listfp);
	  else
	    es_fprintf (listfp, "\\x%02x", *p);
	}
      es_fprintf (listfp, "\"\n");
    }
  return 0;
}


void
make_attribute_uidname (PKT_user_id * uid, size_t max_namelen)
{
  log_assert (max_namelen > 70);
  if (uid->numattribs <= 0)
    sprintf (uid->name, "[bad attribute packet of size %lu]",
	     uid->attrib_len);
  else if (uid->numattribs > 1)
    sprintf (uid->name, "[%d attributes of size %lu]",
	     uid->numattribs, uid->attrib_len);
  else
    {
      /* Only one attribute, so list it as the "user id" */

      if (uid->attribs->type == ATTRIB_IMAGE)
	{
	  u32 len;
	  byte type;

	  if (parse_image_header (uid->attribs, &type, &len))
	    sprintf (uid->name, "[%.20s image of size %lu]",
		     image_type_to_string (type, 1), (ulong) len);
	  else
	    sprintf (uid->name, "[invalid image]");
	}
      else
	sprintf (uid->name, "[unknown attribute of size %lu]",
		 (ulong) uid->attribs->len);
    }

  uid->len = strlen (uid->name);
}


static int
parse_attribute (IOBUF inp, int pkttype, unsigned long pktlen,
		 PACKET * packet)
{
  byte *p;

  (void) pkttype;

  /* We better cap the size of an attribute packet to make DoS not too
     easy.  16MB should be more then enough for one attribute packet
     (ie. a photo).  */
  if (pktlen > MAX_ATTR_PACKET_LENGTH)
    {
      log_error ("packet(%d) too large\n", pkttype);
      if (list_mode)
        es_fprintf (listfp, ":attribute packet: [too large]\n");
      iobuf_skip_rest (inp, pktlen, 0);
      return GPG_ERR_INV_PACKET;
    }

#define EXTRA_UID_NAME_SPACE 71
  packet->pkt.user_id = xmalloc_clear (sizeof *packet->pkt.user_id
				       + EXTRA_UID_NAME_SPACE);
  packet->pkt.user_id->ref = 1;
  packet->pkt.user_id->attrib_data = xmalloc (pktlen? pktlen:1);
  packet->pkt.user_id->attrib_len = pktlen;

  p = packet->pkt.user_id->attrib_data;
  for (; pktlen; pktlen--, p++)
    *p = iobuf_get_noeof (inp);

  /* Now parse out the individual attribute subpackets.  This is
     somewhat pointless since there is only one currently defined
     attribute type (jpeg), but it is correct by the spec. */
  parse_attribute_subpkts (packet->pkt.user_id);

  make_attribute_uidname (packet->pkt.user_id, EXTRA_UID_NAME_SPACE);

  if (list_mode)
    {
      es_fprintf (listfp, ":attribute packet: %s\n", packet->pkt.user_id->name);
    }
  return 0;
}


static int
parse_comment (IOBUF inp, int pkttype, unsigned long pktlen, PACKET * packet)
{
  byte *p;

  /* Cap comment packet at a reasonable value to avoid an integer
     overflow in the malloc below.  Comment packets are actually not
     anymore define my OpenPGP and we even stopped to use our
     private comment packet.  */
  if (pktlen > MAX_COMMENT_PACKET_LENGTH)
    {
      log_error ("packet(%d) too large\n", pkttype);
      if (list_mode)
        es_fprintf (listfp, ":%scomment packet: [too large]\n",
                    pkttype == PKT_OLD_COMMENT ? "OpenPGP draft " : "");
      iobuf_skip_rest (inp, pktlen, 0);
      return GPG_ERR_INV_PACKET;
    }
  packet->pkt.comment = xmalloc (sizeof *packet->pkt.comment + pktlen - 1);
  packet->pkt.comment->len = pktlen;
  p = packet->pkt.comment->data;
  for (; pktlen; pktlen--, p++)
    *p = iobuf_get_noeof (inp);

  if (list_mode)
    {
      int n = packet->pkt.comment->len;
      es_fprintf (listfp, ":%scomment packet: \"", pkttype == PKT_OLD_COMMENT ?
                  "OpenPGP draft " : "");
      for (p = packet->pkt.comment->data; n; p++, n--)
	{
	  if (*p >= ' ' && *p <= 'z')
	    es_putc (*p, listfp);
	  else
	    es_fprintf (listfp, "\\x%02x", *p);
	}
      es_fprintf (listfp, "\"\n");
    }
  return 0;
}


/* Parse a ring trust packet RFC4880 (5.10).
 *
 * This parser is special in that the packet is not stored as a packet
 * but its content is merged into the previous packet.  */
static gpg_error_t
parse_ring_trust (parse_packet_ctx_t ctx, unsigned long pktlen)
{
  gpg_error_t err;
  iobuf_t inp = ctx->inp;
  PKT_ring_trust rt = {0};
  int c;
  int not_gpg = 0;

  if (!pktlen)
    {
      if (list_mode)
	es_fprintf (listfp, ":trust packet: empty\n");
      err = 0;
      goto leave;
    }

  c = iobuf_get_noeof (inp);
  pktlen--;
  rt.trustval = c;
  if (pktlen)
    {
      if (!c)
        {
          c = iobuf_get_noeof (inp);
          /* We require that bit 7 of the sigcache is 0 (easier
           * eof handling).  */
          if (!(c & 0x80))
            rt.sigcache = c;
        }
      else
        iobuf_get_noeof (inp);  /* Dummy read.  */
      pktlen--;
    }

  /* Next is the optional subtype.  */
  if (pktlen > 3)
    {
      char tmp[4];
      tmp[0] = iobuf_get_noeof (inp);
      tmp[1] = iobuf_get_noeof (inp);
      tmp[2] = iobuf_get_noeof (inp);
      tmp[3] = iobuf_get_noeof (inp);
      pktlen -= 4;
      if (!memcmp (tmp, "gpg", 3))
        rt.subtype = tmp[3];
      else
        not_gpg = 1;
    }
  /* If it is a key or uid subtype read the remaining data.  */
  if ((rt.subtype == RING_TRUST_KEY || rt.subtype == RING_TRUST_UID)
      && pktlen >= 6 )
    {
      int i;
      unsigned int namelen;

      rt.keyorg = iobuf_get_noeof (inp);
      pktlen--;
      rt.keyupdate = read_32 (inp);
      pktlen -= 4;
      namelen = iobuf_get_noeof (inp);
      pktlen--;
      if (namelen && pktlen)
        {
          rt.url = xtrymalloc (namelen + 1);
          if (!rt.url)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          for (i = 0; pktlen && i < namelen; pktlen--, i++)
            rt.url[i] = iobuf_get_noeof (inp);
          rt.url[i] = 0;
        }
    }

  if (list_mode)
    {
      if (rt.subtype == RING_TRUST_SIG)
        es_fprintf (listfp, ":trust packet: sig flag=%02x sigcache=%02x\n",
                    rt.trustval, rt.sigcache);
      else if (rt.subtype == RING_TRUST_UID || rt.subtype == RING_TRUST_KEY)
        {
          unsigned char *p;

          es_fprintf (listfp, ":trust packet: %s upd=%lu src=%d%s",
                      (rt.subtype == RING_TRUST_UID? "uid" : "key"),
                      (unsigned long)rt.keyupdate,
                      rt.keyorg,
                      (rt.url? " url=":""));
          if (rt.url)
            {
              for (p = rt.url; *p; p++)
                {
                  if (*p >= ' ' && *p <= 'z')
                    es_putc (*p, listfp);
                  else
                    es_fprintf (listfp, "\\x%02x", *p);
                }
            }
          es_putc ('\n', listfp);
        }
      else if (not_gpg)
        es_fprintf (listfp, ":trust packet: not created by gpg\n");
      else
        es_fprintf (listfp, ":trust packet: subtype=%02x\n",
                    rt.subtype);
    }

  /* Now transfer the data to the respective packet.  Do not do this
   * if SKIP_META is set.  */
  if (!ctx->last_pkt.pkt.generic || ctx->skip_meta)
    ;
  else if (rt.subtype == RING_TRUST_SIG
           && ctx->last_pkt.pkttype == PKT_SIGNATURE)
    {
      PKT_signature *sig = ctx->last_pkt.pkt.signature;

      if ((rt.sigcache & 1))
        {
          sig->flags.checked = 1;
          sig->flags.valid = !!(rt.sigcache & 2);
        }
    }
  else if (rt.subtype == RING_TRUST_UID
           && (ctx->last_pkt.pkttype == PKT_USER_ID
               || ctx->last_pkt.pkttype == PKT_ATTRIBUTE))
    {
      PKT_user_id *uid = ctx->last_pkt.pkt.user_id;

      uid->keyorg = rt.keyorg;
      uid->keyupdate = rt.keyupdate;
      uid->updateurl = rt.url;
      rt.url = NULL;
    }
  else if (rt.subtype == RING_TRUST_KEY
           && (ctx->last_pkt.pkttype == PKT_PUBLIC_KEY
               || ctx->last_pkt.pkttype == PKT_SECRET_KEY))
    {
      PKT_public_key *pk = ctx->last_pkt.pkt.public_key;

      pk->keyorg = rt.keyorg;
      pk->keyupdate = rt.keyupdate;
      pk->updateurl = rt.url;
      rt.url = NULL;
    }

  err = 0;

 leave:
  xfree (rt.url);
  free_packet (NULL, ctx); /* This sets ctx->last_pkt to NULL.  */
  iobuf_skip_rest (inp, pktlen, 0);
  return err;
}


static int
parse_plaintext (IOBUF inp, int pkttype, unsigned long pktlen,
		 PACKET * pkt, int new_ctb, int partial)
{
  int rc = 0;
  int mode, namelen;
  PKT_plaintext *pt;
  byte *p;
  int c, i;

  if (!partial && pktlen < 6)
    {
      log_error ("packet(%d) too short (%lu)\n", pkttype, (ulong) pktlen);
      if (list_mode)
        es_fputs (":literal data packet: [too short]\n", listfp);
      rc = gpg_error (GPG_ERR_INV_PACKET);
      goto leave;
    }
  mode = iobuf_get_noeof (inp);
  if (pktlen)
    pktlen--;
  namelen = iobuf_get_noeof (inp);
  if (pktlen)
    pktlen--;
  /* Note that namelen will never exceed 255 bytes. */
  pt = pkt->pkt.plaintext =
    xmalloc (sizeof *pkt->pkt.plaintext + namelen - 1);
  pt->new_ctb = new_ctb;
  pt->mode = mode;
  pt->namelen = namelen;
  pt->is_partial = partial;
  if (pktlen)
    {
      for (i = 0; pktlen > 4 && i < namelen; pktlen--, i++)
	pt->name[i] = iobuf_get_noeof (inp);
    }
  else
    {
      for (i = 0; i < namelen; i++)
	if ((c = iobuf_get (inp)) == -1)
	  break;
	else
	  pt->name[i] = c;
    }
  /* Fill up NAME so that a check with valgrind won't complain about
   * reading from uninitalized memory.  This case may be triggred by
   * corrupted packets.  */
  for (; i < namelen; i++)
    pt->name[i] = 0;

  pt->timestamp = read_32 (inp);
  if (pktlen)
    pktlen -= 4;
  pt->len = pktlen;
  pt->buf = inp;

  if (list_mode)
    {
      es_fprintf (listfp, ":literal data packet:\n"
                  "\tmode %c (%X), created %lu, name=\"",
                  mode >= ' ' && mode < 'z' ? mode : '?', mode,
                  (ulong) pt->timestamp);
      for (p = pt->name, i = 0; i < namelen; p++, i++)
	{
	  if (*p >= ' ' && *p <= 'z')
	    es_putc (*p, listfp);
	  else
	    es_fprintf (listfp, "\\x%02x", *p);
	}
      es_fprintf (listfp, "\",\n\traw data: ");
      if (partial)
	es_fprintf (listfp, "unknown length\n");
      else
	es_fprintf (listfp, "%lu bytes\n", (ulong) pt->len);
    }

 leave:
  return rc;
}


static int
parse_compressed (IOBUF inp, int pkttype, unsigned long pktlen,
		  PACKET * pkt, int new_ctb)
{
  PKT_compressed *zd;

  /* PKTLEN is here 0, but data follows (this should be the last
     object in a file or the compress algorithm should know the
     length).  */
  (void) pkttype;
  (void) pktlen;

  zd = pkt->pkt.compressed = xmalloc (sizeof *pkt->pkt.compressed);
  zd->algorithm = iobuf_get_noeof (inp);
  zd->len = 0;			/* not used */
  zd->new_ctb = new_ctb;
  zd->buf = inp;
  if (list_mode)
    es_fprintf (listfp, ":compressed packet: algo=%d\n", zd->algorithm);
  return 0;
}


static int
parse_encrypted (IOBUF inp, int pkttype, unsigned long pktlen,
		 PACKET * pkt, int new_ctb, int partial)
{
  int rc = 0;
  PKT_encrypted *ed;
  unsigned long orig_pktlen = pktlen;

  ed = pkt->pkt.encrypted = xmalloc (sizeof *pkt->pkt.encrypted);
  /* ed->len is set below.  */
  ed->extralen = 0;  /* Unknown here; only used in build_packet.  */
  ed->buf = NULL;
  ed->new_ctb = new_ctb;
  ed->is_partial = partial;
  ed->aead_algo = 0;
  ed->cipher_algo = 0; /* Only used with AEAD.  */
  ed->chunkbyte = 0;   /* Only used with AEAD.  */
  if (pkttype == PKT_ENCRYPTED_MDC)
    {
      /* Fixme: add some pktlen sanity checks.  */
      int version;

      version = iobuf_get_noeof (inp);
      if (orig_pktlen)
	pktlen--;
      if (version != 1)
	{
	  log_error ("encrypted_mdc packet with unknown version %d\n",
		     version);
          if (list_mode)
            es_fputs (":encrypted data packet: [unknown version]\n", listfp);
	  /*skip_rest(inp, pktlen); should we really do this? */
	  rc = gpg_error (GPG_ERR_INV_PACKET);
	  goto leave;
	}
      ed->mdc_method = DIGEST_ALGO_SHA1;
    }
  else
    ed->mdc_method = 0;

  /* A basic sanity check.  We need at least an 8 byte IV plus the 2
     detection bytes.  Note that we don't known the algorithm and thus
     we may only check against the minimum blocksize.  */
  if (orig_pktlen && pktlen < 10)
    {
      /* Actually this is blocksize+2.  */
      log_error ("packet(%d) too short\n", pkttype);
      if (list_mode)
        es_fputs (":encrypted data packet: [too short]\n", listfp);
      rc = GPG_ERR_INV_PACKET;
      iobuf_skip_rest (inp, pktlen, partial);
      goto leave;
    }

  /* Store the remaining length of the encrypted data (i.e. without
     the MDC version number but with the IV etc.).  This value is
     required during decryption.  */
  ed->len = pktlen;

  if (list_mode)
    {
      if (orig_pktlen)
	es_fprintf (listfp, ":encrypted data packet:\n\tlength: %lu\n",
                    orig_pktlen);
      else
	es_fprintf (listfp, ":encrypted data packet:\n\tlength: unknown\n");
      if (ed->mdc_method)
	es_fprintf (listfp, "\tmdc_method: %d\n", ed->mdc_method);
    }

  ed->buf = inp;

 leave:
  return rc;
}


/* Note, that this code is not anymore used in real life because the
   MDC checking is now done right after the decryption in
   decrypt_data.  */
static int
parse_mdc (IOBUF inp, int pkttype, unsigned long pktlen,
	   PACKET * pkt, int new_ctb)
{
  int rc = 0;
  PKT_mdc *mdc;
  byte *p;

  (void) pkttype;

  mdc = pkt->pkt.mdc = xmalloc (sizeof *pkt->pkt.mdc);
  if (list_mode)
    es_fprintf (listfp, ":mdc packet: length=%lu\n", pktlen);
  if (!new_ctb || pktlen != 20)
    {
      log_error ("mdc_packet with invalid encoding\n");
      rc = gpg_error (GPG_ERR_INV_PACKET);
      goto leave;
    }
  p = mdc->hash;
  for (; pktlen; pktlen--, p++)
    *p = iobuf_get_noeof (inp);

 leave:
  return rc;
}


static gpg_error_t
parse_encrypted_aead (iobuf_t inp, int pkttype, unsigned long pktlen,
                      PACKET *pkt, int partial)
{
  int rc = 0;
  PKT_encrypted *ed;
  unsigned long orig_pktlen = pktlen;
  int version;

  ed = pkt->pkt.encrypted = xtrymalloc (sizeof *pkt->pkt.encrypted);
  if (!ed)
    return gpg_error_from_syserror ();
  ed->len = 0;
  ed->extralen = 0;  /* (only used in build_packet.)  */
  ed->buf = NULL;
  ed->new_ctb = 1;   /* (packet number requires a new CTB anyway.)  */
  ed->is_partial = partial;
  ed->mdc_method = 0;
  /* A basic sanity check.  We need one version byte, one algo byte,
   * one aead algo byte, one chunkbyte, at least 15 byte IV.  */
  if (orig_pktlen && pktlen < 19)
    {
      log_error ("packet(%d) too short\n", pkttype);
      if (list_mode)
        es_fputs (":aead encrypted packet: [too short]\n", listfp);
      rc = gpg_error (GPG_ERR_INV_PACKET);
      iobuf_skip_rest (inp, pktlen, partial);
      goto leave;
    }

  version = iobuf_get_noeof (inp);
  if (orig_pktlen)
    pktlen--;
  if (version != 1)
    {
      log_error ("aead encrypted packet with unknown version %d\n",
                 version);
      if (list_mode)
        es_fputs (":aead encrypted packet: [unknown version]\n", listfp);
      /*skip_rest(inp, pktlen); should we really do this? */
      rc = gpg_error (GPG_ERR_INV_PACKET);
      goto leave;
    }

  ed->cipher_algo = iobuf_get_noeof (inp);
  if (orig_pktlen)
    pktlen--;
  ed->aead_algo = iobuf_get_noeof (inp);
  if (orig_pktlen)
    pktlen--;
  ed->chunkbyte = iobuf_get_noeof (inp);
  if (orig_pktlen)
    pktlen--;

  /* Store the remaining length of the encrypted data.  We read the
   * rest during decryption.  */
  ed->len = pktlen;

  if (list_mode)
    {
      es_fprintf (listfp, ":aead encrypted packet: cipher=%u aead=%u cb=%u\n",
                  ed->cipher_algo, ed->aead_algo, ed->chunkbyte);
      if (orig_pktlen)
	es_fprintf (listfp, "\tlength: %lu\n", orig_pktlen);
      else
	es_fprintf (listfp, "\tlength: unknown\n");
    }

  ed->buf = inp;

 leave:
  return rc;
}


/*
 * This packet is internally generated by us (in armor.c) to transfer
 * some information to the lower layer.  To make sure that this packet
 * is really a GPG faked one and not one coming from outside, we
 * first check that there is a unique tag in it.
 *
 * The format of such a control packet is:
 *   n byte  session marker
 *   1 byte  control type CTRLPKT_xxxxx
 *   m byte  control data
 */
static int
parse_gpg_control (IOBUF inp, int pkttype, unsigned long pktlen,
		   PACKET * packet, int partial)
{
  byte *p;
  const byte *sesmark;
  size_t sesmarklen;
  int i;

  (void) pkttype;

  if (list_mode)
    es_fprintf (listfp, ":packet 63: length %lu ", pktlen);

  sesmark = get_session_marker (&sesmarklen);
  if (pktlen < sesmarklen + 1)	/* 1 is for the control bytes */
    goto skipit;
  for (i = 0; i < sesmarklen; i++, pktlen--)
    {
      if (sesmark[i] != iobuf_get_noeof (inp))
	goto skipit;
    }
  if (pktlen > 4096)
    goto skipit;  /* Definitely too large.  We skip it to avoid an
                     overflow in the malloc.  */
  if (list_mode)
    es_fputs ("- gpg control packet", listfp);

  packet->pkt.gpg_control = xmalloc (sizeof *packet->pkt.gpg_control
				     + pktlen - 1);
  packet->pkt.gpg_control->control = iobuf_get_noeof (inp);
  pktlen--;
  packet->pkt.gpg_control->datalen = pktlen;
  p = packet->pkt.gpg_control->data;
  for (; pktlen; pktlen--, p++)
    *p = iobuf_get_noeof (inp);

  return 0;

 skipit:
  if (list_mode)
    {
      int c;

      i = 0;
      es_fprintf (listfp, "- private (rest length %lu)\n", pktlen);
      if (partial)
	{
	  while ((c = iobuf_get (inp)) != -1)
	    dump_hex_line (c, &i);
	}
      else
	{
	  for (; pktlen; pktlen--)
	    {
	      dump_hex_line ((c = iobuf_get (inp)), &i);
	      if (c == -1)
		break;
	    }
	}
      es_putc ('\n', listfp);
    }
  iobuf_skip_rest (inp, pktlen, 0);
  return gpg_error (GPG_ERR_INV_PACKET);
}


/* Create a GPG control packet to be used internally as a placeholder.  */
PACKET *
create_gpg_control (ctrlpkttype_t type, const byte * data, size_t datalen)
{
  PACKET *packet;
  byte *p;

  packet = xmalloc (sizeof *packet);
  init_packet (packet);
  packet->pkttype = PKT_GPG_CONTROL;
  packet->pkt.gpg_control = xmalloc (sizeof *packet->pkt.gpg_control
				     + datalen - 1);
  packet->pkt.gpg_control->control = type;
  packet->pkt.gpg_control->datalen = datalen;
  p = packet->pkt.gpg_control->data;
  for (; datalen; datalen--, p++)
    *p = *data++;

  return packet;
}
