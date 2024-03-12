/* t-stutter.c - Test the stutter exploit.
 * Copyright (C) 2016 g10 Code GmbH
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

/* This test is based on the paper: "An Attack on CFB Mode Encryption
 * as Used by OpenPGP."  This attack uses a padding oracle to decrypt
 * the first two bytes of each block (which are normally 16 bytes
 * large).  Concretely, if an attacker can use this attack if it can
 * sense whether the quick integrity check failed.  See RFC 4880,
 * Section 5.7 for an explanation of this quick check.
 *
 * The concrete attack, as described in the paper, only works for
 * PKT_ENCRYPTED packets; it does not work for PKT_ENCRYPTED_MDC
 * packets, which use a slightly different CFB mode (they don't
 * include a sync after the IV).  But, small modifications should
 * allow the attack to work for PKT_ENCRYPTED_MDC packets.
 *
 * The cost of this attack is 2^15 + i * 2^15 oracle queries, where i
 * is the number of blocks the attack wants to decrypt.  This attack
 * is completely unfeasible when gpg is used interactively, but it
 * could work when used as a service.
 *
 * How to generate a test message:
 *
 *   $ echo 0123456789abcdefghijklmnopqrstuvwxyz | \
 *         gpg --disable-mdc -z 0 -c  > msg.asc
 *   $ gpg --list-packets msg.asc
 *   # Make sure the encryption packet contains a literal packet (without
 *   # any nesting).
 *   $ gpgsplit msg.asc
 *   $ gpg --show-session-key -d msg.asc
 *   $ ./t-stutter --debug SESSION_KEY 000002-009.encrypted
 */

#include <config.h>
#include <errno.h>
#include <ctype.h>

#include "gpg.h"
#include "main.h"
#include "../common/types.h"
#include "../common/util.h"
#include "dek.h"
#include "../common/logging.h"

#include "test.c"

static void
log_hexdump (byte *buffer, int length)
{
  int written = 0;

  fprintf (stderr, "%d bytes:\n", length);
  while (length > 0)
    {
      int have = length > 16 ? 16 : length;
      int i;
      char formatted[2 * 16 + 1];
      char text[16 + 1];

      fprintf (stderr, "%-8d ", written);
      bin2hex (buffer, have, formatted);
      for (i = 0; i < 16; i ++)
        {
          if (i % 2 == 0)
            fputc (' ', stderr);
          if (i % 8 == 0)
            fputc (' ', stderr);

          if (i < have)
            fwrite (&formatted[2 * i], 2, 1, stderr);
          else
            fwrite ("  ", 2, 1, stderr);
        }

      for (i = 0; i < have; i ++)
        {
          if (isprint (buffer[i]))
            text[i] = buffer[i];
          else
            text[i] = '.';
        }
      text[i] = 0;

      fprintf (stderr, "    ");
      if (strlen (text) > 8)
        {
          fwrite (text, 8, 1, stderr);
          fputc (' ', stderr);
          fwrite (&text[8], strlen (text) - 8, 1, stderr);
        }
      else
        fwrite (text, strlen (text), 1, stderr);
      fputc ('\n', stderr);

      buffer += have;
      length -= have;
      written += have;
    }

  return;
}

static char *
hexstr (const byte *bytes)
{
  static int i;
  static char bufs[100][7];

  i ++;
  if (i == 100)
    i = 0;

  sprintf (bufs[i], "0x%02X%02X", bytes[0], bytes[1]);
  return bufs[i];
}

/* xor the two bytes starting at A with the two bytes starting at B
   and return the result.  */
static byte *
bufxor2 (const byte *a, const byte *b)
{
  static int i;
  static char bufs[100][2];

  i ++;
  if (i == 100)
    i = 0;

  bufs[i][0] = a[0] ^ b[0];
  bufs[i][1] = a[1] ^ b[1];
  return bufs[i];
}

/* The session key stays constant.  */
static DEK dek;
int blocksize;

/* Decode the session key, which is in the format output by gpg
   --show-session-key.  */
static void
parse_session_key (char *session_key)
{
  char *tail;
  char *p = session_key;

  errno = 0;
  dek.algo = strtol (p, &tail, 10);
  if (errno || (tail && *tail != ':'))
    log_fatal ("Invalid session key specification.  "
               "Expected: cipher-id:HEXADECIMAL-CHRACTERS\n");

  /* Skip the ':'.  */
  p = tail + 1;

  if (strlen (p) % 2 != 0)
    log_fatal ("Session key must consist of an even number of hexadecimal characters.\n");

  dek.keylen = strlen (p) / 2;
  log_assert (dek.keylen <= sizeof (dek.key));

  if (hex2bin (p, dek.key, dek.keylen) == -1)
    log_fatal ("Session key must only contain hexadecimal characters\n");

  blocksize = openpgp_cipher_get_algo_blklen (dek.algo);
  if ( !blocksize || blocksize > 16 )
    log_fatal ("unsupported blocksize %u\n", blocksize );

  return;
}

/* The ciphertext, the plaintext as decrypted by the good session key,
   and the cfb stream (derived from the ciphertext and the
   plaintext).  */
static int msg_len;
static byte *msg;
static byte *msg_plaintext;
static byte *msg_cfb;

/* Whether we need to resynchronize the CFB after writing the random
   data (this is the case for encrypted packets, but not encrypted and
   integrity protected packets).  */
static int sync;

static int
block_offset (int i)
{
  int extra = 0;

  log_assert (i >= 1);
  /* Make sure blocksize has been initialized.  */
  log_assert (blocksize);

  if (i > 2)
    {
      i -= 2;
      extra = blocksize + 2;
    }
  return (i - 1) * blocksize + extra;
}

/* Return the ith block from TEXT.  The first block is labeled 1.
   Note: consistent with the OpenPGP message format, the second block
   (i=2) is just 2 bytes.  */
static byte *
block (byte *text, int len, int i)
{
  int offset = block_offset (i);

  log_assert (offset < len);
  return &text[offset];
}

/* Return true if the quick integrity check passes.  Also, if
   PLAINTEXTP is not NULL, return the decrypted plaintext in
   *PLAINTEXTP.  If CFBP is not NULL, return the CFB byte stream in
   *CFBP.  */
static int
oracle (int debug, byte *ciphertext, int len, byte **plaintextp, byte **cfbp)
{
  int rc = 0;
  unsigned nprefix;
  gcry_cipher_hd_t cipher_hd = NULL;
  byte *plaintext = NULL;
  byte *cfb = NULL;

  /* Make sure DEK was initialized.  */
  log_assert (dek.algo);
  log_assert (dek.keylen);
  log_assert (blocksize);

  nprefix = blocksize;
  if (len < nprefix + 2)
    {
       /* An invalid message.  We can't check that during parsing
          because we may not know the used cipher then.  */
      rc = gpg_error (GPG_ERR_INV_PACKET);
      goto leave;
    }

  rc = openpgp_cipher_open (&cipher_hd, dek.algo,
			    GCRY_CIPHER_MODE_CFB,
			    (! sync /* ed->mdc_method || dek.algo >= 100 */ ?
                             0 : GCRY_CIPHER_ENABLE_SYNC));
  if (rc)
    log_fatal ("Failed to open cipher: %s\n", gpg_strerror (rc));

  rc = gcry_cipher_setkey (cipher_hd, dek.key, dek.keylen);
  if (gpg_err_code (rc) == GPG_ERR_WEAK_KEY)
    {
      log_info ("WARNING: message was encrypted with"
                " a weak key in the symmetric cipher.\n");
      rc=0;
    }
  else if( rc )
    log_fatal ("key setup failed: %s\n", gpg_strerror (rc));

  gcry_cipher_setiv (cipher_hd, NULL, 0);

  if (debug)
    {
      log_debug ("Encrypted data:\n");
      log_hexdump(ciphertext, len);
    }
  plaintext = xmalloc_clear (len);
  gcry_cipher_decrypt (cipher_hd, plaintext, blocksize + 2,
                       ciphertext, blocksize + 2);
  gcry_cipher_sync (cipher_hd);
  if (len > blocksize+2)
    gcry_cipher_decrypt (cipher_hd,
                         &plaintext[blocksize+2], len-(blocksize+2),
                         &ciphertext[blocksize+2], len-(blocksize+2));

  if (debug)
    {
      log_debug ("Decrypted data:\n");
      log_hexdump (plaintext, len);
      log_debug ("R_{b-1,b} = %s\n", hexstr (&plaintext[blocksize - 2]));
      log_debug ("R_{b+1,b+2} = %s\n", hexstr (&plaintext[blocksize]));
    }

  if (cfbp || debug)
    {
      int i;
      cfb = xmalloc (len);
      for (i = 0; i < len; i ++)
        cfb[i] = plaintext[i] ^ ciphertext[i];

      log_assert (len >= blocksize + 2);

      if (debug)
        {
          log_debug ("cfb:\n");
          log_hexdump (cfb, len);

          log_debug ("E_k([C_1]_{1,2}) = C_2 xor R (%s xor %s) = %s\n",
                    hexstr (&ciphertext[blocksize]),
                    hexstr (&plaintext[blocksize]),
                    hexstr (bufxor2 (&ciphertext[blocksize],
                                     &plaintext[blocksize])));
          if (len >= blocksize + 4)
            log_debug ("D = Ek([C1]_{3-b} || C_2)_{1-2} (%s) xor C2 (%s) xor E_k(0)_{b-1,b} (%s) = %s\n",
                       hexstr (&cfb[blocksize + 2]),
                       hexstr (&ciphertext[blocksize]),
                       hexstr (&cfb[blocksize - 2]),
                       hexstr (bufxor2 (bufxor2 (&cfb[blocksize + 2],
                                                 &ciphertext[blocksize]),
                                        &cfb[blocksize - 2])));
        }
    }

  if (plaintext[nprefix-2] != plaintext[nprefix]
      || plaintext[nprefix-1] != plaintext[nprefix+1])
    {
      rc = gpg_error (GPG_ERR_BAD_KEY);
      goto leave;
    }

 leave:
  if (! rc && plaintextp)
    *plaintextp = plaintext;
  else
    xfree (plaintext);

  if (! rc && cfbp)
    *cfbp = cfb;
  else
    xfree (cfb);

  if (cipher_hd)
    gcry_cipher_close (cipher_hd);
  return rc;
}

/* Query the oracle with D=D for block B.  */
static int
oracle_test (unsigned int d, int b, int debug)
{
  byte probe[32 + 2];

  log_assert (blocksize + 2 <= sizeof probe);
  log_assert (d < 256 * 256);

  if (b == 1)
    memcpy (probe, &msg[2], blocksize);
  else
    memcpy (probe, block (msg, msg_len, b), blocksize);

  probe[blocksize] = d >> 8;
  probe[blocksize + 1] = d & 0xff;

  if (debug)
    log_debug ("oracle (0x%04X):\n", d);

  return oracle (debug, probe, blocksize + 2, NULL, NULL) == 0;
}

static void
do_test (int argc, char *argv[])
{
  int i;
  int debug = 0;
  char *filename = NULL;
  int help = 0;

  byte *raw_data;
  int raw_data_len;

  (void)current_test_group_failed;
  for (i = 1; i < argc; i ++)
    {
      if (strcmp (argv[i], "--debug") == 0)
        debug = 1;
      else if (! blocksize)
        parse_session_key (argv[i]);
      else if (! filename)
        filename = argv[i];
      else
        {
          help = 1;
          break;
        }
    }

  if (! blocksize && ! filename && (filename = prepend_srcdir ("t-stutter-data.asc")))
    /* Try defaults.  */
    {
      parse_session_key ("9:9274A8EC128E850C6DDDF9EAC68BFA84FC7BC05F340DA41D78C93D0640C7C503");
    }

  if (help || ! blocksize || ! filename)
    log_fatal ("Usage: %s [--debug] SESSION_KEY ENCRYPTED_PKT\n", argv[0]);

  /* Don't read more than a KB.  */
  raw_data_len = 1024;
  raw_data = xmalloc (raw_data_len);

  {
    FILE *fp;
    int r;

    fp = fopen (filename, "r");
    if (! fp)
      log_fatal ("Opening %s: %s\n", filename, strerror (errno));
    r = fread (raw_data, 1, raw_data_len, fp);
    fclose (fp);

    /* We need at least the random data, the encrypted and literal
       packets' headers and some body.  */
    if (r < (blocksize + 2 /* Random data.  */
             + 2 * blocksize /* Header + some plaintext.  */))
      log_fatal ("Not enough data (need at least %d bytes of plain text): %s.\n",
                 blocksize + 2, strerror (errno));
    raw_data_len = r;

    if (debug)
      {
        log_debug ("First few bytes of the raw data:\n");
        log_hexdump (raw_data, raw_data_len > 8 ? 8 : raw_data_len);
      }
  }

  /* Parse the packet's header.  */
  {
    int ctb = raw_data[0];
    int new_format = ctb & (1 << 7);
    int pkttype = (ctb & ((1 << 5) - 1)) >> (new_format ? 0 : 2);
    int hdrlen;

    if (new_format)
      {
        if (debug)
          log_debug ("len encoded: 0x%x (%d)\n", raw_data[1], raw_data[1]);
        if (raw_data[1] < 192)
          hdrlen = 2;
        else if (raw_data[1] < 224)
          hdrlen = 3;
        else if (raw_data[1] == 255)
          hdrlen = 5;
        else
          hdrlen = 2;
      }
    else
      {
        int lentype = ctb & 0x3;
        if (lentype == 0)
          hdrlen = 2;
        else if (lentype == 1)
          hdrlen = 3;
        else if (lentype == 2)
          hdrlen = 5;
        else
          /* Indeterminate.  */
          hdrlen = 1;
      }

    if (debug)
      log_debug ("ctb = %x; %s format, hdrlen: %d, packet: %s\n",
                 ctb, new_format ? "new" : "old",
                 hdrlen,
                 pkttype_str (pkttype));

    if (! (pkttype == PKT_ENCRYPTED || pkttype == PKT_ENCRYPTED_MDC))
      log_fatal ("%s does not contain an encrypted packet, but a %s.\n",
                 filename, pkttype_str (pkttype));

    if (pkttype == PKT_ENCRYPTED_MDC)
      {
        /* The first byte following the header is the version, which
           is 1.  */
        log_assert (raw_data[hdrlen] == 1);
        hdrlen ++;
        sync = 0;
      }
    else
      sync = 1;

    msg = &raw_data[hdrlen];
    msg_len = raw_data_len - hdrlen;
  }

  log_assert (msg_len >= blocksize + 2);

  {
    /* This can at least partially be guessed.  So we just assume that
       it is known.  */
    int d;
    int found;
    const byte *m1;
    byte e_k_zero[2];

    if (oracle (debug, msg, msg_len, &msg_plaintext, &msg_cfb) == 0)
      {
        if (debug)
          log_debug ("Session key appears to be good.\n");
      }
    else
      log_fatal ("Session key is bad!\n");

    m1 = &msg_plaintext[blocksize + 2];
    if (debug)
      log_debug ("First two bytes of plaintext are: %02X (%c) %02X (%c)\n",
                 m1[0], isprint (m1[0]) ? m1[0] : '?',
                 m1[1], isprint (m1[1]) ? m1[1] : '?');

    for (d = 0; d < 256 * 256; d ++)
      if ((found = oracle_test (d, 1, 0)))
        break;

    if (! found)
      log_fatal ("Failed to find d!\n");

    if (debug)
      oracle_test (d, 1, 1);

    if (debug)
      log_debug ("D = %d (%x) looks good.\n", d, d);

    {
      byte *c2 = block (msg, msg_len, 2);
      byte D[2] = { d >> 8, d & 0xFF };
      byte *c3 = block (msg, msg_len, 3);

      memcpy (e_k_zero,
              bufxor2 (bufxor2 (c2, D),
                       bufxor2 (c3, m1)),
              sizeof (e_k_zero));

      if (debug)
        {
          log_debug ("C2 = %s\n", hexstr (c2));
          log_debug ("D = %s\n", hexstr (D));
          log_debug ("C3 = %s\n", hexstr (c3));
          log_debug ("M = %s\n", hexstr (m1));
          log_debug ("E_k([C1]_{3-b} || C_2) = C3 xor M1 = %s\n",
                     hexstr (bufxor2 (c3, m1)));
          log_debug ("E_k(0)_{b-1,b} = %s\n", hexstr (e_k_zero));
        }
    }

    /* Figure out the first 2 bytes of M2... (offset 16 & 17 of the
       plain text assuming the blocksize == 16 or bytes 34 & 35 of the
       decrypted cipher text, i.e., C4).  */
    for (i = 1; block_offset (i + 3) + 2 <= msg_len; i ++)
      {
        byte e_k_prime[2];
        byte m[2];
        byte *ct = block (msg, msg_len, i + 2);
        byte *pt = block (msg_plaintext, msg_len, 2 + i + 1);

        for (d = 0; d < 256 * 256; d ++)
          if (oracle_test (d, i + 2, 0))
            {
              found = 1;
              break;
            }

        if (! found)
          log_fatal ("Failed to find a valid d for block %d\n", i);

        if (debug)
          log_debug ("Block %d: oracle: D = %04X passes integrity check\n",
                     i, d);

        {
          byte D[2] = { d >> 8, d & 0xFF };
          memcpy (e_k_prime,
                  bufxor2 (bufxor2 (&ct[blocksize - 2], D), e_k_zero),
                  sizeof (e_k_prime));

          memcpy (m, bufxor2 (e_k_prime, block (msg, msg_len, i + 3)),
                  sizeof (m));
        }

        if (debug)
          log_debug ("=> block %d starting at %zd starts with: "
                     "%s (%c%c)\n",
                     i, (size_t) pt - (size_t) msg_plaintext,
                     hexstr (m),
                     isprint (m[0]) ? m[0] : '?', isprint (m[1]) ? m[1] : '?');

        if (m[0] != pt[0] || m[1] != pt[1])
          {
            log_debug ("oracle attack failed!  Expected %s (%c%c), got %s\n",
                       hexstr (pt),
                       isprint (pt[0]) ? pt[0] : '?',
                       isprint (pt[1]) ? pt[1] : '?',
                       hexstr (m));
            tests_failed++;
          }
      }

    if (i == 1)
      log_fatal ("Message is too short, nothing to test.\n");
  }

  xfree (filename);
}
