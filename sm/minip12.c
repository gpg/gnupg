/* minip12.c - A minimal pkcs-12 implementation.
 * Copyright (C) 2002, 2003, 2004, 2006, 2011 Free Software Foundation, Inc.
 * Copyright (C) 2014 Werner Koch
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <gcrypt.h>
#include <errno.h>

#ifdef TEST
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "../common/logging.h"
#include "../common/utf8conv.h"
#include "minip12.h"

#ifndef DIM
#define DIM(v)		     (sizeof(v)/sizeof((v)[0]))
#endif


enum
{
  UNIVERSAL = 0,
  APPLICATION = 1,
  ASNCONTEXT = 2,
  PRIVATE = 3
};


enum
{
  TAG_NONE = 0,
  TAG_BOOLEAN = 1,
  TAG_INTEGER = 2,
  TAG_BIT_STRING = 3,
  TAG_OCTET_STRING = 4,
  TAG_NULL = 5,
  TAG_OBJECT_ID = 6,
  TAG_OBJECT_DESCRIPTOR = 7,
  TAG_EXTERNAL = 8,
  TAG_REAL = 9,
  TAG_ENUMERATED = 10,
  TAG_EMBEDDED_PDV = 11,
  TAG_UTF8_STRING = 12,
  TAG_REALTIVE_OID = 13,
  TAG_SEQUENCE = 16,
  TAG_SET = 17,
  TAG_NUMERIC_STRING = 18,
  TAG_PRINTABLE_STRING = 19,
  TAG_TELETEX_STRING = 20,
  TAG_VIDEOTEX_STRING = 21,
  TAG_IA5_STRING = 22,
  TAG_UTC_TIME = 23,
  TAG_GENERALIZED_TIME = 24,
  TAG_GRAPHIC_STRING = 25,
  TAG_VISIBLE_STRING = 26,
  TAG_GENERAL_STRING = 27,
  TAG_UNIVERSAL_STRING = 28,
  TAG_CHARACTER_STRING = 29,
  TAG_BMP_STRING = 30
};


static unsigned char const oid_data[9] = {
  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01 };
static unsigned char const oid_encryptedData[9] = {
  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x06 };
static unsigned char const oid_pkcs_12_keyBag[11] = {
  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x0A, 0x01, 0x01 };
static unsigned char const oid_pkcs_12_pkcs_8ShroudedKeyBag[11] = {
  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x0A, 0x01, 0x02 };
static unsigned char const oid_pkcs_12_CertBag[11] = {
  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x0A, 0x01, 0x03 };
static unsigned char const oid_pkcs_12_CrlBag[11] = {
  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x0A, 0x01, 0x04 };

static unsigned char const oid_pbeWithSHAAnd3_KeyTripleDES_CBC[10] = {
  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x01, 0x03 };
static unsigned char const oid_pbeWithSHAAnd40BitRC2_CBC[10] = {
  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x01, 0x06 };
static unsigned char const oid_x509Certificate_for_pkcs_12[10] = {
  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x16, 0x01 };

static unsigned char const oid_pkcs5PBKDF2[9] = {
  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C };
static unsigned char const oid_pkcs5PBES2[9] = {
  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D };
static unsigned char const oid_aes128_CBC[9] = {
  0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02 };

static unsigned char const oid_rsaEncryption[9] = {
  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };


static unsigned char const data_3desiter2048[30] = {
  0x30, 0x1C, 0x06, 0x0A, 0x2A, 0x86, 0x48, 0x86,
  0xF7, 0x0D, 0x01, 0x0C, 0x01, 0x03, 0x30, 0x0E,
  0x04, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xFF, 0xFF, 0x02, 0x02, 0x08, 0x00 };
#define DATA_3DESITER2048_SALT_OFF  18

static unsigned char const data_rc2iter2048[30] = {
  0x30, 0x1C, 0x06, 0x0A, 0x2A, 0x86, 0x48, 0x86,
  0xF7, 0x0D, 0x01, 0x0C, 0x01, 0x06, 0x30, 0x0E,
  0x04, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xFF, 0xFF, 0x02, 0x02, 0x08, 0x00 };
#define DATA_RC2ITER2048_SALT_OFF  18

static unsigned char const data_mactemplate[51] = {
  0x30, 0x31, 0x30, 0x21, 0x30, 0x09, 0x06, 0x05,
  0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
  0x14, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0x04, 0x08, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02,
  0x02, 0x08, 0x00 };
#define DATA_MACTEMPLATE_MAC_OFF 17
#define DATA_MACTEMPLATE_SALT_OFF 39

static unsigned char const data_attrtemplate[106] = {
  0x31, 0x7c, 0x30, 0x55, 0x06, 0x09, 0x2a, 0x86,
  0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x14, 0x31,
  0x48, 0x1e, 0x46, 0x00, 0x47, 0x00, 0x6e, 0x00,
  0x75, 0x00, 0x50, 0x00, 0x47, 0x00, 0x20, 0x00,
  0x65, 0x00, 0x78, 0x00, 0x70, 0x00, 0x6f, 0x00,
  0x72, 0x00, 0x74, 0x00, 0x65, 0x00, 0x64, 0x00,
  0x20, 0x00, 0x63, 0x00, 0x65, 0x00, 0x72, 0x00,
  0x74, 0x00, 0x69, 0x00, 0x66, 0x00, 0x69, 0x00,
  0x63, 0x00, 0x61, 0x00, 0x74, 0x00, 0x65, 0x00,
  0x20, 0x00, 0x66, 0x00, 0x66, 0x00, 0x66, 0x00,
  0x66, 0x00, 0x66, 0x00, 0x66, 0x00, 0x66, 0x00,
  0x66, 0x30, 0x23, 0x06, 0x09, 0x2a, 0x86, 0x48,
  0x86, 0xf7, 0x0d, 0x01, 0x09, 0x15, 0x31, 0x16,
  0x04, 0x14 }; /* Need to append SHA-1 digest. */
#define DATA_ATTRTEMPLATE_KEYID_OFF 73

struct buffer_s
{
  unsigned char *buffer;
  size_t length;
};


struct tag_info
{
  int class;
  int is_constructed;
  unsigned long tag;
  unsigned long length;  /* length part of the TLV */
  int nhdr;
  int ndef;              /* It is an indefinite length */
};


/* Parse the buffer at the address BUFFER which is of SIZE and return
   the tag and the length part from the TLV triplet.  Update BUFFER
   and SIZE on success.  Checks that the encoded length does not
   exhaust the length of the provided buffer. */
static int
parse_tag (unsigned char const **buffer, size_t *size, struct tag_info *ti)
{
  int c;
  unsigned long tag;
  const unsigned char *buf = *buffer;
  size_t length = *size;

  ti->length = 0;
  ti->ndef = 0;
  ti->nhdr = 0;

  /* Get the tag */
  if (!length)
    return -1; /* premature eof */
  c = *buf++; length--;
  ti->nhdr++;

  ti->class = (c & 0xc0) >> 6;
  ti->is_constructed = !!(c & 0x20);
  tag = c & 0x1f;

  if (tag == 0x1f)
    {
      tag = 0;
      do
        {
          tag <<= 7;
          if (!length)
            return -1; /* premature eof */
          c = *buf++; length--;
          ti->nhdr++;
          tag |= c & 0x7f;
        }
      while (c & 0x80);
    }
  ti->tag = tag;

  /* Get the length */
  if (!length)
    return -1; /* prematureeof */
  c = *buf++; length--;
  ti->nhdr++;

  if ( !(c & 0x80) )
    ti->length = c;
  else if (c == 0x80)
    ti->ndef = 1;
  else if (c == 0xff)
    return -1; /* forbidden length value */
  else
    {
      unsigned long len = 0;
      int count = c & 0x7f;

      for (; count; count--)
        {
          len <<= 8;
          if (!length)
            return -1; /* premature_eof */
          c = *buf++; length--;
          ti->nhdr++;
          len |= c & 0xff;
        }
      ti->length = len;
    }

  if (ti->class == UNIVERSAL && !ti->tag)
    ti->length = 0;

  if (ti->length > length)
    return -1; /* data larger than buffer. */

  *buffer = buf;
  *size = length;
  return 0;
}


/* Given an ASN.1 chunk of a structure like:

     24 NDEF:       OCTET STRING  -- This is not passed to us
     04    1:         OCTET STRING  -- INPUT point s to here
            :           30
     04    1:         OCTET STRING
            :           80
          [...]
     04    2:         OCTET STRING
            :           00 00
            :         } -- This denotes a Null tag and are the last
                        -- two bytes in INPUT.

   Create a new buffer with the content of that octet string.  INPUT
   is the original buffer with a length as stored at LENGTH.  Returns
   NULL on error or a new malloced buffer with the length of this new
   buffer stored at LENGTH and the number of bytes parsed from input
   are added to the value stored at INPUT_CONSUMED.  INPUT_CONSUMED is
   allowed to be passed as NULL if the caller is not interested in
   this value. */
static unsigned char *
cram_octet_string (const unsigned char *input, size_t *length,
                   size_t *input_consumed)
{
  const unsigned char *s = input;
  size_t n = *length;
  unsigned char *output, *d;
  struct tag_info ti;

  /* Allocate output buf.  We know that it won't be longer than the
     input buffer. */
  d = output = gcry_malloc (n);
  if (!output)
    goto bailout;

  for (;;)
    {
      if (parse_tag (&s, &n, &ti))
        goto bailout;
      if (ti.class == UNIVERSAL && ti.tag == TAG_OCTET_STRING
          && !ti.ndef && !ti.is_constructed)
        {
          memcpy (d, s, ti.length);
          s += ti.length;
          d += ti.length;
          n -= ti.length;
        }
      else if (ti.class == UNIVERSAL && !ti.tag && !ti.is_constructed)
        break; /* Ready */
      else
        goto bailout;
    }


  *length = d - output;
  if (input_consumed)
    *input_consumed += s - input;
  return output;

 bailout:
  if (input_consumed)
    *input_consumed += s - input;
  gcry_free (output);
  return NULL;
}



static int
string_to_key (int id, char *salt, size_t saltlen, int iter, const char *pw,
               int req_keylen, unsigned char *keybuf)
{
  int rc, i, j;
  gcry_md_hd_t md;
  gcry_mpi_t num_b1 = NULL;
  int pwlen;
  unsigned char hash[20], buf_b[64], buf_i[128], *p;
  size_t cur_keylen;
  size_t n;

  cur_keylen = 0;
  pwlen = strlen (pw);
  if (pwlen > 63/2)
    {
      log_error ("password too long\n");
      return -1;
    }

  if (saltlen < 8)
    {
      log_error ("salt too short\n");
      return -1;
    }

  /* Store salt and password in BUF_I */
  p = buf_i;
  for(i=0; i < 64; i++)
    *p++ = salt [i%saltlen];
  for(i=j=0; i < 64; i += 2)
    {
      *p++ = 0;
      *p++ = pw[j];
      if (++j > pwlen) /* Note, that we include the trailing zero */
        j = 0;
    }

  for (;;)
    {
      rc = gcry_md_open (&md, GCRY_MD_SHA1, 0);
      if (rc)
        {
          log_error ( "gcry_md_open failed: %s\n", gpg_strerror (rc));
          return rc;
        }
      for(i=0; i < 64; i++)
        gcry_md_putc (md, id);
      gcry_md_write (md, buf_i, 128);
      memcpy (hash, gcry_md_read (md, 0), 20);
      gcry_md_close (md);
      for (i=1; i < iter; i++)
        gcry_md_hash_buffer (GCRY_MD_SHA1, hash, hash, 20);

      for (i=0; i < 20 && cur_keylen < req_keylen; i++)
        keybuf[cur_keylen++] = hash[i];
      if (cur_keylen == req_keylen)
        {
          gcry_mpi_release (num_b1);
          return 0; /* ready */
        }

      /* need more bytes. */
      for(i=0; i < 64; i++)
        buf_b[i] = hash[i % 20];
      rc = gcry_mpi_scan (&num_b1, GCRYMPI_FMT_USG, buf_b, 64, &n);
      if (rc)
        {
          log_error ( "gcry_mpi_scan failed: %s\n", gpg_strerror (rc));
          return -1;
        }
      gcry_mpi_add_ui (num_b1, num_b1, 1);
      for (i=0; i < 128; i += 64)
        {
          gcry_mpi_t num_ij;

          rc = gcry_mpi_scan (&num_ij, GCRYMPI_FMT_USG, buf_i + i, 64, &n);
          if (rc)
            {
              log_error ( "gcry_mpi_scan failed: %s\n",
                       gpg_strerror (rc));
              return -1;
            }
          gcry_mpi_add (num_ij, num_ij, num_b1);
          gcry_mpi_clear_highbit (num_ij, 64*8);
          rc = gcry_mpi_print (GCRYMPI_FMT_USG, buf_i + i, 64, &n, num_ij);
          if (rc)
            {
              log_error ( "gcry_mpi_print failed: %s\n",
                          gpg_strerror (rc));
              return -1;
            }
          gcry_mpi_release (num_ij);
        }
    }
}


static int
set_key_iv (gcry_cipher_hd_t chd, char *salt, size_t saltlen, int iter,
            const char *pw, int keybytes)
{
  unsigned char keybuf[24];
  int rc;

  assert (keybytes == 5 || keybytes == 24);
  if (string_to_key (1, salt, saltlen, iter, pw, keybytes, keybuf))
    return -1;
  rc = gcry_cipher_setkey (chd, keybuf, keybytes);
  if (rc)
    {
      log_error ( "gcry_cipher_setkey failed: %s\n", gpg_strerror (rc));
      return -1;
    }

  if (string_to_key (2, salt, saltlen, iter, pw, 8, keybuf))
    return -1;
  rc = gcry_cipher_setiv (chd, keybuf, 8);
  if (rc)
    {
      log_error ("gcry_cipher_setiv failed: %s\n", gpg_strerror (rc));
      return -1;
    }
  return 0;
}


static int
set_key_iv_pbes2 (gcry_cipher_hd_t chd, char *salt, size_t saltlen, int iter,
                  const void *iv, size_t ivlen, const char *pw, int algo)
{
  unsigned char *keybuf;
  size_t keylen;
  int rc;

  keylen = gcry_cipher_get_algo_keylen (algo);
  if (!keylen)
    return -1;
  keybuf = gcry_malloc_secure (keylen);
  if (!keybuf)
    return -1;

  rc = gcry_kdf_derive (pw, strlen (pw),
                        GCRY_KDF_PBKDF2, GCRY_MD_SHA1,
                        salt, saltlen, iter, keylen, keybuf);
  if (rc)
    {
      log_error ("gcry_kdf_derive failed: %s\n", gpg_strerror (rc));
      gcry_free (keybuf);
      return -1;
    }

  rc = gcry_cipher_setkey (chd, keybuf, keylen);
  gcry_free (keybuf);
  if (rc)
    {
      log_error ("gcry_cipher_setkey failed: %s\n", gpg_strerror (rc));
      return -1;
    }


  rc = gcry_cipher_setiv (chd, iv, ivlen);
  if (rc)
    {
      log_error ("gcry_cipher_setiv failed: %s\n", gpg_strerror (rc));
      return -1;
    }
  return 0;
}


static void
crypt_block (unsigned char *buffer, size_t length, char *salt, size_t saltlen,
             int iter, const void *iv, size_t ivlen,
             const char *pw, int cipher_algo, int encrypt)
{
  gcry_cipher_hd_t chd;
  int rc;

  rc = gcry_cipher_open (&chd, cipher_algo, GCRY_CIPHER_MODE_CBC, 0);
  if (rc)
    {
      log_error ( "gcry_cipher_open failed: %s\n", gpg_strerror(rc));
      wipememory (buffer, length);
      return;
    }

  if (cipher_algo == GCRY_CIPHER_AES128
      ? set_key_iv_pbes2 (chd, salt, saltlen, iter, iv, ivlen, pw, cipher_algo)
      : set_key_iv (chd, salt, saltlen, iter, pw,
                    cipher_algo == GCRY_CIPHER_RFC2268_40? 5:24))
    {
      wipememory (buffer, length);
      goto leave;
    }

  rc = encrypt? gcry_cipher_encrypt (chd, buffer, length, NULL, 0)
              : gcry_cipher_decrypt (chd, buffer, length, NULL, 0);

  if (rc)
    {
      wipememory (buffer, length);
      log_error ( "en/de-crytion failed: %s\n", gpg_strerror (rc));
      goto leave;
    }

 leave:
  gcry_cipher_close (chd);
}


/* Decrypt a block of data and try several encodings of the key.
   CIPHERTEXT is the encrypted data of size LENGTH bytes; PLAINTEXT is
   a buffer of the same size to receive the decryption result. SALT,
   SALTLEN, ITER and PW are the information required for decryption
   and CIPHER_ALGO is the algorithm id to use.  CHECK_FNC is a
   function called with the plaintext and used to check whether the
   decryption succeeded; i.e. that a correct passphrase has been
   given.  That function shall return true if the decryption has likely
   succeeded. */
static void
decrypt_block (const void *ciphertext, unsigned char *plaintext, size_t length,
               char *salt, size_t saltlen,
               int iter, const void *iv, size_t ivlen,
               const char *pw, int cipher_algo,
               int (*check_fnc) (const void *, size_t))
{
  static const char * const charsets[] = {
    "",   /* No conversion - use the UTF-8 passphrase direct.  */
    "ISO-8859-1",
    "ISO-8859-15",
    "ISO-8859-2",
    "ISO-8859-3",
    "ISO-8859-4",
    "ISO-8859-5",
    "ISO-8859-6",
    "ISO-8859-7",
    "ISO-8859-8",
    "ISO-8859-9",
    "KOI8-R",
    "IBM437",
    "IBM850",
    "EUC-JP",
    "BIG5",
    NULL
  };
  int charsetidx = 0;
  char *convertedpw = NULL;   /* Malloced and converted password or NULL.  */
  size_t convertedpwsize = 0; /* Allocated length.  */

  for (charsetidx=0; charsets[charsetidx]; charsetidx++)
    {
      if (*charsets[charsetidx])
        {
          jnlib_iconv_t cd;
          const char *inptr;
          char *outptr;
          size_t inbytes, outbytes;

          if (!convertedpw)
            {
              /* We assume one byte encodings.  Thus we can allocate
                 the buffer of the same size as the original
                 passphrase; the result will actually be shorter
                 then.  */
              convertedpwsize = strlen (pw) + 1;
              convertedpw = gcry_malloc_secure (convertedpwsize);
              if (!convertedpw)
                {
                  log_info ("out of secure memory while"
                            " converting passphrase\n");
                  break; /* Give up.  */
                }
            }

          cd = jnlib_iconv_open (charsets[charsetidx], "utf-8");
          if (cd == (jnlib_iconv_t)(-1))
            continue;

          inptr = pw;
          inbytes = strlen (pw);
          outptr = convertedpw;
          outbytes = convertedpwsize - 1;
          if ( jnlib_iconv (cd, (const char **)&inptr, &inbytes,
                      &outptr, &outbytes) == (size_t)-1)
            {
              jnlib_iconv_close (cd);
              continue;
            }
          *outptr = 0;
          jnlib_iconv_close (cd);
          log_info ("decryption failed; trying charset '%s'\n",
                    charsets[charsetidx]);
        }
      memcpy (plaintext, ciphertext, length);
      crypt_block (plaintext, length, salt, saltlen, iter, iv, ivlen,
                   convertedpw? convertedpw:pw, cipher_algo, 0);
      if (check_fnc (plaintext, length))
        break; /* Decryption succeeded. */
    }
  gcry_free (convertedpw);
}


/* Return true if the decryption of an bag_encrypted_data object has
   likely succeeded.  */
static int
bag_decrypted_data_p (const void *plaintext, size_t length)
{
  struct tag_info ti;
  const unsigned char *p = plaintext;
  size_t n = length;

  /*   { */
  /* #  warning debug code is enabled */
  /*     FILE *fp = fopen ("tmp-rc2-plain.der", "wb"); */
  /*     if (!fp || fwrite (p, n, 1, fp) != 1) */
  /*       exit (2); */
  /*     fclose (fp); */
  /*   } */

  if (parse_tag (&p, &n, &ti))
    return 0;
  if (ti.class || ti.tag != TAG_SEQUENCE)
    return 0;
  if (parse_tag (&p, &n, &ti))
    return 0;

  return 1;
}

/* Note: If R_RESULT is passed as NULL, a key object as already be
   processed and thus we need to skip it here. */
static int
parse_bag_encrypted_data (const unsigned char *buffer, size_t length,
                          int startoffset, size_t *r_consumed, const char *pw,
                          void (*certcb)(void*, const unsigned char*, size_t),
                          void *certcbarg, gcry_mpi_t **r_result,
                          int *r_badpass)
{
  struct tag_info ti;
  const unsigned char *p = buffer;
  const unsigned char *p_start = buffer;
  size_t n = length;
  const char *where;
  char salt[20];
  size_t saltlen;
  char iv[16];
  unsigned int iter;
  unsigned char *plain = NULL;
  int bad_pass = 0;
  unsigned char *cram_buffer = NULL;
  size_t consumed = 0; /* Number of bytes consumed from the original buffer. */
  int is_3des = 0;
  int is_pbes2 = 0;
  gcry_mpi_t *result = NULL;
  int result_count;

  if (r_result)
    *r_result = NULL;
  where = "start";
  if (parse_tag (&p, &n, &ti))
    goto bailout;
  if (ti.class != ASNCONTEXT || ti.tag)
    goto bailout;
  if (parse_tag (&p, &n, &ti))
    goto bailout;
  if (ti.tag != TAG_SEQUENCE)
    goto bailout;

  where = "bag.encryptedData.version";
  if (parse_tag (&p, &n, &ti))
    goto bailout;
  if (ti.tag != TAG_INTEGER || ti.length != 1 || *p != 0)
    goto bailout;
  p++; n--;
  if (parse_tag (&p, &n, &ti))
    goto bailout;
  if (ti.tag != TAG_SEQUENCE)
    goto bailout;

  where = "bag.encryptedData.data";
  if (parse_tag (&p, &n, &ti))
    goto bailout;
  if (ti.tag != TAG_OBJECT_ID || ti.length != DIM(oid_data)
      || memcmp (p, oid_data, DIM(oid_data)))
    goto bailout;
  p += DIM(oid_data);
  n -= DIM(oid_data);

  where = "bag.encryptedData.keyinfo";
  if (parse_tag (&p, &n, &ti))
    goto bailout;
  if (ti.class || ti.tag != TAG_SEQUENCE)
    goto bailout;
  if (parse_tag (&p, &n, &ti))
    goto bailout;
  if (!ti.class && ti.tag == TAG_OBJECT_ID
      && ti.length == DIM(oid_pbeWithSHAAnd40BitRC2_CBC)
      && !memcmp (p, oid_pbeWithSHAAnd40BitRC2_CBC,
                  DIM(oid_pbeWithSHAAnd40BitRC2_CBC)))
    {
      p += DIM(oid_pbeWithSHAAnd40BitRC2_CBC);
      n -= DIM(oid_pbeWithSHAAnd40BitRC2_CBC);
    }
  else if (!ti.class && ti.tag == TAG_OBJECT_ID
      && ti.length == DIM(oid_pbeWithSHAAnd3_KeyTripleDES_CBC)
      && !memcmp (p, oid_pbeWithSHAAnd3_KeyTripleDES_CBC,
                  DIM(oid_pbeWithSHAAnd3_KeyTripleDES_CBC)))
    {
      p += DIM(oid_pbeWithSHAAnd3_KeyTripleDES_CBC);
      n -= DIM(oid_pbeWithSHAAnd3_KeyTripleDES_CBC);
      is_3des = 1;
    }
  else if (!ti.class && ti.tag == TAG_OBJECT_ID
           && ti.length == DIM(oid_pkcs5PBES2)
           && !memcmp (p, oid_pkcs5PBES2, ti.length))
    {
      p += ti.length;
      n -= ti.length;
      is_pbes2 = 1;
    }
  else
    goto bailout;

  if (is_pbes2)
    {
      where = "pkcs5PBES2-params";
      if (parse_tag (&p, &n, &ti))
        goto bailout;
      if (ti.class || ti.tag != TAG_SEQUENCE)
        goto bailout;
      if (parse_tag (&p, &n, &ti))
        goto bailout;
      if (ti.class || ti.tag != TAG_SEQUENCE)
        goto bailout;
      if (parse_tag (&p, &n, &ti))
        goto bailout;
      if (!(!ti.class && ti.tag == TAG_OBJECT_ID
            && ti.length == DIM(oid_pkcs5PBKDF2)
            && !memcmp (p, oid_pkcs5PBKDF2, ti.length)))
        goto bailout; /* Not PBKDF2.  */
      p += ti.length;
      n -= ti.length;
      if (parse_tag (&p, &n, &ti))
        goto bailout;
      if (ti.class || ti.tag != TAG_SEQUENCE)
        goto bailout;
      if (parse_tag (&p, &n, &ti))
        goto bailout;
      if (!(!ti.class && ti.tag == TAG_OCTET_STRING
            && ti.length >= 8 && ti.length < sizeof salt))
        goto bailout;  /* No salt or unsupported length.  */
      saltlen = ti.length;
      memcpy (salt, p, saltlen);
      p += saltlen;
      n -= saltlen;

      if (parse_tag (&p, &n, &ti))
        goto bailout;
      if (!(!ti.class && ti.tag == TAG_INTEGER && ti.length))
        goto bailout;  /* No valid iteration count.  */
      for (iter=0; ti.length; ti.length--)
        {
          iter <<= 8;
          iter |= (*p++) & 0xff;
          n--;
        }
      /* Note: We don't support the optional parameters but assume
         that the algorithmIdentifier follows. */
      if (parse_tag (&p, &n, &ti))
        goto bailout;
      if (ti.class || ti.tag != TAG_SEQUENCE)
        goto bailout;
      if (parse_tag (&p, &n, &ti))
        goto bailout;
      if (!(!ti.class && ti.tag == TAG_OBJECT_ID
            && ti.length == DIM(oid_aes128_CBC)
            && !memcmp (p, oid_aes128_CBC, ti.length)))
        goto bailout; /* Not AES-128.  */
      p += ti.length;
      n -= ti.length;
      if (parse_tag (&p, &n, &ti))
        goto bailout;
      if (!(!ti.class && ti.tag == TAG_OCTET_STRING && ti.length == sizeof iv))
        goto bailout; /* Bad IV.  */
      memcpy (iv, p, sizeof iv);
      p += sizeof iv;
      n -= sizeof iv;
    }
  else
    {
      where = "rc2or3des-params";
      if (parse_tag (&p, &n, &ti))
        goto bailout;
      if (ti.class || ti.tag != TAG_SEQUENCE)
        goto bailout;
      if (parse_tag (&p, &n, &ti))
        goto bailout;
      if (ti.class || ti.tag != TAG_OCTET_STRING
          || ti.length < 8 || ti.length > 20 )
        goto bailout;
      saltlen = ti.length;
      memcpy (salt, p, saltlen);
      p += saltlen;
      n -= saltlen;
      if (parse_tag (&p, &n, &ti))
        goto bailout;
      if (ti.class || ti.tag != TAG_INTEGER || !ti.length )
        goto bailout;
      for (iter=0; ti.length; ti.length--)
        {
          iter <<= 8;
          iter |= (*p++) & 0xff;
          n--;
        }
    }

  where = "rc2or3desoraes-ciphertext";
  if (parse_tag (&p, &n, &ti))
    goto bailout;

  consumed = p - p_start;
  if (ti.class == ASNCONTEXT && ti.tag == 0 && ti.is_constructed && ti.ndef)
    {
      /* Mozilla exported certs now come with single byte chunks of
         octect strings.  (Mozilla Firefox 1.0.4).  Arghh. */
      where = "cram-rc2or3des-ciphertext";
      cram_buffer = cram_octet_string ( p, &n, &consumed);
      if (!cram_buffer)
        goto bailout;
      p = p_start = cram_buffer;
      if (r_consumed)
        *r_consumed = consumed;
      r_consumed = NULL; /* Ugly hack to not update that value any further. */
      ti.length = n;
    }
  else if (ti.class == ASNCONTEXT && ti.tag == 0 && ti.length )
    ;
  else
    goto bailout;

  log_info ("%lu bytes of %s encrypted text\n",ti.length,
            is_pbes2?"AES128":is_3des?"3DES":"RC2");

  plain = gcry_malloc_secure (ti.length);
  if (!plain)
    {
      log_error ("error allocating decryption buffer\n");
      goto bailout;
    }
  decrypt_block (p, plain, ti.length, salt, saltlen, iter,
                 iv, is_pbes2?16:0, pw,
                 is_pbes2 ? GCRY_CIPHER_AES128 :
                 is_3des  ? GCRY_CIPHER_3DES : GCRY_CIPHER_RFC2268_40,
                 bag_decrypted_data_p);
  n = ti.length;
  startoffset = 0;
  p_start = p = plain;

  where = "outer.outer.seq";
  if (parse_tag (&p, &n, &ti))
    {
      bad_pass = 1;
      goto bailout;
    }
  if (ti.class || ti.tag != TAG_SEQUENCE)
    {
      bad_pass = 1;
      goto bailout;
    }

  if (parse_tag (&p, &n, &ti))
    {
      bad_pass = 1;
      goto bailout;
    }

  /* Loop over all certificates inside the bag. */
  while (n)
    {
      int iscrlbag = 0;
      int iskeybag = 0;

      where = "certbag.nextcert";
      if (ti.class || ti.tag != TAG_SEQUENCE)
        goto bailout;

      where = "certbag.objectidentifier";
      if (parse_tag (&p, &n, &ti))
        goto bailout;
      if (ti.class || ti.tag != TAG_OBJECT_ID)
        goto bailout;
      if ( ti.length == DIM(oid_pkcs_12_CertBag)
           && !memcmp (p, oid_pkcs_12_CertBag, DIM(oid_pkcs_12_CertBag)))
        {
          p += DIM(oid_pkcs_12_CertBag);
          n -= DIM(oid_pkcs_12_CertBag);
        }
      else if ( ti.length == DIM(oid_pkcs_12_CrlBag)
           && !memcmp (p, oid_pkcs_12_CrlBag, DIM(oid_pkcs_12_CrlBag)))
        {
          p += DIM(oid_pkcs_12_CrlBag);
          n -= DIM(oid_pkcs_12_CrlBag);
          iscrlbag = 1;
        }
      else if ( ti.length == DIM(oid_pkcs_12_keyBag)
           && !memcmp (p, oid_pkcs_12_keyBag, DIM(oid_pkcs_12_keyBag)))
        {
          /* The TrustedMIME plugin for MS Outlook started to create
             files with just one outer 3DES encrypted container and
             inside the certificates as well as the key. */
          p += DIM(oid_pkcs_12_keyBag);
          n -= DIM(oid_pkcs_12_keyBag);
          iskeybag = 1;
        }
      else
        goto bailout;

      where = "certbag.before.certheader";
      if (parse_tag (&p, &n, &ti))
        goto bailout;
      if (ti.class != ASNCONTEXT || ti.tag)
        goto bailout;
      if (iscrlbag)
        {
          log_info ("skipping unsupported crlBag\n");
          p += ti.length;
          n -= ti.length;
        }
      else if (iskeybag && (result || !r_result))
        {
          log_info ("one keyBag already processed; skipping this one\n");
          p += ti.length;
          n -= ti.length;
        }
      else if (iskeybag)
        {
          int len;

          log_info ("processing simple keyBag\n");

          /* Fixme: This code is duplicated from parse_bag_data.  */
          if (parse_tag (&p, &n, &ti) || ti.class || ti.tag != TAG_SEQUENCE)
            goto bailout;
          if (parse_tag (&p, &n, &ti) || ti.class || ti.tag != TAG_INTEGER
              || ti.length != 1 || *p)
            goto bailout;
          p++; n--;
          if (parse_tag (&p, &n, &ti) || ti.class || ti.tag != TAG_SEQUENCE)
            goto bailout;
          len = ti.length;
          if (parse_tag (&p, &n, &ti))
            goto bailout;
          if (len < ti.nhdr)
            goto bailout;
          len -= ti.nhdr;
          if (ti.class || ti.tag != TAG_OBJECT_ID
              || ti.length != DIM(oid_rsaEncryption)
              || memcmp (p, oid_rsaEncryption,
                         DIM(oid_rsaEncryption)))
            goto bailout;
          p += DIM (oid_rsaEncryption);
          n -= DIM (oid_rsaEncryption);
          if (len < ti.length)
            goto bailout;
          len -= ti.length;
          if (n < len)
            goto bailout;
          p += len;
          n -= len;
          if ( parse_tag (&p, &n, &ti)
               || ti.class || ti.tag != TAG_OCTET_STRING)
            goto bailout;
          if ( parse_tag (&p, &n, &ti)
               || ti.class || ti.tag != TAG_SEQUENCE)
            goto bailout;
          len = ti.length;

          result = gcry_calloc (10, sizeof *result);
          if (!result)
            {
              log_error ( "error allocating result array\n");
              goto bailout;
            }
          result_count = 0;

          where = "reading.keybag.key-parameters";
          for (result_count = 0; len && result_count < 9;)
            {
              if ( parse_tag (&p, &n, &ti)
                   || ti.class || ti.tag != TAG_INTEGER)
                goto bailout;
              if (len < ti.nhdr)
                goto bailout;
              len -= ti.nhdr;
              if (len < ti.length)
                goto bailout;
              len -= ti.length;
              if (!result_count && ti.length == 1 && !*p)
                ; /* ignore the very first one if it is a 0 */
              else
                {
                  int rc;

                  rc = gcry_mpi_scan (result+result_count, GCRYMPI_FMT_USG, p,
                                      ti.length, NULL);
                  if (rc)
                    {
                      log_error ("error parsing key parameter: %s\n",
                                 gpg_strerror (rc));
                      goto bailout;
                    }
                  result_count++;
                }
              p += ti.length;
              n -= ti.length;
            }
          if (len)
            goto bailout;
        }
      else
        {
          log_info ("processing certBag\n");
          if (parse_tag (&p, &n, &ti))
            goto bailout;
          if (ti.class || ti.tag != TAG_SEQUENCE)
            goto bailout;
          if (parse_tag (&p, &n, &ti))
            goto bailout;
          if (ti.class || ti.tag != TAG_OBJECT_ID
              || ti.length != DIM(oid_x509Certificate_for_pkcs_12)
              || memcmp (p, oid_x509Certificate_for_pkcs_12,
                         DIM(oid_x509Certificate_for_pkcs_12)))
            goto bailout;
          p += DIM(oid_x509Certificate_for_pkcs_12);
          n -= DIM(oid_x509Certificate_for_pkcs_12);

          where = "certbag.before.octetstring";
          if (parse_tag (&p, &n, &ti))
            goto bailout;
          if (ti.class != ASNCONTEXT || ti.tag)
            goto bailout;
          if (parse_tag (&p, &n, &ti))
            goto bailout;
          if (ti.class || ti.tag != TAG_OCTET_STRING || ti.ndef)
            goto bailout;

          /* Return the certificate. */
          if (certcb)
            certcb (certcbarg, p, ti.length);

          p += ti.length;
          n -= ti.length;
        }

      /* Ugly hack to cope with the padding: Forget about the rest if
         that is less or equal to the cipher's block length.  We can
         reasonable assume that all valid data will be longer than
         just one block. */
      if (n <= (is_pbes2? 16:8))
        n = 0;

      /* Skip the optional SET with the pkcs12 cert attributes. */
      if (n)
        {
          where = "bag.attributes";
          if (parse_tag (&p, &n, &ti))
            goto bailout;
          if (!ti.class && ti.tag == TAG_SEQUENCE)
            ; /* No attributes. */
          else if (!ti.class && ti.tag == TAG_SET && !ti.ndef)
            { /* The optional SET. */
              p += ti.length;
              n -= ti.length;
              if (n <= (is_pbes2?16:8))
                n = 0;
              if (n && parse_tag (&p, &n, &ti))
                goto bailout;
            }
          else
            goto bailout;
        }
    }

  if (r_consumed)
    *r_consumed = consumed;
  gcry_free (plain);
  gcry_free (cram_buffer);
  if (r_result)
    *r_result = result;
  return 0;

 bailout:
  if (result)
    {
      int i;

      for (i=0; result[i]; i++)
        gcry_mpi_release (result[i]);
      gcry_free (result);
    }
  if (r_consumed)
    *r_consumed = consumed;
  gcry_free (plain);
  gcry_free (cram_buffer);
  log_error ("encryptedData error at \"%s\", offset %u\n",
             where, (unsigned int)((p - p_start)+startoffset));
  if (bad_pass)
    {
      /* Note, that the following string might be used by other programs
         to check for a bad passphrase; it should therefore not be
         translated or changed. */
      log_error ("possibly bad passphrase given\n");
      *r_badpass = 1;
    }
  return -1;
}


/* Return true if the decryption of a bag_data object has likely
   succeeded.  */
static int
bag_data_p (const void *plaintext, size_t length)
{
  struct tag_info ti;
  const unsigned char *p = plaintext;
  size_t n = length;

/*   { */
/* #  warning debug code is enabled */
/*     FILE *fp = fopen ("tmp-3des-plain-key.der", "wb"); */
/*     if (!fp || fwrite (p, n, 1, fp) != 1) */
/*       exit (2); */
/*     fclose (fp); */
/*   } */

  if (parse_tag (&p, &n, &ti) || ti.class || ti.tag != TAG_SEQUENCE)
    return 0;
  if (parse_tag (&p, &n, &ti) || ti.class || ti.tag != TAG_INTEGER
      || ti.length != 1 || *p)
    return 0;

  return 1;
}


static gcry_mpi_t *
parse_bag_data (const unsigned char *buffer, size_t length, int startoffset,
                size_t *r_consumed, const char *pw)
{
  int rc;
  struct tag_info ti;
  const unsigned char *p = buffer;
  const unsigned char *p_start = buffer;
  size_t n = length;
  const char *where;
  char salt[20];
  size_t saltlen;
  char iv[16];
  unsigned int iter;
  int len;
  unsigned char *plain = NULL;
  gcry_mpi_t *result = NULL;
  int result_count, i;
  unsigned char *cram_buffer = NULL;
  size_t consumed = 0; /* Number of bytes consumed from the original buffer. */
  int is_pbes2 = 0;

  where = "start";
  if (parse_tag (&p, &n, &ti))
    goto bailout;
  if (ti.class != ASNCONTEXT || ti.tag)
    goto bailout;
  if (parse_tag (&p, &n, &ti))
    goto bailout;
  if (ti.class || ti.tag != TAG_OCTET_STRING)
    goto bailout;

  consumed = p - p_start;
  if (ti.is_constructed && ti.ndef)
    {
      /* Mozilla exported certs now come with single byte chunks of
         octect strings.  (Mozilla Firefox 1.0.4).  Arghh. */
      where = "cram-data.outersegs";
      cram_buffer = cram_octet_string ( p, &n, &consumed);
      if (!cram_buffer)
        goto bailout;
      p = p_start = cram_buffer;
      if (r_consumed)
        *r_consumed = consumed;
      r_consumed = NULL; /* Ugly hack to not update that value any further. */
    }


  where = "data.outerseqs";
  if (parse_tag (&p, &n, &ti))
    goto bailout;
  if (ti.class || ti.tag != TAG_SEQUENCE)
    goto bailout;
  if (parse_tag (&p, &n, &ti))
    goto bailout;
  if (ti.class || ti.tag != TAG_SEQUENCE)
    goto bailout;

  where = "data.objectidentifier";
  if (parse_tag (&p, &n, &ti))
    goto bailout;
  if (ti.class || ti.tag != TAG_OBJECT_ID
      || ti.length != DIM(oid_pkcs_12_pkcs_8ShroudedKeyBag)
      || memcmp (p, oid_pkcs_12_pkcs_8ShroudedKeyBag,
                 DIM(oid_pkcs_12_pkcs_8ShroudedKeyBag)))
    goto bailout;
  p += DIM(oid_pkcs_12_pkcs_8ShroudedKeyBag);
  n -= DIM(oid_pkcs_12_pkcs_8ShroudedKeyBag);

  where = "shrouded,outerseqs";
  if (parse_tag (&p, &n, &ti))
    goto bailout;
  if (ti.class != ASNCONTEXT || ti.tag)
    goto bailout;
  if (parse_tag (&p, &n, &ti))
    goto bailout;
  if (ti.class || ti.tag != TAG_SEQUENCE)
    goto bailout;
  if (parse_tag (&p, &n, &ti))
    goto bailout;
  if (ti.class || ti.tag != TAG_SEQUENCE)
    goto bailout;
  if (parse_tag (&p, &n, &ti))
    goto bailout;
  if (ti.class == 0 && ti.tag == TAG_OBJECT_ID
      && ti.length == DIM(oid_pbeWithSHAAnd3_KeyTripleDES_CBC)
      && !memcmp (p, oid_pbeWithSHAAnd3_KeyTripleDES_CBC,
                  DIM(oid_pbeWithSHAAnd3_KeyTripleDES_CBC)))
    {
      p += DIM(oid_pbeWithSHAAnd3_KeyTripleDES_CBC);
      n -= DIM(oid_pbeWithSHAAnd3_KeyTripleDES_CBC);
    }
  else if (ti.class == 0 && ti.tag == TAG_OBJECT_ID
           && ti.length == DIM(oid_pkcs5PBES2)
           && !memcmp (p, oid_pkcs5PBES2, DIM(oid_pkcs5PBES2)))
    {
      p += DIM(oid_pkcs5PBES2);
      n -= DIM(oid_pkcs5PBES2);
      is_pbes2 = 1;
    }
  else
    goto bailout;

  if (is_pbes2)
    {
      where = "pkcs5PBES2-params";
      if (parse_tag (&p, &n, &ti))
        goto bailout;
      if (ti.class || ti.tag != TAG_SEQUENCE)
        goto bailout;
      if (parse_tag (&p, &n, &ti))
        goto bailout;
      if (ti.class || ti.tag != TAG_SEQUENCE)
        goto bailout;
      if (parse_tag (&p, &n, &ti))
        goto bailout;
      if (!(!ti.class && ti.tag == TAG_OBJECT_ID
            && ti.length == DIM(oid_pkcs5PBKDF2)
            && !memcmp (p, oid_pkcs5PBKDF2, ti.length)))
        goto bailout; /* Not PBKDF2.  */
      p += ti.length;
      n -= ti.length;
      if (parse_tag (&p, &n, &ti))
        goto bailout;
      if (ti.class || ti.tag != TAG_SEQUENCE)
        goto bailout;
      if (parse_tag (&p, &n, &ti))
        goto bailout;
      if (!(!ti.class && ti.tag == TAG_OCTET_STRING
            && ti.length >= 8 && ti.length < sizeof salt))
        goto bailout;  /* No salt or unsupported length.  */
      saltlen = ti.length;
      memcpy (salt, p, saltlen);
      p += saltlen;
      n -= saltlen;

      if (parse_tag (&p, &n, &ti))
        goto bailout;
      if (!(!ti.class && ti.tag == TAG_INTEGER && ti.length))
        goto bailout;  /* No valid iteration count.  */
      for (iter=0; ti.length; ti.length--)
        {
          iter <<= 8;
          iter |= (*p++) & 0xff;
          n--;
        }
      /* Note: We don't support the optional parameters but assume
         that the algorithmIdentifier follows. */
      if (parse_tag (&p, &n, &ti))
        goto bailout;
      if (ti.class || ti.tag != TAG_SEQUENCE)
        goto bailout;
      if (parse_tag (&p, &n, &ti))
        goto bailout;
      if (!(!ti.class && ti.tag == TAG_OBJECT_ID
            && ti.length == DIM(oid_aes128_CBC)
            && !memcmp (p, oid_aes128_CBC, ti.length)))
        goto bailout; /* Not AES-128.  */
      p += ti.length;
      n -= ti.length;
      if (parse_tag (&p, &n, &ti))
        goto bailout;
      if (!(!ti.class && ti.tag == TAG_OCTET_STRING && ti.length == sizeof iv))
        goto bailout; /* Bad IV.  */
      memcpy (iv, p, sizeof iv);
      p += sizeof iv;
      n -= sizeof iv;
    }
  else
    {
      where = "3des-params";
      if (parse_tag (&p, &n, &ti))
        goto bailout;
      if (ti.class || ti.tag != TAG_SEQUENCE)
        goto bailout;
      if (parse_tag (&p, &n, &ti))
        goto bailout;
      if (ti.class || ti.tag != TAG_OCTET_STRING
          || ti.length < 8 || ti.length > 20)
        goto bailout;
      saltlen = ti.length;
      memcpy (salt, p, saltlen);
      p += saltlen;
      n -= saltlen;
      if (parse_tag (&p, &n, &ti))
        goto bailout;
      if (ti.class || ti.tag != TAG_INTEGER || !ti.length )
        goto bailout;
      for (iter=0; ti.length; ti.length--)
        {
          iter <<= 8;
          iter |= (*p++) & 0xff;
          n--;
        }
    }

  where = "3desoraes-ciphertext";
  if (parse_tag (&p, &n, &ti))
    goto bailout;
  if (ti.class || ti.tag != TAG_OCTET_STRING || !ti.length )
    goto bailout;

  log_info ("%lu bytes of %s encrypted text\n",
            ti.length, is_pbes2? "AES128":"3DES");

  plain = gcry_malloc_secure (ti.length);
  if (!plain)
    {
      log_error ("error allocating decryption buffer\n");
      goto bailout;
    }
  consumed += p - p_start + ti.length;
  decrypt_block (p, plain, ti.length, salt, saltlen, iter,
                 iv, is_pbes2? 16:0, pw,
                 is_pbes2? GCRY_CIPHER_AES128 : GCRY_CIPHER_3DES,
                 bag_data_p);
  n = ti.length;
  startoffset = 0;
  p_start = p = plain;

  where = "decrypted-text";
  if (parse_tag (&p, &n, &ti) || ti.class || ti.tag != TAG_SEQUENCE)
    goto bailout;
  if (parse_tag (&p, &n, &ti) || ti.class || ti.tag != TAG_INTEGER
      || ti.length != 1 || *p)
    goto bailout;
  p++; n--;
  if (parse_tag (&p, &n, &ti) || ti.class || ti.tag != TAG_SEQUENCE)
    goto bailout;
  len = ti.length;
  if (parse_tag (&p, &n, &ti))
    goto bailout;
  if (len < ti.nhdr)
    goto bailout;
  len -= ti.nhdr;
  if (ti.class || ti.tag != TAG_OBJECT_ID
      || ti.length != DIM(oid_rsaEncryption)
      || memcmp (p, oid_rsaEncryption,
                 DIM(oid_rsaEncryption)))
    goto bailout;
  p += DIM (oid_rsaEncryption);
  n -= DIM (oid_rsaEncryption);
  if (len < ti.length)
    goto bailout;
  len -= ti.length;
  if (n < len)
    goto bailout;
  p += len;
  n -= len;
  if (parse_tag (&p, &n, &ti) || ti.class || ti.tag != TAG_OCTET_STRING)
    goto bailout;
  if (parse_tag (&p, &n, &ti) || ti.class || ti.tag != TAG_SEQUENCE)
    goto bailout;
  len = ti.length;

  result = gcry_calloc (10, sizeof *result);
  if (!result)
    {
      log_error ( "error allocating result array\n");
      goto bailout;
    }
  result_count = 0;

  where = "reading.key-parameters";
  for (result_count=0; len && result_count < 9;)
    {
      if (parse_tag (&p, &n, &ti) || ti.class || ti.tag != TAG_INTEGER)
        goto bailout;
      if (len < ti.nhdr)
        goto bailout;
      len -= ti.nhdr;
      if (len < ti.length)
        goto bailout;
      len -= ti.length;
      if (!result_count && ti.length == 1 && !*p)
        ; /* ignore the very first one if it is a 0 */
      else
        {
          rc = gcry_mpi_scan (result+result_count, GCRYMPI_FMT_USG, p,
                              ti.length, NULL);
          if (rc)
            {
              log_error ("error parsing key parameter: %s\n",
                         gpg_strerror (rc));
              goto bailout;
            }
          result_count++;
        }
      p += ti.length;
      n -= ti.length;
    }
  if (len)
    goto bailout;

  gcry_free (cram_buffer);
  if (r_consumed)
    *r_consumed = consumed;
  return result;

 bailout:
  gcry_free (plain);
  if (result)
    {
      for (i=0; result[i]; i++)
        gcry_mpi_release (result[i]);
      gcry_free (result);
    }
  gcry_free (cram_buffer);
  log_error ( "data error at \"%s\", offset %u\n",
              where, (unsigned int)((p - buffer) + startoffset));
  if (r_consumed)
    *r_consumed = consumed;
  return NULL;
}


/* Parse a PKCS12 object and return an array of MPI representing the
   secret key parameters.  This is a very limited implementation in
   that it is only able to look for 3DES encoded encryptedData and
   tries to extract the first private key object it finds.  In case of
   an error NULL is returned. CERTCB and CERRTCBARG are used to pass
   X.509 certificates back to the caller. */
gcry_mpi_t *
p12_parse (const unsigned char *buffer, size_t length, const char *pw,
           void (*certcb)(void*, const unsigned char*, size_t),
           void *certcbarg, int *r_badpass)
{
  struct tag_info ti;
  const unsigned char *p = buffer;
  const unsigned char *p_start = buffer;
  size_t n = length;
  const char *where;
  int bagseqlength, len;
  int bagseqndef, lenndef;
  gcry_mpi_t *result = NULL;
  unsigned char *cram_buffer = NULL;

  *r_badpass = 0;
  where = "pfx";
  if (parse_tag (&p, &n, &ti))
    goto bailout;
  if (ti.tag != TAG_SEQUENCE)
    goto bailout;

  where = "pfxVersion";
  if (parse_tag (&p, &n, &ti))
    goto bailout;
  if (ti.tag != TAG_INTEGER || ti.length != 1 || *p != 3)
    goto bailout;
  p++; n--;

  where = "authSave";
  if (parse_tag (&p, &n, &ti))
    goto bailout;
  if (ti.tag != TAG_SEQUENCE)
    goto bailout;
  if (parse_tag (&p, &n, &ti))
    goto bailout;
  if (ti.tag != TAG_OBJECT_ID || ti.length != DIM(oid_data)
      || memcmp (p, oid_data, DIM(oid_data)))
    goto bailout;
  p += DIM(oid_data);
  n -= DIM(oid_data);

  if (parse_tag (&p, &n, &ti))
    goto bailout;
  if (ti.class != ASNCONTEXT || ti.tag)
    goto bailout;
  if (parse_tag (&p, &n, &ti))
    goto bailout;
  if (ti.class != UNIVERSAL || ti.tag != TAG_OCTET_STRING)
    goto bailout;

  if (ti.is_constructed && ti.ndef)
    {
      /* Mozilla exported certs now come with single byte chunks of
         octect strings.  (Mozilla Firefox 1.0.4).  Arghh. */
      where = "cram-bags";
      cram_buffer = cram_octet_string ( p, &n, NULL);
      if (!cram_buffer)
        goto bailout;
      p = p_start = cram_buffer;
    }

  where = "bags";
  if (parse_tag (&p, &n, &ti))
    goto bailout;
  if (ti.class != UNIVERSAL || ti.tag != TAG_SEQUENCE)
    goto bailout;
  bagseqndef = ti.ndef;
  bagseqlength = ti.length;
  while (bagseqlength || bagseqndef)
    {
/*       log_debug ( "at offset %u\n", (p - p_start)); */
      where = "bag-sequence";
      if (parse_tag (&p, &n, &ti))
        goto bailout;
      if (bagseqndef && ti.class == UNIVERSAL && !ti.tag && !ti.is_constructed)
        break; /* Ready */
      if (ti.class != UNIVERSAL || ti.tag != TAG_SEQUENCE)
        goto bailout;

      if (!bagseqndef)
        {
          if (bagseqlength < ti.nhdr)
            goto bailout;
          bagseqlength -= ti.nhdr;
          if (bagseqlength < ti.length)
            goto bailout;
          bagseqlength -= ti.length;
        }
      lenndef = ti.ndef;
      len = ti.length;

      if (parse_tag (&p, &n, &ti))
        goto bailout;
      if (lenndef)
        len = ti.nhdr;
      else
        len -= ti.nhdr;

      if (ti.tag == TAG_OBJECT_ID && ti.length == DIM(oid_encryptedData)
          && !memcmp (p, oid_encryptedData, DIM(oid_encryptedData)))
        {
          size_t consumed = 0;

          p += DIM(oid_encryptedData);
          n -= DIM(oid_encryptedData);
          if (!lenndef)
            len -= DIM(oid_encryptedData);
          where = "bag.encryptedData";
          if (parse_bag_encrypted_data (p, n, (p - p_start), &consumed, pw,
                                        certcb, certcbarg,
                                        result? NULL : &result, r_badpass))
            goto bailout;
          if (lenndef)
            len += consumed;
        }
      else if (ti.tag == TAG_OBJECT_ID && ti.length == DIM(oid_data)
               && !memcmp (p, oid_data, DIM(oid_data)))
        {
          if (result)
            {
              log_info ("already got an key object, skipping this one\n");
              p += ti.length;
              n -= ti.length;
            }
          else
            {
              size_t consumed = 0;

              p += DIM(oid_data);
              n -= DIM(oid_data);
              if (!lenndef)
                len -= DIM(oid_data);
              result = parse_bag_data (p, n, (p - p_start), &consumed, pw);
              if (!result)
                goto bailout;
              if (lenndef)
                len += consumed;
            }
        }
      else
        {
          log_info ("unknown bag type - skipped\n");
          p += ti.length;
          n -= ti.length;
        }

      if (len < 0 || len > n)
        goto bailout;
      p += len;
      n -= len;
      if (lenndef)
        {
          /* Need to skip the Null Tag. */
          if (parse_tag (&p, &n, &ti))
            goto bailout;
          if (!(ti.class == UNIVERSAL && !ti.tag && !ti.is_constructed))
            goto bailout;
        }
    }

  gcry_free (cram_buffer);
  return result;
 bailout:
  log_error ("error at \"%s\", offset %u\n",
             where, (unsigned int)(p - p_start));
  if (result)
    {
      int i;

      for (i=0; result[i]; i++)
        gcry_mpi_release (result[i]);
      gcry_free (result);
    }
  gcry_free (cram_buffer);
  return NULL;
}



static size_t
compute_tag_length (size_t n)
{
  int needed = 0;

  if (n < 128)
    needed += 2; /* tag and one length byte */
  else if (n < 256)
    needed += 3; /* tag, number of length bytes, 1 length byte */
  else if (n < 65536)
    needed += 4; /* tag, number of length bytes, 2 length bytes */
  else
    {
      log_error ("object too larger to encode\n");
      return 0;
    }
  return needed;
}

static unsigned char *
store_tag_length (unsigned char *p, int tag, size_t n)
{
  if (tag == TAG_SEQUENCE)
    tag |= 0x20; /* constructed */

  *p++ = tag;
  if (n < 128)
    *p++ = n;
  else if (n < 256)
    {
      *p++ = 0x81;
      *p++ = n;
    }
  else if (n < 65536)
    {
      *p++ = 0x82;
      *p++ = n >> 8;
      *p++ = n;
    }

  return p;
}


/* Create the final PKCS-12 object from the sequences contained in
   SEQLIST.  PW is the password. That array is terminated with an NULL
   object. */
static unsigned char *
create_final (struct buffer_s *sequences, const char *pw, size_t *r_length)
{
  int i;
  size_t needed = 0;
  size_t len[8], n;
  unsigned char *macstart;
  size_t maclen;
  unsigned char *result, *p;
  size_t resultlen;
  char salt[8];
  unsigned char keybuf[20];
  gcry_md_hd_t md;
  int rc;
  int with_mac = 1;


  /* 9 steps to create the pkcs#12 Krampf. */

  /* 8. The MAC. */
  /* We add this at step 0. */

  /* 7. All the buffers. */
  for (i=0; sequences[i].buffer; i++)
    needed += sequences[i].length;

  /* 6. This goes into a sequences. */
  len[6] = needed;
  n = compute_tag_length (needed);
  needed += n;

  /* 5. Encapsulate all in an octet string. */
  len[5] = needed;
  n = compute_tag_length (needed);
  needed += n;

  /* 4. And tag it with [0]. */
  len[4] = needed;
  n = compute_tag_length (needed);
  needed += n;

  /* 3. Prepend an data OID. */
  needed += 2 + DIM (oid_data);

  /* 2. Put all into a sequences. */
  len[2] = needed;
  n = compute_tag_length (needed);
  needed += n;

  /* 1. Prepend the version integer 3. */
  needed += 3;

  /* 0. And the final outer sequence. */
  if (with_mac)
    needed += DIM (data_mactemplate);
  len[0] = needed;
  n = compute_tag_length (needed);
  needed += n;

  /* Allocate a buffer. */
  result = gcry_malloc (needed);
  if (!result)
    {
      log_error ("error allocating buffer\n");
      return NULL;
    }
  p = result;

  /* 0. Store the very outer sequence. */
  p = store_tag_length (p, TAG_SEQUENCE, len[0]);

  /* 1. Store the version integer 3. */
  *p++ = TAG_INTEGER;
  *p++ = 1;
  *p++ = 3;

  /* 2. Store another sequence. */
  p = store_tag_length (p, TAG_SEQUENCE, len[2]);

  /* 3. Store the data OID. */
  p = store_tag_length (p, TAG_OBJECT_ID, DIM (oid_data));
  memcpy (p, oid_data, DIM (oid_data));
  p += DIM (oid_data);

  /* 4. Next comes a context tag. */
  p = store_tag_length (p, 0xa0, len[4]);

  /* 5. And an octet string. */
  p = store_tag_length (p, TAG_OCTET_STRING, len[5]);

  /* 6. And the inner sequence. */
  macstart = p;
  p = store_tag_length (p, TAG_SEQUENCE, len[6]);

  /* 7. Append all the buffers. */
  for (i=0; sequences[i].buffer; i++)
    {
      memcpy (p, sequences[i].buffer, sequences[i].length);
      p += sequences[i].length;
    }

  if (with_mac)
    {
      /* Intermezzo to compute the MAC. */
      maclen = p - macstart;
      gcry_randomize (salt, 8, GCRY_STRONG_RANDOM);
      if (string_to_key (3, salt, 8, 2048, pw, 20, keybuf))
        {
          gcry_free (result);
          return NULL;
        }
      rc = gcry_md_open (&md, GCRY_MD_SHA1, GCRY_MD_FLAG_HMAC);
      if (rc)
        {
          log_error ("gcry_md_open failed: %s\n", gpg_strerror (rc));
          gcry_free (result);
          return NULL;
        }
      rc = gcry_md_setkey (md, keybuf, 20);
      if (rc)
        {
          log_error ("gcry_md_setkey failed: %s\n", gpg_strerror (rc));
          gcry_md_close (md);
          gcry_free (result);
          return NULL;
        }
      gcry_md_write (md, macstart, maclen);

      /* 8. Append the MAC template and fix it up. */
      memcpy (p, data_mactemplate, DIM (data_mactemplate));
      memcpy (p + DATA_MACTEMPLATE_SALT_OFF, salt, 8);
      memcpy (p + DATA_MACTEMPLATE_MAC_OFF, gcry_md_read (md, 0), 20);
      p += DIM (data_mactemplate);
      gcry_md_close (md);
    }

  /* Ready. */
  resultlen = p - result;
  if (needed != resultlen)
    log_debug ("length mismatch: %lu, %lu\n",
               (unsigned long)needed, (unsigned long)resultlen);

  *r_length = resultlen;
  return result;
}


/* Build a DER encoded SEQUENCE with the key:

   SEQUENCE {
     INTEGER 0
     SEQUENCE {
       OBJECT IDENTIFIER rsaEncryption (1 2 840 113549 1 1 1)
       NULL
       }
     OCTET STRING, encapsulates {
       SEQUENCE {
         INTEGER 0
         INTEGER
         INTEGER
         INTEGER
         INTEGER
         INTEGER
         INTEGER
         INTEGER
         INTEGER
         }
       }
     }

  MODE controls what is being generated:
     0 - As described above
     1 - Ditto but without the padding
     2 - Only the inner part (pkcs#1)
*/

static unsigned char *
build_key_sequence (gcry_mpi_t *kparms, int mode, size_t *r_length)
{
  int rc, i;
  size_t needed, n;
  unsigned char *plain, *p;
  size_t plainlen;
  size_t outseqlen, oidseqlen, octstrlen, inseqlen;

  needed = 3; /* The version integer with value 0. */
  for (i=0; kparms[i]; i++)
    {
      n = 0;
      rc = gcry_mpi_print (GCRYMPI_FMT_STD, NULL, 0, &n, kparms[i]);
      if (rc)
        {
          log_error ("error formatting parameter: %s\n", gpg_strerror (rc));
          return NULL;
        }
      needed += n;
      n = compute_tag_length (n);
      if (!n)
        return NULL;
      needed += n;
    }
  if (i != 8)
    {
      log_error ("invalid parameters for p12_build\n");
      return NULL;
    }
  /* Now this all goes into a sequence. */
  inseqlen = needed;
  n = compute_tag_length (needed);
  if (!n)
    return NULL;
  needed += n;

  if (mode != 2)
    {
      /* Encapsulate all into an octet string. */
      octstrlen = needed;
      n = compute_tag_length (needed);
      if (!n)
        return NULL;
      needed += n;
      /* Prepend the object identifier sequence. */
      oidseqlen = 2 + DIM (oid_rsaEncryption) + 2;
      needed += 2 + oidseqlen;
      /* The version number. */
      needed += 3;
      /* And finally put the whole thing into a sequence. */
      outseqlen = needed;
      n = compute_tag_length (needed);
      if (!n)
        return NULL;
      needed += n;
    }

  /* allocate 8 extra bytes for padding */
  plain = gcry_malloc_secure (needed+8);
  if (!plain)
    {
      log_error ("error allocating encryption buffer\n");
      return NULL;
    }

  /* And now fill the plaintext buffer. */
  p = plain;
  if (mode != 2)
    {
      p = store_tag_length (p, TAG_SEQUENCE, outseqlen);
      /* Store version. */
      *p++ = TAG_INTEGER;
      *p++ = 1;
      *p++ = 0;
      /* Store object identifier sequence. */
      p = store_tag_length (p, TAG_SEQUENCE, oidseqlen);
      p = store_tag_length (p, TAG_OBJECT_ID, DIM (oid_rsaEncryption));
      memcpy (p, oid_rsaEncryption, DIM (oid_rsaEncryption));
      p += DIM (oid_rsaEncryption);
      *p++ = TAG_NULL;
      *p++ = 0;
      /* Start with the octet string. */
      p = store_tag_length (p, TAG_OCTET_STRING, octstrlen);
    }

  p = store_tag_length (p, TAG_SEQUENCE, inseqlen);
  /* Store the key parameters. */
  *p++ = TAG_INTEGER;
  *p++ = 1;
  *p++ = 0;
  for (i=0; kparms[i]; i++)
    {
      n = 0;
      rc = gcry_mpi_print (GCRYMPI_FMT_STD, NULL, 0, &n, kparms[i]);
      if (rc)
        {
          log_error ("oops: error formatting parameter: %s\n",
                     gpg_strerror (rc));
          gcry_free (plain);
          return NULL;
        }
      p = store_tag_length (p, TAG_INTEGER, n);

      n = plain + needed - p;
      rc = gcry_mpi_print (GCRYMPI_FMT_STD, p, n, &n, kparms[i]);
      if (rc)
        {
          log_error ("oops: error storing parameter: %s\n",
                     gpg_strerror (rc));
          gcry_free (plain);
          return NULL;
        }
      p += n;
    }

  plainlen = p - plain;
  assert (needed == plainlen);

  if (!mode)
    {
      /* Append some pad characters; we already allocated extra space. */
      n = 8 - plainlen % 8;
      for (i=0; i < n; i++, plainlen++)
        *p++ = n;
    }

  *r_length = plainlen;
  return plain;
}



static unsigned char *
build_key_bag (unsigned char *buffer, size_t buflen, char *salt,
               const unsigned char *sha1hash, const char *keyidstr,
               size_t *r_length)
{
  size_t len[11], needed;
  unsigned char *p, *keybag;
  size_t keybaglen;

  /* Walk 11 steps down to collect the info: */

  /* 10. The data goes into an octet string. */
  needed = compute_tag_length (buflen);
  needed += buflen;

  /* 9. Prepend the algorithm identifier. */
  needed += DIM (data_3desiter2048);

  /* 8. Put a sequence around. */
  len[8] = needed;
  needed += compute_tag_length (needed);

  /* 7. Prepend a [0] tag. */
  len[7] = needed;
  needed += compute_tag_length (needed);

  /* 6b. The attributes which are appended at the end. */
  if (sha1hash)
    needed += DIM (data_attrtemplate) + 20;

  /* 6. Prepend the shroudedKeyBag OID. */
  needed += 2 + DIM (oid_pkcs_12_pkcs_8ShroudedKeyBag);

  /* 5+4. Put all into two sequences. */
  len[5] = needed;
  needed += compute_tag_length ( needed);
  len[4] = needed;
  needed += compute_tag_length (needed);

  /* 3. This all goes into an octet string. */
  len[3] = needed;
  needed += compute_tag_length (needed);

  /* 2. Prepend another [0] tag. */
  len[2] = needed;
  needed += compute_tag_length (needed);

  /* 1. Prepend the data OID. */
  needed += 2 + DIM (oid_data);

  /* 0. Prepend another sequence. */
  len[0] = needed;
  needed += compute_tag_length (needed);

  /* Now that we have all length information, allocate a buffer. */
  p = keybag = gcry_malloc (needed);
  if (!keybag)
    {
      log_error ("error allocating buffer\n");
      return NULL;
    }

  /* Walk 11 steps up to store the data. */

  /* 0. Store the first sequence. */
  p = store_tag_length (p, TAG_SEQUENCE, len[0]);

  /* 1. Store the data OID. */
  p = store_tag_length (p, TAG_OBJECT_ID, DIM (oid_data));
  memcpy (p, oid_data, DIM (oid_data));
  p += DIM (oid_data);

  /* 2. Store a [0] tag. */
  p = store_tag_length (p, 0xa0, len[2]);

  /* 3. And an octet string. */
  p = store_tag_length (p, TAG_OCTET_STRING, len[3]);

  /* 4+5. Two sequences. */
  p = store_tag_length (p, TAG_SEQUENCE, len[4]);
  p = store_tag_length (p, TAG_SEQUENCE, len[5]);

  /* 6. Store the shroudedKeyBag OID. */
  p = store_tag_length (p, TAG_OBJECT_ID,
                        DIM (oid_pkcs_12_pkcs_8ShroudedKeyBag));
  memcpy (p, oid_pkcs_12_pkcs_8ShroudedKeyBag,
          DIM (oid_pkcs_12_pkcs_8ShroudedKeyBag));
  p += DIM (oid_pkcs_12_pkcs_8ShroudedKeyBag);

  /* 7. Store a [0] tag. */
  p = store_tag_length (p, 0xa0, len[7]);

  /* 8. Store a sequence. */
  p = store_tag_length (p, TAG_SEQUENCE, len[8]);

  /* 9. Now for the pre-encoded algorithm identifier and the salt. */
  memcpy (p, data_3desiter2048, DIM (data_3desiter2048));
  memcpy (p + DATA_3DESITER2048_SALT_OFF, salt, 8);
  p += DIM (data_3desiter2048);

  /* 10. And the octet string with the encrypted data. */
  p = store_tag_length (p, TAG_OCTET_STRING, buflen);
  memcpy (p, buffer, buflen);
  p += buflen;

  /* Append the attributes whose length we calculated at step 2b. */
  if (sha1hash)
    {
      int i;

      memcpy (p, data_attrtemplate, DIM (data_attrtemplate));
      for (i=0; i < 8; i++)
        p[DATA_ATTRTEMPLATE_KEYID_OFF+2*i+1] = keyidstr[i];
      p += DIM (data_attrtemplate);
      memcpy (p, sha1hash, 20);
      p += 20;
    }


  keybaglen = p - keybag;
  if (needed != keybaglen)
    log_debug ("length mismatch: %lu, %lu\n",
               (unsigned long)needed, (unsigned long)keybaglen);

  *r_length = keybaglen;
  return keybag;
}


static unsigned char *
build_cert_bag (unsigned char *buffer, size_t buflen, char *salt,
                size_t *r_length)
{
  size_t len[9], needed;
  unsigned char *p, *certbag;
  size_t certbaglen;

  /* Walk 9 steps down to collect the info: */

  /* 8. The data goes into an octet string. */
  needed = compute_tag_length (buflen);
  needed += buflen;

  /* 7. The algorithm identifier. */
  needed += DIM (data_rc2iter2048);

  /* 6. The data OID. */
  needed += 2 + DIM (oid_data);

  /* 5. A sequence. */
  len[5] = needed;
  needed += compute_tag_length ( needed);

  /* 4. An integer. */
  needed += 3;

  /* 3. A sequence. */
  len[3] = needed;
  needed += compute_tag_length (needed);

  /* 2.  A [0] tag. */
  len[2] = needed;
  needed += compute_tag_length (needed);

  /* 1. The encryptedData OID. */
  needed += 2 + DIM (oid_encryptedData);

  /* 0. The first sequence. */
  len[0] = needed;
  needed += compute_tag_length (needed);

  /* Now that we have all length information, allocate a buffer. */
  p = certbag = gcry_malloc (needed);
  if (!certbag)
    {
      log_error ("error allocating buffer\n");
      return NULL;
    }

  /* Walk 9 steps up to store the data. */

  /* 0. Store the first sequence. */
  p = store_tag_length (p, TAG_SEQUENCE, len[0]);

  /* 1. Store the encryptedData OID. */
  p = store_tag_length (p, TAG_OBJECT_ID, DIM (oid_encryptedData));
  memcpy (p, oid_encryptedData, DIM (oid_encryptedData));
  p += DIM (oid_encryptedData);

  /* 2. Store a [0] tag. */
  p = store_tag_length (p, 0xa0, len[2]);

  /* 3. Store a sequence. */
  p = store_tag_length (p, TAG_SEQUENCE, len[3]);

  /* 4. Store the integer 0. */
  *p++ = TAG_INTEGER;
  *p++ = 1;
  *p++ = 0;

  /* 5. Store a sequence. */
  p = store_tag_length (p, TAG_SEQUENCE, len[5]);

  /* 6. Store the data OID. */
  p = store_tag_length (p, TAG_OBJECT_ID, DIM (oid_data));
  memcpy (p, oid_data, DIM (oid_data));
  p += DIM (oid_data);

  /* 7. Now for the pre-encoded algorithm identifier and the salt. */
  memcpy (p, data_rc2iter2048, DIM (data_rc2iter2048));
  memcpy (p + DATA_RC2ITER2048_SALT_OFF, salt, 8);
  p += DIM (data_rc2iter2048);

  /* 8. And finally the [0] tag with the encrypted data. */
  p = store_tag_length (p, 0x80, buflen);
  memcpy (p, buffer, buflen);
  p += buflen;
  certbaglen = p - certbag;

  if (needed != certbaglen)
    log_debug ("length mismatch: %lu, %lu\n",
               (unsigned long)needed, (unsigned long)certbaglen);

  *r_length = certbaglen;
  return certbag;
}


static unsigned char *
build_cert_sequence (const unsigned char *buffer, size_t buflen,
                     const unsigned char *sha1hash, const char *keyidstr,
                     size_t *r_length)
{
  size_t len[8], needed, n;
  unsigned char *p, *certseq;
  size_t certseqlen;
  int i;

  assert (strlen (keyidstr) == 8);

  /* Walk 8 steps down to collect the info: */

  /* 7. The data goes into an octet string. */
  needed = compute_tag_length (buflen);
  needed += buflen;

  /* 6. A [0] tag. */
  len[6] = needed;
  needed += compute_tag_length (needed);

  /* 5. An OID. */
  needed += 2 + DIM (oid_x509Certificate_for_pkcs_12);

  /* 4. A sequence. */
  len[4] = needed;
  needed += compute_tag_length (needed);

  /* 3. A [0] tag. */
  len[3] = needed;
  needed += compute_tag_length (needed);

  /* 2b. The attributes which are appended at the end. */
  if (sha1hash)
    needed += DIM (data_attrtemplate) + 20;

  /* 2. An OID. */
  needed += 2 + DIM (oid_pkcs_12_CertBag);

  /* 1. A sequence. */
  len[1] = needed;
  needed += compute_tag_length (needed);

  /* 0. The first sequence. */
  len[0] = needed;
  needed += compute_tag_length (needed);

  /* Now that we have all length information, allocate a buffer. */
  p = certseq = gcry_malloc (needed + 8 /*(for padding)*/);
  if (!certseq)
    {
      log_error ("error allocating buffer\n");
      return NULL;
    }

  /* Walk 8 steps up to store the data. */

  /* 0. Store the first sequence. */
  p = store_tag_length (p, TAG_SEQUENCE, len[0]);

  /* 1. Store the second sequence. */
  p = store_tag_length (p, TAG_SEQUENCE, len[1]);

  /* 2. Store the pkcs12-cert-bag OID. */
  p = store_tag_length (p, TAG_OBJECT_ID, DIM (oid_pkcs_12_CertBag));
  memcpy (p, oid_pkcs_12_CertBag, DIM (oid_pkcs_12_CertBag));
  p += DIM (oid_pkcs_12_CertBag);

  /* 3. Store a [0] tag. */
  p = store_tag_length (p, 0xa0, len[3]);

  /* 4. Store a sequence. */
  p = store_tag_length (p, TAG_SEQUENCE, len[4]);

  /* 5. Store the x509Certificate OID. */
  p = store_tag_length (p, TAG_OBJECT_ID,
                        DIM (oid_x509Certificate_for_pkcs_12));
  memcpy (p, oid_x509Certificate_for_pkcs_12,
          DIM (oid_x509Certificate_for_pkcs_12));
  p += DIM (oid_x509Certificate_for_pkcs_12);

  /* 6. Store a [0] tag. */
  p = store_tag_length (p, 0xa0, len[6]);

  /* 7. And the octet string with the actual certificate. */
  p = store_tag_length (p, TAG_OCTET_STRING, buflen);
  memcpy (p, buffer, buflen);
  p += buflen;

  /* Append the attributes whose length we calculated at step 2b. */
  if (sha1hash)
    {
      memcpy (p, data_attrtemplate, DIM (data_attrtemplate));
      for (i=0; i < 8; i++)
        p[DATA_ATTRTEMPLATE_KEYID_OFF+2*i+1] = keyidstr[i];
      p += DIM (data_attrtemplate);
      memcpy (p, sha1hash, 20);
      p += 20;
    }

  certseqlen = p - certseq;
  if (needed != certseqlen)
    log_debug ("length mismatch: %lu, %lu\n",
               (unsigned long)needed, (unsigned long)certseqlen);

  /* Append some pad characters; we already allocated extra space. */
  n = 8 - certseqlen % 8;
  for (i=0; i < n; i++, certseqlen++)
    *p++ = n;

  *r_length = certseqlen;
  return certseq;
}


/* Expect the RSA key parameters in KPARMS and a password in PW.
   Create a PKCS structure from it and return it as well as the length
   in R_LENGTH; return NULL in case of an error.  If CHARSET is not
   NULL, re-encode PW to that character set. */
unsigned char *
p12_build (gcry_mpi_t *kparms, const void *cert, size_t certlen,
           const char *pw, const char *charset, size_t *r_length)
{
  unsigned char *buffer = NULL;
  size_t n, buflen;
  char salt[8];
  struct buffer_s seqlist[3];
  int seqlistidx = 0;
  unsigned char sha1hash[20];
  char keyidstr[8+1];
  char *pwbuf = NULL;
  size_t pwbufsize = 0;

  n = buflen = 0; /* (avoid compiler warning). */
  memset (sha1hash, 0, 20);
  *keyidstr = 0;

  if (charset && pw && *pw)
    {
      jnlib_iconv_t cd;
      const char *inptr;
      char *outptr;
      size_t inbytes, outbytes;

      /* We assume that the converted passphrase is at max 2 times
         longer than its utf-8 encoding. */
      pwbufsize = strlen (pw)*2 + 1;
      pwbuf = gcry_malloc_secure (pwbufsize);
      if (!pwbuf)
        {
          log_error ("out of secure memory while converting passphrase\n");
          goto failure;
        }

      cd = jnlib_iconv_open (charset, "utf-8");
      if (cd == (jnlib_iconv_t)(-1))
        {
          log_error ("can't convert passphrase to"
                     " requested charset '%s': %s\n",
                     charset, strerror (errno));
          goto failure;
        }

      inptr = pw;
      inbytes = strlen (pw);
      outptr = pwbuf;
      outbytes = pwbufsize - 1;
      if ( jnlib_iconv (cd, (const char **)&inptr, &inbytes,
                      &outptr, &outbytes) == (size_t)-1)
        {
          log_error ("error converting passphrase to"
                     " requested charset '%s': %s\n",
                     charset, strerror (errno));
          jnlib_iconv_close (cd);
          goto failure;
        }
      *outptr = 0;
      jnlib_iconv_close (cd);
      pw = pwbuf;
    }


  if (cert && certlen)
    {
      /* Calculate the hash value we need for the bag attributes. */
      gcry_md_hash_buffer (GCRY_MD_SHA1, sha1hash, cert, certlen);
      sprintf (keyidstr, "%02x%02x%02x%02x",
               sha1hash[16], sha1hash[17], sha1hash[18], sha1hash[19]);

      /* Encode the certificate. */
      buffer = build_cert_sequence (cert, certlen, sha1hash, keyidstr,
                                    &buflen);
      if (!buffer)
        goto failure;

      /* Encrypt it. */
      gcry_randomize (salt, 8, GCRY_STRONG_RANDOM);
      crypt_block (buffer, buflen, salt, 8, 2048, NULL, 0, pw,
                   GCRY_CIPHER_RFC2268_40, 1);

      /* Encode the encrypted stuff into a bag. */
      seqlist[seqlistidx].buffer = build_cert_bag (buffer, buflen, salt, &n);
      seqlist[seqlistidx].length = n;
      gcry_free (buffer);
      buffer = NULL;
      if (!seqlist[seqlistidx].buffer)
        goto failure;
      seqlistidx++;
    }


  if (kparms)
    {
      /* Encode the key. */
      buffer = build_key_sequence (kparms, 0, &buflen);
      if (!buffer)
        goto failure;

      /* Encrypt it. */
      gcry_randomize (salt, 8, GCRY_STRONG_RANDOM);
      crypt_block (buffer, buflen, salt, 8, 2048, NULL, 0,
                   pw, GCRY_CIPHER_3DES, 1);

      /* Encode the encrypted stuff into a bag. */
      if (cert && certlen)
        seqlist[seqlistidx].buffer = build_key_bag (buffer, buflen, salt,
                                                    sha1hash, keyidstr, &n);
      else
        seqlist[seqlistidx].buffer = build_key_bag (buffer, buflen, salt,
                                                    NULL, NULL, &n);
      seqlist[seqlistidx].length = n;
      gcry_free (buffer);
      buffer = NULL;
      if (!seqlist[seqlistidx].buffer)
        goto failure;
      seqlistidx++;
    }

  seqlist[seqlistidx].buffer = NULL;
  seqlist[seqlistidx].length = 0;

  buffer = create_final (seqlist, pw, &buflen);

 failure:
  if (pwbuf)
    {
      /* Note that wipememory is not really needed due to the use of
         gcry_malloc_secure.  */
      wipememory (pwbuf, pwbufsize);
      gcry_free (pwbuf);
    }
  for ( ; seqlistidx; seqlistidx--)
    gcry_free (seqlist[seqlistidx].buffer);

  *r_length = buffer? buflen : 0;
  return buffer;
}


/* This is actually not a pkcs#12 function but one which creates an
   unencrypted a pkcs#1 private key.  */
unsigned char *
p12_raw_build (gcry_mpi_t *kparms, int rawmode, size_t *r_length)
{
  unsigned char *buffer;
  size_t buflen;

  assert (rawmode == 1 || rawmode == 2);
  buffer = build_key_sequence (kparms, rawmode, &buflen);
  if (!buffer)
    return NULL;

  *r_length = buflen;
  return buffer;
}


#ifdef TEST

static void
cert_cb (void *opaque, const unsigned char *cert, size_t certlen)
{
  printf ("got a certificate of %u bytes length\n", certlen);
}

int
main (int argc, char **argv)
{
  FILE *fp;
  struct stat st;
  unsigned char *buf;
  size_t buflen;
  gcry_mpi_t *result;
  int badpass;

  if (argc != 3)
    {
      fprintf (stderr, "usage: testp12 file passphrase\n");
      return 1;
    }

  gcry_control (GCRYCTL_DISABLE_SECMEM, NULL);
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, NULL);

  fp = gnupg_fopen (argv[1], "rb");
  if (!fp)
    {
      fprintf (stderr, "can't open '%s': %s\n", argv[1], strerror (errno));
      return 1;
    }

  if (fstat (fileno(fp), &st))
    {
      fprintf (stderr, "can't stat '%s': %s\n", argv[1], strerror (errno));
      return 1;
    }

  buflen = st.st_size;
  buf = gcry_malloc (buflen+1);
  if (!buf || fread (buf, buflen, 1, fp) != 1)
    {
      fprintf (stderr, "error reading '%s': %s\n", argv[1], strerror (errno));
      return 1;
    }
  fclose (fp);

  result = p12_parse (buf, buflen, argv[2], cert_cb, NULL, &badpass);
  if (result)
    {
      int i, rc;
      unsigned char *tmpbuf;

      for (i=0; result[i]; i++)
        {
          rc = gcry_mpi_aprint (GCRYMPI_FMT_HEX, &tmpbuf,
                                NULL, result[i]);
          if (rc)
            printf ("%d: [error printing number: %s]\n",
                    i, gpg_strerror (rc));
          else
            {
              printf ("%d: %s\n", i, tmpbuf);
              gcry_free (tmpbuf);
            }
        }
    }

  return 0;

}

/*
Local Variables:
compile-command: "gcc -Wall -O0 -g -DTEST=1 -o minip12 minip12.c ../common/libcommon.a -L /usr/local/lib -lgcrypt -lgpg-error"
End:
*/
#endif /* TEST */
