/* minip12.c - A minilam pkcs-12 implementation.
 *	Copyright (C) 2002 Free Software Foundation, Inc.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <gcrypt.h>

#undef TEST 

#ifdef TEST
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#endif

#include "../jnlib/logging.h"
#include "minip12.h"

#ifndef DIM
#define DIM(v)		     (sizeof(v)/sizeof((v)[0]))
#endif

enum
{
  UNIVERSAL = 0,
  APPLICATION = 1,
  CONTEXT = 2,
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
static unsigned char const oid_pkcs_12_pkcs_8ShroudedKeyBag[11] = {
  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x0A, 0x01, 0x02 };
static unsigned char const oid_pbeWithSHAAnd3_KeyTripleDES_CBC[10] = {
  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x01, 0x03 };

static unsigned char const oid_rsaEncryption[9] = {
  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };



struct tag_info {
  int class;
  int is_constructed;
  unsigned long tag;
  unsigned long length;  /* length part of the TLV */
  int nhdr;
  int ndef;              /* It is an indefinite length */
};


/* Parse the buffer at the address BUFFER which is of SIZE and return
   the tag and the length part from the TLV triplet.  Update BUFFER
   and SIZE on success. */
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


static int 
string_to_key (int id, char *salt, int iter, const char *pw,
               int req_keylen, unsigned char *keybuf)
{
  int rc, i, j;
  GcryMDHd md;
  GcryMPI num_b1 = NULL;
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

  /* Store salt and password in BUF_I */
  p = buf_i;
  for(i=0; i < 64; i++)
    *p++ = salt [i%8];
  for(i=j=0; i < 64; i += 2)
    {
      *p++ = 0;
      *p++ = pw[j];
      if (++j > pwlen) /* Note, that we include the trailing zero */
        j = 0;
    }

  for (;;)
    {
      md = gcry_md_open (GCRY_MD_SHA1, 0);
      if (!md)
        {
          log_error ( "gcry_md_open failed: %s\n", gcry_strerror (-1));
          return -1;
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
      n = 64;
      rc = gcry_mpi_scan (&num_b1, GCRYMPI_FMT_USG, buf_b, &n);
      if (rc)
        {
          log_error ( "gcry_mpi_scan failed: %s\n", gcry_strerror (rc));
          return -1;
        }
      gcry_mpi_add_ui (num_b1, num_b1, 1);
      for (i=0; i < 128; i += 64)
        {
          GcryMPI num_ij;

          n = 64;
          rc = gcry_mpi_scan (&num_ij, GCRYMPI_FMT_USG, buf_i + i, &n);
          if (rc)
            {
              log_error ( "gcry_mpi_scan failed: %s\n",
                       gcry_strerror (rc));
              return -1;
            }
          gcry_mpi_add (num_ij, num_ij, num_b1);
          gcry_mpi_clear_highbit (num_ij, 64*8);
          n = 64;
          rc = gcry_mpi_print (GCRYMPI_FMT_USG, buf_i + i, &n, num_ij);
          if (rc)
            {
              log_error ( "gcry_mpi_print failed: %s\n",
                       gcry_strerror (rc));
              return -1;
            }
          gcry_mpi_release (num_ij);
        }
    }
}


static int 
set_key_iv (GcryCipherHd chd, char *salt, int iter, const char *pw)
{
  unsigned char keybuf[24];
  int rc;

  if (string_to_key (1, salt, iter, pw, 24, keybuf))
    return -1;
  rc = gcry_cipher_setkey (chd, keybuf, 24);
  if (rc)
    {
      log_error ( "gcry_cipher_setkey failed: %s\n", gcry_strerror (rc));
      return -1;
    }

  if (string_to_key (2, salt, iter, pw, 8, keybuf))
    return -1;
  rc = gcry_cipher_setiv (chd, keybuf, 8);
  if (rc)
    {
      log_error ("gcry_cipher_setiv failed: %s\n", gcry_strerror (rc));
      return -1;
    }
  return 0;
}


static void
decrypt_block (unsigned char *buffer, size_t length, char *salt, int iter,
               const char *pw)
{
  GcryCipherHd chd;
  int rc;

  chd = gcry_cipher_open (GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_CBC, 0);
  if (!chd)
    {
      log_error ( "gcry_cipher_open failed: %s\n", gcry_strerror(-1));
      return;
    }
  if (set_key_iv (chd, salt, iter, pw))
    goto leave;

  rc = gcry_cipher_decrypt (chd, buffer, length, NULL, 0);
  if (rc)
    {
      log_error ( "gcry_cipher_decrypt failed: %s\n", gcry_strerror (rc));
      goto leave;
    }

/*    { */
/*      FILE *fp = fopen("inner.der", "wb"); */
/*      fwrite (buffer, 1, length, fp); */
/*      fclose (fp); */
/*    } */

 leave:
  gcry_cipher_close (chd);
}
  



static int
parse_bag_encrypted_data (const unsigned char *buffer, size_t length,
                          int startoffset)
{
  struct tag_info ti;
  const unsigned char *p = buffer;
  size_t n = length;
  const char *where;

  where = "start";
  if (parse_tag (&p, &n, &ti))
    goto bailout;
  if (ti.class != CONTEXT || ti.tag)
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

  /* fixme: continue parsing */

  return 0;
 bailout:
  log_error ("encrptedData error at \"%s\", offset %u\n",
             where, (p - buffer)+startoffset);
  return -1;
}

static GcryMPI *
parse_bag_data (const unsigned char *buffer, size_t length, int startoffset,
                const char *pw)
{
  int rc;
  struct tag_info ti;
  const unsigned char *p = buffer;
  size_t n = length;
  const char *where;
  char salt[8];
  unsigned int iter;
  int len;
  unsigned char *plain = NULL;
  GcryMPI *result = NULL;
  int result_count, i;

  where = "start";
  if (parse_tag (&p, &n, &ti))
    goto bailout;
  if (ti.class != CONTEXT || ti.tag)
    goto bailout;
  if (parse_tag (&p, &n, &ti))
    goto bailout;
  if (ti.class || ti.tag != TAG_OCTET_STRING)
    goto bailout;

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
  if (ti.class != CONTEXT || ti.tag)
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
  if (ti.class || ti.tag != TAG_OBJECT_ID
      || ti.length != DIM(oid_pbeWithSHAAnd3_KeyTripleDES_CBC)
      || memcmp (p, oid_pbeWithSHAAnd3_KeyTripleDES_CBC,
                 DIM(oid_pbeWithSHAAnd3_KeyTripleDES_CBC)))
    goto bailout;
  p += DIM(oid_pbeWithSHAAnd3_KeyTripleDES_CBC);
  n -= DIM(oid_pbeWithSHAAnd3_KeyTripleDES_CBC);

  where = "3des-params";
  if (parse_tag (&p, &n, &ti))
    goto bailout;
  if (ti.class || ti.tag != TAG_SEQUENCE)
    goto bailout;
  if (parse_tag (&p, &n, &ti))
    goto bailout;
  if (ti.class || ti.tag != TAG_OCTET_STRING || ti.length != 8 )
    goto bailout;
  memcpy (salt, p, 8);
  p += 8;
  n -= 8;
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
  
  where = "3des-ciphertext";
  if (parse_tag (&p, &n, &ti))
    goto bailout;
  if (ti.class || ti.tag != TAG_OCTET_STRING || !ti.length )
    goto bailout;
  
  log_info ("%lu bytes of 3DES encrypted text\n", ti.length);
  
  plain = gcry_malloc_secure (ti.length);
  if (!plain)
    {
      log_error ("error allocating decryption buffer\n");
      goto bailout;
    }
  memcpy (plain, p, ti.length);
  decrypt_block (plain, ti.length, salt, iter, pw);
  n = ti.length;
  startoffset = 0;
  buffer = p = plain;

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
      int dummy_n;

      if (parse_tag (&p, &n, &ti) || ti.class || ti.tag != TAG_INTEGER)
        goto bailout;
      if (len < ti.nhdr)
        goto bailout;
      len -= ti.nhdr;
      if (len < ti.length)
        goto bailout;
      len -= ti.length;
      dummy_n = ti.length;
      if (!result_count && ti.length == 1 && !*p)
        ; /* ignore the very first one if it is a 0 */
      else 
        {
          rc = gcry_mpi_scan (result+result_count, GCRYMPI_FMT_USG, p,
                              &dummy_n);
          if (rc)
            {
              log_error ("error parsing key parameter: %s\n",
                         gcry_strerror (rc));
              goto bailout;
            }
          result_count++;
        }
      p += ti.length;
      n -= ti.length;
    }
  if (len)
    goto bailout;

  return result;

 bailout:
  gcry_free (plain);
  if (result)
    {
      for (i=0; result[i]; i++)
        gcry_mpi_release (result[i]);
      gcry_free (result);
    }
  log_error ( "data error at \"%s\", offset %u\n",
              where, (p - buffer) + startoffset);
  return NULL;
}


/* Parse a PKCS12 object and return an array of MPI representing the
   secret key parameters.  This is a very limited inplementation in
   that it is only able to look for 3DES encoded enctyptedData and
   tries to extract the first private key object it finds.  In case of
   an error NULL is returned. */
GcryMPI *
p12_parse (const unsigned char *buffer, size_t length, const char *pw)
{
  struct tag_info ti;
  const unsigned char *p = buffer;
  size_t n = length;
  const char *where;
  int bagseqlength, len;

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
  if (ti.class != CONTEXT || ti.tag)
    goto bailout;
  if (parse_tag (&p, &n, &ti))
    goto bailout;
  if (ti.class != UNIVERSAL || ti.tag != TAG_OCTET_STRING)
    goto bailout;

  where = "bags";
  if (parse_tag (&p, &n, &ti))
    goto bailout;
  if (ti.class != UNIVERSAL || ti.tag != TAG_SEQUENCE)
    goto bailout;
  bagseqlength = ti.length;
  while (bagseqlength)
    {
      log_error ( "at offset %u\n", (p - buffer));
      where = "bag-sequence";
      if (parse_tag (&p, &n, &ti))
        goto bailout;
      if (ti.class != UNIVERSAL || ti.tag != TAG_SEQUENCE)
        goto bailout;

      if (bagseqlength < ti.nhdr)
        goto bailout;
      bagseqlength -= ti.nhdr;
      if (bagseqlength < ti.length)
        goto bailout;
      bagseqlength -= ti.length;
      len = ti.length;

      if (parse_tag (&p, &n, &ti))
        goto bailout;
      len -= ti.nhdr;
      if (ti.tag == TAG_OBJECT_ID && ti.length == DIM(oid_encryptedData)
          && !memcmp (p, oid_encryptedData, DIM(oid_encryptedData)))
        {
          p += DIM(oid_encryptedData);
          n -= DIM(oid_encryptedData);
          len -= DIM(oid_encryptedData);
          where = "bag.encryptedData";
          if (parse_bag_encrypted_data (p, n, (p - buffer)))
            goto bailout;
        }
      else if (ti.tag == TAG_OBJECT_ID && ti.length == DIM(oid_data)
          && !memcmp (p, oid_data, DIM(oid_data)))
        {
          p += DIM(oid_data);
          n -= DIM(oid_data);
          len -= DIM(oid_data);
          return parse_bag_data (p, n, (p-buffer), pw);
        }
      else
        log_info ( "unknown bag type - skipped\n");

      if (len < 0 || len > n)
        goto bailout;
      p += len;
      n -= len;
    }
  
  return NULL;
 bailout:
  log_error ("error at \"%s\", offset %u\n", where, (p - buffer));
  return NULL;
}

#if 0 /* unser construction. */
/* Expect the RSA key parameters in KPARMS and a password in
   PW. Create a PKCS structure from it and return it as well as the
   length in R_LENGTH; return NULL in case of an error. */
unsigned char * 
p12_build (GcryMPI *kparms, const char *pw, size_t *r_length)
{
  int i;
  unsigned char *result;
  size_t resultlen;

  for (i=0; kparms[i]; i++)
    ;
  if (i != 8)
    {
      log_error ("invalid paramters for p12_build\n");
      return NULL;
    }


  *r_length = resultlen;
  return result;
}
#endif


#ifdef TEST
int
main (int argc, char **argv)
{
  FILE *fp;
  struct stat st;
  char *buf;
  size_t buflen;
  GcryMPI *result;

  if (argc != 3)
    {
      fprintf (stderr, "usage: testp12 file passphrase\n");
      return 1;
    }

  gcry_control (GCRYCTL_DISABLE_SECMEM, NULL);
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, NULL);

  fp = fopen (argv[1], "rb");
  if (!fp)
    {
      fprintf (stderr, "can't open `%s': %s\n", argv[1], strerror (errno));
      return 1;
    }
  
  if (fstat (fileno(fp), &st))
    {
      fprintf (stderr, "can't stat `%s': %s\n", argv[1], strerror (errno));
      return 1;
    }

  buflen = st.st_size;
  buf = malloc (buflen+1);
  if (!buf || fread (buf, buflen, 1, fp) != 1)
    {
      fprintf (stderr, "error reading `%s': %s\n", argv[1], strerror (errno));
      return 1;
    }
  fclose (fp);

  result = p12_parse (buf, buflen, argv[2]);
  if (result)
    {
      int i, rc;
      char *buf;

      for (i=0; result[i]; i++)
        {
          rc = gcry_mpi_aprint (GCRYMPI_FMT_HEX, (void**)&buf,
                                NULL, result[i]);
          if (rc)
            printf ("%d: [error printing number: %s]\n",
                    i, gcry_strerror (rc));
          else
            {
              printf ("%d: %s\n", i, buf);
              gcry_free (buf);
            }
        }
    }

  return 0;

}
#endif /* TEST */
