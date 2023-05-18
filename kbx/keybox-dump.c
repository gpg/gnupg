/* keybox-dump.c - Debug helpers
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "keybox-defs.h"
#include <gcrypt.h>
#include "../common/host2net.h"

/* Argg, we can't include ../common/util.h */
char *bin2hexcolon (const void *buffer, size_t length, char *stringbuf);

#define get32(a) buf32_to_ulong ((a))
#define get16(a) buf16_to_ulong ((a))


void
print_string (FILE *fp, const byte *p, size_t n, int delim)
{
  for ( ; n; n--, p++ )
    {
      if (*p < 0x20 || (*p >= 0x7f && *p < 0xa0) || *p == delim)
        {
          putc('\\', fp);
          if( *p == '\n' )
            putc('n', fp);
          else if( *p == '\r' )
            putc('r', fp);
          else if( *p == '\f' )
            putc('f', fp);
          else if( *p == '\v' )
            putc('v', fp);
          else if( *p == '\b' )
            putc('b', fp);
          else if( !*p )
            putc('0', fp);
          else
            fprintf(fp, "x%02x", *p );
	}
      else
        putc(*p, fp);
    }
}


static int
print_checksum (const byte *buffer, size_t length, size_t unhashed, FILE *fp)
{
  const byte *p;
  int i;
  int hashlen;
  unsigned char digest[20];

  fprintf (fp, "Checksum: ");
  if (unhashed && unhashed < 20)
    {
      fputs ("[specified unhashed sized too short]\n", fp);
      return 0;
    }
  if (!unhashed)
    {
      unhashed = 16;
      hashlen = 16;
    }
  else
    hashlen = 20;

  if (length < 5+unhashed)
    {
      fputs ("[blob too short for a checksum]\n", fp);
      return 0;
    }

  p = buffer + length - hashlen;
  for (i=0; i < hashlen; p++, i++)
    fprintf (fp, "%02x", *p);

  if (hashlen == 16) /* Compatibility method.  */
    {
      gcry_md_hash_buffer (GCRY_MD_MD5, digest, buffer, length - 16);
      if (!memcmp (buffer + length - 16, digest, 16))
        fputs (" [valid]\n", fp);
      else
        fputs (" [bad]\n", fp);
    }
  else
    {
      gcry_md_hash_buffer (GCRY_MD_SHA1, digest, buffer, length - unhashed);
      if (!memcmp (buffer + length - hashlen, digest, hashlen))
        fputs (" [valid]\n", fp);
      else
        fputs (" [bad]\n", fp);
    }
  return 0;
}


static int
dump_header_blob (const byte *buffer, size_t length, FILE *fp)
{
  unsigned long n;

  if (length < 32)
    {
      fprintf (fp, "[blob too short]\n");
      return -1;
    }
  fprintf (fp, "Version: %d\n", buffer[5]);

  n = get16 (buffer + 6);
  fprintf( fp, "Flags:   %04lX", n);
  if (n)
    {
      int any = 0;

      fputs (" (", fp);
      if ((n & 2))
        {
          if (any)
            putc (',', fp);
          fputs ("openpgp", fp);
          any++;
        }
      putc (')', fp);
    }
  putc ('\n', fp);

  if ( memcmp (buffer+8, "KBXf", 4))
    fprintf (fp, "[Error: invalid magic number]\n");

  n = get32 (buffer+16);
  fprintf( fp, "created-at: %lu\n", n );
  n = get32 (buffer+20);
  fprintf( fp, "last-maint: %lu\n", n );

  return 0;
}


/* Dump one block to FP */
int
_keybox_dump_blob (KEYBOXBLOB blob, FILE *fp)
{
  const byte *buffer;
  size_t length;
  int type, i;
  ulong n, nkeys, keyinfolen;
  ulong nuids, uidinfolen;
  ulong nsigs, siginfolen;
  ulong rawdata_off, rawdata_len;
  ulong nserial;
  ulong unhashed;
  const byte *p;
  const byte *pend;
  int is_fpr32;  /* blob version 2 */

  buffer = _keybox_get_blob_image (blob, &length);

  if (length < 32)
    {
      fprintf (fp, "[blob too short]\n");
      return -1;
    }

  n = get32( buffer );
  if (n > length)
    fprintf (fp, "[blob larger than length - output truncated]\n");
  else
    length = n;  /* ignore the rest */

  fprintf (fp, "Length: %lu\n", n );
  type = buffer[4];
  switch (type)
    {
    case KEYBOX_BLOBTYPE_EMPTY:
      fprintf (fp, "Type:   Empty\n");
      return 0;

    case KEYBOX_BLOBTYPE_HEADER:
      fprintf (fp, "Type:   Header\n");
      return dump_header_blob (buffer, length, fp);
    case KEYBOX_BLOBTYPE_PGP:
      fprintf (fp, "Type:   OpenPGP\n");
      break;
    case KEYBOX_BLOBTYPE_X509:
      fprintf (fp, "Type:   X.509\n");
      break;
    default:
      fprintf (fp, "Type:   %d\n", type);
      fprintf (fp, "[can't dump this blob type]\n");
      return 0;
    }
  /* Here we have either BLOGTYPE_X509 or BLOBTYPE_OPENPGP */
  fprintf (fp, "Version: %d\n", buffer[5]);
  is_fpr32 = buffer[5] == 2;

  if (length < 40)
    {
      fprintf (fp, "[blob too short]\n");
      return -1;
    }

  n = get16 (buffer + 6);
  fprintf( fp, "Blob-Flags: %04lX", n);
  if (n)
    {
      int any = 0;

      fputs (" (", fp);
      if ((n & 1))
        {
          fputs ("secret", fp);
          any++;
        }
      if ((n & 2))
        {
          if (any)
            putc (',', fp);
          fputs ("ephemeral", fp);
          any++;
        }
      putc (')', fp);
    }
  putc ('\n', fp);

  rawdata_off = get32 (buffer + 8);
  rawdata_len = get32 (buffer + 12);

  fprintf( fp, "Data-Offset: %lu\n", rawdata_off );
  fprintf( fp, "Data-Length: %lu\n", rawdata_len );
  if (rawdata_off > length || rawdata_len > length
      || rawdata_off+rawdata_len > length
      || rawdata_len + 4 > length
      || rawdata_off+rawdata_len + 4 > length)
    {
      fprintf (fp, "[Error: raw data larger than blob]\n");
      return -1;
    }

  if (rawdata_off > length
      || rawdata_len > length
      || rawdata_off + rawdata_len > length)
    {
      fprintf (fp, "[Error: unhashed data larger than blob]\n");
      return -1;
    }
  unhashed = length - rawdata_off - rawdata_len;
  fprintf (fp, "Unhashed: %lu\n", unhashed);

  nkeys = get16 (buffer + 16);
  fprintf (fp, "Key-Count: %lu\n", nkeys );
  if (!nkeys)
    fprintf (fp, "[Error: no keys]\n");
  if (nkeys > 1 && type == KEYBOX_BLOBTYPE_X509)
    fprintf (fp, "[Error: only one key allowed for X509]\n");

  keyinfolen = get16 (buffer + 18 );
  fprintf (fp, "Key-Info-Length: %lu\n", keyinfolen);
  p = buffer + 20;
  pend = buffer + length;
  for (n=0; n < nkeys; n++, p += keyinfolen)
    {
      ulong kidoff, kflags;

      if (p + keyinfolen >= pend)
        {
          fprintf (fp, "[Error: key data larger than blob]\n");
          return -1;
        }

      fprintf (fp, "Key-Fpr[%lu]: ", n );
      if (is_fpr32)
        {
          if (p + 32 + 2 >= pend)
            {
              fprintf (fp, "[Error: fingerprint data larger than blob]\n");
              return -1;
            }
          kflags = get16 (p + 32 );
          for (i=0; i < ((kflags & 0x80)?32:20); i++ )
            fprintf (fp, "%02X", p[i]);
        }
      else
        {
          if (p + 20 + 4 >= pend)
            {
              fprintf (fp, "[Error: fingerprint data larger than blob]\n");
              return -1;
            }
          for (i=0; i < 20; i++ )
            fprintf (fp, "%02X", p[i]);
          kidoff = get32 (p + 20);
          fprintf (fp, "\nKey-Kid-Off[%lu]: %lu\n", n, kidoff );
          fprintf (fp, "Key-Kid[%lu]: ", n );

          if (p + kidoff + 8 >= pend)
            {
              fprintf (fp, "[Error: fingerprint data larger than blob]\n");
              return -1;
            }
          for (i=0; i < 8; i++ )
            fprintf (fp, "%02X", buffer[kidoff+i] );
          if (p + 24 >= pend)
            {
              fprintf (fp, "[Error: fingerprint data larger than blob]\n");
              return -1;
            }
          kflags = get16 (p + 24);
        }
      fprintf( fp, "\nKey-Flags[%lu]: %04lX\n", n, kflags);
    }

  /* serial number */
  if (p + 2 >= pend)
    {
      fprintf (fp, "[Error: data larger than blob]\n");
      return -1;
    }
  fputs ("Serial-No: ", fp);
  nserial = get16 (p);
  p += 2;
  if (!nserial)
    fputs ("none", fp);
  else
    {
      if (p + nserial >= pend)
        {
          fprintf (fp, "[Error: data larger than blob]\n");
          return -1;
        }
      for (; nserial; nserial--, p++)
        fprintf (fp, "%02X", *p);
    }
  putc ('\n', fp);

  /* user IDs */
  if (p + 4 >= pend)
    {
      fprintf (fp, "[Error: data larger than blob]\n");
      return -1;
    }
  nuids = get16 (p);
  fprintf (fp, "Uid-Count: %lu\n", nuids );
  uidinfolen = get16  (p + 2);
  fprintf (fp, "Uid-Info-Length: %lu\n", uidinfolen);
  p += 4;
  for (n=0; n < nuids; n++, p += uidinfolen)
    {
      ulong uidoff, uidlen, uflags;

      if (p + uidinfolen >= pend || uidinfolen < 8)
        {
          fprintf (fp, "[Error: data larger than blob]\n");
          return -1;
        }

      uidoff = get32( p );
      uidlen = get32( p+4 );
      if (type == KEYBOX_BLOBTYPE_X509 && !n)
        {
          fprintf (fp, "Issuer-Off: %lu\n", uidoff );
          fprintf (fp, "Issuer-Len: %lu\n", uidlen );
          fprintf (fp, "Issuer: \"");
        }
      else if (type == KEYBOX_BLOBTYPE_X509 && n == 1)
        {
          fprintf (fp, "Subject-Off: %lu\n", uidoff );
          fprintf (fp, "Subject-Len: %lu\n", uidlen );
          fprintf (fp, "Subject: \"");
        }
      else
        {
          fprintf (fp, "Uid-Off[%lu]: %lu\n", n, uidoff );
          fprintf (fp, "Uid-Len[%lu]: %lu\n", n, uidlen );
          fprintf (fp, "Uid[%lu]: \"", n );
        }

      if (uidoff + uidlen > length
          || uidoff + uidlen < uidoff
          || uidoff + uidlen < uidlen)
        {
          fprintf (fp, "[Error: data larger than blob]\n");
          return -1;
        }
      print_string (fp, buffer+uidoff, uidlen, '\"');
      fputs ("\"\n", fp);
      if (p + 8 + 2 + 1 >= pend)
        {
          fprintf (fp, "[Error: data larger than blob]\n");
          return -1;
        }
      uflags = get16 (p + 8);
      if (type == KEYBOX_BLOBTYPE_X509 && !n)
        {
          fprintf (fp, "Issuer-Flags: %04lX\n", uflags );
          fprintf (fp, "Issuer-Validity: %d\n", p[10] );
        }
      else if (type == KEYBOX_BLOBTYPE_X509 && n == 1)
        {
          fprintf (fp, "Subject-Flags: %04lX\n", uflags );
          fprintf (fp, "Subject-Validity: %d\n", p[10] );
        }
      else
        {
          fprintf (fp, "Uid-Flags[%lu]: %04lX\n", n, uflags );
          fprintf (fp, "Uid-Validity[%lu]: %d\n", n, p[10] );
        }
    }

  if (p + 2 + 2 >= pend)
    {
      fprintf (fp, "[Error: data larger than blob]\n");
      return -1;
    }
  nsigs = get16 (p);
  fprintf (fp, "Sig-Count: %lu\n", nsigs );
  siginfolen = get16 (p + 2);
  fprintf (fp, "Sig-Info-Length: %lu\n", siginfolen );
  p += 4;
  {
    int in_range = 0;
    ulong first = 0;

    for (n=0; n < nsigs; n++, p += siginfolen)
      {
        ulong sflags;

        if (p + siginfolen >= pend || siginfolen < 4)
          {
            fprintf (fp, "[Error: data larger than blob]\n");
            return -1;
          }
        sflags = get32 (p);
        if (!in_range && !sflags)
          {
            in_range = 1;
            first = n;
            continue;
          }
        if (in_range && !sflags)
          continue;
        if (in_range)
          {
            fprintf (fp, "Sig-Expire[%lu-%lu]: [not checked]\n", first, n-1);
            in_range = 0;
          }

        fprintf (fp, "Sig-Expire[%lu]: ", n );
        if (!sflags)
          fputs ("[not checked]", fp);
        else if (sflags == 1 )
          fputs ("[missing key]", fp);
        else if (sflags == 2 )
          fputs ("[bad signature]", fp);
        else if (sflags < 0x10000000)
          fprintf (fp, "[bad flag %0lx]", sflags);
        else if (sflags == (ulong)(-1))
          fputs ("[good - does not expire]", fp );
        else
          fprintf (fp, "[good - expires at %lu]", sflags);
        putc ('\n', fp );
      }
    if (in_range)
      fprintf (fp, "Sig-Expire[%lu-%lu]: [not checked]\n", first, n-1);
  }

  if (p + 16 >= pend)
    {
      fprintf (fp, "[Error: data larger than blob]\n");
      return -1;
    }
  fprintf (fp, "Ownertrust: %d\n", p[0] );
  fprintf (fp, "All-Validity: %d\n", p[1] );
  p += 4;
  n = get32 (p);
  p += 4;
  fprintf (fp, "Recheck-After: %lu\n", n );
  n = get32 (p );
  p += 4;
  fprintf( fp, "Latest-Timestamp: %lu\n", n );
  n = get32 (p );
  p += 4;
  fprintf (fp, "Created-At: %lu\n", n );

  if (p + 4 >= pend)
    {
      fprintf (fp, "[Error: data larger than blob]\n");
      return -1;
    }
  n = get32 (p );
  fprintf (fp, "Reserved-Space: %lu\n", n );

  if (n >= 4 && unhashed >= 24)
    {
      n = get32 ( buffer + length - unhashed);
      fprintf (fp, "Storage-Flags: %08lx\n", n );
    }
  print_checksum (buffer, length, unhashed, fp);
  return 0;
}


/* Compute the SHA-1 checksum of the rawdata in BLOB and put it into
   DIGEST. */
static int
hash_blob_rawdata (KEYBOXBLOB blob, unsigned char *digest)
{
  const unsigned char *buffer;
  size_t n, length;
  int type;
  ulong rawdata_off, rawdata_len;

  buffer = _keybox_get_blob_image (blob, &length);

  if (length < 32)
    return -1;
  n = get32 (buffer);
  if (n < length)
    length = n;  /* Blob larger than length in header - ignore the rest. */

  type = buffer[4];
  switch (type)
    {
    case KEYBOX_BLOBTYPE_PGP:
    case KEYBOX_BLOBTYPE_X509:
      break;

    case KEYBOX_BLOBTYPE_EMPTY:
    case KEYBOX_BLOBTYPE_HEADER:
    default:
      memset (digest, 0, 20);
      return 0;
    }

  if (length < 40)
    return -1;

  rawdata_off = get32 (buffer + 8);
  rawdata_len = get32 (buffer + 12);

  if (rawdata_off > length || rawdata_len > length
      || rawdata_off+rawdata_off > length)
    return -1; /* Out of bounds.  */

  gcry_md_hash_buffer (GCRY_MD_SHA1, digest, buffer+rawdata_off, rawdata_len);
  return 0;
}


struct file_stats_s
{
  unsigned long too_short_blobs;
  unsigned long too_large_blobs;
  unsigned long total_blob_count;
  unsigned long empty_blob_count;
  unsigned long header_blob_count;
  unsigned long pgp_blob_count;
  unsigned long x509_blob_count;
  unsigned long unknown_blob_count;
  unsigned long non_flagged;
  unsigned long secret_flagged;
  unsigned long ephemeral_flagged;
  unsigned long skipped_long_blobs;
};

static int
update_stats (KEYBOXBLOB blob, struct file_stats_s *s)
{
  const unsigned char *buffer;
  size_t length;
  int type;
  unsigned long n;

  buffer = _keybox_get_blob_image (blob, &length);
  if (length < 32)
    {
      s->too_short_blobs++;
      return -1;
    }

  n = get32( buffer );
  if (n > length)
    s->too_large_blobs++;
  else
    length = n;  /* ignore the rest */

  s->total_blob_count++;
  type = buffer[4];
  switch (type)
    {
    case KEYBOX_BLOBTYPE_EMPTY:
      s->empty_blob_count++;
      return 0;
    case KEYBOX_BLOBTYPE_HEADER:
      s->header_blob_count++;
      return 0;
    case KEYBOX_BLOBTYPE_PGP:
      s->pgp_blob_count++;
      break;
    case KEYBOX_BLOBTYPE_X509:
      s->x509_blob_count++;
      break;
    default:
      s->unknown_blob_count++;
      return 0;
    }

  if (length < 40)
    {
      s->too_short_blobs++;
      return -1;
    }

  n = get16 (buffer + 6);
  if (n)
    {
      if ((n & 1))
        s->secret_flagged++;
      if ((n & 2))
        s->ephemeral_flagged++;
    }
  else
    s->non_flagged++;

  return 0;
}



static estream_t
open_file (const char **filename, FILE *outfp)
{
  estream_t fp;

  if (!*filename)
    {
      *filename = "-";
      fp = es_stdin;
    }
  else
    fp = es_fopen (*filename, "rb");
  if (!fp)
    {
      int save_errno = errno;
      fprintf (outfp, "can't open '%s': %s\n", *filename, strerror(errno));
      gpg_err_set_errno (save_errno);
    }
  return fp;
}



int
_keybox_dump_file (const char *filename, int stats_only, FILE *outfp)
{
  estream_t fp;
  KEYBOXBLOB blob;
  int rc;
  unsigned long count = 0;
  struct file_stats_s stats;
  int skipped_deleted;

  memset (&stats, 0, sizeof stats);

  if (!(fp = open_file (&filename, outfp)))
    return gpg_error_from_syserror ();

  for (;;)
    {
      rc = _keybox_read_blob (&blob, fp, &skipped_deleted);
      if (gpg_err_code (rc) == GPG_ERR_TOO_LARGE
          && gpg_err_source (rc) == GPG_ERR_SOURCE_KEYBOX)
        {
          if (stats_only)
            stats.skipped_long_blobs++;
          else
            {
              fprintf (outfp, "BEGIN-RECORD: %lu\n", count );
              fprintf (outfp, "# Record too large\nEND-RECORD\n");
            }
          count++;
          continue;
        }
      if (rc)
        break;

      count += skipped_deleted;

      if (stats_only)
        {
          stats.total_blob_count += skipped_deleted;
          stats.empty_blob_count += skipped_deleted;
          update_stats (blob, &stats);
        }
      else
        {
          fprintf (outfp, "BEGIN-RECORD: %lu\n", count );
          _keybox_dump_blob (blob, outfp);
          fprintf (outfp, "END-RECORD\n");
        }
      _keybox_release_blob (blob);
      count++;
    }
  if (rc == -1)
    rc = 0;
  if (rc)
    fprintf (outfp, "# error reading '%s': %s\n", filename, gpg_strerror (rc));

  if (fp != es_stdin)
    es_fclose (fp);

  if (stats_only)
    {
      fprintf (outfp,
               "Total number of blobs: %8lu\n"
               "               header: %8lu\n"
               "                empty: %8lu\n"
               "              openpgp: %8lu\n"
               "                 x509: %8lu\n"
               "          non flagged: %8lu\n"
               "       secret flagged: %8lu\n"
               "    ephemeral flagged: %8lu\n",
               stats.total_blob_count,
               stats.header_blob_count,
               stats.empty_blob_count,
               stats.pgp_blob_count,
               stats.x509_blob_count,
               stats.non_flagged,
               stats.secret_flagged,
               stats.ephemeral_flagged);
        if (stats.skipped_long_blobs)
          fprintf (outfp, "   skipped long blobs: %8lu\n",
                   stats.skipped_long_blobs);
        if (stats.unknown_blob_count)
          fprintf (outfp, "   unknown blob types: %8lu\n",
                   stats.unknown_blob_count);
        if (stats.too_short_blobs)
          fprintf (outfp, "      too short blobs: %8lu (error)\n",
                   stats.too_short_blobs);
        if (stats.too_large_blobs)
          fprintf (outfp, "      too large blobs: %8lu (error)\n",
                   stats.too_large_blobs);
    }

  return rc;
}



struct dupitem_s
{
  unsigned long recno;
  unsigned char digest[20];
};


static int
cmp_dupitems (const void *arg_a, const void *arg_b)
{
  struct dupitem_s *a = (struct dupitem_s *)arg_a;
  struct dupitem_s *b = (struct dupitem_s *)arg_b;

  return memcmp (a->digest, b->digest, 20);
}


int
_keybox_dump_find_dups (const char *filename, int print_them, FILE *outfp)
{
  estream_t fp;
  KEYBOXBLOB blob;
  int rc;
  unsigned long recno = 0;
  unsigned char zerodigest[20];
  struct dupitem_s *dupitems;
  size_t dupitems_size, dupitems_count, lastn, n;
  char fprbuf[3*20+1];

  (void)print_them;

  memset (zerodigest, 0, sizeof zerodigest);

  if (!(fp = open_file (&filename, outfp)))
    return gpg_error_from_syserror ();

  dupitems_size = 1000;
  dupitems = malloc (dupitems_size * sizeof *dupitems);
  if (!dupitems)
    {
      gpg_error_t tmperr = gpg_error_from_syserror ();
      fprintf (outfp, "error allocating array for '%s': %s\n",
               filename, strerror(errno));
      if (fp != es_stdin)
        es_fclose (fp);
      return tmperr;
    }
  dupitems_count = 0;

  while ( !(rc = _keybox_read_blob (&blob, fp, NULL)) )
    {
      unsigned char digest[20];

      if (hash_blob_rawdata (blob, digest))
        fprintf (outfp, "error in blob %ld of '%s'\n", recno, filename);
      else if (memcmp (digest, zerodigest, 20))
        {
          if (dupitems_count >= dupitems_size)
            {
              struct dupitem_s *tmp;

              dupitems_size += 1000;
              tmp = realloc (dupitems, dupitems_size * sizeof *dupitems);
              if (!tmp)
                {
                  gpg_error_t tmperr = gpg_error_from_syserror ();
                  fprintf (outfp, "error reallocating array for '%s': %s\n",
                           filename, strerror(errno));
                  free (dupitems);
                  if (fp != es_stdin)
                    es_fclose (fp);
                  return tmperr;
                }
              dupitems = tmp;
            }
          dupitems[dupitems_count].recno = recno;
          memcpy (dupitems[dupitems_count].digest, digest, 20);
          dupitems_count++;
        }
      _keybox_release_blob (blob);
      recno++;
    }
  if (rc == -1)
    rc = 0;
  if (rc)
    fprintf (outfp, "error reading '%s': %s\n", filename, gpg_strerror (rc));
  if (fp != es_stdin)
    es_fclose (fp);

  qsort (dupitems, dupitems_count, sizeof *dupitems, cmp_dupitems);

  for (lastn=0, n=1; n < dupitems_count; lastn=n, n++)
    {
      if (!memcmp (dupitems[lastn].digest, dupitems[n].digest, 20))
        {
          bin2hexcolon (dupitems[lastn].digest, 20, fprbuf);
          fprintf (outfp, "fpr=%s recno=%lu", fprbuf, dupitems[lastn].recno);
          do
            fprintf (outfp, " %lu", dupitems[n].recno);
          while (++n < dupitems_count
                 && !memcmp (dupitems[lastn].digest, dupitems[n].digest, 20));
          putc ('\n', outfp);
          n--;
        }
    }

  free (dupitems);

  return rc;
}


/* Print records with record numbers FROM to TO to OUTFP.  */
int
_keybox_dump_cut_records (const char *filename, unsigned long from,
                          unsigned long to, FILE *outfp)
{
  estream_t fp;
  KEYBOXBLOB blob = NULL;
  int rc;
  unsigned long recno = 0;

  if (!(fp = open_file (&filename, stderr)))
    return gpg_error_from_syserror ();

  while ( !(rc = _keybox_read_blob (&blob, fp, NULL)) )
    {
      if (recno > to)
        break; /* Ready.  */
      if (recno >= from)
        {
          if ((rc = _keybox_write_blob (blob, NULL, outfp)))
            {
              fprintf (stderr, "error writing output: %s\n",
                       gpg_strerror (rc));
              goto leave;
            }
        }
      _keybox_release_blob (blob);
      blob = NULL;
      recno++;
    }
  if (rc == -1)
    rc = 0;
  if (rc)
    fprintf (stderr, "error reading '%s': %s\n", filename, gpg_strerror (rc));
 leave:
  _keybox_release_blob (blob);
  if (fp != es_stdin)
    es_fclose (fp);
  return rc;
}
