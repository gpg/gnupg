/* keybox-dump.c - Debug helpers
 *	Copyright (C) 2001 Free Software Foundation, Inc.
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

#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "keybox-defs.h"

static ulong
get32 (const byte *buffer)
{
  ulong a;
  a =  *buffer << 24;
  a |= buffer[1] << 16;
  a |= buffer[2] << 8;
  a |= buffer[3];
  return a;
}

static ulong
get16 (const byte *buffer)
{
  ulong a;
  a =  *buffer << 8;
  a |= buffer[1];
  return a;
}

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
dump_header_blob (const byte *buffer, size_t length, FILE *fp)
{
  fprintf (fp, "Version: %d\n", buffer[5]);
  if ( memcmp (buffer+8, "KBXf", 4))
    fprintf (fp, "[Error: invalid magic number]\n");
  return 0;
}


/* Dump one block to FP */
int
_keybox_dump_blob (KEYBOXBLOB blob, FILE *fp)
{
  const byte *buffer;
  size_t length;
  int type;
  ulong n, nkeys, keyinfolen;
  ulong nuids, uidinfolen;
  ulong nsigs, siginfolen;
  ulong rawdata_off, rawdata_len;
  ulong nserial;
  const byte *p;

  buffer = _keybox_get_blob_image (blob, &length);
  
  if (length < 40)
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
    case BLOBTYPE_HEADER:
      fprintf (fp, "Type:   Header\n");
      return dump_header_blob (buffer, length, fp);
    case BLOBTYPE_PGP:
      fprintf (fp, "Type:   OpenPGP\n");
      break;
    case BLOBTYPE_X509:
      fprintf (fp, "Type:   X.509\n");
      break;
    default:
      fprintf (fp, "Type:   %d\n", type);
      fprintf (fp, "[can't dump this blob type]\n");
      return 0;
    }
  fprintf (fp, "Version: %d\n", buffer[5]);
  
  n = get16 (buffer + 6);
  fprintf( fp, "Blob-Flags: %04lX\n", n);
  
  rawdata_off = get32 (buffer + 8);
  rawdata_len = get32 (buffer + 12);

  fprintf( fp, "Data-Offset: %lu\n", rawdata_off );
  fprintf( fp, "Data-Length: %lu\n", rawdata_len );

  nkeys = get16 (buffer + 16);
  fprintf (fp, "Key-Count: %lu\n", nkeys );
  if (!nkeys)
    fprintf (fp, "[Error: no keys]\n");
  if (nkeys > 1 && type == BLOBTYPE_X509)
    fprintf (fp, "[Error: only one key allowed for X509]\n");

  keyinfolen = get16 (buffer + 18 );
  fprintf (fp, "Key-Info-Length: %lu\n", keyinfolen);
  /* fixme: check bounds */
  p = buffer + 20;
  for (n=0; n < nkeys; n++, p += keyinfolen)
    {
      int i;
      ulong kidoff, kflags;
    
      fprintf (fp, "Key-Fpr[%lu]: ", n );
      for (i=0; i < 20; i++ )
        fprintf (fp, "%02X", p[i]);
      kidoff = get32 (p + 20);
      fprintf (fp, "\nKey-Kid-Off[%lu]: %lu\n", n, kidoff );
      fprintf (fp, "Key-Kid[%lu]: ", n );
      /* fixme: check bounds */
      for (i=0; i < 8; i++ )
        fprintf (fp, "%02X", buffer[kidoff+i] );
      kflags = get16 (p + 24 );
      fprintf( fp, "\nKey-Flags[%lu]: %04lX\n", n, kflags);
    }
  
  /* serial number */
  fputs ("Serial-No: ", fp);
  nserial = get16 (p);
  p += 2;
  if (!nserial)
    fputs ("none", fp);
  else
    {
      for (; nserial; nserial--, p++)
        fprintf (fp, "%02X", *p);
    }
  putc ('\n', fp);

  /* user IDs */
  nuids = get16 (p);
  fprintf (fp, "Uid-Count: %lu\n", nuids );
  uidinfolen = get16  (p + 2);
  fprintf (fp, "Uid-Info-Length: %lu\n", uidinfolen);
  /* fixme: check bounds */
  p += 4;
  for (n=0; n < nuids; n++, p += uidinfolen)
    {
      ulong uidoff, uidlen, uflags;
      
      uidoff = get32( p );
      uidlen = get32( p+4 );
      if (type == BLOBTYPE_X509 && !n)
        {
          fprintf (fp, "Issuer-Off: %lu\n", uidoff );
          fprintf (fp, "Issuer-Len: %lu\n", uidlen );
          fprintf (fp, "Issuer: \"");
        }
      else if (type == BLOBTYPE_X509 && n == 1)
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
      print_string (fp, buffer+uidoff, uidlen, '\"');
      fputs ("\"\n", fp);
      uflags = get16 (p + 8);
      if (type == BLOBTYPE_X509 && !n)
        {
          fprintf (fp, "Issuer-Flags: %04lX\n", uflags );
          fprintf (fp, "Issuer-Validity: %d\n", p[10] );
        }
      else if (type == BLOBTYPE_X509 && n == 1)
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
  
  nsigs = get16 (p);
  fprintf (fp, "Sig-Count: %lu\n", nsigs );
  siginfolen = get16 (p + 2);
  fprintf (fp, "Sig-Info-Length: %lu\n", siginfolen );
  /* fixme: check bounds  */
  p += 4;
  for (n=0; n < nsigs; n++, p += siginfolen)
    {
      ulong sflags;
    
      sflags = get32 (p);
      fprintf (fp, "Sig-Expire[%lu]: ", n );
      if (!sflags)
        fputs ("[not checked]", fp);
      else if (sflags == 1 )
        fputs ("[missing key]", fp);
      else if (sflags == 2 )
        fputs ("[bad signature]", fp);
      else if (sflags < 0x10000000)
        fprintf (fp, "[bad flag %0lx]", sflags);
      else if (sflags == 0xffffffff)
        fputs ("0", fp );
      else
        fputs ("a time"/*strtimestamp( sflags )*/, fp );
      putc ('\n', fp );
    }

  fprintf (fp, "Ownertrust: %d\n", p[0] );
  fprintf (fp, "All-Validity: %d\n", p[1] );
  p += 4;
  n = get32 (p); p += 4;
  fprintf (fp, "Recheck-After: %s\n", /*n? strtimestamp(n) :*/ "0" );
  n = get32 (p ); p += 4;
  fprintf( fp, "Latest-Timestamp: %s\n", "0"/*strtimestamp(n)*/ );
  n = get32 (p ); p += 4;
  fprintf (fp, "Created-At: %s\n", "0"/*strtimestamp(n)*/ );
  n = get32 (p ); p += 4;
  fprintf (fp, "Reserved-Space: %lu\n", n );

  /* check that the keyblock is at the correct offset and other bounds */
  /*fprintf (fp, "Blob-Checksum: [MD5-hash]\n");*/
  return 0;
}



int
_keybox_dump_file (const char *filename, FILE *outfp)
{
  FILE *fp;
  KEYBOXBLOB blob;
  int rc;
  unsigned long count = 0;

  if (!filename)
    {
      filename = "-";
      fp = stdin;
    }
  else
    fp = fopen (filename, "rb");
  if (!fp)
    {
      fprintf (outfp, "can't open `%s': %s\n", filename, strerror(errno));
      return KEYBOX_File_Error;
    }

  while ( !(rc = _keybox_read_blob (&blob, fp)) )
    {
      fprintf (outfp, "BEGIN-RECORD: %lu\n", count );
      _keybox_dump_blob (blob, outfp);
      _keybox_release_blob (blob);
      fprintf (outfp, "END-RECORD\n");
      count++;
    }
  if (rc == -1)
    rc = 0;
  if (rc)
    fprintf (outfp, "error reading `%s': %s\n", filename,
             rc == KEYBOX_Read_Error? keybox_strerror(rc):strerror (errno));
  
  if (fp != stdin)
    fclose (fp);
  return rc;
}
