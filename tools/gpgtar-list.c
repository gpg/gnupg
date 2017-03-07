/* gpgtar-list.c - List a TAR archive
 * Copyright (C) 2010 Free Software Foundation, Inc.
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../common/i18n.h"
#include "gpgtar.h"
#include "../common/exectool.h"
#include "../common/ccparray.h"



static unsigned long long
parse_xoctal (const void *data, size_t length, const char *filename)
{
  const unsigned char *p = data;
  unsigned long long value;

  if (!length)
    value = 0;
  else if ( (*p & 0x80))
    {
      /* Binary format.  */
      value = (*p++ & 0x7f);
      while (--length)
        {
          value <<= 8;
          value |= *p++;
        }
    }
  else
    {
      /* Octal format  */
      value = 0;
      /* Skip leading spaces and zeroes.  */
      for (; length && (*p == ' ' || *p == '0'); length--, p++)
        ;
      for (; length && *p; length--, p++)
        {
          if (*p >= '0' && *p <= '7')
            {
              value <<= 3;
              value += (*p - '0');
            }
          else
            {
              log_error ("%s: invalid octal number encountered - assuming 0\n",
                         filename);
              value = 0;
              break;
            }
        }
    }
  return value;
}


static tar_header_t
parse_header (const void *record, const char *filename)
{
  const struct ustar_raw_header *raw = record;
  size_t n, namelen, prefixlen;
  tar_header_t header;
  int use_prefix;

  use_prefix = (!memcmp (raw->magic, "ustar", 5)
                && (raw->magic[5] == ' ' || !raw->magic[5]));


  for (namelen=0; namelen < sizeof raw->name && raw->name[namelen]; namelen++)
    ;
  if (namelen == sizeof raw->name)
    log_info ("%s: warning: name not terminated by a nul byte\n", filename);
  for (n=namelen+1; n < sizeof raw->name; n++)
    if (raw->name[n])
      {
        log_info ("%s: warning: garbage after name\n", filename);
        break;
      }


  if (use_prefix && raw->prefix[0])
    {
      for (prefixlen=0; (prefixlen < sizeof raw->prefix
                         && raw->prefix[prefixlen]); prefixlen++)
        ;
      if (prefixlen == sizeof raw->prefix)
        log_info ("%s: warning: prefix not terminated by a nul byte\n",
                  filename);
      for (n=prefixlen+1; n < sizeof raw->prefix; n++)
        if (raw->prefix[n])
          {
            log_info ("%s: warning: garbage after prefix\n", filename);
            break;
          }
    }
  else
    prefixlen = 0;

  header = xtrycalloc (1, sizeof *header + prefixlen + 1 + namelen);
  if (!header)
    {
      log_error ("%s: error allocating header: %s\n",
                 filename, gpg_strerror (gpg_error_from_syserror ()));
      return NULL;
    }
  if (prefixlen)
    {
      n = prefixlen;
      memcpy (header->name, raw->prefix, n);
      if (raw->prefix[n-1] != '/')
        header->name[n++] = '/';
    }
  else
    n = 0;
  memcpy (header->name+n, raw->name, namelen);
  header->name[n+namelen] = 0;

  header->mode  = parse_xoctal (raw->mode, sizeof raw->mode, filename);
  header->uid   = parse_xoctal (raw->uid, sizeof raw->uid, filename);
  header->gid   = parse_xoctal (raw->gid, sizeof raw->gid, filename);
  header->size  = parse_xoctal (raw->size, sizeof raw->size, filename);
  header->mtime = parse_xoctal (raw->mtime, sizeof raw->mtime, filename);
  /* checksum = */
  switch (raw->typeflag[0])
    {
    case '0': header->typeflag = TF_REGULAR; break;
    case '1': header->typeflag = TF_HARDLINK; break;
    case '2': header->typeflag = TF_SYMLINK; break;
    case '3': header->typeflag = TF_CHARDEV; break;
    case '4': header->typeflag = TF_BLOCKDEV; break;
    case '5': header->typeflag = TF_DIRECTORY; break;
    case '6': header->typeflag = TF_FIFO; break;
    case '7': header->typeflag = TF_RESERVED; break;
    default:  header->typeflag = TF_UNKNOWN; break;
    }


  /* Compute the number of data records following this header.  */
  if (header->typeflag == TF_REGULAR || header->typeflag == TF_UNKNOWN)
    header->nrecords = (header->size + RECORDSIZE-1)/RECORDSIZE;
  else
    header->nrecords = 0;


  return header;
}



/* Read the next block, assming it is a tar header.  Returns a header
   object on success in R_HEADER, or an error.  If the stream is
   consumed, R_HEADER is set to NULL.  In case of an error an error
   message has been printed.  */
static gpg_error_t
read_header (estream_t stream, tar_header_t *r_header)
{
  gpg_error_t err;
  char record[RECORDSIZE];
  int i;

  err = read_record (stream, record);
  if (err)
    return err;

  for (i=0; i < RECORDSIZE && !record[i]; i++)
    ;
  if (i == RECORDSIZE)
    {
      /* All zero header - check whether it is the first part of an
         end of archive mark.  */
      err = read_record (stream, record);
      if (err)
        return err;

      for (i=0; i < RECORDSIZE && !record[i]; i++)
        ;
      if (i != RECORDSIZE)
        log_info ("%s: warning: skipping empty header\n",
                  es_fname_get (stream));
      else
        {
          /* End of archive - FIXME: we might want to check for garbage.  */
          *r_header = NULL;
          return 0;
        }
    }

  *r_header = parse_header (record, es_fname_get (stream));
  return *r_header ? 0 : gpg_error_from_syserror ();
}


/* Skip the data records according to HEADER.  Prints an error message
   on error and return -1. */
static int
skip_data (estream_t stream, tar_header_t header)
{
  char record[RECORDSIZE];
  unsigned long long n;

  for (n=0; n < header->nrecords; n++)
    {
      if (read_record (stream, record))
        return -1;
    }

  return 0;
}



static void
print_header (tar_header_t header, estream_t out)
{
  unsigned long mask;
  char modestr[10+1];
  int i;

  *modestr = '?';
  switch (header->typeflag)
    {
    case TF_REGULAR:  *modestr = '-'; break;
    case TF_HARDLINK: *modestr = 'h'; break;
    case TF_SYMLINK:  *modestr = 'l'; break;
    case TF_CHARDEV:  *modestr = 'c'; break;
    case TF_BLOCKDEV: *modestr = 'b'; break;
    case TF_DIRECTORY:*modestr = 'd'; break;
    case TF_FIFO:     *modestr = 'f'; break;
    case TF_RESERVED: *modestr = '='; break;
    case TF_UNKNOWN:  break;
    case TF_NOTSUP:   break;
    }
  for (mask = 0400, i = 0; i < 9; i++, mask >>= 1)
    modestr[1+i] = (header->mode & mask)? "rwxrwxrwx"[i]:'-';
  if ((header->typeflag & 04000))
    modestr[3] = modestr[3] == 'x'? 's':'S';
  if ((header->typeflag & 02000))
    modestr[6] = modestr[6] == 'x'? 's':'S';
  if ((header->typeflag & 01000))
    modestr[9] = modestr[9] == 'x'? 't':'T';
  modestr[10] = 0;

  es_fprintf (out, "%s %lu %lu/%lu %12llu %s %s\n",
              modestr, header->nlink, header->uid, header->gid, header->size,
              isotimestamp (header->mtime), header->name);
}



/* List the tarball FILENAME or, if FILENAME is NULL, the tarball read
   from stdin.  */
gpg_error_t
gpgtar_list (const char *filename, int decrypt)
{
  gpg_error_t err;
  estream_t stream;
  estream_t cipher_stream = NULL;
  tar_header_t header = NULL;

  if (filename)
    {
      if (!strcmp (filename, "-"))
        stream = es_stdin;
      else
        stream = es_fopen (filename, "rb");
      if (!stream)
        {
          err = gpg_error_from_syserror ();
          log_error ("error opening '%s': %s\n", filename, gpg_strerror (err));
          return err;
        }
    }
  else
    stream = es_stdin;

  if (stream == es_stdin)
    es_set_binary (es_stdin);

  if (decrypt)
    {
      strlist_t arg;
      ccparray_t ccp;
      const char **argv;

      cipher_stream = stream;
      stream = es_fopenmem (0, "rwb");
      if (! stream)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }

      ccparray_init (&ccp, 0);

      ccparray_put (&ccp, "--decrypt");
      for (arg = opt.gpg_arguments; arg; arg = arg->next)
        ccparray_put (&ccp, arg->d);

      ccparray_put (&ccp, NULL);
      argv = ccparray_get (&ccp, NULL);
      if (!argv)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }

      err = gnupg_exec_tool_stream (opt.gpg_program, argv,
                                    cipher_stream, NULL, stream, NULL, NULL);
      xfree (argv);
      if (err)
        goto leave;

      err = es_fseek (stream, 0, SEEK_SET);
      if (err)
        goto leave;
    }

  for (;;)
    {
      err = read_header (stream, &header);
      if (err || header == NULL)
        goto leave;

      print_header (header, es_stdout);

      if (skip_data (stream, header))
        goto leave;
      xfree (header);
      header = NULL;
    }


 leave:
  xfree (header);
  if (stream != es_stdin)
    es_fclose (stream);
  if (stream != cipher_stream)
    es_fclose (cipher_stream);
  return err;
}

gpg_error_t
gpgtar_read_header (estream_t stream, tar_header_t *r_header)
{
  return read_header (stream, r_header);
}

void
gpgtar_print_header (tar_header_t header, estream_t out)
{
  if (header && out)
    print_header (header, out);
}
