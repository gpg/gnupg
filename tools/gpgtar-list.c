/* gpgtar-list.c - List a TAR archive
 * Copyright (C) 2016-2017, 2019-2022 g10 Code GmbH
 * Copyright (C) 2010, 2012, 2013 Werner Koch
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
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../common/i18n.h"
#include <gpg-error.h>
#include "gpgtar.h"
#include "../common/exechelp.h"
#include "../common/sysutils.h"
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
parse_header (const void *record, const char *filename, tarinfo_t info)
{
  const struct ustar_raw_header *raw = record;
  size_t n, namelen, prefixlen;
  tar_header_t header;
  int use_prefix;
  int anyerror = 0;

  info->headerblock = info->nblocks - 1;

  use_prefix = (!memcmp (raw->magic, "ustar", 5)
                && (raw->magic[5] == ' ' || !raw->magic[5]));


  for (namelen=0; namelen < sizeof raw->name && raw->name[namelen]; namelen++)
    ;
  if (namelen == sizeof raw->name)
    {
      log_info ("%s: warning: name not terminated by a nul\n", filename);
      anyerror = 1;
    }
  for (n=namelen+1; n < sizeof raw->name; n++)
    if (raw->name[n])
      {
        log_info ("%s: warning: garbage after name\n", filename);
        anyerror = 1;
        break;
      }

  if (use_prefix && raw->prefix[0])
    {
      for (prefixlen=0; (prefixlen < sizeof raw->prefix
                         && raw->prefix[prefixlen]); prefixlen++)
        ;
      if (prefixlen == sizeof raw->prefix)
        log_info ("%s: warning: prefix not terminated by a nul (block %llu)\n",
                  filename, info->headerblock);
      for (n=prefixlen+1; n < sizeof raw->prefix; n++)
        if (raw->prefix[n])
          {
            log_info ("%s: warning: garbage after prefix\n", filename);
            anyerror = 1;
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
    case 'g': header->typeflag = TF_GEXTHDR; break;
    case 'x': header->typeflag = TF_EXTHDR; break;
    default:  header->typeflag = TF_UNKNOWN; break;
    }

  /* Compute the number of data records following this header.  */
  if (header->typeflag == TF_REGULAR
      || header->typeflag == TF_EXTHDR
      || header->typeflag == TF_UNKNOWN)
    header->nrecords = (header->size + RECORDSIZE-1)/RECORDSIZE;
  else
    header->nrecords = 0;

  if (anyerror)
    {
      log_info ("%s: header block %llu is corrupt"
                " (size=%llu type=%d nrec=%llu)\n",
                filename, info->headerblock,
                header->size, header->typeflag, header->nrecords);
      /* log_printhex (record, RECORDSIZE, " "); */
    }

  return header;
}

/* Parse the extended header.  This funcion may modify BUFFER.  */
static gpg_error_t
parse_extended_header (const char *fname,
                       char *buffer, size_t buflen, strlist_t *r_exthdr)
{
  unsigned int reclen;
  unsigned char *p, *record;
  strlist_t sl;

  while (buflen)
    {
      record = buffer; /* Remember begin of record.  */
      reclen = 0;
      for (p = buffer; buflen && digitp (p); buflen--, p++)
        {
          reclen *= 10;
          reclen += (*p - '0');
        }
      if (!buflen || *p != ' ')
        {
          log_error ("%s: malformed record length in extended header\n", fname);
          return gpg_error (GPG_ERR_INV_RECORD);
        }
      p++;  /* Skip space.  */
      buflen--;
      if (buflen + (p-record) < reclen)
        {
          log_error ("%s: extended header record larger"
                     " than total extended header data\n", fname);
          return gpg_error (GPG_ERR_INV_RECORD);
        }
      if (reclen < (p-record)+2 || record[reclen-1] != '\n')
        {
          log_error ("%s: malformed extended header record\n", fname);
          return gpg_error (GPG_ERR_INV_RECORD);
        }
      record[reclen-1] = 0; /* For convenience change LF to a Nul. */
      reclen -= (p-record);
      /* P points to the begin of the keyword and RECLEN is the
       * remaining length of the record excluding the LF.  */
      if (memchr (p, 0, reclen-1)
          && (!strncmp (p, "path=", 5) || !strncmp (p, "linkpath=", 9)))
        {
          log_error ("%s: extended header record has an embedded nul"
                     " - ignoring\n", fname);
        }
      else if (!strncmp (p, "path=", 5))
        {
          sl = add_to_strlist_try (r_exthdr, p+5);
          if (!sl)
            return gpg_error_from_syserror ();
          sl->flags = 1;  /* Mark as path */
        }
      else if (!strncmp (p, "linkpath=", 9))
        {
          sl = add_to_strlist_try (r_exthdr, p+9);
          if (!sl)
            return gpg_error_from_syserror ();
          sl->flags = 2;  /* Mark as linkpath */
        }

      buffer = p + reclen;
      buflen -= reclen;
    }

  return 0;
}


/* Read the next block, assuming it is a tar header.  Returns a header
 * object on success in R_HEADER, or an error.  If the stream is
 * consumed (i.e. end-of-archive), R_HEADER is set to NULL.  In case
 * of an error an error message is printed.  If the header is an
 * extended header, a string list is allocated and stored at
 * R_EXTHEADER; the caller should provide a pointer to NULL.  Such an
 * extended header is fully processed here and the returned R_HEADER
 * has then the next regular header.  */
static gpg_error_t
read_header (estream_t stream, tarinfo_t info,
             tar_header_t *r_header, strlist_t *r_extheader)
{
  gpg_error_t err;
  char record[RECORDSIZE];
  int i;
  tar_header_t hdr;
  char *buffer;
  size_t buflen, nrec;

  err = read_record (stream, record);
  if (err)
    return err;
  info->nblocks++;

  for (i=0; i < RECORDSIZE && !record[i]; i++)
    ;
  if (i == RECORDSIZE)
    {
      /* All zero header - check whether it is the first part of an
         end of archive mark.  */
      err = read_record (stream, record);
      if (err)
        return err;
      info->nblocks++;

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

  *r_header = parse_header (record, es_fname_get (stream), info);
  if (!*r_header)
    return gpg_error_from_syserror ();
  hdr = *r_header;

  if (hdr->typeflag != TF_EXTHDR || !r_extheader)
    return 0;

  /* Read the extended header.  */
  if (!hdr->nrecords)
    {
      /* More than 64k for an extedned header is surely too large.  */
      log_info ("%s: warning: empty extended header\n",
                 es_fname_get (stream));
      return 0;
    }
  if (hdr->nrecords > 65536 / RECORDSIZE)
    {
      /* More than 64k for an extedned header is surely too large.  */
      log_error ("%s: extended header too large - skipping\n",
                 es_fname_get (stream));
      return 0;
    }

  buffer = xtrymalloc (hdr->nrecords * RECORDSIZE);
  if (!buffer)
    {
      err = gpg_error_from_syserror ();
      log_error ("%s: error allocating space for extended header: %s\n",
                 es_fname_get (stream), gpg_strerror (err));
      return err;
    }
  buflen = 0;

  for (nrec=0; nrec < hdr->nrecords;)
    {
      err = read_record (stream, buffer + buflen);
      if (err)
        {
          xfree (buffer);
          return err;
        }
      info->nblocks++;
      nrec++;
      if (nrec < hdr->nrecords || (hdr->size && !(hdr->size % RECORDSIZE)))
        buflen += RECORDSIZE;
      else
        buflen += (hdr->size % RECORDSIZE);
    }

  err = parse_extended_header (es_fname_get (stream),
                               buffer, buflen, r_extheader);
  if (err)
    {
      free_strlist (*r_extheader);
      *r_extheader = NULL;
    }

  xfree (buffer);
  /* Now tha the extedned header has been read, we read the next
   * header without allowing an extended header.  */
  return read_header (stream, info, r_header, NULL);
}


/* Skip the data records according to HEADER.  Prints an error message
   on error and return -1. */
static int
skip_data (estream_t stream, tarinfo_t info, tar_header_t header)
{
  char record[RECORDSIZE];
  unsigned long long n;

  for (n=0; n < header->nrecords; n++)
    {
      if (read_record (stream, record))
        return -1;
      info->nblocks++;
    }

  return 0;
}



static void
print_header (tar_header_t header, strlist_t extheader, estream_t out)
{
  unsigned long mask;
  char modestr[10+1];
  int i;
  strlist_t sl;
  const char *name, *linkname;

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
    case TF_EXTHDR:   break;
    case TF_GEXTHDR:  break;
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

  /* FIXME: We do not parse the linkname unless its part of an
   * extended header.  */
  name = header->name;
  linkname = header->typeflag == TF_SYMLINK? "?" : NULL;

  for (sl = extheader; sl; sl = sl->next)
    {
      if (sl->flags == 1)
        name = sl->d;
      else if (sl->flags == 2)
        linkname = sl->d;
    }

  es_fprintf (out, "%s %lu %lu/%lu %12llu %s %s%s%s\n",
              modestr, header->nlink, header->uid, header->gid, header->size,
              isotimestamp (header->mtime),
              name,
              linkname? " -> " : "",
              linkname? linkname : "");
}



/* List the tarball FILENAME or, if FILENAME is NULL, the tarball read
   from stdin.  */
gpg_error_t
gpgtar_list (const char *filename, int decrypt)
{
  gpg_error_t err;
  estream_t stream = NULL;
  tar_header_t header = NULL;
  strlist_t extheader = NULL;
  struct tarinfo_s tarinfo_buffer;
  tarinfo_t tarinfo = &tarinfo_buffer;
  pid_t pid = (pid_t)(-1);

  memset (&tarinfo_buffer, 0, sizeof tarinfo_buffer);

  if (decrypt)
    {
      strlist_t arg;
      ccparray_t ccp;
      int except[2] = { -1, -1 };
      const char **argv;

      ccparray_init (&ccp, 0);
      if (opt.batch)
        ccparray_put (&ccp, "--batch");
      if (opt.require_compliance)
        ccparray_put (&ccp, "--require-compliance");
      if (opt.status_fd != -1)
        {
          static char tmpbuf[40];

          snprintf (tmpbuf, sizeof tmpbuf, "--status-fd=%d", opt.status_fd);
          ccparray_put (&ccp, tmpbuf);
          except[0] = opt.status_fd;
        }
      ccparray_put (&ccp, "--output");
      ccparray_put (&ccp, "-");
      ccparray_put (&ccp, "--decrypt");
      for (arg = opt.gpg_arguments; arg; arg = arg->next)
        ccparray_put (&ccp, arg->d);
      if (filename)
        {
          ccparray_put (&ccp, "--");
          ccparray_put (&ccp, filename);
        }

      ccparray_put (&ccp, NULL);
      argv = ccparray_get (&ccp, NULL);
      if (!argv)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }

      err = gnupg_spawn_process (opt.gpg_program, argv,
                                 except[0] == -1? NULL : except,
                                 NULL,
                                 ((filename? 0 : GNUPG_SPAWN_KEEP_STDIN)
                                  | GNUPG_SPAWN_KEEP_STDERR),
                                 NULL, &stream, NULL, &pid);
      xfree (argv);
      if (err)
        goto leave;
      es_set_binary (stream);
    }
  else if (filename)  /* No decryption requested.  */
    {
      if (!strcmp (filename, "-"))
        stream = es_stdin;
      else
        stream = es_fopen (filename, "rb,sysopen");
      if (!stream)
        {
          err = gpg_error_from_syserror ();
          log_error ("error opening '%s': %s\n", filename, gpg_strerror (err));
          goto leave;
        }
      if (stream == es_stdin)
        es_set_binary (es_stdin);
    }
  else
    {
      stream = es_stdin;
      es_set_binary (es_stdin);
    }

  for (;;)
    {
      err = read_header (stream, tarinfo, &header, &extheader);
      if (err || header == NULL)
        goto leave;

      print_header (header, extheader, es_stdout);

      if (skip_data (stream, tarinfo, header))
        goto leave;
      free_strlist (extheader);
      extheader = NULL;
      xfree (header);
      header = NULL;
    }

  if (pid != (pid_t)(-1))
    {
      int exitcode;

      err = es_fclose (stream);
      stream = NULL;
      if (err)
        log_error ("error closing pipe: %s\n", gpg_strerror (err));
      else
        {
          err = gnupg_wait_process (opt.gpg_program, pid, 1, &exitcode);
          if (err)
            log_error ("running %s failed (exitcode=%d): %s",
                       opt.gpg_program, exitcode, gpg_strerror (err));
          gnupg_release_process (pid);
          pid = (pid_t)(-1);
        }
    }

 leave:
  free_strlist (extheader);
  xfree (header);
  if (stream != es_stdin)
    es_fclose (stream);
  return err;
}


gpg_error_t
gpgtar_read_header (estream_t stream, tarinfo_t info,
                    tar_header_t *r_header, strlist_t *r_extheader)
{
  return read_header (stream, info, r_header, r_extheader);
}

void
gpgtar_print_header (tar_header_t header, strlist_t extheader, estream_t out)
{
  if (header && out)
    print_header (header, extheader, out);
}
