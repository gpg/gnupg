/* gpgtar-create.c - Create a TAR archive
 * Copyright (C) 2016-2017, 2019-2023 g10 Code GmbH
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
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#ifdef HAVE_W32_SYSTEM
# define WIN32_LEAN_AND_MEAN
# include <windows.h>
#else /*!HAVE_W32_SYSTEM*/
# include <pwd.h>
# include <grp.h>
#endif /*!HAVE_W32_SYSTEM*/

#include "../common/i18n.h"
#include <gpg-error.h>
#include "../common/exechelp.h"
#include "../common/sysutils.h"
#include "../common/ccparray.h"
#include "../common/membuf.h"
#include "gpgtar.h"

#ifndef HAVE_LSTAT
#define lstat(a,b) gnupg_stat ((a), (b))
#endif

/* Number of files to be write.  */
static unsigned long global_total_files;

/* Count the number of written file and thus headers.  Extended
 * headers are not counted. */
static unsigned long global_written_files;

/* Total data expected to be written.  */
static unsigned long long global_total_data;

/* Number of data bytes written so far.  */
static unsigned long long global_written_data;



/* Object to control the file scanning.  */
struct scanctrl_s;
typedef struct scanctrl_s *scanctrl_t;
struct scanctrl_s
{
  tar_header_t flist;
  tar_header_t *flist_tail;
  unsigned long file_count;
  int nestlevel;
};


/* See ../g10/progress.c:write_status_progress for some background.  */
static void
write_progress (int countmode, unsigned long long current,
                unsigned long long total_arg)
{
  char units[] = "BKMGTPEZY?";
  int unitidx = 0;
  uint64_t total = total_arg;

  if (!opt.status_stream)
    return;  /* Not enabled.  */

  if (countmode)
    {
      if (total && current > total)
        current = total;
    }
  else if (total)  /* Size mode: This may use units.  */
    {
      if (current > total)
        current = total;

      while (total > 1024*1024)
        {
          total /= 1024;
          current /= 1024;
          unitidx++;
        }
    }
  else /* Size mode */
    {
      while (current > 1024*1024)
        {
          current /= 1024;
          unitidx++;
        }
    }

  if (unitidx > sizeof units - 1)
    unitidx = sizeof units - 1;

  if (countmode)
    es_fprintf (opt.status_stream, "[GNUPG:] PROGRESS gpgtar c %zu %zu\n",
                (size_t)current, (size_t)total);
  else
    es_fprintf (opt.status_stream, "[GNUPG:] PROGRESS gpgtar s %zu %zu %c%s\n",
                (size_t)current, (size_t)total,
                units[unitidx],
                unitidx? "iB" : "");
}


/* On Windows convert name to UTF8 and return it; caller must release
 * the result.  On Unix or if ALREADY_UTF8 is set, this function is a
 * mere xtrystrcopy.  On failure NULL is returned and ERRNO set. */
static char *
name_to_utf8 (const char *name, int already_utf8)
{
#ifdef HAVE_W32_SYSTEM
  wchar_t *wstring;
  char *result;

  if (already_utf8)
    result = xtrystrdup (name);
  else
    {
      wstring = native_to_wchar (name);
      if (!wstring)
        return NULL;
      result = wchar_to_utf8 (wstring);
      xfree (wstring);
    }
  return result;

#else /*!HAVE_W32_SYSTEM */

  (void)already_utf8;
  return xtrystrdup (name);

#endif /*!HAVE_W32_SYSTEM */
}




/* Given a fresh header object HDR with only the name field set, try
   to gather all available info.  This is the W32 version.  */
#ifdef HAVE_W32_SYSTEM
static gpg_error_t
fillup_entry_w32 (tar_header_t hdr)
{
  char *p;
  wchar_t *wfname;
  WIN32_FILE_ATTRIBUTE_DATA fad;
  DWORD attr;

  for (p=hdr->name; *p; p++)
    if (*p == '/')
      *p = '\\';
  wfname = gpgrt_fname_to_wchar (hdr->name);
  for (p=hdr->name; *p; p++)
    if (*p == '\\')
      *p = '/';
  if (!wfname)
    {
      log_error ("error converting '%s': %s\n", hdr->name, w32_strerror (-1));
      return gpg_error_from_syserror ();
    }
  if (!GetFileAttributesExW (wfname, GetFileExInfoStandard, &fad))
    {
      log_error ("error stat-ing '%s': %s\n", hdr->name, w32_strerror (-1));
      xfree (wfname);
      return gpg_error_from_syserror ();
    }
  xfree (wfname);

  attr = fad.dwFileAttributes;

  if ((attr & FILE_ATTRIBUTE_NORMAL))
    hdr->typeflag = TF_REGULAR;
  else if ((attr & FILE_ATTRIBUTE_DIRECTORY))
    hdr->typeflag = TF_DIRECTORY;
  else if ((attr & FILE_ATTRIBUTE_DEVICE))
    hdr->typeflag = TF_NOTSUP;
  else if ((attr & (FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_TEMPORARY)))
    hdr->typeflag = TF_NOTSUP;
  else
    hdr->typeflag = TF_REGULAR;

  /* Map some attributes to  USTAR defined mode bits.  */
  hdr->mode = 0640;      /* User may read and write, group only read.  */
  if ((attr & FILE_ATTRIBUTE_DIRECTORY))
    hdr->mode |= 0110;   /* Dirs are user and group executable.  */
  if ((attr & FILE_ATTRIBUTE_READONLY))
    hdr->mode &= ~0200;  /* Clear the user write bit.  */
  if ((attr & FILE_ATTRIBUTE_HIDDEN))
    hdr->mode &= ~0707;  /* Clear all user and other bits.  */
  if ((attr & FILE_ATTRIBUTE_SYSTEM))
    hdr->mode |= 0004;   /* Make it readable by other.  */

  /* Only set the size for a regular file.  */
  if (hdr->typeflag == TF_REGULAR)
    hdr->size = (fad.nFileSizeHigh * ((unsigned long long)MAXDWORD+1)
                 + fad.nFileSizeLow);

  hdr->mtime = (((unsigned long long)fad.ftLastWriteTime.dwHighDateTime << 32)
                | fad.ftLastWriteTime.dwLowDateTime);
  if (!hdr->mtime)
    hdr->mtime = (((unsigned long long)fad.ftCreationTime.dwHighDateTime << 32)
                  | fad.ftCreationTime.dwLowDateTime);
  hdr->mtime -= 116444736000000000ULL; /* The filetime epoch is 1601-01-01.  */
  hdr->mtime /= 10000000;  /* Convert from 0.1us to seconds. */

  return 0;
}
#endif /*HAVE_W32_SYSTEM*/


/* Given a fresh header object HDR with only the name field set, try
   to gather all available info.  This is the POSIX version.  */
#ifndef HAVE_W32_SYSTEM
static gpg_error_t
fillup_entry_posix (tar_header_t hdr)
{
  gpg_error_t err;
  struct stat sbuf;

  if (lstat (hdr->name, &sbuf))
    {
      err = gpg_error_from_syserror ();
      log_error ("error stat-ing '%s': %s\n", hdr->name, gpg_strerror (err));
      return err;
    }

  if (S_ISREG (sbuf.st_mode))
    hdr->typeflag = TF_REGULAR;
  else if (S_ISDIR (sbuf.st_mode))
    hdr->typeflag = TF_DIRECTORY;
  else if (S_ISCHR (sbuf.st_mode))
    hdr->typeflag = TF_CHARDEV;
  else if (S_ISBLK (sbuf.st_mode))
    hdr->typeflag = TF_BLOCKDEV;
  else if (S_ISFIFO (sbuf.st_mode))
    hdr->typeflag = TF_FIFO;
  else if (S_ISLNK (sbuf.st_mode))
    hdr->typeflag = TF_SYMLINK;
  else
    hdr->typeflag = TF_NOTSUP;

  /* FIXME: Save DEV and INO? */

  /* Set the USTAR defined mode bits using the system macros.  */
  if (sbuf.st_mode & S_IRUSR)
    hdr->mode |= 0400;
  if (sbuf.st_mode & S_IWUSR)
    hdr->mode |= 0200;
  if (sbuf.st_mode & S_IXUSR)
    hdr->mode |= 0100;
  if (sbuf.st_mode & S_IRGRP)
    hdr->mode |= 0040;
  if (sbuf.st_mode & S_IWGRP)
    hdr->mode |= 0020;
  if (sbuf.st_mode & S_IXGRP)
    hdr->mode |= 0010;
  if (sbuf.st_mode & S_IROTH)
    hdr->mode |= 0004;
  if (sbuf.st_mode & S_IWOTH)
    hdr->mode |= 0002;
  if (sbuf.st_mode & S_IXOTH)
    hdr->mode |= 0001;
#ifdef S_IXUID
  if (sbuf.st_mode & S_IXUID)
    hdr->mode |= 04000;
#endif
#ifdef S_IXGID
  if (sbuf.st_mode & S_IXGID)
    hdr->mode |= 02000;
#endif
#ifdef S_ISVTX
  if (sbuf.st_mode & S_ISVTX)
    hdr->mode |= 01000;
#endif

  hdr->nlink = sbuf.st_nlink;

  hdr->uid = sbuf.st_uid;
  hdr->gid = sbuf.st_gid;

  /* Only set the size for a regular file.  */
  if (hdr->typeflag == TF_REGULAR)
    hdr->size = sbuf.st_size;

  hdr->mtime = sbuf.st_mtime;

  return 0;
}
#endif /*!HAVE_W32_SYSTEM*/


/* Add a new entry.  The name of a directory entry is ENTRYNAME; if
   that is NULL, DNAME is the name of the directory itself.  Under
   Windows ENTRYNAME shall have backslashes replaced by standard
   slashes.  */
static gpg_error_t
add_entry (const char *dname, const char *entryname, scanctrl_t scanctrl)
{
  gpg_error_t err;
  tar_header_t hdr;
  char *p;
  size_t dnamelen = strlen (dname);

  log_assert (dnamelen);

  hdr = xtrycalloc (1, sizeof *hdr + dnamelen + 1
                    + (entryname? strlen (entryname) : 0) + 1);
  if (!hdr)
    return gpg_error_from_syserror ();

  p = stpcpy (hdr->name, dname);
  if (entryname)
    {
      if (dname[dnamelen-1] != '/')
        *p++ = '/';
      strcpy (p, entryname);
    }
  else
    {
      if (hdr->name[dnamelen-1] == '/')
        hdr->name[dnamelen-1] = 0;
    }
#ifdef HAVE_DOSISH_SYSTEM
  err = fillup_entry_w32 (hdr);
#else
  err = fillup_entry_posix (hdr);
#endif
  if (err)
    xfree (hdr);
  else
    {
      /* FIXME: We don't have the extended info yet available so we
       * can't print them.  */
      if (opt.verbose)
        gpgtar_print_header (hdr, NULL, log_get_stream ());
      *scanctrl->flist_tail = hdr;
      scanctrl->flist_tail = &hdr->next;
      scanctrl->file_count++;
      /* Print a progress line during scnanning in increments of 5000
       * and not of 100 as we doing during write: Scanning is of
       * course much faster.  */
      if (!(scanctrl->file_count % 5000))
        write_progress (1, scanctrl->file_count, 0);
    }

  return 0;
}


static gpg_error_t
scan_directory (const char *dname, scanctrl_t scanctrl)
{
  gpg_error_t err = 0;

#ifdef HAVE_W32_SYSTEM
  /* Note that we introduced gnupg_opendir only after we had deployed
   * this code and thus we don't change it for now.  */
  WIN32_FIND_DATAW fi;
  HANDLE hd = INVALID_HANDLE_VALUE;
  char *p;

  if (!*dname)
    return 0;  /* An empty directory name has no entries.  */

  {
    char *fname;
    wchar_t *wfname;

    fname = xtrymalloc (strlen (dname) + 2 + 2 + 1);
    if (!fname)
      {
        err = gpg_error_from_syserror ();
        goto leave;
      }
    if (!strcmp (dname, "/"))
      strcpy (fname, "/*"); /* Trailing slash is not allowed.  */
    else if (!strcmp (dname, "."))
      strcpy (fname, "*");
    else if (*dname && dname[strlen (dname)-1] == '/')
      strcpy (stpcpy (fname, dname), "*");
    else if (*dname && dname[strlen (dname)-1] != '*')
      strcpy (stpcpy (fname, dname), "/*");
    else
      strcpy (fname, dname);

    for (p=fname; *p; p++)
      if (*p == '/')
        *p = '\\';
    wfname = gpgrt_fname_to_wchar (fname);
    xfree (fname);
    if (!wfname)
      {
        err = gpg_error_from_syserror ();
        log_error (_("error reading directory '%s': %s\n"),
                   dname, gpg_strerror (err));
        goto leave;
      }
    hd = FindFirstFileW (wfname, &fi);
    if (hd == INVALID_HANDLE_VALUE)
      {
        err = gpg_error_from_syserror ();
        log_error (_("error reading directory '%s': %s\n"),
                   dname, w32_strerror (-1));
        xfree (wfname);
        goto leave;
      }
    xfree (wfname);
  }

  do
    {
      char *fname = wchar_to_utf8 (fi.cFileName);
      if (!fname)
        {
          err = gpg_error_from_syserror ();
          log_error ("error converting filename: %s\n", w32_strerror (-1));
          break;
        }
      for (p=fname; *p; p++)
        if (*p == '\\')
          *p = '/';
      if (!strcmp (fname, "." ) || !strcmp (fname, ".."))
        err = 0; /* Skip self and parent dir entry.  */
      else if (!strncmp (dname, "./", 2) && dname[2])
        err = add_entry (dname+2, fname, scanctrl);
      else
        err = add_entry (dname, fname, scanctrl);
      xfree (fname);
    }
  while (!err && FindNextFileW (hd, &fi));
  if (err)
    ;
  else if (GetLastError () == ERROR_NO_MORE_FILES)
    err = 0;
  else
    {
      err = gpg_error_from_syserror ();
      log_error (_("error reading directory '%s': %s\n"),
                 dname, w32_strerror (-1));
    }

 leave:
  if (hd != INVALID_HANDLE_VALUE)
    FindClose (hd);

#else /*!HAVE_W32_SYSTEM*/
  DIR *dir;
  struct dirent *de;

  if (!*dname)
    return 0;  /* An empty directory name has no entries.  */

  dir = opendir (dname);
  if (!dir)
    {
      err = gpg_error_from_syserror ();
      log_error (_("error reading directory '%s': %s\n"),
                 dname, gpg_strerror (err));
      return err;
    }

  while ((de = readdir (dir)))
    {
      if (!strcmp (de->d_name, "." ) || !strcmp (de->d_name, ".."))
        continue; /* Skip self and parent dir entry.  */

      err = add_entry (dname, de->d_name, scanctrl);
      if (err)
        goto leave;
     }

 leave:
  closedir (dir);
#endif /*!HAVE_W32_SYSTEM*/
  return err;
}


static gpg_error_t
scan_recursive (const char *dname, scanctrl_t scanctrl)
{
  gpg_error_t err = 0;
  tar_header_t hdr, *start_tail, *stop_tail;

  if (scanctrl->nestlevel > 200)
    {
      log_error ("directories too deeply nested\n");
      return gpg_error (GPG_ERR_RESOURCE_LIMIT);
    }
  scanctrl->nestlevel++;

  log_assert (scanctrl->flist_tail);
  start_tail = scanctrl->flist_tail;
  scan_directory (dname, scanctrl);
  stop_tail = scanctrl->flist_tail;
  hdr = *start_tail;
  for (; hdr && hdr != *stop_tail; hdr = hdr->next)
    if (hdr->typeflag == TF_DIRECTORY)
      {
        if (opt.verbose > 1)
          log_info ("scanning directory '%s'\n", hdr->name);
        scan_recursive (hdr->name, scanctrl);
      }

  scanctrl->nestlevel--;
  return err;
}


/* Returns true if PATTERN is acceptable.  */
static int
pattern_valid_p (const char *pattern)
{
  if (!*pattern)
    return 0;
  if (*pattern == '.' && pattern[1] == '.')
    return 0;
  if (*pattern == '/'
#ifdef HAVE_DOSISH_SYSTEM
      || *pattern == '\\'
#endif
      )
    return 0; /* Absolute filenames are not supported.  */
#ifdef HAVE_DRIVE_LETTERS
  if (((*pattern >= 'a' && *pattern <= 'z')
       || (*pattern >= 'A' && *pattern <= 'Z'))
      && pattern[1] == ':')
    return 0; /* Drive letter are not allowed either.  */
#endif /*HAVE_DRIVE_LETTERS*/

  return 1; /* Okay.  */
}



static void
store_xoctal (char *buffer, size_t length, unsigned long long value)
{
  char *p, *pend;
  size_t n;
  unsigned long long v;

  log_assert (length > 1);

  v = value;
  n = length;
  p = pend = buffer + length;
  *--p = 0; /* Nul byte.  */
  n--;
  do
    {
      *--p = '0' + (v % 8);
      v /= 8;
      n--;
    }
  while (v && n);
  if (!v)
    {
      /* Pad.  */
      for ( ; n; n--)
        *--p = '0';
    }
  else /* Does not fit into the field.  Store as binary number.  */
    {
      v = value;
      n = length;
      p = pend = buffer + length;
      do
        {
          *--p = v;
          v /= 256;
          n--;
        }
      while (v && n);
      if (!v)
        {
          /* Pad.  */
          for ( ; n; n--)
            *--p = 0;
          if (*p & 0x80)
            BUG ();
          *p |= 0x80; /* Set binary flag.  */
        }
      else
        BUG ();
    }
}


static void
store_uname (char *buffer, size_t length, unsigned long uid)
{
  static int initialized;
  static unsigned long lastuid;
  static char lastuname[32];

  if (!initialized || uid != lastuid)
    {
#ifdef HAVE_W32_SYSTEM
      mem2str (lastuname, uid? "user":"root", sizeof lastuname);
#else
      struct passwd *pw = getpwuid (uid);

      lastuid = uid;
      initialized = 1;
      if (pw)
        mem2str (lastuname, pw->pw_name, sizeof lastuname);
      else
        {
          log_info ("failed to get name for uid %lu\n", uid);
          *lastuname = 0;
        }
#endif
    }
  mem2str (buffer, lastuname, length);
}


static void
store_gname (char *buffer, size_t length, unsigned long gid)
{
  static int initialized;
  static unsigned long lastgid;
  static char lastgname[32];

  if (!initialized || gid != lastgid)
    {
#ifdef HAVE_W32_SYSTEM
      mem2str (lastgname, gid? "users":"root", sizeof lastgname);
#else
      struct group *gr = getgrgid (gid);

      lastgid = gid;
      initialized = 1;
      if (gr)
        mem2str (lastgname, gr->gr_name, sizeof lastgname);
      else
        {
          log_info ("failed to get name for gid %lu\n", gid);
          *lastgname = 0;
        }
#endif
    }
  mem2str (buffer, lastgname, length);
}


static void
compute_checksum (void *record)
{
  struct ustar_raw_header *raw = record;
  unsigned long chksum = 0;
  unsigned char *p;
  size_t n;

  memset (raw->checksum, ' ', sizeof raw->checksum);
  p = record;
  for (n=0; n < RECORDSIZE; n++)
    chksum += *p++;
  store_xoctal (raw->checksum, sizeof raw->checksum - 1, chksum);
  raw->checksum[7] = ' ';
}



/* Read a symlink without truncating it.  Caller must release the
 * returned buffer.  Returns NULL on error.  */
#ifndef HAVE_W32_SYSTEM
static char *
myreadlink (const char *name)
{
  char *buffer;
  size_t size;
  int nread;

  for (size = 1024; size <= 65536; size *= 2)
    {
      buffer = xtrymalloc (size);
      if (!buffer)
        return NULL;

      nread = readlink (name, buffer, size - 1);
      if (nread < 0)
        {
          xfree (buffer);
          return NULL;
        }
      if (nread < size - 1)
        {
          buffer[nread] = 0;
          return buffer;  /* Got it. */
        }

      xfree (buffer);
    }
  gpg_err_set_errno (ERANGE);
  return NULL;
}
#endif /*Unix*/



/* Build a header.  If the filename or the link name ist too long
 * allocate an exthdr and use a replacement file name in RECORD.
 * Caller should always release R_EXTHDR; this function initializes it
 * to point to NULL.  */
static gpg_error_t
build_header (void *record, tar_header_t hdr, strlist_t *r_exthdr)
{
  gpg_error_t err;
  struct ustar_raw_header *raw = record;
  size_t namelen, n;
  strlist_t sl;

  memset (record, 0, RECORDSIZE);
  *r_exthdr = NULL;

  /* Store name and prefix.  */
  namelen = strlen (hdr->name);
  if (namelen < sizeof raw->name)
    memcpy (raw->name, hdr->name, namelen);
  else
    {
      n = (namelen < sizeof raw->prefix)? namelen : sizeof raw->prefix;
      for (n--; n ; n--)
        if (hdr->name[n] == '/')
          break;
      if (namelen - n < sizeof raw->name)
        {
          /* Note that the N is < sizeof prefix and that the
             delimiting slash is not stored.  */
          memcpy (raw->prefix, hdr->name, n);
          memcpy (raw->name, hdr->name+n+1, namelen - n);
        }
      else
        {
          /* Too long - prepare extended header.  */
          sl = add_to_strlist_try (r_exthdr, hdr->name);
          if (!sl)
            {
              err = gpg_error_from_syserror ();
              log_error ("error storing file '%s': %s\n",
                         hdr->name, gpg_strerror (err));
              return err;
            }
          sl->flags = 1;  /* Mark as path */
          /* The name we use is not POSIX compliant but because we
           * expect that (for security issues) a tarball will anyway
           * be extracted to a unique new directory, a simple counter
           * will do.  To ease testing we also put in the PID.  The
           * count is bumped after the header has been written.  */
          snprintf (raw->name, sizeof raw->name-1, "_@paxheader.%u.%lu",
                    (unsigned int)getpid(), global_written_files + 1);
        }
    }

  store_xoctal (raw->mode,  sizeof raw->mode,  hdr->mode);
  store_xoctal (raw->uid,   sizeof raw->uid,   hdr->uid);
  store_xoctal (raw->gid,   sizeof raw->gid,   hdr->gid);
  store_xoctal (raw->size,  sizeof raw->size,  hdr->size);
  store_xoctal (raw->mtime, sizeof raw->mtime, hdr->mtime);

  switch (hdr->typeflag)
    {
    case TF_REGULAR:   raw->typeflag[0] = '0'; break;
    case TF_HARDLINK:  raw->typeflag[0] = '1'; break;
    case TF_SYMLINK:   raw->typeflag[0] = '2'; break;
    case TF_CHARDEV:   raw->typeflag[0] = '3'; break;
    case TF_BLOCKDEV:  raw->typeflag[0] = '4'; break;
    case TF_DIRECTORY: raw->typeflag[0] = '5'; break;
    case TF_FIFO:      raw->typeflag[0] = '6'; break;
    default: return gpg_error (GPG_ERR_NOT_SUPPORTED);
    }

  memcpy (raw->magic, "ustar", 6);
  raw->version[0] = '0';
  raw->version[1] = '0';

  store_uname (raw->uname, sizeof raw->uname, hdr->uid);
  store_gname (raw->gname, sizeof raw->gname, hdr->gid);

#ifndef HAVE_W32_SYSTEM
  if (hdr->typeflag == TF_SYMLINK)
    {
      int nread;
      char *p;

      nread = readlink (hdr->name, raw->linkname, sizeof raw->linkname -1);
      if (nread < 0)
        {
          err = gpg_error_from_syserror ();
          log_error ("error reading symlink '%s': %s\n",
                     hdr->name, gpg_strerror (err));
          return err;
        }
      raw->linkname[nread] = 0;
      if (nread == sizeof raw->linkname -1)
        {
          /* Truncated - read again and store as extended header.  */
          p = myreadlink (hdr->name);
          if (!p)
            {
              err = gpg_error_from_syserror ();
              log_error ("error reading symlink '%s': %s\n",
                         hdr->name, gpg_strerror (err));
              return err;
            }

          sl = add_to_strlist_try (r_exthdr, p);
          xfree (p);
          if (!sl)
            {
              err = gpg_error_from_syserror ();
              log_error ("error storing syslink '%s': %s\n",
                         hdr->name, gpg_strerror (err));
              return err;
            }
          sl->flags = 2;  /* Mark as linkpath */
        }
    }
#endif /*!HAVE_W32_SYSTEM*/

  compute_checksum (record);

  return 0;
}


/* Add an extended header record (NAME,VALUE) to the buffer MB.  */
static void
add_extended_header_record (membuf_t *mb, const char *name, const char *value)
{
  size_t n, n0, n1;
  char numbuf[35];
  size_t valuelen;

  /* To avoid looping in most cases, we guess the initial value.  */
  valuelen = strlen (value);
  n1 = valuelen > 95? 3 : 2;
  do
    {
      n0 = n1;
      /*       (3 for the space before name, the '=', and the LF.)  */
      n = n0 + strlen (name) + valuelen + 3;
      snprintf (numbuf, sizeof numbuf, "%zu", n);
      n1 = strlen (numbuf);
    }
  while (n0 != n1);
  put_membuf_str (mb, numbuf);
  put_membuf (mb, " ", 1);
  put_membuf_str (mb, name);
  put_membuf (mb, "=", 1);
  put_membuf (mb, value, valuelen);
  put_membuf (mb, "\n", 1);
}



/* Write the extended header specified by EXTHDR to STREAM.   */
static gpg_error_t
write_extended_header (estream_t stream, const void *record, strlist_t exthdr)
{
  gpg_error_t err = 0;
  struct ustar_raw_header raw;
  strlist_t sl;
  membuf_t mb;
  char *buffer, *p;
  size_t buflen;

  init_membuf (&mb, 2*RECORDSIZE);

  for (sl=exthdr; sl; sl = sl->next)
    {
      if (sl->flags == 1)
        add_extended_header_record (&mb, "path", sl->d);
      else if (sl->flags == 2)
        add_extended_header_record (&mb, "linkpath", sl->d);
    }

  buffer = get_membuf (&mb, &buflen);
  if (!buffer)
    {
      err = gpg_error_from_syserror ();
      log_error ("error building extended header: %s\n", gpg_strerror (err));
      goto leave;
    }

  /* We copy the header from the standard header record, so that an
   * extracted extended header (using a non-pax aware software) is
   * written with the same properties as the original file.  The real
   * entry will overwrite it anyway.  Of course we adjust the size and
   * the type.  */
  memcpy (&raw, record, RECORDSIZE);
  store_xoctal (raw.size,  sizeof raw.size,  buflen);
  raw.typeflag[0] = 'x'; /* Mark as extended header.  */
  compute_checksum (&raw);

  err = write_record (stream, &raw);
  if (err)
    goto leave;

  for (p = buffer; buflen >= RECORDSIZE; p += RECORDSIZE, buflen -= RECORDSIZE)
    {
      err = write_record (stream, p);
      if (err)
        goto leave;
    }
  if (buflen)
    {
      /* Reuse RAW for builidng the last record.  */
      memcpy (&raw, p, buflen);
      memset ((char*)&raw+buflen, 0, RECORDSIZE - buflen);
      err = write_record (stream, &raw);
      if (err)
        goto leave;
    }

 leave:
  xfree (buffer);
  return err;
}


static gpg_error_t
write_file (estream_t stream, tar_header_t hdr, unsigned int *skipped_open)
{
  gpg_error_t err;
  char record[RECORDSIZE];
  estream_t infp;
  size_t nread, nbytes;
  strlist_t exthdr = NULL;
  int any;

  err = build_header (record, hdr, &exthdr);
  if (err)
    {
      if (gpg_err_code (err) == GPG_ERR_NOT_SUPPORTED)
        {
          log_info ("silently skipping unsupported file '%s'\n", hdr->name);
          err = 0;
        }
      return err;
    }

  if (hdr->typeflag == TF_REGULAR)
    {
      infp = es_fopen (hdr->name, "rb,sysopen");
      if (!infp)
        {
          err = gpg_error_from_syserror ();
          log_info ("can't open '%s': %s - skipped\n",
                     hdr->name, gpg_strerror (err));
          ++*skipped_open;
          if (!*skipped_open) /* Protect against overflow.  */
            --*skipped_open;
          return 0;
        }
    }
  else
    infp = NULL;

  if (exthdr && (err = write_extended_header (stream, record, exthdr)))
    goto leave;
  err = write_record (stream, record);
  if (err)
    goto leave;
  global_written_files++;
  if (!(global_written_files % 100))
    write_progress (1, global_written_files, global_total_files);

  if (hdr->typeflag == TF_REGULAR)
    {
      hdr->nrecords = (hdr->size + RECORDSIZE-1)/RECORDSIZE;
      any = 0;
      while (hdr->nrecords--)
        {
          nbytes = hdr->nrecords? RECORDSIZE : (hdr->size % RECORDSIZE);
          if (!nbytes)
            nbytes = RECORDSIZE;
          nread = es_fread (record, 1, nbytes, infp);
          if (nread != nbytes)
            {
              err = gpg_error_from_syserror ();
              log_error ("error reading file '%s': %s%s\n",
                         hdr->name, gpg_strerror (err),
                         any? " (file shrunk?)":"");
              goto leave;
            }
          else if (nbytes < RECORDSIZE)
            memset (record + nbytes, 0, RECORDSIZE - nbytes);
          any = 1;
          err = write_record (stream, record);
          if (err)
            goto leave;
          global_written_data += nbytes;
          if (!((global_written_data/nbytes) % (2048*100)))
            write_progress (0, global_written_data, global_total_data);
        }
      nread = es_fread (record, 1, 1, infp);
      if (nread)
        log_info ("note: file '%s' has grown\n", hdr->name);
    }

 leave:
  if (err)
    es_fclose (infp);
  else if ((err = es_fclose (infp)))
    log_error ("error closing file '%s': %s\n", hdr->name, gpg_strerror (err));

  free_strlist (exthdr);
  return err;
}


static gpg_error_t
write_eof_mark (estream_t stream)
{
  gpg_error_t err;
  char record[RECORDSIZE];

  memset (record, 0, sizeof record);
  err = write_record (stream, record);
  if (!err)
    err = write_record (stream, record);
  return err;
}



/* Create a new tarball using the names in the array INPATTERN.  If
   INPATTERN is NULL take the pattern as null terminated strings from
   stdin or from the file specified by FILES_FROM.  If NULL_NAMES is
   set the filenames in such a file are delimited by a binary Nul and
   not by a LF.  */
gpg_error_t
gpgtar_create (char **inpattern, const char *files_from, int null_names,
               int encrypt, int sign)
{
  gpg_error_t err = 0;
  struct scanctrl_s scanctrl_buffer;
  scanctrl_t scanctrl = &scanctrl_buffer;
  tar_header_t hdr, *start_tail;
  estream_t files_from_stream = NULL;
  estream_t outstream = NULL;
  int eof_seen = 0;
  pid_t pid = (pid_t)(-1);
  unsigned int skipped_open = 0;

  memset (scanctrl, 0, sizeof *scanctrl);
  scanctrl->flist_tail = &scanctrl->flist;

  /* { unsigned int cpno, cpno2, cpno3; */

  /*   cpno = GetConsoleOutputCP (); */
  /*   cpno2 = GetACP (); */
  /*   cpno3 = GetOEMCP (); */
  /*   log_debug ("Codepages: Console: %u  ANSI: %u  OEM: %u\n", */
  /*              cpno, cpno2, cpno3); */
  /* } */


  if (!inpattern)
    {
      if (!files_from || !strcmp (files_from, "-"))
        {
          files_from = "-";
          files_from_stream = es_stdin;
          if (null_names)
            es_set_binary (es_stdin);
        }
      else if (!(files_from_stream=es_fopen (files_from, null_names? "rb":"r")))
        {
          err = gpg_error_from_syserror ();
          log_error ("error opening '%s': %s\n",
                     files_from, gpg_strerror (err));
          return err;
        }
    }


  if (opt.directory && gnupg_chdir (opt.directory))
    {
      err = gpg_error_from_syserror ();
      log_error ("chdir to '%s' failed: %s\n",
                 opt.directory, gpg_strerror (err));
      return err;
    }

  while (!eof_seen)
    {
      char *pat, *p;
      int skip_this = 0;

      if (inpattern)
        {
          const char *pattern = *inpattern;

          if (!pattern)
            break; /* End of array.  */
          inpattern++;

          if (!*pattern)
            continue;

          pat = name_to_utf8 (pattern, 0);
        }
      else /* Read Nul or LF delimited pattern from files_from_stream.  */
        {
          int c;
          char namebuf[4096];
          size_t n = 0;

          for (;;)
            {
              if ((c = es_getc (files_from_stream)) == EOF)
                {
                  if (es_ferror (files_from_stream))
                    {
                      err = gpg_error_from_syserror ();
                      log_error ("error reading '%s': %s\n",
                                 files_from, gpg_strerror (err));
                      goto leave;
                    }
                  c = null_names ? 0 : '\n';
                  eof_seen = 1;
                }
              if (n >= sizeof namebuf - 1)
                {
                  if (!skip_this)
                    {
                      skip_this = 1;
                      log_error ("error reading '%s': %s\n",
                                 files_from, "filename too long");
                    }
                }
              else
                namebuf[n++] = c;

              if (null_names)
                {
                  if (!c)
                    {
                      namebuf[n] = 0;
                      break;
                    }
                }
              else /* Shall be LF delimited.  */
                {
                  if (!c)
                    {
                      if (!skip_this)
                        {
                          skip_this = 1;
                          log_error ("error reading '%s': %s\n",
                                     files_from, "filename with embedded Nul");
                        }
                    }
                  else if ( c == '\n' )
                    {
                      namebuf[n] = 0;
                      ascii_trim_spaces (namebuf);
                      n = strlen (namebuf);
                      break;
                    }
                }
            }

          if (skip_this || n < 2)
            continue;

          pat = name_to_utf8 (namebuf, opt.utf8strings);
        }

      if (!pat)
        {
          err = gpg_error_from_syserror ();
          log_error ("memory allocation problem: %s\n", gpg_strerror (err));
          goto leave;
        }
      for (p=pat; *p; p++)
        if (*p == '\\')
          *p = '/';

      if (opt.verbose > 1)
        log_info ("scanning '%s'\n", pat);

      start_tail = scanctrl->flist_tail;
      if (skip_this || !pattern_valid_p (pat))
        log_error ("skipping invalid name '%s'\n", pat);
      else if (!add_entry (pat, NULL, scanctrl)
               && *start_tail && ((*start_tail)->typeflag & TF_DIRECTORY))
        scan_recursive (pat, scanctrl);

      xfree (pat);
    }

  if (files_from_stream && files_from_stream != es_stdin)
    es_fclose (files_from_stream);

  global_total_files = global_total_data = 0;
  global_written_files = global_written_data = 0;
  for (hdr = scanctrl->flist; hdr; hdr = hdr->next)
    {
      global_total_files++;
      global_total_data += hdr->size;
    }
  write_progress (1, 0, global_total_files);
  write_progress (0, 0, global_total_data);


  if (encrypt || sign)
    {
      strlist_t arg;
      ccparray_t ccp;
      int except[2] = { -1, -1 };
      const char **argv;

      /* '--encrypt' may be combined with '--symmetric', but 'encrypt'
       * is set either way.  Clear it if no recipients are specified.
       */
      if (opt.symmetric && opt.recipients == NULL)
        encrypt = 0;

      ccparray_init (&ccp, 0);
      if (opt.batch)
        ccparray_put (&ccp, "--batch");
      if (opt.answer_yes)
        ccparray_put (&ccp, "--yes");
      if (opt.answer_no)
        ccparray_put (&ccp, "--no");
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
      ccparray_put (&ccp, opt.outfile? opt.outfile : "-");
      if (encrypt)
        ccparray_put (&ccp, "--encrypt");
      if (sign)
        ccparray_put (&ccp, "--sign");
      if (opt.user)
        {
          ccparray_put (&ccp, "--local-user");
          ccparray_put (&ccp, opt.user);
        }
      if (opt.symmetric)
        ccparray_put (&ccp, "--symmetric");
      for (arg = opt.recipients; arg; arg = arg->next)
        {
          ccparray_put (&ccp, "--recipient");
          ccparray_put (&ccp, arg->d);
        }
      if (opt.no_compress)
        ccparray_put (&ccp, "-z0");
      for (arg = opt.gpg_arguments; arg; arg = arg->next)
        ccparray_put (&ccp, arg->d);

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
                                 (GNUPG_SPAWN_KEEP_STDOUT
                                  | GNUPG_SPAWN_KEEP_STDERR),
                                 &outstream, NULL, NULL, &pid);
      xfree (argv);
      if (err)
        goto leave;
      es_set_binary (outstream);
    }
  else if (opt.outfile) /* No crypto  */
    {
      if (!strcmp (opt.outfile, "-"))
        outstream = es_stdout;
      else
        outstream = es_fopen (opt.outfile, "wb,sysopen");
      if (!outstream)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      if (outstream == es_stdout)
        es_set_binary (es_stdout);

    }
  else /* Also no crypto.  */
    {
      outstream = es_stdout;
      es_set_binary (outstream);
    }

  skipped_open = 0;
  for (hdr = scanctrl->flist; hdr; hdr = hdr->next)
    {
      err = write_file (outstream, hdr, &skipped_open);
      if (err)
        goto leave;
    }

  err = write_eof_mark (outstream);
  if (err)
    goto leave;

  write_progress (1, global_written_files, global_total_files);
  write_progress (0, global_written_data, global_total_data);

  if (pid != (pid_t)(-1))
    {
      int exitcode;

      err = es_fclose (outstream);
      outstream = NULL;
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

  if (skipped_open)
    {
      log_info ("number of skipped files: %u\n", skipped_open);
      log_error ("exiting with failure status due to previous errors\n");
    }

 leave:
  if (!err)
    {
      gpg_error_t first_err;
      if (outstream != es_stdout || pid != (pid_t)(-1))
        first_err = es_fclose (outstream);
      else
        first_err = es_fflush (outstream);
      outstream = NULL;
      if (! err)
        err = first_err;
    }
  if (err)
    {
      log_error ("creating tarball '%s' failed: %s\n",
                 opt.outfile ? opt.outfile : "-", gpg_strerror (err));
      if (outstream && outstream != es_stdout)
        es_fclose (outstream);
      if (opt.outfile)
        gnupg_remove (opt.outfile);
    }
  scanctrl->flist_tail = NULL;
  while ( (hdr = scanctrl->flist) )
    {
      scanctrl->flist = hdr->next;
      xfree (hdr);
    }
  return err;
}
