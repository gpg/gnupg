/* gpgtar-create.c - Create a TAR archive
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
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#ifdef HAVE_W32_SYSTEM
# define WIN32_LEAN_AND_MEAN
# include <windows.h>
#else /*!HAVE_W32_SYSTEM*/
# include <unistd.h>
# include <pwd.h>
# include <grp.h>
#endif /*!HAVE_W32_SYSTEM*/
#include <assert.h>

#include "../common/i18n.h"
#include "../common/exectool.h"
#include "../common/sysutils.h"
#include "../common/ccparray.h"
#include "gpgtar.h"

#ifndef HAVE_LSTAT
#define lstat(a,b) gnupg_stat ((a), (b))
#endif


/* Object to control the file scanning.  */
struct scanctrl_s;
typedef struct scanctrl_s *scanctrl_t;
struct scanctrl_s
{
  tar_header_t flist;
  tar_header_t *flist_tail;
  int nestlevel;
};



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
  wfname = utf8_to_wchar (hdr->name);
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
    hdr->size = (fad.nFileSizeHigh * (unsigned long long)(MAXDWORD+1)
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
      if (opt.verbose)
        gpgtar_print_header (hdr, log_get_stream ());
      *scanctrl->flist_tail = hdr;
      scanctrl->flist_tail = &hdr->next;
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
    wfname = utf8_to_wchar (fname);
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

  assert (scanctrl->flist_tail);
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

  assert (length > 1);

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


static gpg_error_t
build_header (void *record, tar_header_t hdr)
{
  gpg_error_t err;
  struct ustar_raw_header *raw = record;
  size_t namelen, n;
  unsigned long chksum;
  unsigned char *p;

  memset (record, 0, RECORDSIZE);

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
          err = gpg_error (GPG_ERR_TOO_LARGE);
          log_error ("error storing file '%s': %s\n",
                     hdr->name, gpg_strerror (err));
          return err;
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

      nread = readlink (hdr->name, raw->linkname, sizeof raw->linkname -1);
      if (nread < 0)
        {
          err = gpg_error_from_syserror ();
          log_error ("error reading symlink '%s': %s\n",
                     hdr->name, gpg_strerror (err));
          return err;
        }
      raw->linkname[nread] = 0;
    }
#endif /*HAVE_W32_SYSTEM*/

  /* Compute the checksum.  */
  memset (raw->checksum, ' ', sizeof raw->checksum);
  chksum = 0;
  p = record;
  for (n=0; n < RECORDSIZE; n++)
    chksum += *p++;
  store_xoctal (raw->checksum, sizeof raw->checksum - 1, chksum);
  raw->checksum[7] = ' ';

  return 0;
}


static gpg_error_t
write_file (estream_t stream, tar_header_t hdr)
{
  gpg_error_t err;
  char record[RECORDSIZE];
  estream_t infp;
  size_t nread, nbytes;
  int any;

  err = build_header (record, hdr);
  if (err)
    {
      if (gpg_err_code (err) == GPG_ERR_NOT_SUPPORTED)
        {
          log_info ("skipping unsupported file '%s'\n", hdr->name);
          err = 0;
        }
      return err;
    }

  if (hdr->typeflag == TF_REGULAR)
    {
      infp = es_fopen (hdr->name, "rb");
      if (!infp)
        {
          err = gpg_error_from_syserror ();
          log_error ("can't open '%s': %s - skipped\n",
                     hdr->name, gpg_strerror (err));
          return err;
        }
    }
  else
    infp = NULL;

  err = write_record (stream, record);
  if (err)
    goto leave;

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
          any = 1;
          err = write_record (stream, record);
          if (err)
            goto leave;
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
  estream_t cipher_stream = NULL;
  int eof_seen = 0;

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

  if (opt.outfile)
    {
      if (!strcmp (opt.outfile, "-"))
        outstream = es_stdout;
      else
        outstream = es_fopen (opt.outfile, "wb");
      if (!outstream)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }
  else
    {
      outstream = es_stdout;
    }

  if (outstream == es_stdout)
    es_set_binary (es_stdout);

  if (encrypt || sign)
    {
      cipher_stream = outstream;
      outstream = es_fopenmem (0, "rwb");
      if (! outstream)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }

  for (hdr = scanctrl->flist; hdr; hdr = hdr->next)
    {
      err = write_file (outstream, hdr);
      if (err)
        goto leave;
    }
  err = write_eof_mark (outstream);
  if (err)
    goto leave;

  if (encrypt || sign)
    {
      strlist_t arg;
      ccparray_t ccp;
      const char **argv;

      err = es_fseek (outstream, 0, SEEK_SET);
      if (err)
        goto leave;

      /* '--encrypt' may be combined with '--symmetric', but 'encrypt'
         is set either way.  Clear it if no recipients are specified.
         XXX: Fix command handling.  */
      if (opt.symmetric && opt.recipients == NULL)
        encrypt = 0;

      ccparray_init (&ccp, 0);
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
                                    outstream, NULL, cipher_stream, NULL, NULL);
      xfree (argv);
      if (err)
        goto leave;
    }

 leave:
  if (!err)
    {
      gpg_error_t first_err;
      if (outstream != es_stdout)
        first_err = es_fclose (outstream);
      else
        first_err = es_fflush (outstream);
      outstream = NULL;
      if (cipher_stream != es_stdout)
        err = es_fclose (cipher_stream);
      else
        err = es_fflush (cipher_stream);
      cipher_stream = NULL;
      if (! err)
        err = first_err;
    }
  if (err)
    {
      log_error ("creating tarball '%s' failed: %s\n",
                 opt.outfile ? opt.outfile : "-", gpg_strerror (err));
      if (outstream && outstream != es_stdout)
        es_fclose (outstream);
      if (cipher_stream && cipher_stream != es_stdout)
        es_fclose (cipher_stream);
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
