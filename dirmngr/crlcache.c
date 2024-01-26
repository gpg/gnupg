/* crlcache.c - LDAP access
 * Copyright (C) 2002 Klarälvdalens Datakonsult AB
 * Copyright (C) 2003, 2004, 2005, 2008 g10 Code GmbH
 *
 * This file is part of DirMngr.
 *
 * DirMngr is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * DirMngr is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/*

   1. To keep track of the CRLs actually cached and to store the meta
      information of the CRLs a simple record oriented text file is
      used.  Fields in the file are colon (':') separated and values
      containing colons or linefeeds are percent escaped (e.g. a colon
      itself is represented as "%3A").

      The first field is a record type identifier, so that the file is
      useful to keep track of other meta data too.

      The name of the file is "DIR.txt".


   1.1. Comment record

        Field 1: Constant beginning with "#".

        Other fields are not defined and such a record is simply
        skipped during processing.

   1.2. Version record

        Field 1: Constant "v"
        Field 2: Version number of this file.  Must be 1.

        This record must be the first non-comment record and
        there shall only exist one record of this type.

   1.3. CRL cache record

        Field 1: Constant "c", "u" or "i".
                 A "c" or "u" indicate a valid cache entry, however
                 "u" requires that a user root certificate check needs
                 to be done.
                 An "i" indicates an invalid cache entry which should
                 not be used but still exists so that it can be
                 updated at NEXT_UPDATE.
        Field 2: Hexadecimal encoded SHA-1 hash of the issuer DN using
                 uppercase letters.
        Field 3: Issuer DN in RFC-2253 notation.
        Field 4: URL used to retrieve the corresponding CRL.
        Field 5: 15 character ISO timestamp with THIS_UPDATE.
        Field 6: 15 character ISO timestamp with NEXT_UPDATE.
        Field 7: Hexadecimal encoded MD-5 hash of the DB file to detect
                 accidental modified (i.e. deleted and created) cache files.
        Field 8: optional CRL number as a hex string.
        Field 9:  AuthorityKeyID.issuer, each Name separated by 0x01
        Field 10: AuthorityKeyID.serial
        Field 11: Hex fingerprint of trust anchor if field 1 is 'u'.

   2. Layout of the standard CRL Cache DB file:

      We use records of variable length with this structure

      n  bytes  Serialnumber (binary) used as key
                thus there is no need to store the length explicitly with DB2.
      1  byte   Reason for revocation
                (currently the KSBA reason flags are used)
      15 bytes  ISO date of revocation (e.g. 19980815T142000)
                Note that there is no terminating 0 stored.

      The filename used is the hexadecimal (using uppercase letters)
      SHA-1 hash value of the issuer DN prefixed with a "crl-" and
      suffixed with a ".db".  Thus the length of the filename is 47.


*/

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#ifndef HAVE_W32_SYSTEM
#include <sys/utsname.h>
#endif

#include "dirmngr.h"
#include "validate.h"
#include "certcache.h"
#include "crlcache.h"
#include "crlfetch.h"
#include "misc.h"
#include "cdb.h"

/* Change this whenever the format changes */
#define DBDIR_D "crls.d"
#define DBDIRFILE "DIR.txt"
#define DBDIRVERSION 1

/* The number of DB files we may have open at one time.  We need to
   limit this because there is no guarantee that the number of issuers
   has a upper limit.  We are currently using mmap, so it is a good
   idea anyway to limit the number of opened cache files. */
#define MAX_OPEN_DB_FILES 5

#ifndef O_BINARY
# define O_BINARY 0
#endif


/* Reason flags for an invalid CRL.  */
#define INVCRL_TOO_OLD       1
#define INVCRL_UNKNOWN_EXTN  2
#define INVCRL_GENERAL       127


static const char oidstr_crlNumber[] = "2.5.29.20";
/* static const char oidstr_issuingDistributionPoint[] = "2.5.29.28"; */
static const char oidstr_authorityKeyIdentifier[] = "2.5.29.35";


/* Definition of one cached item. */
struct crl_cache_entry_s
{
  struct crl_cache_entry_s *next;
  int deleted;        /* True if marked for deletion. */
  int mark;           /* Internally used by update_dir. */
  unsigned int lineno;/* A 0 indicates a new entry. */
  char *release_ptr;  /* The actual allocated memory. */
  char *url;          /* Points into RELEASE_PTR. */
  char *issuer;       /* Ditto. */
  char *issuer_hash;  /* Ditto. */
  char *dbfile_hash;  /* MD5 sum of the cache file, points into RELEASE_PTR.*/
  int invalid;        /* Can't use this CRL. */
  int user_trust_req; /* User supplied root certificate required.  */
  char *check_trust_anchor;  /* Malloced fingerprint.  */
  ksba_isotime_t this_update;
  ksba_isotime_t next_update;
  ksba_isotime_t last_refresh; /* Use for the force_crl_refresh feature. */
  char *crl_number;
  char *authority_issuer;
  char *authority_serialno;

  struct cdb *cdb;             /* The cache file handle or NULL if not open. */

  unsigned int cdb_use_count;  /* Current use count. */
  unsigned int cdb_lru_count;  /* Used for LRU purposes. */
  int dbfile_checked;          /* Set to true if the dbfile_hash value has
                                  been checked once. */
};


/* Definition of the entire cache object. */
struct crl_cache_s
{
  crl_cache_entry_t entries;
};

typedef struct crl_cache_s *crl_cache_t;


/* Prototypes.  */
static crl_cache_entry_t find_entry (crl_cache_entry_t first,
                                     const char *issuer_hash);



/* The currently loaded cache object.  This is usually initialized
   right at startup.  */
static crl_cache_t current_cache;





/* Return the current cache object or bail out if it is has not yet
   been initialized.  */
static crl_cache_t
get_current_cache (void)
{
  if (!current_cache)
    log_fatal ("CRL cache has not yet been initialized\n");
  return current_cache;
}


/*
   Create ae directory if it does not yet exists.  Returns on
   success, or -1 on error.
 */
static int
create_directory_if_needed (const char *name)
{
  gnupg_dir_t dir;
  char *fname;

  fname = make_filename (opt.homedir_cache, name, NULL);
  dir = gnupg_opendir (fname);
  if (!dir)
    {
      log_info (_("creating directory '%s'\n"), fname);
      if (gnupg_mkdir (fname, "-rwx"))
        {
          int save_errno = errno;
          log_error (_("error creating directory '%s': %s\n"),
                     fname, strerror (errno));
          xfree (fname);
          gpg_err_set_errno (save_errno);
          return -1;
        }
    }
  else
    gnupg_closedir (dir);
  xfree (fname);
  return 0;
}

/* Remove all files from the cache directory.  If FORCE is not true,
   some sanity checks on the filenames are done. Return 0 if
   everything went fine. */
static int
cleanup_cache_dir (int force)
{
  char *dname = make_filename (opt.homedir_cache, DBDIR_D, NULL);
  gnupg_dir_t dir;
  gnupg_dirent_t de;
  int problem = 0;

  if (!force)
    { /* Very minor sanity checks. */
      if (!strcmp (dname, "~/") || !strcmp (dname, "/" ))
        {
          log_error (_("ignoring database dir '%s'\n"), dname);
          xfree (dname);
          return -1;
        }
    }

  dir = gnupg_opendir (dname);
  if (!dir)
    {
      log_error (_("error reading directory '%s': %s\n"),
                 dname, strerror (errno));
      xfree (dname);
      return -1;
    }

  while ((de = gnupg_readdir (dir)))
    {
      if (strcmp (de->d_name, "." ) && strcmp (de->d_name, ".."))
        {
          char *cdbname = make_filename (dname, de->d_name, NULL);
          int okay;
          struct stat sbuf;

          if (force)
            okay = 1;
          else
            okay = (!gnupg_stat (cdbname, &sbuf) && S_ISREG (sbuf.st_mode));

          if (okay)
            {
              log_info (_("removing cache file '%s'\n"), cdbname);
              if (gnupg_remove (cdbname))
                {
                  log_error ("failed to remove '%s': %s\n",
                             cdbname, strerror (errno));
                  problem = -1;
                }
            }
          else
            log_info (_("not removing file '%s'\n"), cdbname);
          xfree (cdbname);
        }
    }
  xfree (dname);
  gnupg_closedir (dir);
  return problem;
}


/* Read the next line from the file FP and return the line in an
   malloced buffer.  Return NULL on error or EOF.  There is no
   limitation os the line length.  The trailing linefeed has been
   removed, the function will read the last line of a file, even if
   that is not terminated by a LF. */
static char *
next_line_from_file (estream_t fp, gpg_error_t *r_err)
{
  char buf[300];
  char *largebuf = NULL;
  size_t buflen;
  size_t len = 0;
  unsigned char *p;
  int c;
  char *tmpbuf;

  *r_err = 0;
  p = buf;
  buflen = sizeof buf - 1;
  while ((c=es_getc (fp)) != EOF && c != '\n')
    {
      if (len >= buflen)
        {
          if (!largebuf)
            {
              buflen += 1024;
              largebuf = xtrymalloc ( buflen + 1 );
              if (!largebuf)
                {
                  *r_err = gpg_error_from_syserror ();
                  return NULL;
                }
              memcpy (largebuf, buf, len);
            }
          else
            {
              buflen += 1024;
              tmpbuf = xtryrealloc (largebuf, buflen + 1);
              if (!tmpbuf)
                {
                  *r_err = gpg_error_from_syserror ();
                  xfree (largebuf);
                  return NULL;
                }
              largebuf = tmpbuf;
            }
          p = largebuf;
        }
      p[len++] = c;
    }
  if (c == EOF && !len)
    return NULL;
  p[len] = 0;

  if (largebuf)
    tmpbuf = xtryrealloc (largebuf, len+1);
  else
    tmpbuf = xtrystrdup (buf);
  if (!tmpbuf)
    {
      *r_err = gpg_error_from_syserror ();
      xfree (largebuf);
    }
  return tmpbuf;
}


/* Release one cache entry.  */
static void
release_one_cache_entry (crl_cache_entry_t entry)
{
  if (entry)
    {
      if (entry->cdb)
        {
          int fd = cdb_fileno (entry->cdb);
          cdb_free (entry->cdb);
          xfree (entry->cdb);
          if (close (fd))
            log_error (_("error closing cache file: %s\n"), strerror(errno));
        }
      xfree (entry->release_ptr);
      xfree (entry->check_trust_anchor);
      xfree (entry);
    }
}


/* Release the CACHE object. */
static void
release_cache (crl_cache_t cache)
{
  crl_cache_entry_t entry, entry2;

  if (!cache)
    return;

  for (entry = cache->entries; entry; entry = entry2)
    {
      entry2 = entry->next;
      release_one_cache_entry (entry);
    }
  cache->entries = NULL;
  xfree (cache);
}


/* Open the dir file FNAME or create a new one if it does not yet
   exist. */
static estream_t
open_dir_file (const char *fname)
{
  estream_t fp;

  fp = es_fopen (fname, "r");
  if (!fp)
    {
      log_error (_("failed to open cache dir file '%s': %s\n"),
                 fname, strerror (errno));

      /* Make sure that the directory exists, try to create if otherwise. */
      if (create_directory_if_needed (NULL)
          || create_directory_if_needed (DBDIR_D))
        return NULL;
      fp = es_fopen (fname, "w");
      if (!fp)
        {
          log_error (_("error creating new cache dir file '%s': %s\n"),
                     fname, strerror (errno));
          return NULL;
        }
      es_fprintf (fp, "v:%d:\n", DBDIRVERSION);
      if (es_ferror (fp))
        {
          log_error (_("error writing new cache dir file '%s': %s\n"),
                     fname, strerror (errno));
          es_fclose (fp);
          return NULL;
        }
      if (es_fclose (fp))
        {
          log_error (_("error closing new cache dir file '%s': %s\n"),
                     fname, strerror (errno));
          return NULL;
        }

      log_info (_("new cache dir file '%s' created\n"), fname);

      fp = es_fopen (fname, "r");
      if (!fp)
        {
          log_error (_("failed to re-open cache dir file '%s': %s\n"),
                     fname, strerror (errno));
          return NULL;
        }
    }

  return fp;
}

/* Helper for open_dir. */
static gpg_error_t
check_dir_version (estream_t *fpadr, const char *fname,
                         unsigned int *lineno,
                         int cleanup_on_mismatch)
{
  char *line;
  gpg_error_t lineerr = 0;
  estream_t fp = *fpadr;
  int created = 0;

 retry:
  while ((line = next_line_from_file (fp, &lineerr)))
    {
      ++*lineno;
      if (*line == 'v' && line[1] == ':')
        break;
      else if (*line != '#')
        {
          log_error (_("first record of '%s' is not the version\n"), fname);
          xfree (line);
          return gpg_error (GPG_ERR_CONFIGURATION);
        }
      xfree (line);
    }
  if (lineerr)
    return lineerr;

  /* The !line catches the case of an empty DIR file.  We handle this
     the same as a non-matching version.  */
  if (!line || strtol (line+2, NULL, 10) != DBDIRVERSION)
    {
      if (!created && cleanup_on_mismatch)
        {
          log_error (_("old version of cache directory - cleaning up\n"));
          es_fclose (fp);
          *fpadr = NULL;
          if (!cleanup_cache_dir (1))
            {
              *lineno = 0;
              fp = *fpadr = open_dir_file (fname);
              if (!fp)
                {
                  xfree (line);
                  return gpg_error (GPG_ERR_CONFIGURATION);
                }
              created = 1;
              goto retry;
            }
        }
      log_error (_("old version of cache directory - giving up\n"));
      xfree (line);
      return gpg_error (GPG_ERR_CONFIGURATION);
    }
  xfree (line);
  return 0;
}


/* Open the dir file and read in all available information.  Store
   that in a newly allocated cache object and return that if
   everything worked out fine.  Create the cache directory and the dir
   if it does not yet exist.  Remove all files in that directory if
   the version does not match. */
static gpg_error_t
open_dir (crl_cache_t *r_cache)
{
  crl_cache_t cache;
  char *fname;
  char *line = NULL;
  gpg_error_t lineerr = 0;
  estream_t fp;
  crl_cache_entry_t entry, *entrytail;
  unsigned int lineno;
  gpg_error_t err = 0;
  int anyerr = 0;

  cache = xtrycalloc (1, sizeof *cache);
  if (!cache)
    return gpg_error_from_syserror ();

  fname = make_filename (opt.homedir_cache, DBDIR_D, DBDIRFILE, NULL);

  lineno = 0;
  fp = open_dir_file (fname);
  if (!fp)
    {
      err = gpg_error (GPG_ERR_CONFIGURATION);
      goto leave;
    }

  err = check_dir_version (&fp, fname, &lineno, 1);
  if (err)
    goto leave;


  /* Read in all supported entries from the dir file. */
  cache->entries = NULL;
  entrytail = &cache->entries;
  xfree (line);
  while ((line = next_line_from_file (fp, &lineerr)))
    {
      int fieldno;
      char *p, *endp;

      lineno++;
      if ( *line == 'c' || *line == 'u' || *line == 'i' )
        {
          entry = xtrycalloc (1, sizeof *entry);
          if (!entry)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          entry->lineno = lineno;
          entry->release_ptr = line;
          if (*line == 'i')
            {
              entry->invalid = atoi (line+1);
              if (!entry->invalid)
                entry->invalid = INVCRL_GENERAL;
            }
          else if (*line == 'u')
            entry->user_trust_req = 1;

          for (fieldno=1, p = line; p; p = endp, fieldno++)
            {
              endp = strchr (p, ':');
              if (endp)
                *endp++ = '\0';

              switch (fieldno)
                {
                case 1: /* record type */ break;
                case 2: entry->issuer_hash = p; break;
                case 3: entry->issuer = unpercent_string (p); break;
                case 4: entry->url = unpercent_string (p); break;
                case 5:
		  strncpy (entry->this_update, p, 15);
		  entry->this_update[15] = 0;
		  break;
                case 6:
		  strncpy (entry->next_update, p, 15);
		  entry->next_update[15] = 0;
		  break;
                case 7: entry->dbfile_hash = p; break;
                case 8: if (*p) entry->crl_number = p; break;
                case 9:
                  if (*p)
                    entry->authority_issuer = unpercent_string (p);
                  break;
                case 10:
                  if (*p)
                    entry->authority_serialno = unpercent_string (p);
                  break;
                case 11:
                  if (*p)
                    entry->check_trust_anchor = xtrystrdup (p);
                  break;
                default:
                  if (*p)
                    log_info (_("extra field detected in crl record of "
                                "'%s' line %u\n"), fname, lineno);
                  break;
                }
            }

          if (!entry->issuer_hash)
            {
              log_info (_("invalid line detected in '%s' line %u\n"),
                        fname, lineno);
              xfree (entry);
              entry = NULL;
            }
          else if (find_entry (cache->entries, entry->issuer_hash))
            {
              /* Fixme: The duplicate checking used is not very
                 effective for large numbers of issuers. */
              log_info (_("duplicate entry detected in '%s' line %u\n"),
                        fname, lineno);
              xfree (entry);
              entry = NULL;
            }
          else
            {
              line = NULL;
              *entrytail = entry;
              entrytail = &entry->next;
            }
        }
      else if (*line == '#')
        ;
      else
        log_info (_("unsupported record type in '%s' line %u skipped\n"),
                  fname, lineno);

      if (line)
        xfree (line);
    }
  if (lineerr)
    {
      err = lineerr;
      log_error (_("error reading '%s': %s\n"), fname, gpg_strerror (err));
      goto leave;
    }
  if (es_ferror (fp))
    {
      log_error (_("error reading '%s': %s\n"), fname, strerror (errno));
      err = gpg_error (GPG_ERR_CONFIGURATION);
      goto leave;
    }

  /* Now do some basic checks on the data. */
  for (entry = cache->entries; entry; entry = entry->next)
    {
      assert (entry->lineno);
      if (strlen (entry->issuer_hash) != 40)
        {
          anyerr++;
          log_error (_("invalid issuer hash in '%s' line %u\n"),
                     fname, entry->lineno);
        }
      else if ( !*entry->issuer )
        {
          anyerr++;
          log_error (_("no issuer DN in '%s' line %u\n"),
                     fname, entry->lineno);
        }
      else if ( check_isotime (entry->this_update)
                || check_isotime (entry->next_update))
        {
          anyerr++;
          log_error (_("invalid timestamp in '%s' line %u\n"),
                     fname, entry->lineno);
        }

      /* Checks not leading to an immediate fail. */
      if (strlen (entry->dbfile_hash) != 32)
        log_info (_("WARNING: invalid cache file hash in '%s' line %u\n"),
                  fname, entry->lineno);
    }

  if (anyerr)
    {
      log_error (_("detected errors in cache dir file\n"));
      log_info (_("please check the reason and manually delete that file\n"));
      err = gpg_error (GPG_ERR_CONFIGURATION);
    }


 leave:
  es_fclose (fp);
  xfree (line);
  xfree (fname);
  if (err)
    {
      release_cache (cache);
      cache = NULL;
    }
  *r_cache = cache;
  return err;
}

static void
write_percented_string (const char *s, estream_t fp)
{
  for (; *s; s++)
    if (*s == ':')
      es_fputs ("%3A", fp);
    else if (*s == '\n')
      es_fputs ("%0A", fp);
    else if (*s == '\r')
      es_fputs ("%0D", fp);
    else
      es_putc (*s, fp);
}


static void
write_dir_line_crl (estream_t fp, crl_cache_entry_t e)
{
  if (e->invalid)
    es_fprintf (fp, "i%d", e->invalid);
  else if (e->user_trust_req)
    es_putc ('u', fp);
  else
    es_putc ('c', fp);
  es_putc (':', fp);
  es_fputs (e->issuer_hash, fp);
  es_putc (':', fp);
  write_percented_string (e->issuer, fp);
  es_putc (':', fp);
  write_percented_string (e->url, fp);
  es_putc (':', fp);
  es_fwrite (e->this_update, 15, 1, fp);
  es_putc (':', fp);
  es_fwrite (e->next_update, 15, 1, fp);
  es_putc (':', fp);
  es_fputs (e->dbfile_hash, fp);
  es_putc (':', fp);
  if (e->crl_number)
    es_fputs (e->crl_number, fp);
  es_putc (':', fp);
  if (e->authority_issuer)
    write_percented_string (e->authority_issuer, fp);
  es_putc (':', fp);
  if (e->authority_serialno)
    es_fputs (e->authority_serialno, fp);
  es_putc (':', fp);
  if (e->check_trust_anchor && e->user_trust_req)
    es_fputs (e->check_trust_anchor, fp);
  es_putc ('\n', fp);
}


/* Update the current dir file using the cache. */
static gpg_error_t
update_dir (crl_cache_t cache)
{
  char *fname = NULL;
  char *tmpfname = NULL;
  char *line = NULL;
  gpg_error_t lineerr = 0;
  estream_t fp;
  estream_t fpout = NULL;
  crl_cache_entry_t e;
  unsigned int lineno;
  gpg_error_t err = 0;

  fname = make_filename (opt.homedir_cache, DBDIR_D, DBDIRFILE, NULL);

  /* Fixme: Take an update file lock here. */

  for (e= cache->entries; e; e = e->next)
    e->mark = 1;

  lineno = 0;
  fp = es_fopen (fname, "r");
  if (!fp)
    {
      err = gpg_error_from_errno (errno);
      log_error (_("failed to open cache dir file '%s': %s\n"),
                 fname, strerror (errno));
      goto leave;
    }
  err = check_dir_version (&fp, fname, &lineno, 0);
  if (err)
    goto leave;
  es_rewind (fp);
  lineno = 0;

  /* Create a temporary DIR file. */
  {
    char *tmpbuf, *p;
    const char *nodename;
#ifndef HAVE_W32_SYSTEM
    struct utsname utsbuf;
#endif

#ifdef HAVE_W32_SYSTEM
    nodename = "unknown";
#else
    if (uname (&utsbuf))
      nodename = "unknown";
    else
      nodename = utsbuf.nodename;
#endif

    gpgrt_asprintf (&tmpbuf, "DIR-tmp-%s-%u-%p.txt.tmp",
                    nodename, (unsigned int)getpid (), &tmpbuf);
    if (!tmpbuf)
      {
        err = gpg_error_from_errno (errno);
        log_error (_("failed to create temporary cache dir file '%s': %s\n"),
                   tmpfname, strerror (errno));
        goto leave;
      }
    for (p=tmpbuf; *p; p++)
      if (*p == '/')
        *p = '.';
    tmpfname = make_filename (opt.homedir_cache, DBDIR_D, tmpbuf, NULL);
    xfree (tmpbuf);
  }
  fpout = es_fopen (tmpfname, "w");
  if (!fpout)
    {
      err = gpg_error_from_errno (errno);
      log_error (_("failed to create temporary cache dir file '%s': %s\n"),
                 tmpfname, strerror (errno));
      goto leave;
    }

  while ((line = next_line_from_file (fp, &lineerr)))
    {
      lineno++;
      if (*line == 'c' || *line == 'u' || *line == 'i')
        {
          /* Extract the issuer hash field. */
          char *fieldp, *endp;

          fieldp = strchr (line, ':');
          endp = fieldp? strchr (++fieldp, ':') : NULL;
          if (endp)
            {
              /* There should be no percent within the issuer hash
                 field, thus we can compare it pretty easily. */
              *endp = 0;
              e = find_entry ( cache->entries, fieldp);
              *endp = ':'; /* Restore original line. */
              if (e && e->deleted)
                {
                  /* Marked for deletion, so don't write it. */
                  e->mark = 0;
                }
              else if (e)
                {
                  /* Yep, this is valid entry we know about; write it out */
                  write_dir_line_crl (fpout, e);
                  e->mark = 0;
                }
              else
                { /* We ignore entries we don't have in our cache
                     because they may have been added in the meantime
                     by other instances of dirmngr. */
                  es_fprintf (fpout, "# Next line added by "
                              "another process; our pid is %lu\n",
                              (unsigned long)getpid ());
                  es_fputs (line, fpout);
                  es_putc ('\n', fpout);
                }
            }
          else
            {
              es_fputs ("# Invalid line detected: ", fpout);
              es_fputs (line, fpout);
              es_putc ('\n', fpout);
            }
        }
      else
        {
          /* Write out all non CRL lines as they are. */
          es_fputs (line, fpout);
          es_putc ('\n', fpout);
        }

      xfree (line);
    }
  if (!es_ferror (fp) && !es_ferror (fpout) && !lineerr)
    {
      /* Write out the remaining entries. */
      for (e= cache->entries; e; e = e->next)
        if (e->mark)
          {
            if (!e->deleted)
              write_dir_line_crl (fpout, e);
            e->mark = 0;
          }
    }
  if (lineerr)
    {
      err = lineerr;
      log_error (_("error reading '%s': %s\n"), fname, gpg_strerror (err));
      goto leave;
    }
  if (es_ferror (fp))
    {
      err = gpg_error_from_errno (errno);
      log_error (_("error reading '%s': %s\n"), fname, strerror (errno));
    }
  if (es_ferror (fpout))
    {
      err = gpg_error_from_errno (errno);
      log_error (_("error writing '%s': %s\n"), tmpfname, strerror (errno));
    }
  if (err)
    goto leave;

  /* Rename the files. */
  es_fclose (fp);
  fp = NULL;
  if (es_fclose (fpout))
    {
      err = gpg_error_from_errno (errno);
      log_error (_("error closing '%s': %s\n"), tmpfname, strerror (errno));
      goto leave;
    }
  fpout = NULL;

#ifdef HAVE_W32_SYSTEM
  /* No atomic mv on W32 systems.  */
  gnupg_remove (fname);
#endif
  if (rename (tmpfname, fname))
    {
      err = gpg_error_from_errno (errno);
      log_error (_("error renaming '%s' to '%s': %s\n"),
                 tmpfname, fname, strerror (errno));
      goto leave;
    }

 leave:
  /* Fixme: Relinquish update lock. */
  xfree (line);
  es_fclose (fp);
  xfree (fname);
  if (fpout)
    {
      es_fclose (fpout);
      if (err && tmpfname)
        gnupg_remove (tmpfname);
    }
  xfree (tmpfname);
  return err;
}




/* Create the filename for the cache file from the 40 byte ISSUER_HASH
   string. Caller must release the return string. */
static char *
make_db_file_name (const char *issuer_hash)
{
  char bname[50];

  assert (strlen (issuer_hash) == 40);
  memcpy (bname, "crl-", 4);
  memcpy (bname + 4, issuer_hash, 40);
  strcpy (bname + 44, ".db");
  return make_filename (opt.homedir_cache, DBDIR_D, bname, NULL);
}


/* Hash the file FNAME and return the MD5 digest in MD5BUFFER. The
 * caller must allocate MD5buffer with at least 16 bytes. Returns 0
 * on success. */
static int
hash_dbfile (const char *fname, unsigned char *md5buffer)
{
  estream_t fp;
  char *buffer;
  size_t n;
  gcry_md_hd_t md5;
  gpg_error_t err;

  buffer = xtrymalloc (65536);
  fp = buffer? es_fopen (fname, "rb") : NULL;
  if (!fp)
    {
      log_error (_("can't hash '%s': %s\n"), fname, strerror (errno));
      xfree (buffer);
      return -1;
    }

  err = gcry_md_open (&md5, GCRY_MD_MD5, 0);
  if (err)
    {
      log_error (_("error setting up MD5 hash context: %s\n"),
                 gpg_strerror (err));
      xfree (buffer);
      es_fclose (fp);
      return -1;
    }

  /* We better hash some information about the cache file layout in. */
  sprintf (buffer, "%.100s/%.100s:%d", DBDIR_D, DBDIRFILE, DBDIRVERSION);
  gcry_md_write (md5, buffer, strlen (buffer));

  for (;;)
    {
      n = es_fread (buffer, 1, 65536, fp);
      if (n < 65536 && es_ferror (fp))
        {
          log_error (_("error hashing '%s': %s\n"), fname, strerror (errno));
          xfree (buffer);
          es_fclose (fp);
          gcry_md_close (md5);
          return -1;
        }
      if (!n)
        break;
      gcry_md_write (md5, buffer, n);
    }
  es_fclose (fp);
  xfree (buffer);
  gcry_md_final (md5);

  memcpy (md5buffer, gcry_md_read (md5, GCRY_MD_MD5), 16);
  gcry_md_close (md5);
  return 0;
}

/* Compare the file FNAME against the dexified MD5 hash MD5HASH and
   return 0 if they match. */
static int
check_dbfile (const char *fname, const char *md5hexvalue)
{
  unsigned char buffer1[16], buffer2[16];

  if (strlen (md5hexvalue) != 32)
    {
      log_error (_("invalid formatted checksum for '%s'\n"), fname);
      return -1;
    }
  unhexify (buffer1, md5hexvalue);

  if (hash_dbfile (fname, buffer2))
    return -1;

  return memcmp (buffer1, buffer2, 16);
}


/* Open the cache file for ENTRY.  This function implements a caching
   strategy and might close unused cache files. It is required to use
   unlock_db_file after using the file. */
static struct cdb *
lock_db_file (crl_cache_t cache, crl_cache_entry_t entry)
{
  char *fname;
  int fd;
  int open_count;
  crl_cache_entry_t e;

  if (entry->cdb)
    {
      entry->cdb_use_count++;
      return entry->cdb;
    }

  for (open_count = 0, e = cache->entries; e; e = e->next)
    {
      if (e->cdb)
        open_count++;
/*       log_debug ("CACHE: cdb=%p use_count=%u lru_count=%u\n", */
/*                  e->cdb,e->cdb_use_count,e->cdb_lru_count); */
    }

  /* If there are too many file open, find the least recent used DB
     file and close it.  Note that for Pth thread safeness we need to
     use a loop here. */
  while (open_count >= MAX_OPEN_DB_FILES )
    {
      crl_cache_entry_t last_e = NULL;
      unsigned int last_lru = (unsigned int)(-1);

      for (e = cache->entries; e; e = e->next)
        if (e->cdb && !e->cdb_use_count && e->cdb_lru_count < last_lru)
          {
            last_lru = e->cdb_lru_count;
            last_e = e;
          }
      if (!last_e)
        {
          log_error (_("too many open cache files; can't open anymore\n"));
          return NULL;
        }

/*       log_debug ("CACHE: closing file at cdb=%p\n", last_e->cdb); */

      fd = cdb_fileno (last_e->cdb);
      cdb_free (last_e->cdb);
      xfree (last_e->cdb);
      last_e->cdb = NULL;
      if (close (fd))
        log_error (_("error closing cache file: %s\n"), strerror(errno));
      open_count--;
    }


  fname = make_db_file_name (entry->issuer_hash);
  if (opt.verbose)
    log_info (_("opening cache file '%s'\n"), fname );

  if (!entry->dbfile_checked)
    {
      if (!check_dbfile (fname, entry->dbfile_hash))
        entry->dbfile_checked = 1;
      /* Note, in case of an error we don't print an error here but
         let require the caller to do that check. */
    }

  entry->cdb = xtrycalloc (1, sizeof *entry->cdb);
  if (!entry->cdb)
    {
      xfree (fname);
      return NULL;
    }
  fd = gnupg_open (fname, O_RDONLY | O_BINARY, 0);
  if (fd == -1)
    {
      log_error (_("error opening cache file '%s': %s\n"),
                 fname, strerror (errno));
      xfree (entry->cdb);
      entry->cdb = NULL;
      xfree (fname);
      return NULL;
    }
  if (cdb_init (entry->cdb, fd))
    {
      log_error (_("error initializing cache file '%s' for reading: %s\n"),
                 fname, strerror (errno));
      xfree (entry->cdb);
      entry->cdb = NULL;
      close (fd);
      xfree (fname);
      return NULL;
    }
  xfree (fname);

  entry->cdb_use_count = 1;
  entry->cdb_lru_count = 0;

  return entry->cdb;
}

/* Unlock a cache file, so that it can be reused. */
static void
unlock_db_file (crl_cache_t cache, crl_cache_entry_t entry)
{
  if (!entry->cdb)
    log_error (_("calling unlock_db_file on a closed file\n"));
  else if (!entry->cdb_use_count)
    log_error (_("calling unlock_db_file on an unlocked file\n"));
  else
    {
      entry->cdb_use_count--;
      entry->cdb_lru_count++;
    }

  /* If the entry was marked for deletion in the meantime do it now.
     We do this for the sake of Pth thread safeness. */
  if (!entry->cdb_use_count && entry->deleted)
    {
      crl_cache_entry_t eprev, enext;

      enext = entry->next;
      for (eprev = cache->entries;
           eprev && eprev->next != entry; eprev = eprev->next)
        ;
      assert (eprev);
      if (eprev == cache->entries)
        cache->entries = enext;
      else
        eprev->next = enext;
      /* FIXME: Do we leak ENTRY? */
    }
}


/* Find ISSUER_HASH in our cache FIRST. This may be used to enumerate
   the linked list we use to keep the CRLs of an issuer. */
static crl_cache_entry_t
find_entry (crl_cache_entry_t first, const char *issuer_hash)
{
  while (first && (first->deleted || strcmp (issuer_hash, first->issuer_hash)))
    first = first->next;
  return first;
}


/* Create a new CRL cache. This function is usually called only once.
   never fail. */
void
crl_cache_init(void)
{
  crl_cache_t cache = NULL;
  gpg_error_t err;

  if (current_cache)
    {
      log_error ("crl cache has already been initialized - not doing twice\n");
      return;
    }

  err = open_dir (&cache);
  if (err)
    log_fatal (_("failed to create a new cache object: %s\n"),
               gpg_strerror (err));
  current_cache = cache;
}


/* Remove the cache information and all its resources.  Note that we
   still keep the cache on disk. */
void
crl_cache_deinit (void)
{
  if (current_cache)
    {
      release_cache (current_cache);
      current_cache = NULL;
    }
}


/* Delete the cache from disk and memory. Return 0 on success.*/
int
crl_cache_flush (void)
{
  int rc;

  crl_cache_deinit ();
  rc = cleanup_cache_dir (0)? -1 : 0;
  crl_cache_init ();

  return rc;
}


/* Check whether the certificate identified by ISSUER_HASH and
   SN/SNLEN is valid; i.e. not listed in our cache.  With
   FORCE_REFRESH set to true, a new CRL will be retrieved even if the
   cache has not yet expired.  We use a 30 minutes threshold here so
   that invoking this function several times won't load the CRL over
   and over.  */
static crl_cache_result_t
cache_isvalid (ctrl_t ctrl, const char *issuer_hash,
               const unsigned char *sn, size_t snlen,
               int force_refresh)
{
  crl_cache_t cache = get_current_cache ();
  crl_cache_result_t retval;
  struct cdb *cdb;
  int rc;
  crl_cache_entry_t entry;
  gnupg_isotime_t current_time;
  size_t n;

  (void)ctrl;

  entry = find_entry (cache->entries, issuer_hash);
  if (!entry)
    {
      log_info (_("no CRL available for issuer id %s\n"), issuer_hash );
      return CRL_CACHE_DONTKNOW;
    }

  gnupg_get_isotime (current_time);
  if (strcmp (entry->next_update, current_time) < 0 )
    {
      log_info (_("cached CRL for issuer id %s too old; update required\n"),
                issuer_hash);
      return CRL_CACHE_DONTKNOW;
    }
  if (force_refresh)
    {
      gnupg_isotime_t tmptime;

      if (*entry->last_refresh)
        {
          gnupg_copy_time (tmptime, entry->last_refresh);
          add_seconds_to_isotime (tmptime, 30 * 60);
          if (strcmp (tmptime, current_time) < 0 )
            {
              log_info (_("force-crl-refresh active and %d minutes passed for"
                          " issuer id %s; update required\n"),
                        30, issuer_hash);
              return CRL_CACHE_DONTKNOW;
            }
        }
      else
        {
          log_info (_("force-crl-refresh active for"
                      " issuer id %s; update required\n"),
                    issuer_hash);
          return CRL_CACHE_DONTKNOW;
        }
    }

  if (entry->invalid)
    {
      log_info (_("available CRL for issuer ID %s can't be used\n"),
                issuer_hash);
      return CRL_CACHE_CANTUSE;
    }

  cdb = lock_db_file (cache, entry);
  if (!cdb)
    return CRL_CACHE_DONTKNOW; /* Hmmm, not the best error code. */

  if (!entry->dbfile_checked)
    {
      log_error (_("cached CRL for issuer id %s tampered; we need to update\n")
                 , issuer_hash);
      unlock_db_file (cache, entry);
      return CRL_CACHE_DONTKNOW;
    }

  rc = cdb_find (cdb, sn, snlen);
  if (rc == 1)
    {
      n = cdb_datalen (cdb);
      if (n != 16)
        {
          log_error (_("WARNING: invalid cache record length for S/N "));
          log_printf ("0x");
          log_printhex (sn, snlen, "");
        }
      else if (opt.verbose)
        {
          unsigned char record[16];
          char *tmp = hexify_data (sn, snlen, 1);

          if (cdb_read (cdb, record, n, cdb_datapos (cdb)))
            log_error (_("problem reading cache record for S/N %s: %s\n"),
                       tmp, strerror (errno));
          else
            log_info (_("S/N %s is not valid; reason=%02X  date=%.15s\n"),
                      tmp, *record, record+1);
          xfree (tmp);
        }
      retval = CRL_CACHE_INVALID;
    }
  else if (!rc)
    {
      if (opt.verbose)
        {
          char *serialno = hexify_data (sn, snlen, 1);
          log_info (_("S/N %s is valid, it is not listed in the CRL\n"),
                    serialno );
          xfree (serialno);
        }
      retval = CRL_CACHE_VALID;
    }
  else
    {
      log_error (_("error getting data from cache file: %s\n"),
                 strerror (errno));
      retval = CRL_CACHE_DONTKNOW;
    }


  if (entry->user_trust_req
      && (retval == CRL_CACHE_VALID || retval == CRL_CACHE_INVALID))
    {
      if (!entry->check_trust_anchor)
        {
          log_error ("inconsistent data on user trust check\n");
          retval = CRL_CACHE_CANTUSE;
        }
      else if (get_istrusted_from_client (ctrl, entry->check_trust_anchor))
        {
          if (opt.verbose)
            log_info ("no system trust and client does not trust either\n");
          retval = CRL_CACHE_NOTTRUSTED;
        }
      else
        {
          /* Okay, the CRL is considered valid by the client and thus
             we can return the result as is.  */
        }
    }

  unlock_db_file (cache, entry);

  return retval;
}


/* Check whether the certificate identified by ISSUER_HASH and
   SERIALNO is valid; i.e. not listed in our cache.  With
   FORCE_REFRESH set to true, a new CRL will be retrieved even if the
   cache has not yet expired.  We use a 30 minutes threshold here so
   that invoking this function several times won't load the CRL over
   and over.  */
crl_cache_result_t
crl_cache_isvalid (ctrl_t ctrl, const char *issuer_hash, const char *serialno,
                   int force_refresh)
{
  crl_cache_result_t result;
  unsigned char snbuf_buffer[50];
  unsigned char *snbuf;
  size_t n;

  n = strlen (serialno)/2+1;
  if (n < sizeof snbuf_buffer - 1)
    snbuf = snbuf_buffer;
  else
    {
      snbuf = xtrymalloc (n);
      if (!snbuf)
        return CRL_CACHE_DONTKNOW;
    }

  n = unhexify (snbuf, serialno);

  result = cache_isvalid (ctrl, issuer_hash, snbuf, n, force_refresh);

  if (snbuf != snbuf_buffer)
    xfree (snbuf);

  return result;
}


/* Check whether the certificate CERT is valid; i.e. not listed in our
   cache.  With FORCE_REFRESH set to true, a new CRL will be retrieved
   even if the cache has not yet expired.  We use a 30 minutes
   threshold here so that invoking this function several times won't
   load the CRL over and over.  */
gpg_error_t
crl_cache_cert_isvalid (ctrl_t ctrl, ksba_cert_t cert,
                        int force_refresh)
{
  gpg_error_t err;
  crl_cache_result_t result;
  unsigned char issuerhash[20];
  char issuerhash_hex[41];
  ksba_sexp_t serial;
  unsigned char *sn;
  size_t snlen;
  char *endp, *tmp;
  int i;

  /* Compute the hash value of the issuer name.  */
  tmp = ksba_cert_get_issuer (cert, 0);
  if (!tmp)
    {
      log_error ("oops: issuer missing in certificate\n");
      return gpg_error (GPG_ERR_INV_CERT_OBJ);
    }
  gcry_md_hash_buffer (GCRY_MD_SHA1, issuerhash, tmp, strlen (tmp));
  xfree (tmp);
  for (i=0,tmp=issuerhash_hex; i < 20; i++, tmp += 2)
    sprintf (tmp, "%02X", issuerhash[i]);

  /* Get the serial number.  */
  serial = ksba_cert_get_serial (cert);
  if (!serial)
    {
      log_error ("oops: S/N missing in certificate\n");
      return gpg_error (GPG_ERR_INV_CERT_OBJ);
    }
  sn = serial;
  if (*sn != '(')
    {
      log_error ("oops: invalid S/N\n");
      xfree (serial);
      return gpg_error (GPG_ERR_INV_CERT_OBJ);
    }
  sn++;
  snlen = strtoul (sn, &endp, 10);
  sn = endp;
  if (*sn != ':')
    {
      log_error ("oops: invalid S/N\n");
      xfree (serial);
      return gpg_error (GPG_ERR_INV_CERT_OBJ);
    }
  sn++;

  /* Check the cache.  */
  result = cache_isvalid (ctrl, issuerhash_hex, sn, snlen, force_refresh);
  switch (result)
    {
    case CRL_CACHE_VALID:
      err = 0;
      break;
    case CRL_CACHE_INVALID:
      err = gpg_error (GPG_ERR_CERT_REVOKED);
      break;
    case CRL_CACHE_DONTKNOW:
      err = gpg_error (GPG_ERR_NO_CRL_KNOWN);
      break;
    case CRL_CACHE_NOTTRUSTED:
      err = gpg_error (GPG_ERR_NOT_TRUSTED);
      break;
    case CRL_CACHE_CANTUSE:
      err = gpg_error (GPG_ERR_INV_CRL_OBJ);
      break;
    default:
      log_fatal ("cache_isvalid returned invalid status code %d\n", result);
    }

  xfree (serial);
  return err;
}


/* Return the hash algorithm's algo id from its name given in the
 * non-null termnated string in (buffer,buflen).  Returns 0 on failure
 * or if the algo is not known.  */
static int
hash_algo_from_buffer (const void *buffer, size_t buflen)
{
  char *string;
  int algo;

  string = xtrymalloc (buflen + 1);
  if (!string)
    {
      log_error (_("out of core\n"));
      return 0;
    }
  memcpy (string, buffer, buflen);
  string[buflen] = 0;
  algo = gcry_md_map_name (string);
  if (!algo)
    log_error ("unknown digest algorithm '%s' used in certificate\n", string);
  xfree (string);
  return algo;
}


/* Return an unsigned integer from the non-null termnated string
 * (buffer,buflen).  Returns 0 on failure.  */
static unsigned int
uint_from_buffer (const void *buffer, size_t buflen)
{
  char *string;
  unsigned int val;

  string = xtrymalloc (buflen + 1);
  if (!string)
    {
      log_error (_("out of core\n"));
      return 0;
    }
  memcpy (string, buffer, buflen);
  string[buflen] = 0;
  val = strtoul (string, NULL, 10);
  xfree (string);
  return val;
}


/* Prepare a hash context for the signature verification.  Input is
   the CRL and the output is the hash context MD as well as the uses
   algorithm identifier ALGO. */
static gpg_error_t
start_sig_check (ksba_crl_t crl, gcry_md_hd_t *md, int *algo, int *use_pss)
{
  gpg_error_t err;
  const char *algoid;

  *use_pss = 0;
  algoid = ksba_crl_get_digest_algo (crl);
  if (algoid && !strcmp (algoid, "1.2.840.113549.1.1.10"))
    {
      /* Parse rsaPSS parameter.  */
      gcry_buffer_t ioarray[1] = { {0} };
      ksba_sexp_t pssparam;
      size_t n;
      gcry_sexp_t psssexp;

      pssparam = ksba_crl_get_sig_val (crl);
      n = gcry_sexp_canon_len (pssparam, 0, NULL, NULL);
      if (!n)
        {
          ksba_free (pssparam);
          log_error (_("got an invalid S-expression from libksba\n"));
          return gpg_error (GPG_ERR_INV_SEXP);
        }
      err = gcry_sexp_sscan (&psssexp, NULL, pssparam, n);
      ksba_free (pssparam);
      if (err)
        {
          log_error (_("converting S-expression failed: %s\n"),
                     gcry_strerror (err));
          return err;
        }

      err = gcry_sexp_extract_param (psssexp, "sig-val",
                                    "&'hash-algo'", ioarray, NULL);
      gcry_sexp_release (psssexp);
      if (err)
        {
          log_error ("extracting params from PSS failed: %s\n",
                     gpg_strerror (err));
          return err;
        }
      *algo = hash_algo_from_buffer (ioarray[0].data, ioarray[0].len);
      xfree (ioarray[0].data);
      *use_pss = 1;
    }
  else
    *algo = gcry_md_map_name (algoid);
  if (!*algo)
    {
      log_error (_("unknown hash algorithm '%s'\n"), algoid? algoid:"?");
      return gpg_error (GPG_ERR_DIGEST_ALGO);
    }

  err = gcry_md_open (md, *algo, 0);
  if (err)
    {
      log_error (_("gcry_md_open for algorithm %d failed: %s\n"),
                 *algo, gcry_strerror (err));
      return err;
    }
  if (DBG_HASHING)
    gcry_md_debug (*md, "hash.cert");

  ksba_crl_set_hash_function (crl, HASH_FNC, *md);
  return 0;
}


/* Finish a hash context and verify the signature.  This function
   should return 0 on a good signature, GPG_ERR_BAD_SIGNATURE if the
   signature does not verify or any other error code. CRL is the CRL
   object we are working on, MD the hash context and ISSUER_CERT the
   certificate of the CRL issuer.  This function takes ownership of MD.  */
static gpg_error_t
finish_sig_check (ksba_crl_t crl, gcry_md_hd_t md, int algo,
                  ksba_cert_t issuer_cert, int use_pss)
{
  gpg_error_t err;
  ksba_sexp_t sigval = NULL, pubkey = NULL;
  size_t n;
  gcry_sexp_t s_sig = NULL, s_hash = NULL, s_pkey = NULL;
  unsigned int saltlen = 0;  /* (used only with use_pss)  */
  int pkalgo;

  /* This also stops debugging on the MD.  */
  gcry_md_final (md);

  /* Get and convert the signature value. */
  sigval = ksba_crl_get_sig_val (crl);
  n = gcry_sexp_canon_len (sigval, 0, NULL, NULL);
  if (!n)
    {
      log_error (_("got an invalid S-expression from libksba\n"));
      err = gpg_error (GPG_ERR_INV_SEXP);
      goto leave;
    }
  err = gcry_sexp_sscan (&s_sig, NULL, sigval, n);
  if (err)
    {
      log_error (_("converting S-expression failed: %s\n"),
                 gcry_strerror (err));
      goto leave;
    }

  if (use_pss)
    {
      /* Parse rsaPSS parameter which we should find in S_SIG.  */
      gcry_buffer_t ioarray[2] = { {0}, {0} };
      ksba_sexp_t pssparam;
      gcry_sexp_t psssexp;
      int hashalgo;

      pssparam = ksba_crl_get_sig_val (crl);
      n = gcry_sexp_canon_len (pssparam, 0, NULL, NULL);
      if (!n)
        {
          ksba_free (pssparam);
          log_error (_("got an invalid S-expression from libksba\n"));
          err = gpg_error (GPG_ERR_INV_SEXP);
          goto leave;
        }
      err = gcry_sexp_sscan (&psssexp, NULL, pssparam, n);
      ksba_free (pssparam);
      if (err)
        {
          log_error (_("converting S-expression failed: %s\n"),
                     gcry_strerror (err));
          goto leave;
        }

      err = gcry_sexp_extract_param (psssexp, "sig-val",
                                    "&'hash-algo''salt-length'",
                                     ioarray+0, ioarray+1, NULL);
      gcry_sexp_release (psssexp);
      if (err)
        {
          log_error ("extracting params from PSS failed: %s\n",
                     gpg_strerror (err));
          goto leave;
        }
      hashalgo = hash_algo_from_buffer (ioarray[0].data, ioarray[0].len);
      saltlen = uint_from_buffer (ioarray[1].data, ioarray[1].len);
      xfree (ioarray[0].data);
      xfree (ioarray[1].data);
      if (hashalgo != algo)
        {
          log_error ("hash algo mismatch: %d announced but %d used\n",
                     algo, hashalgo);
          err = gpg_error (GPG_ERR_INV_CRL);
          goto leave;
        }
      /* Add some restrictions; see ../sm/certcheck.c for details.  */
      switch (algo)
        {
        case GCRY_MD_SHA1:
        case GCRY_MD_SHA256:
        case GCRY_MD_SHA384:
        case GCRY_MD_SHA512:
        case GCRY_MD_SHA3_256:
        case GCRY_MD_SHA3_384:
        case GCRY_MD_SHA3_512:
          break;
        default:
          log_error ("PSS hash algorithm '%s' rejected\n",
                     gcry_md_algo_name (algo));
          err = gpg_error (GPG_ERR_DIGEST_ALGO);
          goto leave;
        }

      if (gcry_md_get_algo_dlen (algo) != saltlen)
        {
          log_error ("PSS hash algorithm '%s' rejected due to salt length %u\n",
                     gcry_md_algo_name (algo), saltlen);
          err = gpg_error (GPG_ERR_DIGEST_ALGO);
          goto leave;
        }
    }


  /* Get and convert the public key for the issuer certificate. */
  if (DBG_X509)
    dump_cert ("crl_issuer_cert", issuer_cert);
  pubkey = ksba_cert_get_public_key (issuer_cert);
  n = gcry_sexp_canon_len (pubkey, 0, NULL, NULL);
  if (!n)
    {
      log_error (_("got an invalid S-expression from libksba\n"));
      err = gpg_error (GPG_ERR_INV_SEXP);
      goto leave;
    }
  err = gcry_sexp_sscan (&s_pkey, NULL, pubkey, n);
  if (err)
    {
      log_error (_("converting S-expression failed: %s\n"),
                 gcry_strerror (err));
      goto leave;
    }

  /* Create an S-expression with the actual hash value. */
  if (use_pss)
    {
      err = gcry_sexp_build (&s_hash, NULL,
                             "(data (flags pss)"
                             "(hash %s %b)"
                             "(salt-length %u))",
                             hash_algo_to_string (algo),
                             (int)gcry_md_get_algo_dlen (algo),
                             gcry_md_read (md, algo),
                             saltlen);
    }
  else if ((pkalgo = pk_algo_from_sexp (s_pkey)) == GCRY_PK_ECC)
    {
      unsigned int qbits0, qbits;

      qbits0 = gcry_pk_get_nbits (s_pkey);
      qbits = qbits0 == 521? 512 : qbits0;

      if ((qbits%8))
	{
	  log_error ("ECDSA requires the hash length to be a"
                     " multiple of 8 bits\n");
	  err = gpg_error (GPG_ERR_INTERNAL);
          goto leave;
	}

      /* Don't allow any Q smaller than 160 bits.  */
      if (qbits < 160)
	{
	  log_error (_("%s key uses an unsafe (%u bit) hash\n"),
                     gcry_pk_algo_name (pkalgo), qbits0);
	  err = gpg_error (GPG_ERR_INTERNAL);
          goto leave;
	}

      /* Check if we're too short.  */
      n = gcry_md_get_algo_dlen (algo);
      if (n < qbits/8)
        {
	  log_error (_("a %u bit hash is not valid for a %u bit %s key\n"),
                     (unsigned int)n*8,
                     qbits0,
                     gcry_pk_algo_name (pkalgo));
          if (n < 20)
            {
              err = gpg_error (GPG_ERR_INTERNAL);
              goto leave;
            }
        }

      /* Truncate.  */
      if (n > qbits/8)
        n = qbits/8;

      err = gcry_sexp_build (&s_hash, NULL, "(data(flags raw)(value %b))",
                             (int)n,
                             gcry_md_read (md, algo));

    }
  else
    {
      err = gcry_sexp_build (&s_hash, NULL,
                             "(data(flags pkcs1)(hash %s %b))",
                             hash_algo_to_string (algo),
                             (int)gcry_md_get_algo_dlen (algo),
                             gcry_md_read (md, algo));
    }
  if (err)
    {
      log_error (_("creating S-expression failed: %s\n"), gcry_strerror (err));
      goto leave;
    }

  /* Pass this on to the signature verification. */
  err = gcry_pk_verify (s_sig, s_hash, s_pkey);
  if (DBG_X509)
    log_debug ("%s: gcry_pk_verify: %s\n", __func__, gpg_strerror (err));

 leave:
  xfree (sigval);
  xfree (pubkey);
  gcry_sexp_release (s_sig);
  gcry_sexp_release (s_hash);
  gcry_sexp_release (s_pkey);
  gcry_md_close (md);

  return err;
}


/* Call this to match a start_sig_check that can not be completed
   normally.  Takes ownership of MD if MD is not NULL.  */
static void
abort_sig_check (ksba_crl_t crl, gcry_md_hd_t md)
{
  (void)crl;
  if (md)
    gcry_md_close (md);
}


/* Workhorse of the CRL loading machinery.  The CRL is read using the
   CRL object and stored in the data base file DB with the name FNAME
   (only used for printing error messages).  That DB should be a
   temporary one and not the actual one.  If the function fails the
   caller should delete this temporary database file.  CTRL is
   required to retrieve certificates using the general dirmngr
   callback service.  R_CRLISSUER returns an allocated string with the
   crl-issuer DN, THIS_UPDATE and NEXT_UPDATE are filled with the
   corresponding data from the CRL.  Note that these values might get
   set even if the CRL processing fails at a later step; thus the
   caller should free *R_ISSUER even if the function returns with an
   error.  R_TRUST_ANCHOR is set on exit to NULL or a string with the
   hexified fingerprint of the root certificate, if checking this
   certificate for trustiness is required.
*/
static int
crl_parse_insert (ctrl_t ctrl, ksba_crl_t crl,
                  struct cdb_make *cdb, const char *fname,
                  char **r_crlissuer,
                  ksba_isotime_t thisupdate, ksba_isotime_t nextupdate,
                  char **r_trust_anchor)
{
  gpg_error_t err;
  ksba_stop_reason_t stopreason;
  ksba_cert_t crlissuer_cert = NULL;
  gcry_md_hd_t md = NULL;
  int algo = 0;
  int use_pss = 0;
  size_t n;

  (void)fname;

  *r_crlissuer = NULL;
  *thisupdate = *nextupdate = 0;
  *r_trust_anchor = NULL;

  /* Start of the KSBA parser loop. */
  do
    {
      err = ksba_crl_parse (crl, &stopreason);
      if (err)
        {
          log_error (_("ksba_crl_parse failed: %s\n"), gpg_strerror (err) );
          goto failure;
        }

      switch (stopreason)
        {
        case KSBA_SR_BEGIN_ITEMS:
          {
            err = start_sig_check (crl, &md, &algo, &use_pss);
            if (err)
              goto failure;

            err = ksba_crl_get_update_times (crl, thisupdate, nextupdate);
            if (err)
              {
                log_error (_("error getting update times of CRL: %s\n"),
                           gpg_strerror (err));
                err = gpg_error (GPG_ERR_INV_CRL);
                goto failure;
              }

            if (opt.verbose || !*nextupdate)
              log_info (_("update times of this CRL: this=%s next=%s\n"),
                        thisupdate, nextupdate);
            if (!*nextupdate)
              {
                log_info (_("nextUpdate not given; "
                            "assuming a validity period of one day\n"));
                gnupg_copy_time (nextupdate, thisupdate);
                add_seconds_to_isotime (nextupdate, 86400);
              }
          }
          break;

        case KSBA_SR_GOT_ITEM:
          {
            ksba_sexp_t serial;
            const unsigned char *p;
            ksba_isotime_t rdate;
            ksba_crl_reason_t reason;
            int rc;
            unsigned char record[1+15];

            err = ksba_crl_get_item (crl, &serial, rdate, &reason);
            if (err)
              {
                log_error (_("error getting CRL item: %s\n"),
                           gpg_strerror (err));
                err = gpg_error (GPG_ERR_INV_CRL);
                ksba_free (serial);
                goto failure;
              }
            p = serial_to_buffer (serial, &n);
            if (!p)
              BUG ();
            record[0] = (reason & 0xff);
            memcpy (record+1, rdate, 15);
            rc = cdb_make_add (cdb, p, n, record, 1+15);
            if (rc)
              {
                err = gpg_error_from_errno (errno);
                log_error (_("error inserting item into "
                             "temporary cache file: %s\n"),
                           strerror (errno));
                goto failure;
              }

            ksba_free (serial);
          }
          break;

        case KSBA_SR_END_ITEMS:
          break;

        case KSBA_SR_READY:
          {
            char *crlissuer;
            ksba_name_t authid;
            ksba_sexp_t authidsn;
            ksba_sexp_t keyid;

            /* We need to look for the issuer only after having read
               all items.  The issuer itself comes before the items
               but the optional authorityKeyIdentifier comes after the
               items. */
            err = ksba_crl_get_issuer (crl, &crlissuer);
            if( err )
              {
                log_error (_("no CRL issuer found in CRL: %s\n"),
                           gpg_strerror (err) );
                err = gpg_error (GPG_ERR_INV_CRL);
                goto failure;
              }
	    /* Note: This should be released by ksba_free, not xfree.
	       May need a memory reallocation dance.  */
            *r_crlissuer = crlissuer; /* (Do it here so we don't need
                                         to free it later) */

            if (!ksba_crl_get_auth_key_id (crl, &keyid, &authid, &authidsn))
              {
                const char *s;

                if (opt.verbose)
                  log_info (_("locating CRL issuer certificate by "
                              "authorityKeyIdentifier\n"));

                s = ksba_name_enum (authid, 0);
                if (s && *authidsn)
                  crlissuer_cert = find_cert_bysn (ctrl, s, authidsn);
                if (!crlissuer_cert && keyid)
                  crlissuer_cert = find_cert_bysubject (ctrl,
                                                        crlissuer, keyid);

                if (!crlissuer_cert)
                  {
                    log_info ("CRL issuer certificate ");
                    if (keyid)
                      {
                        log_printf ("{");
                        dump_serial (keyid);
                        log_printf ("} ");
                      }
                    if (authidsn)
                      {
                        log_printf ("(#");
                        dump_serial (authidsn);
                        log_printf ("/");
                        dump_string (s);
                        log_printf (") ");
                      }
                    log_printf ("not found\n");
                  }
                ksba_name_release (authid);
                xfree (authidsn);
                xfree (keyid);
              }
            else
              crlissuer_cert = find_cert_bysubject (ctrl, crlissuer, NULL);
            err = 0;
            if (!crlissuer_cert)
              {
                err = gpg_error (GPG_ERR_MISSING_CERT);
                goto failure;
              }

            err = finish_sig_check (crl, md, algo, crlissuer_cert, use_pss);
            md = NULL; /* Closed.  */
            if (err)
              {
                log_error (_("CRL signature verification failed: %s\n"),
                           gpg_strerror (err));
                goto failure;
              }

            err = validate_cert_chain (ctrl, crlissuer_cert, NULL,
                                       (VALIDATE_FLAG_TRUST_CONFIG
                                        | VALIDATE_FLAG_TRUST_SYSTEM
                                        | VALIDATE_FLAG_CRL
                                        | VALIDATE_FLAG_RECURSIVE),
                                       r_trust_anchor);
            if (err)
              {
                log_error (_("error checking validity of CRL "
                             "issuer certificate: %s\n"),
                           gpg_strerror (err));
                goto failure;
              }

          }
          break;

        default:
          log_debug ("crl_parse_insert: unknown stop reason\n");
          err = gpg_error (GPG_ERR_BUG);
          goto failure;
        }
    }
  while (stopreason != KSBA_SR_READY);
  log_assert (!err);


 failure:
  abort_sig_check (crl, md);
  ksba_cert_release (crlissuer_cert);
  return err;
}



/* Return the crlNumber extension as an allocated hex string or NULL
   if there is none. */
static char *
get_crl_number (ksba_crl_t crl)
{
  gpg_error_t err;
  ksba_sexp_t number;
  char *string;

  err = ksba_crl_get_crl_number (crl, &number);
  if (err)
    return NULL;
  string = serial_hex (number);
  ksba_free (number);
  return string;
}


/* Return the authorityKeyIdentifier or NULL if it is not available.
   The issuer name may consists of several parts - they are delimited by
   0x01. */
static char *
get_auth_key_id (ksba_crl_t crl, char **serialno)
{
  gpg_error_t err;
  ksba_name_t name;
  ksba_sexp_t sn;
  int idx;
  const char *s;
  char *string;
  size_t length;

  *serialno = NULL;
  err = ksba_crl_get_auth_key_id (crl, NULL, &name, &sn);
  if (err)
    return NULL;
  *serialno = serial_hex (sn);
  ksba_free (sn);

  if (!name)
    return xstrdup ("");

  length = 0;
  for (idx=0; (s = ksba_name_enum (name, idx)); idx++)
    {
      char *p = ksba_name_get_uri (name, idx);
      length += strlen (p?p:s) + 1;
      xfree (p);
    }
  string = xtrymalloc (length+1);
  if (string)
    {
      *string = 0;
      for (idx=0; (s = ksba_name_enum (name, idx)); idx++)
        {
          char *p = ksba_name_get_uri (name, idx);
          if (*string)
            strcat (string, "\x01");
          strcat (string, p?p:s);
          xfree (p);
        }
    }
  ksba_name_release (name);
  return string;
}



/* Insert the CRL retrieved using URL into the cache specified by
   CACHE.  The CRL itself will be read from the stream FP and is
   expected in binary format.

   Called by:
      crl_cache_load
         cmd_loadcrl
         --load-crl
      crl_cache_reload_crl
         cmd_isvalid
         cmd_checkcrl
      cmd_loadcrl
      --fetch-crl

 */
gpg_error_t
crl_cache_insert (ctrl_t ctrl, const char *url, ksba_reader_t reader)
{
  crl_cache_t cache = get_current_cache ();
  gpg_error_t err, err2;
  ksba_crl_t crl;
  char *fname = NULL;
  char *newfname = NULL;
  struct cdb_make cdb;
  int fd_cdb = -1;
  char *issuer = NULL;
  char *issuer_hash = NULL;
  ksba_isotime_t thisupdate, nextupdate;
  crl_cache_entry_t entry = NULL;
  crl_cache_entry_t e;
  gnupg_isotime_t current_time;
  char *checksum = NULL;
  int invalidate_crl = 0;
  int idx;
  const char *oid;
  int critical;
  char *trust_anchor = NULL;

  /* FIXME: We should acquire a mutex for the URL, so that we don't
     simultaneously enter the same CRL twice.  However this needs to be
     interweaved with the checking function.*/

  err2 = 0;

  err = ksba_crl_new (&crl);
  if (err)
    {
      log_error (_("ksba_crl_new failed: %s\n"), gpg_strerror (err));
      goto leave;
    }

  err = ksba_crl_set_reader (crl, reader);
  if ( err )
    {
      log_error (_("ksba_crl_set_reader failed: %s\n"), gpg_strerror (err));
      goto leave;
    }

  /* Create a temporary cache file to load the CRL into. */
  {
    char *tmpfname, *p;
    const char *nodename;
#ifndef HAVE_W32_SYSTEM
    struct utsname utsbuf;
#endif

#ifdef HAVE_W32_SYSTEM
    nodename = "unknown";
#else
    if (uname (&utsbuf))
      nodename = "unknown";
    else
      nodename = utsbuf.nodename;
#endif

    gpgrt_asprintf (&tmpfname, "crl-tmp-%s-%u-%p.db.tmp",
                    nodename, (unsigned int)getpid (), &tmpfname);
    if (!tmpfname)
      {
        err = gpg_error_from_syserror ();
        goto leave;
      }
    for (p=tmpfname; *p; p++)
      if (*p == '/')
        *p = '.';
    fname = make_filename (opt.homedir_cache, DBDIR_D, tmpfname, NULL);
    xfree (tmpfname);
    if (!gnupg_remove (fname))
      log_info (_("removed stale temporary cache file '%s'\n"), fname);
    else if (errno != ENOENT)
      {
        err = gpg_error_from_syserror ();
        log_error (_("problem removing stale temporary cache file '%s': %s\n"),
                   fname, gpg_strerror (err));
        goto leave;
      }
  }

  fd_cdb = gnupg_open (fname, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
  if (fd_cdb == -1)
    {
      err = gpg_error_from_errno (errno);
      log_error (_("error creating temporary cache file '%s': %s\n"),
                 fname, strerror (errno));
      goto leave;
    }
  cdb_make_start(&cdb, fd_cdb);

  err = crl_parse_insert (ctrl, crl, &cdb, fname,
                          &issuer, thisupdate, nextupdate, &trust_anchor);
  if (err)
    {
      log_error (_("crl_parse_insert failed: %s\n"), gpg_strerror (err));
      /* Error in cleanup ignored.  */
      cdb_make_finish (&cdb);
      goto leave;
    }

  /* Finish the database. */
  if (cdb_make_finish (&cdb))
    {
      err = gpg_error_from_errno (errno);
      log_error (_("error finishing temporary cache file '%s': %s\n"),
                 fname, strerror (errno));
      goto leave;
    }
  if (close (fd_cdb))
    {
      err = gpg_error_from_errno (errno);
      log_error (_("error closing temporary cache file '%s': %s\n"),
                 fname, strerror (errno));
      goto leave;
    }
  fd_cdb = -1;


  /* Create a checksum. */
  {
    unsigned char md5buf[16];

    if (hash_dbfile (fname, md5buf))
      {
        err = gpg_error (GPG_ERR_CHECKSUM);
        goto leave;
      }
    checksum = hexify_data (md5buf, 16, 0);
  }


  /* Check whether that new CRL is still not expired. */
  gnupg_get_isotime (current_time);
  if (strcmp (nextupdate, current_time) < 0 )
    {
      if (opt.force)
        log_info (_("WARNING: new CRL still too old; it expired on %s "
                    "- loading anyway\n"),  nextupdate);
      else
        {
          log_error (_("new CRL still too old; it expired on %s\n"),
                     nextupdate);
          if (!err2)
            err2 = gpg_error (GPG_ERR_CRL_TOO_OLD);
          invalidate_crl |= INVCRL_TOO_OLD;
        }
    }

  /* Check for unknown critical extensions. */
  for (idx=0; !(err=ksba_crl_get_extension (crl, idx, &oid, &critical,
                                              NULL, NULL)); idx++)
    {
      strlist_t sl;

      if (!critical
          || !strcmp (oid, oidstr_authorityKeyIdentifier)
          || !strcmp (oid, oidstr_crlNumber) )
        continue;

      for (sl=opt.ignored_crl_extensions;
           sl && strcmp (sl->d, oid); sl = sl->next)
        ;
      if (sl)
        continue;  /* Is in ignored list.  */

      log_error (_("unknown critical CRL extension %s\n"), oid);
      log_info ("(CRL='%s')\n", url);
      if (!err2)
        err2 = gpg_error (GPG_ERR_INV_CRL);
      invalidate_crl |= INVCRL_UNKNOWN_EXTN;
    }
  if (gpg_err_code (err) == GPG_ERR_EOF
      || gpg_err_code (err) == GPG_ERR_NO_DATA )
    err = 0;
  if (err)
    {
      log_error (_("error reading CRL extensions: %s\n"), gpg_strerror (err));
      err = gpg_error (GPG_ERR_INV_CRL);
    }


  /* Create an hex encoded SHA-1 hash of the issuer DN to be
     used as the key for the cache. */
  issuer_hash = hashify_data (issuer, strlen (issuer));

  /* Create an ENTRY. */
  entry = xtrycalloc (1, sizeof *entry);
  if (!entry)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  entry->release_ptr = xtrymalloc (strlen (issuer_hash) + 1
                                   + strlen (issuer) + 1
                                   + strlen (url) + 1
                                   + strlen (checksum) + 1);
  if (!entry->release_ptr)
    {
      err = gpg_error_from_syserror ();
      xfree (entry);
      entry = NULL;
      goto leave;
    }
  entry->issuer_hash = entry->release_ptr;
  entry->issuer = stpcpy (entry->issuer_hash, issuer_hash) + 1;
  entry->url = stpcpy (entry->issuer, issuer) + 1;
  entry->dbfile_hash = stpcpy (entry->url, url) + 1;
  strcpy (entry->dbfile_hash, checksum);
  gnupg_copy_time (entry->this_update, thisupdate);
  gnupg_copy_time (entry->next_update, nextupdate);
  gnupg_copy_time (entry->last_refresh, current_time);
  entry->crl_number = get_crl_number (crl);
  entry->authority_issuer = get_auth_key_id (crl, &entry->authority_serialno);
  entry->invalid = invalidate_crl;
  entry->user_trust_req = !!trust_anchor;
  entry->check_trust_anchor = trust_anchor;
  trust_anchor = NULL;

  /* Check whether we already have an entry for this issuer and mark
     it as deleted. We better use a loop, just in case duplicates got
     somehow into the list. */
  for (e = cache->entries; (e=find_entry (e, entry->issuer_hash)); e = e->next)
    e->deleted = 1;

  /* Rename the temporary DB to the real name. */
  newfname = make_db_file_name (entry->issuer_hash);
  if (opt.verbose)
    log_info (_("creating cache file '%s'\n"), newfname);

  /* Just in case close unused matching files.  Actually we need this
     only under Windows but saving file descriptors is never bad.  */
  {
    int any;
    do
      {
        any = 0;
        for (e = cache->entries; e; e = e->next)
          if (!e->cdb_use_count && e->cdb
              && !strcmp (e->issuer_hash, entry->issuer_hash))
            {
              int fd = cdb_fileno (e->cdb);
              cdb_free (e->cdb);
              xfree (e->cdb);
              e->cdb = NULL;
              if (close (fd))
                log_error (_("error closing cache file: %s\n"),
                           strerror(errno));
              any = 1;
              break;
            }
      }
    while (any);
  }
#ifdef HAVE_W32_SYSTEM
  gnupg_remove (newfname);
#endif
  if (rename (fname, newfname))
    {
      err = gpg_error_from_syserror ();
      log_error (_("problem renaming '%s' to '%s': %s\n"),
                 fname, newfname, gpg_strerror (err));
      goto leave;
    }
  xfree (fname); fname = NULL; /*(let the cleanup code not try to remove it)*/

  /* Link the new entry in. */
  entry->next = cache->entries;
  cache->entries = entry;
  entry = NULL;

  err = update_dir (cache);
  if (err)
    {
      log_error (_("updating the DIR file failed - "
                   "cache entry will get lost with the next program start\n"));
      err = 0; /* Keep on running. */
    }


 leave:
  release_one_cache_entry (entry);
  if (fd_cdb != -1)
    close (fd_cdb);
  if (fname)
    {
      gnupg_remove (fname);
      xfree (fname);
    }
  xfree (newfname);
  ksba_crl_release (crl);
  xfree (issuer);
  xfree (issuer_hash);
  xfree (checksum);
  xfree (trust_anchor);
  return err ? err : err2;
}


/* Print one cached entry E in a human readable format to stream
   FP. Return 0 on success. */
static gpg_error_t
list_one_crl_entry (crl_cache_t cache, crl_cache_entry_t e, estream_t fp)
{
  struct cdb_find cdbfp;
  struct cdb *cdb;
  int rc;
  int warn = 0;
  const unsigned char *s;
  unsigned int invalid;

  es_fputs ("--------------------------------------------------------\n", fp );
  es_fprintf (fp, _("Begin CRL dump (retrieved via %s)\n"), e->url );
  es_fprintf (fp, " Issuer:\t%s\n", e->issuer );
  es_fprintf (fp, " Issuer Hash:\t%s\n", e->issuer_hash );
  es_fprintf (fp, " This Update:\t%s\n", e->this_update );
  es_fprintf (fp, " Next Update:\t%s\n", e->next_update );
  es_fprintf (fp, " CRL Number :\t%s\n", e->crl_number? e->crl_number: "none");
  es_fprintf (fp, " AuthKeyId  :\t%s\n",
              e->authority_serialno? e->authority_serialno:"none");
  if (e->authority_serialno && e->authority_issuer)
    {
      es_fputs ("             \t", fp);
      for (s=e->authority_issuer; *s; s++)
        if (*s == '\x01')
          es_fputs ("\n             \t", fp);
        else
          es_putc (*s, fp);
      es_putc ('\n', fp);
    }
  es_fprintf (fp, " Trust Check:\t%s\n",
              !e->user_trust_req? "[system]" :
              e->check_trust_anchor? e->check_trust_anchor:"[missing]");

  invalid = e->invalid;
  if ((invalid & INVCRL_TOO_OLD))
    {
      invalid &= ~INVCRL_TOO_OLD;
      es_fprintf (fp, _(" ERROR: The CRL will not be used "
                        "because it was still too old after an update!\n"));
    }
  if ((invalid & INVCRL_UNKNOWN_EXTN))
    {
      invalid &= ~INVCRL_UNKNOWN_EXTN;
      es_fprintf (fp, _(" ERROR: The CRL will not be used "
                      "due to an unknown critical extension!\n"));
    }
  if (invalid)  /* INVCRL_GENERAL or some other bits are set.  */
    es_fprintf (fp, _(" ERROR: The CRL will not be used\n"));

  cdb = lock_db_file (cache, e);
  if (!cdb)
    return gpg_error (GPG_ERR_GENERAL);

  if (!e->dbfile_checked)
    es_fprintf (fp, _(" ERROR: This cached CRL may have been tampered with!\n"));

  es_putc ('\n', fp);

  rc = cdb_findinit (&cdbfp, cdb, NULL, 0);
  while (!rc && (rc=cdb_findnext (&cdbfp)) > 0 )
    {
      unsigned char keyrecord[256];
      unsigned char record[16];
      int reason;
      int any = 0;
      cdbi_t n;
      cdbi_t i;

      rc = 0;
      n = cdb_datalen (cdb);
      if (n != 16)
        {
          log_error (_(" WARNING: invalid cache record length\n"));
          warn = 1;
          continue;
        }

      if (cdb_read (cdb, record, n, cdb_datapos (cdb)))
        {
          log_error (_("problem reading cache record: %s\n"),
                     strerror (errno));
          warn = 1;
          continue;
        }

      n = cdb_keylen (cdb);
      if (n > sizeof keyrecord)
        n = sizeof keyrecord;
      if (cdb_read (cdb, keyrecord, n, cdb_keypos (cdb)))
        {
          log_error (_("problem reading cache key: %s\n"), strerror (errno));
          warn = 1;
          continue;
        }

      reason = *record;
      es_fputs ("  ", fp);
      for (i = 0; i < n; i++)
        es_fprintf (fp, "%02X", keyrecord[i]);
      es_fputs (":\t reasons( ", fp);

      if (reason & KSBA_CRLREASON_UNSPECIFIED)
        es_fputs( "unspecified ", fp ), any = 1;
      if (reason & KSBA_CRLREASON_KEY_COMPROMISE )
        es_fputs( "key_compromise ", fp ), any = 1;
      if (reason & KSBA_CRLREASON_CA_COMPROMISE )
        es_fputs( "ca_compromise ", fp ), any = 1;
      if (reason & KSBA_CRLREASON_AFFILIATION_CHANGED )
        es_fputs( "affiliation_changed ", fp ), any = 1;
      if (reason & KSBA_CRLREASON_SUPERSEDED )
        es_fputs( "superseded", fp ), any = 1;
      if (reason & KSBA_CRLREASON_CESSATION_OF_OPERATION )
        es_fputs( "cessation_of_operation", fp ), any = 1;
      if (reason & KSBA_CRLREASON_CERTIFICATE_HOLD )
        es_fputs( "certificate_hold", fp ), any = 1;
      if (reason && !any)
        es_fputs( "other", fp );

      es_fprintf (fp, ") rdate: %.15s\n", record+1);
    }
  if (rc)
    log_error (_("error reading cache entry from db: %s\n"), strerror (rc));

  unlock_db_file (cache, e);
  es_fprintf (fp, _("End CRL dump\n") );
  es_putc ('\n', fp);

  return (rc||warn)? gpg_error (GPG_ERR_GENERAL) : 0;
}


/* Print the contents of the CRL CACHE in a human readable format to
   stream FP. */
gpg_error_t
crl_cache_list (estream_t fp)
{
  crl_cache_t cache = get_current_cache ();
  crl_cache_entry_t entry;
  gpg_error_t err = 0;

  for (entry = cache->entries;
       entry && !entry->deleted && !err;
       entry = entry->next )
    err = list_one_crl_entry (cache, entry, fp);

  return err;
}


/* Load the CRL containing the file named FILENAME into our CRL cache. */
gpg_error_t
crl_cache_load (ctrl_t ctrl, const char *filename)
{
  gpg_error_t err;
  estream_t fp;
  ksba_reader_t reader;

  fp = es_fopen (filename, "rb");
  if (!fp)
    {
      err = gpg_error_from_errno (errno);
      log_error (_("can't open '%s': %s\n"), filename, strerror (errno));
      return err;
    }

  err = create_estream_ksba_reader (&reader, fp);
  if (!err)
    {
      err = crl_cache_insert (ctrl, filename, reader);
      ksba_reader_release (reader);
    }
  es_fclose (fp);
  return err;
}


/* Locate the corresponding CRL for the certificate CERT, read and
   verify the CRL and store it in the cache.  */
gpg_error_t
crl_cache_reload_crl (ctrl_t ctrl, ksba_cert_t cert)
{
  gpg_error_t err;
  ksba_reader_t reader = NULL;
  char *issuer = NULL;
  ksba_name_t distpoint = NULL;
  ksba_name_t issuername = NULL;
  char *distpoint_uri = NULL;
  int any_dist_point = 0;
  int seq;
  gpg_error_t last_err = 0;

  /* Loop over all distribution points, get the CRLs and put them into
     the cache. */
  if (opt.verbose)
    log_info ("checking distribution points\n");
  seq = 0;
  while (xfree (distpoint), xfree (issuername),
         !(err = ksba_cert_get_crl_dist_point (cert, seq++,
                                                &distpoint,
                                                &issuername, NULL )))
    {
      int name_seq;

      if (!distpoint && !issuername)
        {
          if (opt.verbose)
            log_info ("no issuer name and no distribution point\n");
          break; /* Not allowed; i.e. an invalid certificate.  We give
                    up here and hope that the default method returns a
                    suitable CRL. */
        }

      /* Get the URIs.  We do this in a loop to iterate over all names
         in the crlDP. */
      for (name_seq=0; ksba_name_enum (distpoint, name_seq); name_seq++)
        {
          xfree (distpoint_uri);
          distpoint_uri = ksba_name_get_uri (distpoint, name_seq);
          if (!distpoint_uri)
            continue;

          if (!strncmp (distpoint_uri, "ldap:", 5)
              || !strncmp (distpoint_uri, "ldaps:", 6))
            {
              if (opt.ignore_ldap_dp)
                continue;
            }
          else if (!strncmp (distpoint_uri, "http:", 5)
                   || !strncmp (distpoint_uri, "https:", 6))
            {
              if (opt.ignore_http_dp)
                continue;
            }
          else
            continue; /* Skip unknown schemes. */

          any_dist_point = 1;

          crl_close_reader (reader);
          err = crl_fetch (ctrl, distpoint_uri, &reader);
          if (err)
            {
              log_error (_("crl_fetch via DP failed: %s\n"),
                         gpg_strerror (err));
              last_err = err;
              continue; /* with the next name. */
            }

          if (opt.verbose)
            log_info ("inserting CRL (reader %p)\n", reader);
          err = crl_cache_insert (ctrl, distpoint_uri, reader);
          if (err)
            {
              log_error (_("crl_cache_insert via DP failed: %s\n"),
                         gpg_strerror (err));
              last_err = err;
              continue; /* with the next name. */
            }
          goto leave; /* Ready - we got the CRL. */
        }
    }
  if (gpg_err_code (err) == GPG_ERR_EOF)
    err = 0;
  if (!err && last_err)
    {
      err = last_err;
      goto leave;
    }

  /* If we did not found any distpoint, try something reasonable. */
  if (!any_dist_point )
    {
      if (opt.verbose)
        log_info ("no distribution point - trying issuer name\n");

      issuer = ksba_cert_get_issuer (cert, 0);
      if (!issuer)
        {
          log_error ("oops: issuer missing in certificate\n");
          err = gpg_error (GPG_ERR_INV_CERT_OBJ);
          goto leave;
        }

      if (opt.verbose)
        log_info ("fetching CRL from default location\n");
      crl_close_reader (reader);
      err = crl_fetch_default (ctrl, issuer, &reader);
      if (err)
          {
            log_error ("crl_fetch via issuer failed: %s\n",
                       gpg_strerror (err));
            goto leave;
          }

      if (opt.verbose)
        log_info ("inserting CRL (reader %p)\n", reader);
      err = crl_cache_insert (ctrl, "default location(s)", reader);
      if (err)
        {
          log_error (_("crl_cache_insert via issuer failed: %s\n"),
                     gpg_strerror (err));
          goto leave;
        }
    }

 leave:
  crl_close_reader (reader);
  xfree (distpoint_uri);
  ksba_name_release (distpoint);
  ksba_name_release (issuername);
  ksba_free (issuer);
  return err;
}
