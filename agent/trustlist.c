/* trustlist.c - Maintain the list of trusted keys
 *	Copyright (C) 2002, 2004, 2006 Free Software Foundation, Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
 */

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pth.h>

#include "agent.h"
#include <assuan.h> /* fixme: need a way to avoid assuan calls here */
#include "i18n.h"


/* A structure to store the information from the trust file. */
struct trustitem_s
{
  int keyflag;            /* The keyflag:  '*', 'P' or 'S'. */
  unsigned char fpr[20];  /* The binary fingerprint. */
};
typedef struct trustitem_s trustitem_t;

/* Malloced table and its allocated size with all trust items. */
static trustitem_t *trusttable; 
static size_t trusttablesize; 
/* A mutex used to protect the table. */
static pth_mutex_t trusttable_lock = PTH_MUTEX_INIT;



static const char headerblurb[] =
"# This is the list of trusted keys.  Comment lines, like this one, as\n"
"# well as empty lines are ignored.  Lines have a length limit but this\n"
"# is not serious limitation as the format of the entries is fixed and\n"
"# checked by gpg-agent.  A non-comment line starts with optional white\n"
"# space, followed by the SHA-1 fingerpint in hex, optionally followed\n"
"# by a flag character which my either be 'P', 'S' or '*'.  You should\n"
"# give the gpg-agent a HUP after editing this file.\n"
"\n\n"
"# Include the default trust list\n"
"include-default\n"
"\n";




static void
lock_trusttable (void)
{
  if (!pth_mutex_acquire (&trusttable_lock, 0, NULL))
    log_fatal ("failed to acquire mutex in %s\n", __FILE__);
}

static void
unlock_trusttable (void)
{
  if (!pth_mutex_release (&trusttable_lock))
    log_fatal ("failed to release mutex in %s\n", __FILE__);
}



static gpg_error_t
read_one_trustfile (const char *fname, int allow_include,
                    trustitem_t **addr_of_table, 
                    size_t *addr_of_tablesize,
                    int *addr_of_tableidx)
{
  gpg_error_t err = 0;
  FILE *fp;
  int n, c;
  char *p, line[256];
  trustitem_t *table, *ti;
  int tableidx;
  size_t tablesize;
  int lnr = 0;

  table = *addr_of_table;
  tablesize = *addr_of_tablesize;
  tableidx = *addr_of_tableidx;

  fp = fopen (fname, "r");
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      log_error (_("error opening `%s': %s\n"), fname, gpg_strerror (err));
      goto leave;
    }

  while (fgets (line, DIM(line)-1, fp))
    {
      lnr++;
      
      if (!*line || line[strlen(line)-1] != '\n')
        {
          /* Eat until end of line. */
          while ( (c=getc (fp)) != EOF && c != '\n')
            ;
          err = gpg_error (*line? GPG_ERR_LINE_TOO_LONG
                           : GPG_ERR_INCOMPLETE_LINE);
          log_error (_("file `%s', line %d: %s\n"),
                     fname, lnr, gpg_strerror (err));
          continue;
        }
      line[strlen(line)-1] = 0; /* Chop the LF. */
      
      /* Allow for empty lines and spaces */
      for (p=line; spacep (p); p++)
        ;
      if (!*p || *p == '#')
        continue;
  
      if (!strncmp (p, "include-default", 15)
          && (!p[15] || spacep (p+15)))
        {
          char *etcname;
          gpg_error_t err2;

          if (!allow_include)
            {
              log_error (_("statement \"%s\" ignored in `%s', line %d\n"),
                         "include-default", fname, lnr);
              continue;
            }
          /* fixme: Should check for trailing garbage.  */

          etcname = make_filename (GNUPG_SYSCONFDIR, "trustlist.txt", NULL);
          if ( !strcmp (etcname, fname) ) /* Same file. */
            log_info (_("statement \"%s\" ignored in `%s', line %d\n"),
                      "include-default", fname, lnr);
          else if ( access (etcname, F_OK) && errno == ENOENT )
            {
              /* A non existent system trustlist is not an error.
                 Just print a note. */
              log_info (_("system trustlist `%s' not available\n"), etcname);
            }
          else
            {
              err2 = read_one_trustfile (etcname, 0,
                                         &table, &tablesize, &tableidx);
              if (err2)
                err = err2;
            }
          xfree (etcname);
          
          continue;
        }

      if (tableidx == tablesize)  /* Need more space. */
        {
          trustitem_t *tmp;
          size_t tmplen;
          
          tmplen = tablesize + 20;
          tmp = xtryrealloc (table, tmplen * sizeof *table);
          if (!tmp)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          table = tmp;
          tablesize = tmplen;
        }

      ti = table + tableidx;

      n = hexcolon2bin (p, ti->fpr, 20);
      if (n < 0)
        {
          log_error (_("bad fingerprint in `%s', line %d\n"), fname, lnr);
          err = gpg_error (GPG_ERR_BAD_DATA); 
          continue;
        }
      p += n;
      for (; spacep (p); p++)
        ;
      
      if (!*p)
        ti->keyflag = '*';
      else if ( *p == 'P' || *p == 'p')
        ti->keyflag = 'P';
      else if ( *p == 'S' || *p == 's')
        ti->keyflag = 'S';
      else if ( *p == '*')
        ti->keyflag = '*';
      else
        {
          log_error (_("invalid keyflag in `%s', line %d\n"), fname, lnr);
          err = gpg_error (GPG_ERR_BAD_DATA);
          continue;
        }
      p++;
      if ( *p && !spacep (p) )
        {
          log_error (_("invalid keyflag in `%s', line %d\n"), fname, lnr);
          err = gpg_error (GPG_ERR_BAD_DATA);
          continue;
        }
      /* Fixme: need to check for trailing garbage. */
      tableidx++;
    }
  if ( !err && !feof (fp) )
    {
      err = gpg_error_from_syserror ();
      log_error (_("error reading `%s', line %d: %s\n"),
                 fname, lnr, gpg_strerror (err));
    }

 leave:
  if (fp)
    fclose (fp);
  *addr_of_table = table;
  *addr_of_tablesize = tablesize;
  *addr_of_tableidx = tableidx;
  return err;
}


/* Read the trust files and update the global table on success. */
static gpg_error_t
read_trustfiles (void)
{
  gpg_error_t err;
  trustitem_t *table, *ti;
  int tableidx;
  size_t tablesize;
  char *fname;
  int allow_include = 1;

  tablesize = 10;
  table = xtrycalloc (tablesize, sizeof *table);
  if (!table)
    return gpg_error_from_syserror ();
  tableidx = 0;

  fname = make_filename (opt.homedir, "trustlist.txt", NULL);
  if ( access (fname, F_OK) )
    {
      if ( errno == ENOENT )
        ; /* Silently ignore a non-existing trustfile.  */
      else
        {
          err = gpg_error_from_syserror ();
          log_error (_("error opening `%s': %s\n"), fname, gpg_strerror (err));
        }
      xfree (fname);
      fname = make_filename (GNUPG_SYSCONFDIR, "trustlist.txt", NULL);
      allow_include = 0;
    }
  err = read_one_trustfile (fname, allow_include,
                            &table, &tablesize, &tableidx);
  xfree (fname);

  if (err)
    {
      xfree (table);
      return err;
    }

  /* Fixme: we should drop duplicates and sort the table. */

  ti = xtryrealloc (table, tableidx * sizeof *table);
  if (!ti)
    {
      xfree (table);
      return err;
    }

  lock_trusttable ();
  xfree (trusttable);
  trusttable = table;
  trusttablesize = tableidx;
  unlock_trusttable ();
  return 0;
}



/* Check whether the given fpr is in our trustdb.  We expect FPR to be
   an all uppercase hexstring of 40 characters. */
gpg_error_t 
agent_istrusted (const char *fpr)
{
  gpg_error_t err;
  trustitem_t *ti;
  size_t len;
  unsigned char fprbin[20];

  if ( hexcolon2bin (fpr, fprbin, 20) < 0 )
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!trusttable)
    {
      err = read_trustfiles ();
      if (err)
        {
          log_error (_("error reading list of trusted root certificates\n"));
          return err;
        }
    }

  if (trusttable)
    {
      for (ti=trusttable, len = trusttablesize; len; ti++, len--)
        if (!memcmp (ti->fpr, fprbin, 20))
          return 0; /* Trusted. */
    }
  return gpg_error (GPG_ERR_NOT_TRUSTED);
}


/* Write all trust entries to FP. */
gpg_error_t 
agent_listtrusted (void *assuan_context)
{
  trustitem_t *ti;
  char key[51];
  gpg_error_t err;
  size_t len;

  if (!trusttable)
    {
      err = read_trustfiles ();
      if (err)
        {
          log_error (_("error reading list of trusted root certificates\n"));
          return err;
        }
    }

  if (trusttable)
    {
      /* We need to lock the table because the scheduler may interrupt
         assuan_send_data and an other thread may then re-read the table. */
      lock_trusttable ();
      for (ti=trusttable, len = trusttablesize; len; ti++, len--)
        {
          bin2hex (ti->fpr, 20, key);
          key[40] = ' ';
          key[41] = ti->keyflag;
          key[42] = '\n';
          assuan_send_data (assuan_context, key, 43);
          assuan_send_data (assuan_context, NULL, 0); /* flush */
        }
      unlock_trusttable ();
    }

  return 0;
}


/* Insert the given fpr into our trustdb.  We expect FPR to be an all
   uppercase hexstring of 40 characters. FLAG is either 'P' or 'C'.
   This function does first check whether that key has alreay been put
   into the trustdb and returns success in this case.  Before a FPR
   actually gets inserted, the user is asked by means of the pin-entry
   whether this is actual wants he want to do.
*/
gpg_error_t
agent_marktrusted (ctrl_t ctrl, const char *name, const char *fpr, int flag)
{
  gpg_error_t err = 0;
  char *desc;
  char *fname;
  FILE *fp;

  /* Check whether we are at all allowed to modify the trustlist.
     This is useful so that the trustlist may be a symlink to a global
     trustlist with only admin priviliges to modify it.  Of course
     this is not a secure way of denying access, but it avoids the
     usual clicking on an Okay button most users are used to. */
  fname = make_filename (opt.homedir, "trustlist.txt", NULL);
  if ( access (fname, W_OK) && errno != ENOENT)
    {
      xfree (fname);
      return gpg_error (GPG_ERR_EPERM);
    }    
  xfree (fname);

  if (!agent_istrusted (fpr))
    {
      return 0; /* We already got this fingerprint.  Silently return
                   success. */
    }

  /* This feature must explicitly been enabled. */
  if (!opt.allow_mark_trusted)
    return gpg_error (GPG_ERR_NOT_SUPPORTED);

  /* Insert a new one. */
  if (asprintf (&desc,
                /* TRANSLATORS: This prompt is shown by the Pinentry
                   and has one special property: A "%%0A" is used by
                   Pinentry to insert a line break.  The double
                   percent sign is actually needed because it is also
                   a printf format string.  If you need to insert a
                   plain % sign, you need to encode it as "%%25".  The
                   second "%s" gets replaced by a hexdecimal
                   fingerprint string whereas the first one receives
                   the name as store in the certificate. */
                _("Please verify that the certificate identified as:%%0A"
                  "  \"%s\"%%0A"
                  "has the fingerprint:%%0A"
                  "  %s"), name, fpr) < 0 )
    return out_of_core ();

  /* TRANSLATORS: "Correct" is the label of a button and intended to
     be hit if the fingerprint matches the one of the CA.  The other
     button is "the default "Cancel" of the Pinentry. */
  err = agent_get_confirmation (ctrl, desc, _("Correct"), NULL);
  free (desc);
  if (err)
    return err;

  if (asprintf (&desc,
                /* TRANSLATORS: This prompt is shown by the Pinentry
                   and has one special property: A "%%0A" is used by
                   Pinentry to insert a line break.  The double
                   percent sign is actually needed because it is also
                   a printf format string.  If you need to insert a
                   plain % sign, you need to encode it as "%%25".  The
                   "%s" gets replaced by the name as store in the
                   certificate. */
                _("Do you ultimately trust%%0A"
                  "  \"%s\"%%0A"
                  "to correctly certify user certificates?"),
                name) < 0 )
    return out_of_core ();

  err = agent_get_confirmation (ctrl, desc, _("Yes"), _("No"));
  free (desc);
  if (err)
    return err;

  /* Now check again to avoid duplicates.  We take the lock to make
     sure that nobody else plays with our file.  Frankly we don't work
     with the trusttable but using this lock is just fine for our
     purpose.  */
  lock_trusttable ();
  if (!agent_istrusted (fpr))
    {
      unlock_trusttable ();
      return 0; 
    }


  fname = make_filename (opt.homedir, "trustlist.txt", NULL);
  if ( access (fname, F_OK) && errno == ENOENT)
    {
      fp = fopen (fname, "wx"); /* Warning: "x" is a GNU extension. */
      if (!fp)
        {
          err = gpg_error_from_syserror ();
          log_error ("can't create `%s': %s\n", fname, gpg_strerror (err));
          xfree (fname);
          unlock_trusttable ();
          return err;
        }
      fputs (headerblurb, fp);
      fclose (fp);
    }
  fp = fopen (fname, "a+");
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      log_error ("can't open `%s': %s\n", fname, gpg_strerror (err));
      xfree (fname);
      unlock_trusttable ();
      return err;
    }

  /* Append the key. */
  fputs ("\n# ", fp);
  print_sanitized_string (fp, name, 0);
  fprintf (fp, "\n%s %c\n", fpr, flag);
  if (ferror (fp))
    err = gpg_error_from_syserror ();
  
  if (fclose (fp))
    err = gpg_error_from_syserror ();

  if (!err)
    agent_reload_trustlist ();
  xfree (fname);
  unlock_trusttable ();
  return err;
}


/* This function may be called to force reloading of the
   trustlist.  */
void
agent_reload_trustlist (void)
{
  /* All we need to do is to delete the trusttable.  At the next
     access it will get re-read. */
  lock_trusttable ();
  xfree (trusttable);
  trusttable = NULL;
  trusttablesize = 0;
  unlock_trusttable ();
}
