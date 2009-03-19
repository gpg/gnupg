/* trustlist.c - Maintain the list of trusted keys
 * Copyright (C) 2002, 2004, 2006, 2007, 2009 Free Software Foundation, Inc.
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
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
  struct
  {
    int disabled:1;       /* This entry is disabled.  */
    int for_pgp:1;        /* Set by '*' or 'P' as first flag. */
    int for_smime:1;      /* Set by '*' or 'S' as first flag. */
    int relax:1;          /* Relax checking of root certificate
                             constraints. */
    int cm:1;             /* Use chain model for validation. */
  } flags;
  unsigned char fpr[20];  /* The binary fingerprint. */
};
typedef struct trustitem_s trustitem_t;

/* Malloced table and its allocated size with all trust items. */
static trustitem_t *trusttable; 
static size_t trusttablesize; 
/* A mutex used to protect the table. */
static pth_mutex_t trusttable_lock;



static const char headerblurb[] =
"# This is the list of trusted keys.  Comment lines, like this one, as\n"
"# well as empty lines are ignored.  Lines have a length limit but this\n"
"# is not a serious limitation as the format of the entries is fixed and\n"
"# checked by gpg-agent.  A non-comment line starts with optional white\n"
"# space, followed by the SHA-1 fingerpint in hex, followed by a flag\n"
"# which may be one of 'P', 'S' or '*' and optionally followed by a list of\n"
"# other flags.  The fingerprint may be prefixed with a '!' to mark the\n"
"# key as not trusted.  You should give the gpg-agent a HUP or run the\n"
"# command \"gpgconf --reload gpg-agent\" after changing this file.\n"
"\n\n"
"# Include the default trust list\n"
"include-default\n"
"\n";


/* This function must be called once to initialize this module.  This
   has to be done before a second thread is spawned.  We can't do the
   static initialization because Pth emulation code might not be able
   to do a static init; in particular, it is not possible for W32. */
void
initialize_module_trustlist (void)
{
  static int initialized;

  if (!initialized)
    {
      if (!pth_mutex_init (&trusttable_lock))
        log_fatal ("error initializing mutex: %s\n", strerror (errno));
      initialized = 1;
    }
}




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

          etcname = make_filename (gnupg_sysconfdir (), "trustlist.txt", NULL);
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

      memset (&ti->flags, 0, sizeof ti->flags);
      if (*p == '!')
        {
          ti->flags.disabled = 1;
          p++;
          while (spacep (p))
            p++;
        }

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
      
      /* Process the first flag which needs to be the first for
         backward compatibility. */
      if (!*p || *p == '*' )
        {
          ti->flags.for_smime = 1;
          ti->flags.for_pgp = 1;
        }
      else if ( *p == 'P' || *p == 'p')
        {
          ti->flags.for_pgp = 1;
        }
      else if ( *p == 'S' || *p == 's')
        {
          ti->flags.for_smime = 1;
        }
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

      /* Now check for more key-value pairs of the form NAME[=VALUE]. */
      while (*p)
        {
          for (; spacep (p); p++)
            ;
          if (!*p)
            break;
          n = strcspn (p, "= \t");
          if (p[n] == '=')
            {
              log_error ("assigning a value to a flag is not yet supported; "
                         "in `%s', line %d\n", fname, lnr);
              err = gpg_error (GPG_ERR_BAD_DATA);
              p++;
            }
          else if (n == 5 && !memcmp (p, "relax", 5))
            ti->flags.relax = 1;
          else if (n == 2 && !memcmp (p, "cm", 2))
            ti->flags.cm = 1;
          else
            log_error ("flag `%.*s' in `%s', line %d ignored\n",
                       n, p, fname, lnr);
          p += n;
        }
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


/* Read the trust files and update the global table on success.  */
static gpg_error_t
read_trustfiles (void)
{
  gpg_error_t err;
  trustitem_t *table, *ti;
  int tableidx;
  size_t tablesize;
  char *fname;
  int allow_include = 1;

  tablesize = 20;
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
      fname = make_filename (gnupg_sysconfdir (), "trustlist.txt", NULL);
      allow_include = 0;
    }
  err = read_one_trustfile (fname, allow_include,
                            &table, &tablesize, &tableidx);
  xfree (fname);

  if (err)
    {
      xfree (table);
      if (gpg_err_code (err) == GPG_ERR_ENOENT)
        {
          /* Take a missing trustlist as an empty one.  */
          lock_trusttable ();
          xfree (trusttable);
          trusttable = NULL;
          trusttablesize = 0;
          unlock_trusttable ();
          err = 0;
        }
      return err;
    }

  /* Fixme: we should drop duplicates and sort the table. */
  ti = xtryrealloc (table, (tableidx?tableidx:1) * sizeof *table);
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
agent_istrusted (ctrl_t ctrl, const char *fpr, int *r_disabled)
{
  gpg_error_t err;
  trustitem_t *ti;
  size_t len;
  unsigned char fprbin[20];

  if (r_disabled)
    *r_disabled = 0;

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
          {
            if (ti->flags.relax)
              {
                err = agent_write_status (ctrl,
                                          "TRUSTLISTFLAG", "relax", 
                                          NULL);
                if (err)
                  return err;
              }
            else if (ti->flags.cm)
              {
                err = agent_write_status (ctrl,
                                          "TRUSTLISTFLAG", "cm", 
                                          NULL);
                if (err)
                  return err;
              }
            if (ti->flags.disabled)
              {
                if (r_disabled)
                  *r_disabled = 1;
                return gpg_error (GPG_ERR_NOT_TRUSTED);
              }
            return 0; /* Trusted.  */
          }
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
          if (ti->flags.disabled)
            continue;
          bin2hex (ti->fpr, 20, key);
          key[40] = ' ';
          key[41] = ((ti->flags.for_smime && ti->flags.for_pgp)? '*'
                     : ti->flags.for_smime? 'S': ti->flags.for_pgp? 'P':' ');
          key[42] = '\n';
          assuan_send_data (assuan_context, key, 43);
          assuan_send_data (assuan_context, NULL, 0); /* flush */
        }
      unlock_trusttable ();
    }

  return 0;
}


/* Create a copy of string with colons inserted after each two bytes.
   Caller needs to release the string.  In case of a memory failure,
   NULL is returned.  */
static char *
insert_colons (const char *string)
{
  char *buffer, *p;
  size_t n = strlen (string);
  size_t nnew = n + (n+1)/2;

  p = buffer = xtrymalloc ( nnew + 1 );
  if (!buffer)
    return NULL;
  while (*string)
    {
      *p++ = *string++;
      if (*string)
        {
          *p++ = *string++;
          if (*string)
            *p++ = ':';
        }
    }
  *p = 0;
  assert (strlen (buffer) <= nnew);

  return buffer;
}


/* Insert the given fpr into our trustdb.  We expect FPR to be an all
   uppercase hexstring of 40 characters. FLAG is either 'P' or 'C'.
   This function does first check whether that key has already been put
   into the trustdb and returns success in this case.  Before a FPR
   actually gets inserted, the user is asked by means of the Pinentry
   whether this is actual want he wants to do.  */
gpg_error_t
agent_marktrusted (ctrl_t ctrl, const char *name, const char *fpr, int flag)
{
  gpg_error_t err = 0;
  char *desc;
  char *fname;
  FILE *fp;
  char *fprformatted;
  int is_disabled;
  int yes_i_trust;

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

  if (!agent_istrusted (ctrl, fpr, &is_disabled))
    {
      return 0; /* We already got this fingerprint.  Silently return
                   success. */
    }
  
  /* This feature must explicitly been enabled. */
  if (!opt.allow_mark_trusted)
    return gpg_error (GPG_ERR_NOT_SUPPORTED);

  if (is_disabled)
    {
      /* There is an disabled entry in the trustlist.  Return an error
         so that the user won't be asked again for that one.  Changing
         this flag with the integrated marktrusted feature is and will
         not be made possible.  */
      return gpg_error (GPG_ERR_NOT_TRUSTED);
    }


  /* Insert a new one. */

  /* First a general question whether this is trusted.  */
  desc = xtryasprintf (
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
                name);
  if (!desc)
    return out_of_core ();
  err = agent_get_confirmation (ctrl, desc, _("Yes"), _("No"));
  xfree (desc);
  if (!err)
    yes_i_trust = 1;
  else if (gpg_err_code (err) == GPG_ERR_NOT_CONFIRMED)
    yes_i_trust = 0;
  else
    return err;


  fprformatted = insert_colons (fpr);
  if (!fprformatted)
    return out_of_core ();

  /* If the user trusts this certificate he has to verify the
     fingerprint of course.  */
  if (yes_i_trust)
    {
      desc = xtryasprintf 
        (
         /* TRANSLATORS: This prompt is shown by the Pinentry and has
            one special property: A "%%0A" is used by Pinentry to
            insert a line break.  The double percent sign is actually
            needed because it is also a printf format string.  If you
            need to insert a plain % sign, you need to encode it as
            "%%25".  The second "%s" gets replaced by a hexdecimal
            fingerprint string whereas the first one receives the name
            as stored in the certificate. */
         _("Please verify that the certificate identified as:%%0A"
           "  \"%s\"%%0A"
           "has the fingerprint:%%0A"
           "  %s"), name, fprformatted);
      if (!desc)
        {
          xfree (fprformatted);
          return out_of_core ();
        }
      
      /* TRANSLATORS: "Correct" is the label of a button and intended
         to be hit if the fingerprint matches the one of the CA.  The
         other button is "the default "Cancel" of the Pinentry. */
      err = agent_get_confirmation (ctrl, desc, _("Correct"), _("Wrong"));
      xfree (desc);
      if (gpg_err_code (err) == GPG_ERR_NOT_CONFIRMED)
        yes_i_trust = 0;
      else if (err)
        {
          xfree (fprformatted);
          return err;
        }
    }


  /* Now check again to avoid duplicates.  We take the lock to make
     sure that nobody else plays with our file.  Frankly we don't work
     with the trusttable but using this lock is just fine for our
     purpose.  */
  lock_trusttable ();
  {
    int now_disabled;

    if (!agent_istrusted (ctrl, fpr, &now_disabled) || now_disabled)
      {
        unlock_trusttable ();
        xfree (fprformatted);
        return now_disabled? gpg_error (GPG_ERR_NOT_TRUSTED) : 0; 
      }
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
          xfree (fprformatted);
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
      xfree (fprformatted);
      return err;
    }

  /* Append the key. */
  fputs ("\n# ", fp);
  print_sanitized_string (fp, name, 0);
  fprintf (fp, "\n%s%s %c\n", yes_i_trust?"":"!", fprformatted, flag);
  if (ferror (fp))
    err = gpg_error_from_syserror ();
  
  if (fclose (fp))
    err = gpg_error_from_syserror ();

  if (!err)
    agent_reload_trustlist ();
  xfree (fname);
  unlock_trusttable ();
  xfree (fprformatted);
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
  bump_key_eventcounter ();
}
