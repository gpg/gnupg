/* trustlist.c - Maintain the list of trusted keys
 *	Copyright (C) 2002, 2004 Free Software Foundation, Inc.
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>

#include "agent.h"
#include <assuan.h> /* fixme: need a way to avoid assuan calls here */

static const char headerblurb[] =
"# This is the list of trusted keys.  Comments like this one and empty\n"
"# lines are allowed but keep in mind that the entire file is integrity\n"
"# protected by the use of a MAC, so changing the file does not make\n"
"# much sense without the knowledge of the MAC key.  Lines do have a\n"
"# length limit but this is not serious limitation as the format of the\n"
"# entries is fixed and checked by gpg-agent: A non-comment line starts\n"
"# with optional white spaces, followed by exactly 40 hex character,\n"
"# optioanlly followed by a flag character which my either be 'P', 'S'\n"
"# or '*'. Additional data delimited with by a white space is ignored.\n"
"# NOTE: You should give the gpg-agent a HUP after editing this file.\n"
"\n";


static FILE *trustfp;
static int   trustfp_used; /* Counter to track usage of TRUSTFP. */
static int   reload_trustlist_pending;


static int
open_list (int append)
{
  char *fname;

  fname = make_filename (opt.homedir, "trustlist.txt", NULL);
  trustfp = fopen (fname, append? "a+":"r");
  if (!trustfp && errno == ENOENT)
    {
      trustfp = fopen (fname, "wx");
      if (!trustfp)
        {
          gpg_error_t tmperr = gpg_error (gpg_err_code_from_errno (errno));
          log_error ("can't create `%s': %s\n", fname, strerror (errno));
          xfree (fname);
          return tmperr;
        }
      fputs (headerblurb, trustfp);
      fclose (trustfp);
      trustfp = fopen (fname, append? "a+":"r");
    }

  if (!trustfp)
    {
      gpg_error_t tmperr = gpg_error (gpg_err_code_from_errno (errno));
      log_error ("can't open `%s': %s\n", fname, strerror (errno));
      xfree (fname);
      return tmperr;
    }

  /*FIXME: check the MAC */

  return 0;
}



/* Read the trustlist and return entry by entry.  KEY must point to a
   buffer of at least 41 characters. KEYFLAG does return either 'P',
   'S' or '*'.

   Reading a valid entry return 0, EOF returns -1 any other error
   returns the appropriate error code. */
static int
read_list (char *key, int *keyflag)
{
  int rc;
  int c, i;
  char *p, line[256];
  
  if (!trustfp)
    {
      rc = open_list (0);
      if (rc)
        return rc;
    }

  do
    {
      if (!fgets (line, DIM(line)-1, trustfp) )
        {
          if (feof (trustfp))
            return -1;
          return gpg_error (gpg_err_code_from_errno (errno));
        }
      
      if (!*line || line[strlen(line)-1] != '\n')
        {
          /* eat until end of line */
          while ( (c=getc (trustfp)) != EOF && c != '\n')
            ;
          return gpg_error (*line? GPG_ERR_LINE_TOO_LONG
                                 : GPG_ERR_INCOMPLETE_LINE);
        }
      
      /* Allow for emty lines and spaces */
      for (p=line; spacep (p); p++)
        ;
    }
  while (!*p || *p == '\n' || *p == '#');
  
  for (i=0; hexdigitp (p+i) && i < 40; i++)
    key[i] = p[i] >= 'a'? (p[i] & 0xdf): p[i];
  key[i] = 0;
  if (i!=40 || !(spacep (p+i) || p[i] == '\n'))
    {
      log_error ("invalid formatted fingerprint in trustlist\n");
      return gpg_error (GPG_ERR_BAD_DATA);
    }
  assert (p[i]);
  if (p[i] == '\n')
    *keyflag = '*';
  else 
    {
      i++;
      if ( p[i] == 'P' || p[i] == 'p')
        *keyflag = 'P';
      else if ( p[i] == 'S' || p[i] == 's')
        *keyflag = 'S';
      else if ( p[i] == '*')
        *keyflag = '*';
      else
        {
          log_error ("invalid keyflag in trustlist\n");
          return gpg_error (GPG_ERR_BAD_DATA);
        }
      i++;
      if ( !(spacep (p+i) || p[i] == '\n'))
        {
          log_error ("invalid keyflag in trustlist\n");
          return gpg_error (GPG_ERR_BAD_DATA);
        }
    }

  return 0;
}

/* Check whether the given fpr is in our trustdb.  We expect FPR to be
   an all uppercase hexstring of 40 characters. */
int 
agent_istrusted (const char *fpr)
{
  int rc;
  static char key[41];
  int keyflag;

  trustfp_used++;
  if (trustfp)
    rewind (trustfp);
  while (!(rc=read_list (key, &keyflag)))
    {
      if (!strcmp (key, fpr))
        {
          trustfp_used--;
          return 0;
        }
    }
  if (rc != -1)
    {
      /* Error in the trustdb - close it to give the user a chance for
         correction */
      if (trustfp)
        fclose (trustfp);
      trustfp = NULL;
    }
  trustfp_used--;
  return rc;
}


/* Write all trust entries to FP. */
int 
agent_listtrusted (void *assuan_context)
{
  int rc;
  static char key[51];
  int keyflag;

  trustfp_used++;
  if (trustfp)
    rewind (trustfp);
  while (!(rc=read_list (key, &keyflag)))
    {
      key[40] = ' ';
      key[41] = keyflag;
      key[42] = '\n';
      assuan_send_data (assuan_context, key, 43);
      assuan_send_data (assuan_context, NULL, 0); /* flush */
    } 
  if (rc == -1)
    rc = 0;
  if (rc)
    {
      /* Error in the trustdb - close it to give the user a chance for
         correction */
      if (trustfp)
        fclose (trustfp);
      trustfp = NULL;
    }
  trustfp_used--;
  return rc;
}


/* Insert the given fpr into our trustdb.  We expect FPR to be an all
   uppercase hexstring of 40 characters. FLAG is either 'P' or 'C'.
   This function does first check whether that key has alreay been put
   into the trustdb and returns success in this case.  Before a FPR
   actually gets inserted, the user is asked by means of the pin-entry
   whether this is actual wants he want to do.
*/
int 
agent_marktrusted (CTRL ctrl, const char *name, const char *fpr, int flag)
{
  int rc;
  static char key[41];
  int keyflag;
  char *desc;
  char *fname;

  /* Check whether we are at all allowed to modify the trustlist.
     This is useful so that the trustlist may be a symlink to a global
     trustlist with only admin priviliges to modify it.  Of course
     this is not a secure way of denying access, but it avoids the
     usual clicking on an Okay buttun thing most users are used to. */
  fname = make_filename (opt.homedir, "trustlist.txt", NULL);
  rc = access (fname, W_OK);
  if (rc && errno != ENOENT)
    {
      xfree (fname);
      return gpg_error (GPG_ERR_EPERM);
    }    
  xfree (fname);

  trustfp_used++;
  if (trustfp)
    rewind (trustfp);
  while (!(rc=read_list (key, &keyflag)))
    {
      if (!strcmp (key, fpr))
        return 0;
    }
  if (trustfp)
    fclose (trustfp);
  trustfp = NULL;
  if (rc != -1)
    {
      trustfp_used--;
      return rc;   /* Error in the trustlist. */
    }

  /* This feature must explicitly been enabled. */
  if (!opt.allow_mark_trusted)
    {
      trustfp_used--;
      return gpg_error (GPG_ERR_NOT_SUPPORTED);
    }

  /* insert a new one */
  if (asprintf (&desc,
                "Please verify that the certificate identified as:%%0A"
                "  \"%s\"%%0A"
                "has the fingerprint:%%0A"
                "  %s", name, fpr) < 0 )
    {
      trustfp_used--;
      return out_of_core ();
    }
  rc = agent_get_confirmation (ctrl, desc, "Correct", "No");
  free (desc);
  if (rc)
    {
      trustfp_used--;
      return rc;
    }

  if (asprintf (&desc,
                "Do you ultimately trust%%0A"
                "  \"%s\"%%0A"
                "to correctly certify user certificates?",
                name) < 0 )
    {
      trustfp_used--;
      return out_of_core ();
    }
  rc = agent_get_confirmation (ctrl, desc, "Yes", "No");
  free (desc);
  if (rc)
    {
      trustfp_used--;
      return rc;
    }

  /* Now check again to avoid duplicates.  Also open in append mode now. */
  rc = open_list (1);
  if (rc)
    {
      trustfp_used--;
      return rc;
    }
  rewind (trustfp);
  while (!(rc=read_list (key, &keyflag)))
    {
      if (!strcmp (key, fpr))
        {
          trustfp_used--;
          return 0;
        }
    }
  if (rc != -1)
    {
      if (trustfp)
        fclose (trustfp);
      trustfp = NULL;
      trustfp_used--;
      return rc;   /* Error in the trustlist. */
    }
  rc = 0;

  /* Append the key. */
  fflush (trustfp);
  fputs ("\n# ", trustfp);
  print_sanitized_string (trustfp, name, 0);
  fprintf (trustfp, "\n%s %c\n", fpr, flag);
  if (ferror (trustfp))
    rc = gpg_error (gpg_err_code_from_errno (errno));
  
  /* close because we are in append mode */
  if (fclose (trustfp))
    rc = gpg_error (gpg_err_code_from_errno (errno));
  trustfp = NULL;
  trustfp_used--;
  return rc;
}


void
agent_trustlist_housekeeping (void)
{
  if (reload_trustlist_pending && !trustfp_used)
    {
      if (trustfp)
        {
          fclose (trustfp);
          trustfp = NULL;
        }
      reload_trustlist_pending = 0;
    }
}


/* Not all editors are editing files in place, thus a changes
   trustlist.txt won't be recognozed if we keep the file descriptor
   open. This function may be used to explicitly close that file
   descriptor, which will force a reopen in turn. */
void
agent_reload_trustlist (void)
{
  reload_trustlist_pending = 1;
  agent_trustlist_housekeeping ();
}
