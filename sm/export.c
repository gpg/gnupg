/* export.c
 * Copyright (C) 2002, 2003, 2004 Free Software Foundation, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h> 
#include <time.h>
#include <assert.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/wait.h>

#include "gpgsm.h"
#include <gcrypt.h>
#include <ksba.h>

#include "keydb.h"
#include "i18n.h"

#ifdef _POSIX_OPEN_MAX
#define MAX_OPEN_FDS _POSIX_OPEN_MAX
#else
#define MAX_OPEN_FDS 20
#endif


/* A table to store a fingerprint as used in a duplicates table.  We
   don't need to hash here because a fingerprint is alrady a perfect
   hash value.  This we use the most significant bits to index the
   table and then use a linked list for the overflow.  Possible
   enhancement for very large number of certictates: Add a second
   level table and then resort to a linked list. */
struct duptable_s
{
  struct duptable_s *next;

  /* Note that we only need to store 19 bytes because the first byte
     is implictly given by the table index (we require at least 8
     bits). */
  unsigned char fpr[19];
};
typedef struct duptable_s *duptable_t;
#define DUPTABLE_BITS 12
#define DUPTABLE_SIZE (1 << DUPTABLE_BITS)


static void print_short_info (ksba_cert_t cert, FILE *fp);
static gpg_error_t export_p12 (ctrl_t ctrl,
                               const unsigned char *certimg, size_t certimglen,
                               const char *prompt, const char *keygrip,
                               FILE **retfp);


/* Create a table used to indetify duplicated certificates. */
static duptable_t *
create_duptable (void)
{
  return xtrycalloc (DUPTABLE_SIZE, sizeof (duptable_t));
}

static void
destroy_duptable (duptable_t *table)
{
  int idx;
  duptable_t t, t2;

  if (table)
    {
      for (idx=0; idx < DUPTABLE_SIZE; idx++) 
        for (t = table[idx]; t; t = t2)
          {
            t2 = t->next;
            xfree (t);
          }
      xfree (table);
    }
}

/* Insert the 20 byte fingerprint FPR into TABLE.  Sets EXITS to true
   if the fingerprint already exists in the table. */
static gpg_error_t
insert_duptable (duptable_t *table, unsigned char *fpr, int *exists)
{
  size_t idx;
  duptable_t t;
  
  *exists = 0;
  idx = fpr[0];
#if DUPTABLE_BITS > 16 || DUPTABLE_BITS < 8
#error cannot handle a table larger than 16 bits or smaller than 8 bits
#elif DUPTABLE_BITS > 8
  idx <<= (DUPTABLE_BITS - 8);  
  idx |= (fpr[1] & ~(~0 << 4)); 
#endif  

  for (t = table[idx]; t; t = t->next)
    if (!memcmp (t->fpr, fpr+1, 19))
      break;
  if (t)
    {
      *exists = 1;
      return 0;
    }
  /* Insert that fingerprint. */
  t = xtrymalloc (sizeof *t);
  if (!t)
    return gpg_error_from_errno (errno);
  memcpy (t->fpr, fpr+1, 19);
  t->next = table[idx];
  table[idx] = t;
  return 0;
}




/* Export all certificates or just those given in NAMES. */
void
gpgsm_export (CTRL ctrl, STRLIST names, FILE *fp)
{
  KEYDB_HANDLE hd = NULL;
  KEYDB_SEARCH_DESC *desc = NULL;
  int ndesc;
  Base64Context b64writer = NULL;
  ksba_writer_t writer;
  STRLIST sl;
  ksba_cert_t cert = NULL;
  int rc=0;
  int count = 0;
  int i;
  duptable_t *dtable;

  
  dtable = create_duptable ();
  if (!dtable)
    {
      log_error ("creating duplicates table failed: %s\n", strerror (errno));
      goto leave;
    }

  hd = keydb_new (0);
  if (!hd)
    {
      log_error ("keydb_new failed\n");
      goto leave;
    }

  if (!names)
    ndesc = 1;
  else
    {
      for (sl=names, ndesc=0; sl; sl = sl->next, ndesc++) 
        ;
    }

  desc = xtrycalloc (ndesc, sizeof *desc);
  if (!ndesc)
    {
      log_error ("allocating memory for export failed: %s\n",
                 gpg_strerror (OUT_OF_CORE (errno)));
      goto leave;
    }

  if (!names)
    desc[0].mode = KEYDB_SEARCH_MODE_FIRST;
  else 
    {
      for (ndesc=0, sl=names; sl; sl = sl->next) 
        {
          rc = keydb_classify_name (sl->d, desc+ndesc);
          if (rc)
            {
              log_error ("key `%s' not found: %s\n",
                         sl->d, gpg_strerror (rc));
              rc = 0;
            }
          else
            ndesc++;
        }
    }

  /* If all specifications are done by fingerprint, we switch to
     ephemeral mode so that _all_ currently available and matching
     certificates are exported. 

     fixme: we should in this case keep a list of certificates to
     avoid accidential export of duplicate certificates. */
  if (names && ndesc)
    {
      for (i=0; (i < ndesc
                 && (desc[i].mode == KEYDB_SEARCH_MODE_FPR
                     || desc[i].mode == KEYDB_SEARCH_MODE_FPR20
                     || desc[i].mode == KEYDB_SEARCH_MODE_FPR16)); i++)
        ;
      if (i == ndesc)
        keydb_set_ephemeral (hd, 1);
    }
      
  while (!(rc = keydb_search (hd, desc, ndesc)))
    {
      unsigned char fpr[20];
      int exists;

      if (!names) 
        desc[0].mode = KEYDB_SEARCH_MODE_NEXT;

      rc = keydb_get_cert (hd, &cert);
      if (rc) 
        {
          log_error ("keydb_get_cert failed: %s\n", gpg_strerror (rc));
          goto leave;
        }

      gpgsm_get_fingerprint (cert, 0, fpr, NULL);
      rc = insert_duptable (dtable, fpr, &exists);
      if (rc)
        {
          log_error ("inserting into duplicates table fauiled: %s\n",
                     gpg_strerror (rc));
          goto leave;
        }

      if (!exists && count && !ctrl->create_pem)
        {
          log_info ("exporting more than one certificate "
                    "is not possible in binary mode\n");
          log_info ("ignoring other certificates\n");
          break;
        }

      if (!exists)
        {
          const unsigned char *image;
          size_t imagelen;

          image = ksba_cert_get_image (cert, &imagelen);
          if (!image)
            {
              log_error ("ksba_cert_get_image failed\n");
              goto leave;
            }


          if (ctrl->create_pem)
            {
              if (count)
                putc ('\n', fp);
              print_short_info (cert, fp);
              putc ('\n', fp);
            }
          count++;

          if (!b64writer)
            {
              ctrl->pem_name = "CERTIFICATE";
              rc = gpgsm_create_writer (&b64writer, ctrl, fp, &writer);
              if (rc)
                {
                  log_error ("can't create writer: %s\n", gpg_strerror (rc));
                  goto leave;
                }
            }

          rc = ksba_writer_write (writer, image, imagelen);
          if (rc)
            {
              log_error ("write error: %s\n", gpg_strerror (rc));
              goto leave;
            }

          if (ctrl->create_pem)
            {
              /* We want one certificate per PEM block */
              rc = gpgsm_finish_writer (b64writer);
              if (rc) 
                {
                  log_error ("write failed: %s\n", gpg_strerror (rc));
                  goto leave;
                }
              gpgsm_destroy_writer (b64writer);
              b64writer = NULL;
            }
        }

      ksba_cert_release (cert); 
      cert = NULL;
    }
  if (rc && rc != -1)
    log_error ("keydb_search failed: %s\n", gpg_strerror (rc));
  else if (b64writer)
    {
      rc = gpgsm_finish_writer (b64writer);
      if (rc) 
        {
          log_error ("write failed: %s\n", gpg_strerror (rc));
          goto leave;
        }
    }
  
 leave:
  gpgsm_destroy_writer (b64writer);
  ksba_cert_release (cert);
  xfree (desc);
  keydb_release (hd);
  destroy_duptable (dtable);
}


/* Export a certificates and its private key. */
void
gpgsm_p12_export (ctrl_t ctrl, const char *name, FILE *fp)
{
  KEYDB_HANDLE hd;
  KEYDB_SEARCH_DESC *desc = NULL;
  Base64Context b64writer = NULL;
  ksba_writer_t writer;
  ksba_cert_t cert = NULL;
  int rc=0;
  const unsigned char *image;
  size_t imagelen;
  char *keygrip = NULL;
  char *prompt;
  char buffer[1024];
  int  nread;
  FILE *datafp = NULL;


  hd = keydb_new (0);
  if (!hd)
    {
      log_error ("keydb_new failed\n");
      goto leave;
    }

  desc = xtrycalloc (1, sizeof *desc);
  if (!desc)
    {
      log_error ("allocating memory for export failed: %s\n",
                 gpg_strerror (OUT_OF_CORE (errno)));
      goto leave;
    }

  rc = keydb_classify_name (name, desc);
  if (rc)
    {
      log_error ("key `%s' not found: %s\n",
                 name, gpg_strerror (rc));
      goto leave;
    }

  /* Lookup the certificate an make sure that it is unique. */
  rc = keydb_search (hd, desc, 1);
  if (!rc)
    {
      rc = keydb_get_cert (hd, &cert);
      if (rc) 
        {
          log_error ("keydb_get_cert failed: %s\n", gpg_strerror (rc));
          goto leave;
        }
      
      rc = keydb_search (hd, desc, 1);
      if (!rc)
        rc = gpg_error (GPG_ERR_AMBIGUOUS_NAME);
      else if (rc == -1 || gpg_err_code (rc) == GPG_ERR_EOF)
        rc = 0;
      if (rc)
        {
          log_error ("key `%s' not found: %s\n",
                     name, gpg_strerror (rc));
          goto leave;
        }
    }
      
  keygrip = gpgsm_get_keygrip_hexstring (cert);
  if (!keygrip || gpgsm_agent_havekey (ctrl, keygrip))
    {
      /* Note, that the !keygrip case indicates a bad certificate. */
      rc = gpg_error (GPG_ERR_NO_SECKEY);
      log_error ("can't export key `%s': %s\n", name, gpg_strerror (rc));
      goto leave;
    }
  
  image = ksba_cert_get_image (cert, &imagelen);
  if (!image)
    {
      log_error ("ksba_cert_get_image failed\n");
      goto leave;
    }

  if (ctrl->create_pem)
    {
      print_short_info (cert, fp);
      putc ('\n', fp);
    }

  ctrl->pem_name = "PKCS12";
  rc = gpgsm_create_writer (&b64writer, ctrl, fp, &writer);
  if (rc)
    {
      log_error ("can't create writer: %s\n", gpg_strerror (rc));
      goto leave;
    }


  prompt = gpgsm_format_keydesc (cert);
  rc = export_p12 (ctrl, image, imagelen, prompt, keygrip, &datafp);
  xfree (prompt);
  if (rc)
    goto leave;
  rewind (datafp);
  while ( (nread = fread (buffer, 1, sizeof buffer, datafp)) > 0 )
    if ((rc = ksba_writer_write (writer, buffer, nread)))
      {
        log_error ("write failed: %s\n", gpg_strerror (rc));
        goto leave;
      }
  if (ferror (datafp))
    {
      rc = gpg_error_from_errno (rc);
      log_error ("error reading temporary file: %s\n", gpg_strerror (rc));
      goto leave;
    }

  if (ctrl->create_pem)
    {
      /* We want one certificate per PEM block */
      rc = gpgsm_finish_writer (b64writer);
      if (rc) 
        {
          log_error ("write failed: %s\n", gpg_strerror (rc));
          goto leave;
        }
      gpgsm_destroy_writer (b64writer);
      b64writer = NULL;
    }
  
  ksba_cert_release (cert); 
  cert = NULL;

 leave:
  if (datafp)
    fclose (datafp);
  gpgsm_destroy_writer (b64writer);
  ksba_cert_release (cert);
  xfree (desc);
  keydb_release (hd);
}


/* Print some info about the certifciate CERT to FP */
static void
print_short_info (ksba_cert_t cert, FILE *fp)
{
  char *p;
  ksba_sexp_t sexp;
  int idx;

  for (idx=0; (p = ksba_cert_get_issuer (cert, idx)); idx++)
    {
      fputs (!idx?   "Issuer ...: "
                 : "\n   aka ...: ", fp); 
      gpgsm_print_name (fp, p);
      xfree (p);
    }
  putc ('\n', fp);

  fputs ("Serial ...: ", fp); 
  sexp = ksba_cert_get_serial (cert);
  if (sexp)
    {
      int len;
      const unsigned char *s = sexp;
      
      if (*s == '(')
        {
          s++;
          for (len=0; *s && *s != ':' && digitp (s); s++)
            len = len*10 + atoi_1 (s);
          if (*s == ':')
            for (s++; len; len--, s++)
              fprintf (fp, "%02X", *s);
        }
      xfree (sexp);
    }
  putc ('\n', fp);

  for (idx=0; (p = ksba_cert_get_subject (cert, idx)); idx++)
    {
      fputs (!idx?   "Subject ..: "
                 : "\n    aka ..: ", fp); 
      gpgsm_print_name (fp, p);
      xfree (p);
    }
  putc ('\n', fp);
}


static gpg_error_t
popen_protect_tool (const char *pgmname,
                    FILE *infile, FILE *outfile, FILE **statusfile, 
                    const char *prompt, const char *keygrip,
                    pid_t *pid)
{
  gpg_error_t err;
  int fd, fdout, rp[2];
  int n, i;

  fflush (infile);
  rewind (infile);
  fd = fileno (infile);
  fdout = fileno (outfile);
  if (fd == -1 || fdout == -1)
    log_fatal ("no file descriptor for temporary file: %s\n",
               strerror (errno));

  /* Now start the protect-tool. */
  if (pipe (rp) == -1)
    {
      err = gpg_error_from_errno (errno);
      log_error (_("error creating a pipe: %s\n"), strerror (errno));
      return err;
    }
      
  *pid = fork ();
  if (*pid == -1)
    {
      err = gpg_error_from_errno (errno);
      log_error (_("error forking process: %s\n"), strerror (errno));
      close (rp[0]);
      close (rp[1]);
      return err;
    }

  if (!*pid)
    { /* Child. */
      const char *arg0;

      arg0 = strrchr (pgmname, '/');
      if (arg0)
        arg0++;
      else
        arg0 = pgmname;

      /* Connect the infile to stdin. */
      if (fd != 0 && dup2 (fd, 0) == -1)
        log_fatal ("dup2 stdin failed: %s\n", strerror (errno));

      /* Connect the outfile to stdout. */
      if (fdout != 1 && dup2 (fdout, 1) == -1)
        log_fatal ("dup2 stdout failed: %s\n", strerror (errno));
      
      /* Connect stderr to our pipe. */
      if (rp[1] != 2 && dup2 (rp[1], 2) == -1)
        log_fatal ("dup2 stderr failed: %s\n", strerror (errno));

      /* Close all other files. */
      n = sysconf (_SC_OPEN_MAX);
      if (n < 0)
        n = MAX_OPEN_FDS;
      for (i=3; i < n; i++)
        close(i);
      errno = 0;

      setup_pinentry_env ();

      execlp (pgmname, arg0,
              "--homedir", opt.homedir,
              "--p12-export",
              "--prompt", prompt?prompt:"", 
              "--enable-status-msg",
              "--",
              keygrip,
              NULL);
      /* No way to print anything, as we have closed all streams. */
      _exit (31);
    }

  /* Parent. */
  close (rp[1]);
  *statusfile = fdopen (rp[0], "r");
  if (!*statusfile)
    {
      err = gpg_error_from_errno (errno);
      log_error ("can't fdopen pipe for reading: %s", strerror (errno));
      kill (*pid, SIGTERM);
      return err;
    }

  return 0;
}


static gpg_error_t
export_p12 (ctrl_t ctrl, const unsigned char *certimg, size_t certimglen,
            const char *prompt, const char *keygrip,
            FILE **retfp)
{
  const char *pgmname;
  gpg_error_t err = 0, child_err = 0;
  int i, c, cont_line;
  unsigned int pos;
  FILE *infp = NULL, *outfp = NULL, *fp = NULL;
  char buffer[1024];
  pid_t pid = -1;
  int bad_pass = 0;

  if (!opt.protect_tool_program || !*opt.protect_tool_program)
    pgmname = GNUPG_DEFAULT_PROTECT_TOOL;
  else
    pgmname = opt.protect_tool_program;

  infp = tmpfile ();
  if (!infp)
    {
      err = gpg_error_from_errno (errno);
      log_error (_("error creating temporary file: %s\n"), strerror (errno));
      goto cleanup;
    }

  if (fwrite (certimg, certimglen, 1, infp) != 1)
    {
      err = gpg_error_from_errno (errno);
      log_error (_("error writing to temporary file: %s\n"),
                 strerror (errno));
      goto cleanup;
    }

  outfp = tmpfile ();
  if (!outfp)
    {
      err = gpg_error_from_errno (errno);
      log_error (_("error creating temporary file: %s\n"), strerror (errno));
      goto cleanup;
    }

  err = popen_protect_tool (pgmname, infp, outfp, &fp, prompt, keygrip, &pid);
  if (err)
    {
      pid = -1;
      goto cleanup;
    }
  fclose (infp);
  infp = NULL;

  /* Read stderr of the protect tool. */
  pos = 0;
  cont_line = 0;
  while ((c=getc (fp)) != EOF)
    {
      /* fixme: We could here grep for status information of the
         protect tool to figure out better error codes for
         CHILD_ERR. */
      buffer[pos++] = c;
      if (pos >= sizeof buffer - 5 || c == '\n')
        {
          buffer[pos - (c == '\n')] = 0;
          if (cont_line)
            log_printf ("%s", buffer);
          else
            {
              if (!strncmp (buffer, "gpg-protect-tool: [PROTECT-TOOL:] ",34))
                {
                  char *p, *pend;

                  p = buffer + 34;
                  pend = strchr (p, ' ');
                  if (pend)
                    *pend = 0;
                  if ( !strcmp (p, "bad-passphrase"))
                    bad_pass++;
                }
              else 
                log_info ("%s", buffer);
            }
          pos = 0;
          cont_line = (c != '\n');
        }
    }

  if (pos)
    {
      buffer[pos] = 0;
      if (cont_line)
        log_printf ("%s\n", buffer);
      else
        log_info ("%s\n", buffer);
    }
  else if (cont_line)
    log_printf ("\n");

  /* If we found no error in the output of the child, setup a suitable
     error code, which will later be reset if the exit status of the
     child is 0. */
  if (!child_err)
    child_err = gpg_error (GPG_ERR_DECRYPT_FAILED);

 cleanup:
  if (infp)
    fclose (infp);
  if (fp)
    fclose (fp);
  if (pid != -1)
    {
      int status;

      while ( (i=waitpid (pid, &status, 0)) == -1 && errno == EINTR)
        ;
      if (i == -1)
        log_error (_("waiting for protect-tools to terminate failed: %s\n"),
                   strerror (errno));
      else if (WIFEXITED (status) && WEXITSTATUS (status) == 31)
        log_error (_("error running `%s': probably not installed\n"), pgmname);
      else if (WIFEXITED (status) && WEXITSTATUS (status))
        log_error (_("error running `%s': exit status %d\n"), pgmname,
                     WEXITSTATUS (status));
      else if (!WIFEXITED (status))
        log_error (_("error running `%s': terminated\n"), pgmname);
      else 
        child_err = 0;
    }
  if (!err)
    err = child_err;
  if (err)
    {
      if (outfp)
        fclose (outfp);
    }
  else
    *retfp = outfp;
  if (bad_pass)
    {
      /* During export this is the passphrase used to unprotect the
         key and not the pkcs#12 thing as in export.  Therefore we can
         issue the regular passphrase status.  FIXME: replace the all
         zero keyid by a regular one. */
      gpgsm_status (ctrl, STATUS_BAD_PASSPHRASE, "0000000000000000");
    }
  return err;
}

