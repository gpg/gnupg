/* import.c - Import certificates
 *	Copyright (C) 2001, 2003, 2004 Free Software Foundation, Inc.
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


struct stats_s {
  unsigned long count;
  unsigned long imported;
  unsigned long unchanged;
  unsigned long not_imported;
};


static gpg_error_t parse_p12 (ksba_reader_t reader, FILE **retfp);



static void
print_imported_status (CTRL ctrl, ksba_cert_t cert, int new_cert)
{
  char *fpr;
     
  fpr = gpgsm_get_fingerprint_hexstring (cert, GCRY_MD_SHA1);
  if (new_cert)
    gpgsm_status2 (ctrl, STATUS_IMPORTED, fpr, "[X.509]", NULL);

  gpgsm_status2 (ctrl, STATUS_IMPORT_OK, 
                 new_cert? "1":"0",  fpr, NULL);

  xfree (fpr);
}


/* Print an IMPORT_PROBLEM status.  REASON is one of:
   0 := "No specific reason given".
   1 := "Invalid Certificate".
   2 := "Issuer Certificate missing".
   3 := "Certificate Chain too long".
   4 := "Error storing certificate".
*/
static void
print_import_problem (CTRL ctrl, ksba_cert_t cert, int reason)
{
  char *fpr = NULL;
  char buf[25];
  int i;

  sprintf (buf, "%d", reason);
  if (cert)
    {
      fpr = gpgsm_get_fingerprint_hexstring (cert, GCRY_MD_SHA1);
      /* detetect an error (all high) value */
      for (i=0; fpr[i] == 'F'; i++)
        ;
      if (!fpr[i])
        {
          xfree (fpr);
          fpr = NULL;
        }
    }
  gpgsm_status2 (ctrl, STATUS_IMPORT_PROBLEM, buf, fpr, NULL);
  xfree (fpr);
}


void
print_imported_summary (CTRL ctrl, struct stats_s *stats)
{
  char buf[14*25];

  if (!opt.quiet)
    {
      log_info (_("total number processed: %lu\n"), stats->count);
      if (stats->imported) 
        {
          log_info (_("              imported: %lu"), stats->imported );
          log_printf ("\n");
	}
      if (stats->unchanged)
        log_info (_("             unchanged: %lu\n"), stats->unchanged);
      if (stats->not_imported)
        log_info (_("          not imported: %lu\n"), stats->not_imported);
    }

  sprintf (buf, "%lu 0 %lu 0 %lu 0 0 0 0 0 0 0 0 %lu",
           stats->count,
           stats->imported,
           stats->unchanged,
           stats->not_imported
           );
  gpgsm_status (ctrl, STATUS_IMPORT_RES, buf);
}



static void
check_and_store (CTRL ctrl, struct stats_s *stats, ksba_cert_t cert, int depth)
{
  int rc;

  stats->count++;
  if ( depth >= 50 )
    {
      log_error (_("certificate chain too long\n"));
      stats->not_imported++;
      print_import_problem (ctrl, cert, 3);
      return;
    }

  /* Some basic checks, but don't care about missing certificates;
     this is so that we are able to import entire certificate chains
     w/o requirening a special order (i.e. root-CA first).  This used
     to be different but because gpgsm_verify even imports
     certificates without any checks, it doesn't matter much and the
     code gets much cleaner.  A housekeeping function to remove
     certificates w/o an anchor would be nice, though. */
  rc = gpgsm_basic_cert_check (cert);
  if (!rc || gpg_err_code (rc) == GPG_ERR_MISSING_CERT)
    {
      int existed;

      if (!keydb_store_cert (cert, 0, &existed))
        {
          ksba_cert_t next = NULL;

          if (!existed)
            {
              print_imported_status (ctrl, cert, 1);
              stats->imported++;
            }
          else
            {
              print_imported_status (ctrl, cert, 0);
              stats->unchanged++;
            }
            
          if (opt.verbose > 1 && existed)
            {
              if (depth)
                log_info ("issuer certificate already in DB\n");
              else
                log_info ("certificate already in DB\n");
            }
          else if (opt.verbose && !existed)
            {
              if (depth)
                log_info ("issuer certificate imported\n");
              else
                log_info ("certificate imported\n");
            }

          /* Now lets walk up the chain and import all certificates up
             the chain.  This is required in case we already stored
             parent certificates in the ephemeral keybox. */
          if (!gpgsm_walk_cert_chain (cert, &next))
            {
              check_and_store (ctrl, stats, next, depth+1);
              ksba_cert_release (next);
            }
        }
      else
        {
          log_error (_("error storing certificate\n"));
          stats->not_imported++;
          print_import_problem (ctrl, cert, 4);
        }
    }
  else
    {
      log_error (_("basic certificate checks failed - not imported\n"));
      stats->not_imported++;
      print_import_problem (ctrl, cert,
                            gpg_err_code (rc) == GPG_ERR_MISSING_CERT? 2 :
                            gpg_err_code (rc) == GPG_ERR_BAD_CERT?     1 : 0);
    }
}




static int
import_one (CTRL ctrl, struct stats_s *stats, int in_fd)
{
  int rc;
  Base64Context b64reader = NULL;
  ksba_reader_t reader;
  ksba_cert_t cert = NULL;
  ksba_cms_t cms = NULL;
  FILE *fp = NULL;
  ksba_content_type_t ct;
  int any = 0;

  fp = fdopen ( dup (in_fd), "rb");
  if (!fp)
    {
      rc = gpg_error (gpg_err_code_from_errno (errno));
      log_error ("fdopen() failed: %s\n", strerror (errno));
      goto leave;
    }

  rc = gpgsm_create_reader (&b64reader, ctrl, fp, 1, &reader);
  if (rc)
    {
      log_error ("can't create reader: %s\n", gpg_strerror (rc));
      goto leave;
    }
  
  
  /* We need to loop here to handle multiple PEM objects in one
     file. */
  do
    {
      ksba_cms_release (cms); cms = NULL;
      ksba_cert_release (cert); cert = NULL;
      
      ct = ksba_cms_identify (reader);
      if (ct == KSBA_CT_SIGNED_DATA)
        { /* This is probably a signed-only message - import the certs */
          ksba_stop_reason_t stopreason;
          int i;
          
          rc = ksba_cms_new (&cms);
          if (rc)
            goto leave;
          
          rc = ksba_cms_set_reader_writer (cms, reader, NULL);
          if (rc)
            {
              log_error ("ksba_cms_set_reader_writer failed: %s\n",
                         gpg_strerror (rc));
              goto leave;
            }

          do 
            {
              rc = ksba_cms_parse (cms, &stopreason);
              if (rc)
                {
                  log_error ("ksba_cms_parse failed: %s\n", gpg_strerror (rc));
                  goto leave;
                }

              if (stopreason == KSBA_SR_BEGIN_DATA)
                log_info ("not a certs-only message\n");
            }
          while (stopreason != KSBA_SR_READY);   
      
          for (i=0; (cert=ksba_cms_get_cert (cms, i)); i++)
            {
              check_and_store (ctrl, stats, cert, 0);
              ksba_cert_release (cert); 
              cert = NULL;
            }
          if (!i)
            log_error ("no certificate found\n");
          else
            any = 1;
        }
      else if (ct == KSBA_CT_PKCS12)
        { /* This seems to be a pkcs12 message.  We use an external
             tool to parse the message and to store the private keys.
             We need to use a another reader here to parse the
             certificate we included in the p12 file; then we continue
             to look for other pkcs12 files (works only if they are in
             PEM format. */
          FILE *certfp;
          Base64Context b64p12rdr;
          ksba_reader_t p12rdr;
          
          rc = parse_p12 (reader, &certfp);
          if (!rc)
            {
              any = 1;
              
              rewind (certfp);
              rc = gpgsm_create_reader (&b64p12rdr, ctrl, certfp, 1, &p12rdr);
              if (rc)
                {
                  log_error ("can't create reader: %s\n", gpg_strerror (rc));
                  fclose (certfp);
                  goto leave;
                }

              do
                {
                  ksba_cert_release (cert); cert = NULL;
                  rc = ksba_cert_new (&cert);
                  if (!rc)
                    {
                      rc = ksba_cert_read_der (cert, p12rdr);
                      if (!rc)
                        check_and_store (ctrl, stats, cert, 0);
                    }
                  ksba_reader_clear (p12rdr, NULL, NULL);
                }
              while (!rc && !gpgsm_reader_eof_seen (b64p12rdr));

              if (gpg_err_code (rc) == GPG_ERR_EOF)
                rc = 0;
              gpgsm_destroy_reader (b64p12rdr);
              fclose (certfp);
              if (rc)
                goto leave;
            }
        }
      else if (ct == KSBA_CT_NONE)
        { /* Failed to identify this message - assume a certificate */

          rc = ksba_cert_new (&cert);
          if (rc)
            goto leave;

          rc = ksba_cert_read_der (cert, reader);
          if (rc)
            goto leave;

          check_and_store (ctrl, stats, cert, 0);
          any = 1;
        }
      else
        {
          log_error ("can't extract certificates from input\n");
          rc = gpg_error (GPG_ERR_NO_DATA);
        }
      
      ksba_reader_clear (reader, NULL, NULL);
    }
  while (!gpgsm_reader_eof_seen (b64reader));

 leave:
  if (any && gpg_err_code (rc) == GPG_ERR_EOF)
    rc = 0;
  ksba_cms_release (cms);
  ksba_cert_release (cert);
  gpgsm_destroy_reader (b64reader);
  if (fp)
    fclose (fp);
  return rc;
}


int
gpgsm_import (CTRL ctrl, int in_fd)
{
  int rc;
  struct stats_s stats;

  memset (&stats, 0, sizeof stats);
  rc = import_one (ctrl, &stats, in_fd);
  print_imported_summary (ctrl, &stats);
  /* If we never printed an error message do it now so that a command
     line invocation will return with an error (log_error keeps a
     global errorcount) */
  if (rc && !log_get_errorcount (0))
    log_error (_("error importing certificate: %s\n"), gpg_strerror (rc));
  return rc;
}


int
gpgsm_import_files (CTRL ctrl, int nfiles, char **files,
                    int (*of)(const char *fname))
{
  int rc = 0;
  struct stats_s stats;

  memset (&stats, 0, sizeof stats);
  
  if (!nfiles)
    rc = import_one (ctrl, &stats, 0);
  else
    {
      for (; nfiles && !rc ; nfiles--, files++)
        {
          int fd = of (*files);
          rc = import_one (ctrl, &stats, fd);
          close (fd);
          if (rc == -1)
            rc = 0;
        }
    }
  print_imported_summary (ctrl, &stats);
  /* If we never printed an error message do it now so that a command
     line invocation will return with an error (log_error keeps a
     global errorcount) */
  if (rc && !log_get_errorcount (0))
    log_error (_("error importing certificate: %s\n"), gpg_strerror (rc));
  return rc;
}


/* Fork and exec the protecttool, connect the file descriptor of
   INFILE to stdin, return a new stream in STATUSFILE, write the
   output to OUTFILE and the pid of the process in PID.  Returns 0 on
   success or an error code. */
static gpg_error_t
popen_protect_tool (const char *pgmname,
                    FILE *infile, FILE *outfile, FILE **statusfile, pid_t *pid)
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

      execlp (pgmname, arg0,
              "--homedir", opt.homedir,
              "--p12-import",
              "--store", 
              "--no-fail-on-exist",
              "--",
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


/* Assume that the reader is at a pkcs#12 message and try to import
   certificates from that stupid format. We will alos store secret
   keys.  All of the pkcs#12 parsing and key storing is handled by the
   gpg-protect-tool, we merely have to take care of receiving the
   certificates. On success RETFP returns a temporary file with
   certificates. */
static gpg_error_t
parse_p12 (ksba_reader_t reader, FILE **retfp)
{
  const char *pgmname;
  gpg_error_t err = 0, child_err = 0;
  int i, c, cont_line;
  unsigned int pos;
  FILE *tmpfp, *certfp = NULL, *fp = NULL;
  char buffer[1024];
  size_t nread;
  pid_t pid = -1;

  if (!opt.protect_tool_program || !*opt.protect_tool_program)
    pgmname = GNUPG_DEFAULT_PROTECT_TOOL;
  else
    pgmname = opt.protect_tool_program;

  *retfp = NULL;

  /* To avoid an extra feeder process or doing selects and because
     gpg-protect-tool will anyway parse the entire pkcs#12 message in
     memory, we simply use tempfiles here and pass them to
     the gpg-protect-tool. */
  tmpfp = tmpfile ();
  if (!tmpfp)
    {
      err = gpg_error_from_errno (errno);
      log_error (_("error creating temporary file: %s\n"), strerror (errno));
      goto cleanup;
    }
  while (!(err = ksba_reader_read (reader, buffer, sizeof buffer, &nread)))
    {
      if (nread && fwrite (buffer, nread, 1, tmpfp) != 1)
        {
          err = gpg_error_from_errno (errno);
          log_error (_("error writing to temporary file: %s\n"),
                     strerror (errno));
          goto cleanup;
        }
    }
  if (gpg_err_code (err) == GPG_ERR_EOF)
    err = 0;
  if (err)
    {
      log_error (_("error reading input: %s\n"), gpg_strerror (err));
      goto cleanup;
    }

  certfp = tmpfile ();
  if (!certfp)
    {
      err = gpg_error_from_errno (errno);
      log_error (_("error creating temporary file: %s\n"), strerror (errno));
      goto cleanup;
    }

  err = popen_protect_tool (pgmname, tmpfp, certfp, &fp, &pid);
  if (err)
    {
      pid = -1;
      goto cleanup;
    }
  fclose (tmpfp);
  tmpfp = NULL;

  /* Read stderr of the protect tool. */
  pos = 0;
  cont_line = 0;
  while ((c=getc (fp)) != EOF)
    {
      /* fixme: We could here grep for status information of the
         protect tool to figure out better error codes for
         CHILD_ERR. */
      buffer[pos++] = c;
      if (pos >= 5 /*sizeof buffer - 1*/ || c == '\n')
        {
          buffer[pos - (c == '\n')] = 0;
          if (cont_line)
            log_printf ("%s", buffer);
          else
            log_info ("%s", buffer);
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

  /* If we found no error in the output of the cild, setup a suitable
     error code, which will later be reset if the exit status of the
     child is 0. */
  if (!child_err)
    child_err = gpg_error (GPG_ERR_DECRYPT_FAILED);


 cleanup:
  if (tmpfp)
    fclose (tmpfp);
  if (fp)
    fclose (fp);
  if (pid != -1)
    {
      int status;

      while ( (i=waitpid (pid, &status, 0)) == -1 && errno == EINTR)
        ;
      if (i == -1)
        log_error (_("waiting for protect-tool to terminate failed: %s\n"),
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
      if (certfp)
        fclose (certfp);
    }
  else
    *retfp = certfp;
  return err;
}
