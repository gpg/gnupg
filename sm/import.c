/* import.c - Import certificates
 * Copyright (C) 2001, 2003, 2004, 2009 Free Software Foundation, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <assert.h>
#include <unistd.h>

#include "gpgsm.h"
#include <gcrypt.h>
#include <ksba.h>

#include "keydb.h"
#include "exechelp.h"
#include "i18n.h"
#include "sysutils.h"
#include "../kbx/keybox.h" /* for KEYBOX_FLAG_* */


struct stats_s {
  unsigned long count;
  unsigned long imported;
  unsigned long unchanged;
  unsigned long not_imported;
  unsigned long secret_read;
  unsigned long secret_imported;
  unsigned long secret_dups;
 };


static gpg_error_t parse_p12 (ctrl_t ctrl, ksba_reader_t reader, FILE **retfp,
                              struct stats_s *stats);



static void
print_imported_status (ctrl_t ctrl, ksba_cert_t cert, int new_cert)
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
print_import_problem (ctrl_t ctrl, ksba_cert_t cert, int reason)
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
print_imported_summary (ctrl_t ctrl, struct stats_s *stats)
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
      if (stats->secret_read)
        log_info (_("      secret keys read: %lu\n"), stats->secret_read );
      if (stats->secret_imported)
        log_info (_("  secret keys imported: %lu\n"), stats->secret_imported );
      if (stats->secret_dups)
        log_info (_(" secret keys unchanged: %lu\n"), stats->secret_dups );
      if (stats->not_imported)
        log_info (_("          not imported: %lu\n"), stats->not_imported);
    }

  sprintf(buf, "%lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
          stats->count,
          0l /*stats->no_user_id*/,
          stats->imported,
          0l /*stats->imported_rsa*/,
          stats->unchanged,
          0l /*stats->n_uids*/,
          0l /*stats->n_subk*/,
          0l /*stats->n_sigs*/,
          0l /*stats->n_revoc*/,
          stats->secret_read,
          stats->secret_imported,
          stats->secret_dups,
          0l /*stats->skipped_new_keys*/,
          stats->not_imported
          );
  gpgsm_status (ctrl, STATUS_IMPORT_RES, buf);
}



static void
check_and_store (ctrl_t ctrl, struct stats_s *stats,
                 ksba_cert_t cert, int depth)
{
  int rc;

  if (stats)
    stats->count++;
  if ( depth >= 50 )
    {
      log_error (_("certificate chain too long\n"));
      if (stats)
        stats->not_imported++;
      print_import_problem (ctrl, cert, 3);
      return;
    }

  /* Some basic checks, but don't care about missing certificates;
     this is so that we are able to import entire certificate chains
     w/o requiring a special order (i.e. root-CA first).  This used
     to be different but because gpgsm_verify even imports
     certificates without any checks, it doesn't matter much and the
     code gets much cleaner.  A housekeeping function to remove
     certificates w/o an anchor would be nice, though. 
     
     Optionally we do a full validation in addition to the basic test.
  */
  rc = gpgsm_basic_cert_check (ctrl, cert);
  if (!rc && ctrl->with_validation)
    rc = gpgsm_validate_chain (ctrl, cert, "", NULL, 0, NULL, 0, NULL);
  if (!rc || (!ctrl->with_validation
              && (gpg_err_code (rc) == GPG_ERR_MISSING_CERT
                  || gpg_err_code (rc) == GPG_ERR_MISSING_ISSUER_CERT)))
    {
      int existed;

      if (!keydb_store_cert (cert, 0, &existed))
        {
          ksba_cert_t next = NULL;

          if (!existed)
            {
              print_imported_status (ctrl, cert, 1);
              if (stats)
                stats->imported++;
            }
          else
            {
              print_imported_status (ctrl, cert, 0);
              if (stats)
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
             parent certificates in the ephemeral keybox.  Do not
             update the statistics, though. */
          if (!gpgsm_walk_cert_chain (ctrl, cert, &next))
            {
              check_and_store (ctrl, NULL, next, depth+1);
              ksba_cert_release (next);
            }
        }
      else
        {
          log_error (_("error storing certificate\n"));
          if (stats)
            stats->not_imported++;
          print_import_problem (ctrl, cert, 4);
        }
    }
  else
    {
      log_error (_("basic certificate checks failed - not imported\n"));
      if (stats)
        stats->not_imported++;
      /* We keep the test for GPG_ERR_MISSING_CERT only in case
         GPG_ERR_MISSING_CERT has been used instead of the newer
         GPG_ERR_MISSING_ISSUER_CERT.  */
      print_import_problem 
        (ctrl, cert,
         gpg_err_code (rc) == GPG_ERR_MISSING_ISSUER_CERT? 2 :
         gpg_err_code (rc) == GPG_ERR_MISSING_CERT? 2 :
         gpg_err_code (rc) == GPG_ERR_BAD_CERT?     1 : 0);
    }
}




static int
import_one (ctrl_t ctrl, struct stats_s *stats, int in_fd)
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
          
          rc = parse_p12 (ctrl, reader, &certfp, stats);
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



/* Re-import certifciates.  IN_FD is a list of linefeed delimited
   fingerprints t re-import.  The actual re-import is done by clearing
   the ephemeral flag.  */
static int
reimport_one (ctrl_t ctrl, struct stats_s *stats, int in_fd)
{
  gpg_error_t err = 0;
  estream_t fp = NULL;
  char line[100];  /* Sufficient for a fingerprint.  */
  KEYDB_HANDLE kh;
  KEYDB_SEARCH_DESC desc;
  ksba_cert_t cert = NULL;
  unsigned int flags;

  kh = keydb_new (0);
  if (!kh)
    {
      err = gpg_error (GPG_ERR_ENOMEM);;
      log_error (_("failed to allocate keyDB handle\n"));
      goto leave;
    }
  keydb_set_ephemeral (kh, 1);
   
  fp = es_fdopen_nc (in_fd, "r");
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      log_error ("es_fdopen(%d) failed: %s\n", in_fd, gpg_strerror (err));
      goto leave;
    }

  while (es_fgets (line, DIM(line)-1, fp) )
    {
      if (*line && line[strlen(line)-1] != '\n')
        {
          err = gpg_error (GPG_ERR_LINE_TOO_LONG);
          goto leave;
	}
      trim_spaces (line);
      if (!*line)
        continue;
    
      stats->count++;

      err = keydb_classify_name (line, &desc);
      if (err)
        {
          print_import_problem (ctrl, NULL, 0);
          stats->not_imported++;
          continue;
        }

      keydb_search_reset (kh);
      err = keydb_search (kh, &desc, 1);
      if (err)
        {
          print_import_problem (ctrl, NULL, 0);
          stats->not_imported++;
          continue;
        }

      ksba_cert_release (cert);
      cert = NULL;
      err = keydb_get_cert (kh, &cert);
      if (err)
        {
          log_error ("keydb_get_cert() failed: %s\n", gpg_strerror (err));
          print_import_problem (ctrl, NULL, 1);
          stats->not_imported++;
          continue;
        }

      err = keydb_get_flags (kh, KEYBOX_FLAG_BLOB, 0, &flags);
      if (err)
        {
          log_error (_("error getting stored flags: %s\n"), gpg_strerror (err));
          print_imported_status (ctrl, cert, 0);
          stats->not_imported++;
          continue;
        }
      if ( !(flags & KEYBOX_FLAG_BLOB_EPHEMERAL) )
        {
          print_imported_status (ctrl, cert, 0);
          stats->unchanged++;
          continue;
        }

      err = keydb_set_cert_flags (cert, 1, KEYBOX_FLAG_BLOB, 0,
                                  KEYBOX_FLAG_BLOB_EPHEMERAL, 0);
      if (err)
        {
          log_error ("clearing ephemeral flag failed: %s\n",
                     gpg_strerror (err)); 
          print_import_problem (ctrl, cert, 0);
          stats->not_imported++;
          continue;
        }

      print_imported_status (ctrl, cert, 1);
      stats->imported++;
    }
  err = 0;
  if (es_ferror (fp))
    {
      err = gpg_error_from_syserror ();
      log_error ("error reading fd %d: %s\n", in_fd, gpg_strerror (err));
      goto leave;
    }

 leave:
  ksba_cert_release (cert);
  keydb_release (kh);
  es_fclose (fp);
  return err;
}



int
gpgsm_import (ctrl_t ctrl, int in_fd, int reimport_mode)
{
  int rc;
  struct stats_s stats;

  memset (&stats, 0, sizeof stats);
  if (reimport_mode)
    rc = reimport_one (ctrl, &stats, in_fd);
  else
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
gpgsm_import_files (ctrl_t ctrl, int nfiles, char **files,
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
popen_protect_tool (ctrl_t ctrl, const char *pgmname,
                    FILE *infile, FILE *outfile, FILE **statusfile, pid_t *pid)
{
  const char *argv[22];
  int i=0;

  /* Make sure that the agent is running so that the protect tool is
     able to ask for a passphrase.  This has only an effect under W32
     where the agent is started on demand; sending a NOP does not harm
     on other platforms.  This is not really necessary anymore because
     the protect tool does this now by itself; it does not harm either. */
  gpgsm_agent_send_nop (ctrl);

  argv[i++] = "--homedir";
  argv[i++] = opt.homedir;
  argv[i++] = "--p12-import";
  argv[i++] = "--store";
  argv[i++] = "--no-fail-on-exist";
  argv[i++] = "--enable-status-msg";
  if (opt.fixed_passphrase)
    {
      argv[i++] = "--passphrase";
      argv[i++] = opt.fixed_passphrase;
    }
  if (opt.agent_program)
    {
      argv[i++] = "--agent-program";
      argv[i++] = opt.agent_program;
    }
  argv[i++] = "--",
  argv[i] = NULL;
  assert (i < sizeof argv);

  return gnupg_spawn_process (pgmname, argv, infile, outfile,
                              setup_pinentry_env, (128 | 64),
                              statusfile, pid);
}


/* Assume that the reader is at a pkcs#12 message and try to import
   certificates from that stupid format.  We will also store secret
   keys.  All of the pkcs#12 parsing and key storing is handled by the
   gpg-protect-tool, we merely have to take care of receiving the
   certificates. On success RETFP returns a temporary file with
   certificates. */
static gpg_error_t
parse_p12 (ctrl_t ctrl, ksba_reader_t reader,
           FILE **retfp, struct stats_s *stats)
{
  const char *pgmname;
  gpg_error_t err = 0, child_err = 0;
  int c, cont_line;
  unsigned int pos;
  FILE *tmpfp, *certfp = NULL, *fp = NULL;
  char buffer[1024];
  size_t nread;
  pid_t pid = -1;
  int bad_pass = 0;

  if (!opt.protect_tool_program || !*opt.protect_tool_program)
    pgmname = gnupg_module_name (GNUPG_MODULE_NAME_PROTECT_TOOL);
  else
    pgmname = opt.protect_tool_program;

  *retfp = NULL;

  /* To avoid an extra feeder process or doing selects and because
     gpg-protect-tool will anyway parse the entire pkcs#12 message in
     memory, we simply use tempfiles here and pass them to
     the gpg-protect-tool. */
  tmpfp = gnupg_tmpfile ();
  if (!tmpfp)
    {
      err = gpg_error_from_syserror ();
      log_error (_("error creating temporary file: %s\n"), strerror (errno));
      goto cleanup;
    }
  while (!(err = ksba_reader_read (reader, buffer, sizeof buffer, &nread)))
    {
      if (nread && fwrite (buffer, nread, 1, tmpfp) != 1)
        {
          err = gpg_error_from_syserror ();
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

  certfp = gnupg_tmpfile ();
  if (!certfp)
    {
      err = gpg_error_from_syserror ();
      log_error (_("error creating temporary file: %s\n"), strerror (errno));
      goto cleanup;
    }

  err = popen_protect_tool (ctrl, pgmname, tmpfp, certfp, &fp, &pid);
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
                  if ( !strcmp (p, "secretkey-stored"))
                    {
                      stats->count++;
                      stats->secret_read++;
                      stats->secret_imported++;
                    }
                  else if ( !strcmp (p, "secretkey-exists"))
                    {
                      stats->count++;
                      stats->secret_read++;
                      stats->secret_dups++;
                    }
                  else if ( !strcmp (p, "bad-passphrase"))
                    {

                    }
                }
              else 
                {
                  log_info ("%s", buffer);
                  if (!strncmp (buffer, "gpg-protect-tool: "
                                "possibly bad passphrase given",46))
                    bad_pass++;
                }
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


  /* If we found no error in the output of the child, setup a suitable
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
      if (!gnupg_wait_process (pgmname, pid, NULL))
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

  if (bad_pass)
    {
      /* We only write a plain error code and not direct
         BAD_PASSPHRASE because the pkcs12 parser might issue this
         message multiple times, BAD_PASSPHRASE in general requires a
         keyID and parts of the import might actually succeed so that
         IMPORT_PROBLEM is also not appropriate. */
      gpgsm_status_with_err_code (ctrl, STATUS_ERROR,
                                  "import.parsep12", GPG_ERR_BAD_PASSPHRASE);
    }
  
  return err;
}
