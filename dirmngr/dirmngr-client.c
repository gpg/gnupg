/* dirmngr-client.c  -  A client for the dirmngr daemon
 *	Copyright (C) 2004, 2007 g10 Code GmbH
 *	Copyright (C) 2002, 2003 Free Software Foundation, Inc.
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
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include <gpg-error.h>
#include <assuan.h>

#include "../common/logging.h"
#include "../common/stringhelp.h"
#include "../common/mischelp.h"
#include "../common/strlist.h"
#include "../common/asshelp.h"

#include "../common/i18n.h"
#include "../common/util.h"
#include "../common/init.h"


/* Constants for the options.  */
enum
  {
    oQuiet	  = 'q',
    oVerbose	  = 'v',
    oLocal        = 'l',
    oUrl          = 'u',

    oOCSP         = 500,
    oPing,
    oCacheCert,
    oValidate,
    oLookup,
    oLoadCRL,
    oSquidMode,
    oPEM,
    oEscapedPEM,
    oForceDefaultResponder
  };


/* The list of options as used by the argparse.c code.  */
static gpgrt_opt_t opts[] = {
  { oVerbose,  "verbose",   0, N_("verbose") },
  { oQuiet,    "quiet",     0, N_("be somewhat more quiet") },
  { oOCSP,     "ocsp",      0, N_("use OCSP instead of CRLs") },
  { oPing,     "ping",      0, N_("check whether a dirmngr is running")},
  { oCacheCert,"cache-cert",0, N_("add a certificate to the cache")},
  { oValidate, "validate",  0, N_("validate a certificate")},
  { oLookup,   "lookup",    0, N_("lookup a certificate")},
  { oLocal,    "local",     0, N_("lookup only locally stored certificates")},
  { oUrl,      "url",       0, N_("expect an URL for --lookup")},
  { oLoadCRL,  "load-crl",  0, N_("load a CRL into the dirmngr")},
  { oSquidMode,"squid-mode",0, N_("special mode for use by Squid")},
  { oPEM,      "pem",       0, N_("expect certificates in PEM format")},
  { oForceDefaultResponder, "force-default-responder", 0,
    N_("force the use of the default OCSP responder")},
  ARGPARSE_end ()
};


/* The usual structure for the program flags.  */
static struct
{
  int quiet;
  int verbose;
  const char *dirmngr_program;
  int force_default_responder;
  int pem;
  int escaped_pem; /* PEM is additional percent encoded.  */
  int url;         /* Expect an URL.  */
  int local;       /* Lookup up only local certificates.  */

  int use_ocsp;
} opt;


/* Communication structure for the certificate inquire callback. */
struct inq_cert_parm_s
{
  assuan_context_t ctx;
  const unsigned char *cert;
  size_t certlen;
};


/* Base64 conversion tables. */
static unsigned char bintoasc[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                  "abcdefghijklmnopqrstuvwxyz"
			          "0123456789+/";
static unsigned char asctobin[256]; /* runtime initialized */


/* Build the helptable for radix64 to bin conversion. */
static void
init_asctobin (void)
{
  static int initialized;
  int i;
  unsigned char *s;

  if (initialized)
    return;
  initialized = 1;

  for (i=0; i < 256; i++ )
    asctobin[i] = 255; /* Used to detect invalid characters. */
  for (s=bintoasc, i=0; *s; s++, i++)
    asctobin[*s] = i;
}


/* Prototypes.  */
static gpg_error_t read_certificate (const char *fname,
                                     unsigned char **rbuf, size_t *rbuflen);
static gpg_error_t do_check (assuan_context_t ctx,
                             const unsigned char *cert, size_t certlen);
static gpg_error_t do_cache (assuan_context_t ctx,
                             const unsigned char *cert, size_t certlen);
static gpg_error_t do_validate (assuan_context_t ctx,
                                const unsigned char *cert, size_t certlen);
static gpg_error_t do_loadcrl (assuan_context_t ctx, const char *filename);
static gpg_error_t do_lookup (assuan_context_t ctx, const char *pattern);
static gpg_error_t squid_loop_body (assuan_context_t ctx);



/* Function called by argparse.c to display information.  */
static const char *
my_strusage (int level)
{
  const char *p;

  switch(level)
    {
    case  9: p = "GPL-3.0-or-later"; break;
    case 11: p = "dirmngr-client (@GNUPG@)";
      break;
    case 13: p = VERSION; break;
    case 14: p = GNUPG_DEF_COPYRIGHT_LINE; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = _("Please report bugs to <@EMAIL@>.\n"); break;
    case 49: p = PACKAGE_BUGREPORT; break;
    case 1:
    case 40: p =
                 _("Usage: dirmngr-client [options] "
                   "[certfile|pattern] (-h for help)\n");
      break;
    case 41: p =
          _("Syntax: dirmngr-client [options] [certfile|pattern]\n"
            "Test an X.509 certificate against a CRL or do an OCSP check\n"
            "The process returns 0 if the certificate is valid, 1 if it is\n"
            "not valid and other error codes for general failures\n");
      break;

    default: p = NULL;
    }
  return p;
}



int
main (int argc, char **argv )
{
  gpgrt_argparse_t pargs;
  assuan_context_t ctx;
  gpg_error_t err;
  unsigned char *certbuf;
  size_t certbuflen = 0;
  int cmd_ping = 0;
  int cmd_cache_cert = 0;
  int cmd_validate = 0;
  int cmd_lookup = 0;
  int cmd_loadcrl = 0;
  int cmd_squid_mode = 0;

  early_system_init ();
  gpgrt_set_strusage (my_strusage);
  log_set_prefix ("dirmngr-client",
                  GPGRT_LOG_WITH_PREFIX);
  /* Register our string mapper with gpgrt.  Usually done in
   * init_common_subsystems, but we don't need that here.  */
  gpgrt_set_fixed_string_mapper (map_static_macro_string);

  /* For W32 we need to initialize the socket subsystem.  Because we
     don't use Pth we need to do this explicit. */
#ifdef HAVE_W32_SYSTEM
 {
   WSADATA wsadat;

   WSAStartup (0x202, &wsadat);
 }
#endif /*HAVE_W32_SYSTEM*/

  /* Init Assuan.  */
  assuan_set_assuan_log_prefix (log_get_prefix (NULL));
  assuan_set_gpg_err_source (GPG_ERR_SOURCE_DEFAULT);

  /* Setup I18N. */
  i18n_init();

  /* Parse the command line.  */
  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags= ARGPARSE_FLAG_KEEP;
  while (gpgrt_argparse (NULL, &pargs, opts))
    {
      switch (pargs.r_opt)
        {
        case oVerbose: opt.verbose++; break;
        case oQuiet: opt.quiet++; break;

        case oOCSP: opt.use_ocsp++; break;
        case oPing: cmd_ping = 1; break;
        case oCacheCert: cmd_cache_cert = 1; break;
        case oValidate: cmd_validate = 1; break;
        case oLookup: cmd_lookup = 1; break;
        case oUrl: opt.url = 1; break;
        case oLocal: opt.local = 1; break;
        case oLoadCRL: cmd_loadcrl = 1; break;
        case oPEM: opt.pem = 1; break;
        case oSquidMode:
          opt.pem = 1;
          opt.escaped_pem = 1;
          cmd_squid_mode = 1;
          break;
        case oForceDefaultResponder: opt.force_default_responder = 1; break;

        default : pargs.err = ARGPARSE_PRINT_ERROR; break;
	}
    }
  gpgrt_argparse (NULL, &pargs, NULL);

  if (log_get_errorcount (0))
    exit (2);

  if (cmd_ping)
    err = 0;
  else if (cmd_lookup || cmd_loadcrl)
    {
      if (!argc)
        gpgrt_usage (1);
      err = 0;
    }
  else if (cmd_squid_mode)
    {
      err = 0;
      if (argc)
        gpgrt_usage (1);
    }
  else if (!argc)
    {
      err = read_certificate (NULL, &certbuf, &certbuflen);
      if (err)
        log_error (_("error reading certificate from stdin: %s\n"),
                   gpg_strerror (err));
    }
  else if (argc == 1)
    {
      err = read_certificate (*argv, &certbuf, &certbuflen);
      if (err)
        log_error (_("error reading certificate from '%s': %s\n"),
                   *argv, gpg_strerror (err));
    }
  else
    {
      err = 0;
      gpgrt_usage (1);
    }

  if (log_get_errorcount (0))
    exit (2);

  if (certbuflen > 20000)
    {
      log_error (_("certificate too large to make any sense\n"));
      exit (2);
    }

  err = start_new_dirmngr (&ctx,
                           GPG_ERR_SOURCE_DEFAULT,
                           opt.dirmngr_program
                             ? opt.dirmngr_program
                             : gnupg_module_name (GNUPG_MODULE_NAME_DIRMNGR),
                           ! cmd_ping,
                           opt.verbose,
                           0,
                           NULL, NULL);
  if (err)
    {
      log_error (_("can't connect to the dirmngr: %s\n"), gpg_strerror (err));
      exit (2);
    }

  if (cmd_ping)
    ;
  else if (cmd_squid_mode)
    {
      while (!(err = squid_loop_body (ctx)))
        ;
      if (gpg_err_code (err) == GPG_ERR_EOF)
        err = 0;
    }
  else if (cmd_lookup)
    {
      int last_err = 0;

      for (; argc; argc--, argv++)
        {
          err = do_lookup (ctx, *argv);
          if (err)
            {
              log_error (_("lookup failed: %s\n"), gpg_strerror (err));
              last_err = err;
            }
        }
      err = last_err;
    }
  else if (cmd_loadcrl)
    {
      int last_err = 0;

      for (; argc; argc--, argv++)
        {
          err = do_loadcrl (ctx, *argv);
          if (err)
            {
              log_error (_("loading CRL '%s' failed: %s\n"),
                         *argv, gpg_strerror (err));
              last_err = err;
            }
        }
      err = last_err;
    }
  else if (cmd_cache_cert)
    {
      err = do_cache (ctx, certbuf, certbuflen);
      xfree (certbuf);
    }
  else if (cmd_validate)
    {
      err = do_validate (ctx, certbuf, certbuflen);
      xfree (certbuf);
    }
  else
    {
      err = do_check (ctx, certbuf, certbuflen);
      xfree (certbuf);
    }

  assuan_release (ctx);

  if (cmd_ping)
    {
      if (!opt.quiet)
        log_info (_("a dirmngr daemon is up and running\n"));
      return 0;
    }
  else if (cmd_lookup|| cmd_loadcrl || cmd_squid_mode)
    return err? 1:0;
  else if (cmd_cache_cert)
    {
      if (err && gpg_err_code (err) == GPG_ERR_DUP_VALUE )
        {
          if (!opt.quiet)
            log_info (_("certificate already cached\n"));
        }
      else if (err)
        {
          log_error (_("error caching certificate: %s\n"),
                     gpg_strerror (err));
          return 1;
        }
      return 0;
    }
  else if (cmd_validate && err)
    {
      log_error (_("validation of certificate failed: %s\n"),
                 gpg_strerror (err));
      return 1;
    }
  else if (!err)
    {
      if (!opt.quiet)
        log_info (_("certificate is valid\n"));
      return 0;
    }
  else if (gpg_err_code (err) == GPG_ERR_CERT_REVOKED )
    {
      if (!opt.quiet)
        log_info (_("certificate has been revoked\n"));
      return 1;
    }
  else
    {
      log_error (_("certificate check failed: %s\n"), gpg_strerror (err));
      return 2;
    }
}


/* Print status line from the assuan protocol.  */
static gpg_error_t
status_cb (void *opaque, const char *line)
{
  (void)opaque;

  if (opt.verbose > 2)
    log_info (_("got status: '%s'\n"), line);
  return 0;
}

/* Print data as retrieved by the lookup function.  */
static gpg_error_t
data_cb (void *opaque, const void *buffer, size_t length)
{
  gpg_error_t err;
  struct b64state *state = opaque;

  if (buffer)
    {
      err = b64enc_write (state, buffer, length);
      if (err)
        log_error (_("error writing base64 encoding: %s\n"),
                   gpg_strerror (err));
    }
  return 0;
}


/* Read the first PEM certificate from the file FNAME.  If fname is
   NULL the next certificate is read from stdin.  The certificate is
   returned in an alloced buffer whose address will be returned in
   RBUF and its length in RBUFLEN.  */
static gpg_error_t
read_pem_certificate (const char *fname, unsigned char **rbuf, size_t *rbuflen,
                      int no_errmsg)
{
  estream_t fp;
  int c;
  int pos;
  int value;
  unsigned char *buf;
  size_t bufsize, buflen;
  enum {
    s_init, s_idle, s_lfseen, s_begin,
    s_b64_0, s_b64_1, s_b64_2, s_b64_3,
    s_waitend
  } state = s_init;

  init_asctobin ();

  fp = fname? es_fopen (fname, "r") : es_stdin;
  if (!fp)
    return gpg_error_from_syserror ();

  pos = 0;
  value = 0;
  bufsize = 8192;
  buf = xmalloc (bufsize);
  buflen = 0;
  while ((c=es_getc (fp)) != EOF)
    {
      int escaped_c = 0;

      if (opt.escaped_pem)
        {
          if (c == '%')
            {
              char tmp[2];
              if ((c = es_getc(fp)) == EOF)
                break;
              tmp[0] = c;
              if ((c = es_getc(fp)) == EOF)
                break;
              tmp[1] = c;
              if (!hexdigitp (tmp) || !hexdigitp (tmp+1))
                {
                  log_error ("invalid percent escape sequence\n");
                  state = s_idle; /* Force an error. */
                  /* Skip to end of line.  */
                  while ( (c=es_getc (fp)) != EOF && c != '\n')
                    ;
                  goto ready;
                }
              c = xtoi_2 (tmp);
              escaped_c = 1;
            }
          else if (c == '\n')
            goto ready; /* Ready.  */
        }
      switch (state)
        {
        case s_idle:
          if (c == '\n')
            {
              state = s_lfseen;
              pos = 0;
            }
          break;
        case s_init:
          state = s_lfseen; /* fall through */
        case s_lfseen:
          if (c != "-----BEGIN "[pos])
            state = s_idle;
          else if (pos == 10)
            state = s_begin;
          else
            pos++;
          break;
        case s_begin:
          if (c == '\n')
            state = s_b64_0;
          break;
        case s_b64_0:
        case s_b64_1:
        case s_b64_2:
        case s_b64_3:
          {
            if (buflen >= bufsize)
              {
                bufsize += 8192;
                buf = xrealloc (buf, bufsize);
              }

            if (c == '-')
              state = s_waitend;
            else if ((c = asctobin[c & 0xff]) == 255 )
              ; /* Just skip invalid base64 characters. */
            else if (state == s_b64_0)
              {
                value = c << 2;
                state = s_b64_1;
              }
            else if (state == s_b64_1)
              {
                value |= (c>>4)&3;
                buf[buflen++] = value;
                value = (c<<4)&0xf0;
                state = s_b64_2;
              }
            else if (state == s_b64_2)
              {
                value |= (c>>2)&15;
                buf[buflen++] = value;
                value = (c<<6)&0xc0;
                state = s_b64_3;
              }
            else
              {
                value |= c&0x3f;
                buf[buflen++] = value;
                state = s_b64_0;
              }
          }
          break;
        case s_waitend:
          /* Note that we do not check that the base64 decoder has
             been left in the expected state.  We assume that the PEM
             header is just fine.  However we need to wait for the
             real LF and not a trailing percent escaped one. */
          if (c== '\n' && !escaped_c)
            goto ready;
          break;
        default:
          BUG();
        }
    }
 ready:
  if (fname)
    es_fclose (fp);

  if (state == s_init && c == EOF)
    {
      xfree (buf);
      return gpg_error (GPG_ERR_EOF);
    }
  else if (state != s_waitend)
    {
      if (!no_errmsg)
        log_error ("no certificate or invalid encoded\n");
      xfree (buf);
      return gpg_error (GPG_ERR_INV_ARMOR);
    }

  *rbuf = buf;
  *rbuflen = buflen;
  return 0;
}

/* Read a binary certificate from the file FNAME.  If fname is NULL the
   file is read from stdin.  The certificate is returned in an alloced
   buffer whose address will be returned in RBUF and its length in
   RBUFLEN.  */
static gpg_error_t
read_certificate (const char *fname, unsigned char **rbuf, size_t *rbuflen)
{
  gpg_error_t err;
  estream_t fp;
  unsigned char *buf;
  size_t nread, bufsize, buflen;

  if (opt.pem)
    return read_pem_certificate (fname, rbuf, rbuflen, 0);
  else if (fname)
    {
      /* A filename has been given.  Let's just assume it is in PEM
         format and decode it, and fall back to interpreting it as
         binary certificate if that fails.  */
      err = read_pem_certificate (fname, rbuf, rbuflen, 1);
      if (! err)
        return 0;
      /* Clear the error count to try as binary certificate.  */
      log_get_errorcount (1);
    }

  fp = fname? es_fopen (fname, "rb") : es_stdin;
  if (!fp)
    return gpg_error_from_syserror ();

  buf = NULL;
  bufsize = buflen = 0;
#define NCHUNK 8192
  do
    {
      bufsize += NCHUNK;
      if (!buf)
        buf = xmalloc (bufsize);
      else
        buf = xrealloc (buf, bufsize);

      nread = es_fread (buf+buflen, 1, NCHUNK, fp);
      if (nread < NCHUNK && es_ferror (fp))
        {
          err = gpg_error_from_syserror ();
          xfree (buf);
          if (fname)
            es_fclose (fp);
          return err;
        }
      buflen += nread;
    }
  while (nread == NCHUNK);
#undef NCHUNK
  if (fname)
    es_fclose (fp);
  *rbuf = buf;
  *rbuflen = buflen;
  return 0;
}


/* Callback for the inquire fiunction to send back the certificate.  */
static gpg_error_t
inq_cert (void *opaque, const char *line)
{
  struct inq_cert_parm_s *parm = opaque;
  gpg_error_t err;

  if (!strncmp (line, "TARGETCERT", 10) && (line[10] == ' ' || !line[10]))
    {
      err = assuan_send_data (parm->ctx, parm->cert, parm->certlen);
    }
  else if (!strncmp (line, "SENDCERT", 8) && (line[8] == ' ' || !line[8]))
    {
      /* We don't support this but dirmngr might ask for it.  So
         simply ignore it by sending back and empty value. */
      err = assuan_send_data (parm->ctx, NULL, 0);
    }
  else if (!strncmp (line, "SENDCERT_SKI", 12)
           && (line[12]==' ' || !line[12]))
    {
      /* We don't support this but dirmngr might ask for it.  So
         simply ignore it by sending back an empty value. */
      err = assuan_send_data (parm->ctx, NULL, 0);
    }
  else if (!strncmp (line, "SENDISSUERCERT", 14)
           && (line[14] == ' ' || !line[14]))
    {
      /* We don't support this but dirmngr might ask for it.  So
         simply ignore it by sending back an empty value. */
      err = assuan_send_data (parm->ctx, NULL, 0);
    }
  else
    {
      log_info (_("unsupported inquiry '%s'\n"), line);
      err = gpg_error (GPG_ERR_ASS_UNKNOWN_INQUIRE);
      /* Note that this error will let assuan_transact terminate
         immediately instead of return the error to the caller.  It is
         not clear whether this is the desired behaviour - it may
         change in future. */
    }

  return err;
}


/* Check the certificate CERT,CERTLEN for validity using a CRL or OCSP.
   Return a proper error code. */
static gpg_error_t
do_check (assuan_context_t ctx, const unsigned char *cert, size_t certlen)
{
  gpg_error_t err;
  struct inq_cert_parm_s parm;

  memset (&parm, 0, sizeof parm);
  parm.ctx = ctx;
  parm.cert = cert;
  parm.certlen = certlen;

  err = assuan_transact (ctx,
                         (opt.use_ocsp && opt.force_default_responder
                          ? "CHECKOCSP --force-default-responder"
                          : opt.use_ocsp? "CHECKOCSP" : "CHECKCRL"),
                         NULL, NULL, inq_cert, &parm, status_cb, NULL);
  if (opt.verbose > 1)
    log_info ("response of dirmngr: %s\n", err? gpg_strerror (err): "okay");
  return err;
}

/* Check the certificate CERT,CERTLEN for validity using a CRL or OCSP.
   Return a proper error code. */
static gpg_error_t
do_cache (assuan_context_t ctx, const unsigned char *cert, size_t certlen)
{
  gpg_error_t err;
  struct inq_cert_parm_s parm;

  memset (&parm, 0, sizeof parm);
  parm.ctx = ctx;
  parm.cert = cert;
  parm.certlen = certlen;

  err = assuan_transact (ctx, "CACHECERT", NULL, NULL,
                        inq_cert, &parm,
                        status_cb, NULL);
  if (opt.verbose > 1)
    log_info ("response of dirmngr: %s\n", err? gpg_strerror (err): "okay");
  return err;
}

/* Check the certificate CERT,CERTLEN for validity using dirmngrs
   internal validate feature.  Return a proper error code. */
static gpg_error_t
do_validate (assuan_context_t ctx, const unsigned char *cert, size_t certlen)
{
  gpg_error_t err;
  struct inq_cert_parm_s parm;

  memset (&parm, 0, sizeof parm);
  parm.ctx = ctx;
  parm.cert = cert;
  parm.certlen = certlen;

  err = assuan_transact (ctx, "VALIDATE", NULL, NULL,
                        inq_cert, &parm,
                        status_cb, NULL);
  if (opt.verbose > 1)
    log_info ("response of dirmngr: %s\n", err? gpg_strerror (err): "okay");
  return err;
}

/* Load a CRL into the dirmngr.  */
static gpg_error_t
do_loadcrl (assuan_context_t ctx, const char *filename)
{
  gpg_error_t err;
  const char *s;
  char *fname, *line, *p;

  if (opt.url)
    fname = xstrdup (filename);
  else
    {
#ifdef HAVE_CANONICALIZE_FILE_NAME
      fname = canonicalize_file_name (filename);
      if (!fname)
        {
          log_error ("error canonicalizing '%s': %s\n",
                     filename, strerror (errno));
          return gpg_error (GPG_ERR_GENERAL);
        }
#else
      fname = xstrdup (filename);
#endif
      if (*fname != '/')
        {
          log_error (_("absolute file name expected\n"));
          return gpg_error (GPG_ERR_GENERAL);
        }
    }

  line = xmalloc (8 + 6 + strlen (fname) * 3 + 1);
  p = stpcpy (line, "LOADCRL ");
  if (opt.url)
    p = stpcpy (p, "--url ");
  for (s = fname; *s; s++)
    {
      if (*s < ' ' || *s == '+')
        {
          sprintf (p, "%%%02X", *s);
          p += 3;
        }
      else if (*s == ' ')
        *p++ = '+';
      else
        *p++ = *s;
        }
  *p = 0;

  err = assuan_transact (ctx, line, NULL, NULL,
                        NULL, NULL,
                        status_cb, NULL);
  if (opt.verbose > 1)
    log_info ("response of dirmngr: %s\n", err? gpg_strerror (err): "okay");
  xfree (line);
  xfree (fname);
  return err;
}


/* Do a LDAP lookup using PATTERN and print the result in a base-64
   encoded format.  */
static gpg_error_t
do_lookup (assuan_context_t ctx, const char *pattern)
{
  gpg_error_t err;
  const unsigned char *s;
  char *line, *p;
  struct b64state state;

  if (opt.verbose)
    log_info (_("looking up '%s'\n"), pattern);

  err = b64enc_start (&state, stdout, NULL);
  if (err)
    return err;

  line = xmalloc (10 + 6 + 13 + strlen (pattern)*3 + 1);

  p = stpcpy (line, "LOOKUP ");
  if (opt.url)
    p = stpcpy (p, "--url ");
  if (opt.local)
    p = stpcpy (p, "--cache-only ");
  for (s=pattern; *s; s++)
    {
      if (*s < ' ' || *s == '+')
        {
          sprintf (p, "%%%02X", *s);
          p += 3;
        }
      else if (*s == ' ')
        *p++ = '+';
      else
        *p++ = *s;
    }
  *p = 0;


  err = assuan_transact (ctx, line,
                         data_cb, &state,
                         NULL, NULL,
                         status_cb, NULL);
  if (opt.verbose > 1)
    log_info ("response of dirmngr: %s\n", err? gpg_strerror (err): "okay");

  err = b64enc_finish (&state);

  xfree (line);
  return err;
}

/* The body of an endless loop: Read a line from stdin, retrieve the
   certificate from it, validate it and print "ERR" or "OK" to stdout.
   Continue.  */
static gpg_error_t
squid_loop_body (assuan_context_t ctx)
{
  gpg_error_t err;
  unsigned char *certbuf;
  size_t certbuflen = 0;

  err = read_pem_certificate (NULL, &certbuf, &certbuflen, 0);
  if (gpg_err_code (err) == GPG_ERR_EOF)
    return err;
  if (err)
    {
      log_error (_("error reading certificate from stdin: %s\n"),
                 gpg_strerror (err));
      puts ("ERROR");
      return 0;
    }

  err = do_check (ctx, certbuf, certbuflen);
  xfree (certbuf);
  if (!err)
    {
      if (opt.verbose)
        log_info (_("certificate is valid\n"));
      puts ("OK");
    }
  else
    {
      if (!opt.quiet)
        {
          if (gpg_err_code (err) == GPG_ERR_CERT_REVOKED )
            log_info (_("certificate has been revoked\n"));
          else
            log_error (_("certificate check failed: %s\n"),
                       gpg_strerror (err));
        }
      puts ("ERROR");
    }

  fflush (stdout);

  return 0;
}
