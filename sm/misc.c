/* misc.c - Miscellaneous functions
 * Copyright (C) 2004, 2009, 2011 Free Software Foundation, Inc.
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
#include <ctype.h>
#include <unistd.h>
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif

#include "gpgsm.h"
#include "../common/i18n.h"
#include "../common/sysutils.h"
#include "../common/tlv.h"
#include "../common/sexp-parse.h"


/* Setup the environment so that the pinentry is able to get all
   required information.  This is used prior to an exec of the
   protect-tool. */
void
setup_pinentry_env (void)
{
#ifndef HAVE_W32_SYSTEM
  char *lc;
  const char *name, *value;
  int iterator;

  /* Try to make sure that GPG_TTY has been set.  This is needed if we
     call for example the protect-tools with redirected stdin and thus
     it won't be able to ge a default by itself.  Try to do it here
     but print a warning.  */
  value = session_env_getenv (opt.session_env, "GPG_TTY");
  if (value)
    gnupg_setenv ("GPG_TTY", value, 1);
  else if (!(lc=getenv ("GPG_TTY")) || !*lc)
    {
      log_error (_("GPG_TTY has not been set - "
                   "using maybe bogus default\n"));
      lc = gnupg_ttyname (0);
      if (!lc)
        lc = "/dev/tty";
      gnupg_setenv ("GPG_TTY", lc, 1);
    }

  if (opt.lc_ctype)
    gnupg_setenv ("LC_CTYPE", opt.lc_ctype, 1);
#if defined(HAVE_SETLOCALE) && defined(LC_CTYPE)
  else if ( (lc = setlocale (LC_CTYPE, "")) )
    gnupg_setenv ("LC_CTYPE", lc, 1);
#endif

  if (opt.lc_messages)
    gnupg_setenv ("LC_MESSAGES", opt.lc_messages, 1);
#if defined(HAVE_SETLOCALE) && defined(LC_MESSAGES)
  else if ( (lc = setlocale (LC_MESSAGES, "")) )
    gnupg_setenv ("LC_MESSAGES", lc, 1);
#endif

  iterator = 0;
  while ((name = session_env_list_stdenvnames (&iterator, NULL)))
    {
      if (!strcmp (name, "GPG_TTY"))
        continue;  /* Already set.  */
      value = session_env_getenv (opt.session_env, name);
      if (value)
        gnupg_setenv (name, value, 1);
    }

#endif /*!HAVE_W32_SYSTEM*/
}



/* Transform a sig-val style s-expression as returned by Libgcrypt to
   one which includes an algorithm identifier encoding the public key
   and the hash algorithm.  The public key algorithm is taken directly
   from SIGVAL and the hash algorithm is given by MDALGO.  This is
   required because X.509 merges the public key algorithm and the hash
   algorithm into one OID but Libgcrypt is not aware of that.  The
   function ignores missing parameters so that it can also be used to
   create an siginfo value as expected by ksba_certreq_set_siginfo.
   To create a siginfo s-expression a public-key s-expression may be
   used instead of a sig-val.  We only support RSA for now.  */
gpg_error_t
transform_sigval (const unsigned char *sigval, size_t sigvallen, int mdalgo,
                  unsigned char **r_newsigval, size_t *r_newsigvallen)
{
  gpg_error_t err;
  const unsigned char *buf, *tok;
  size_t buflen, toklen;
  int depth, last_depth1, last_depth2;
  int is_pubkey = 0;
  const unsigned char *rsa_s = NULL;
  size_t rsa_s_len = 0;
  const char *oid;
  gcry_sexp_t sexp;

  *r_newsigval = NULL;
  if (r_newsigvallen)
    *r_newsigvallen = 0;

  buf = sigval;
  buflen = sigvallen;
  depth = 0;
  if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
    return err;
  if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
    return err;
  if (tok && toklen == 7 && !memcmp ("sig-val", tok, toklen))
    ;
  else if (tok && toklen == 10 && !memcmp ("public-key", tok, toklen))
    is_pubkey = 1;
  else
    return gpg_error (GPG_ERR_UNKNOWN_SEXP);
  if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
    return err;
  if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
    return err;
  if (!tok || toklen != 3 || memcmp ("rsa", tok, toklen))
    return gpg_error (GPG_ERR_WRONG_PUBKEY_ALGO);

  last_depth1 = depth;
  while (!(err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen))
         && depth && depth >= last_depth1)
    {
      if (tok)
        return gpg_error (GPG_ERR_UNKNOWN_SEXP);
      if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
        return err;
      if (tok && toklen == 1)
        {
          const unsigned char **mpi;
          size_t *mpi_len;

          switch (*tok)
            {
            case 's': mpi = &rsa_s; mpi_len = &rsa_s_len; break;
            default:  mpi = NULL;   mpi_len = NULL; break;
            }
          if (mpi && *mpi)
            return gpg_error (GPG_ERR_DUP_VALUE);

          if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
            return err;
          if (tok && mpi)
            {
              *mpi = tok;
              *mpi_len = toklen;
            }
        }

      /* Skip to the end of the list. */
      last_depth2 = depth;
      while (!(err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen))
             && depth && depth >= last_depth2)
        ;
      if (err)
        return err;
    }
  if (err)
    return err;

  /* Map the hash algorithm to an OID.  */
  switch (mdalgo)
    {
    case GCRY_MD_SHA1:
      oid = "1.2.840.113549.1.1.5";  /* sha1WithRSAEncryption */
      break;

    case GCRY_MD_SHA256:
      oid = "1.2.840.113549.1.1.11"; /* sha256WithRSAEncryption */
      break;

    case GCRY_MD_SHA384:
      oid = "1.2.840.113549.1.1.12"; /* sha384WithRSAEncryption */
      break;

    case GCRY_MD_SHA512:
      oid = "1.2.840.113549.1.1.13"; /* sha512WithRSAEncryption */
      break;

    default:
      return gpg_error (GPG_ERR_DIGEST_ALGO);
    }

  if (rsa_s && !is_pubkey)
    err = gcry_sexp_build (&sexp, NULL, "(sig-val(%s(s%b)))",
                           oid, (int)rsa_s_len, rsa_s);
  else
    err = gcry_sexp_build (&sexp, NULL, "(sig-val(%s))", oid);
  if (err)
    return err;
  err = make_canon_sexp (sexp, r_newsigval, r_newsigvallen);
  gcry_sexp_release (sexp);

  return err;
}
