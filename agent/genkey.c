/* pksign.c - Generate a keypair
 *	Copyright (C) 2002 Free Software Foundation, Inc.
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

#include "agent.h"
#include "i18n.h"

static int
store_key (GCRY_SEXP private, const char *passphrase, int force)
{
  int rc;
  char *buf;
  size_t len;
  unsigned char grip[20];
  
  if ( !gcry_pk_get_keygrip (private, grip) )
    {
      log_error ("can't calculate keygrip\n");
      return gpg_error (GPG_ERR_GENERAL);
    }

  len = gcry_sexp_sprint (private, GCRYSEXP_FMT_CANON, NULL, 0);
  assert (len);
  buf = gcry_malloc_secure (len);
  if (!buf)
      return out_of_core ();
  len = gcry_sexp_sprint (private, GCRYSEXP_FMT_CANON, buf, len);
  assert (len);

  if (passphrase)
    {
      unsigned char *p;

      rc = agent_protect (buf, passphrase, &p, &len);
      if (rc)
        {
          xfree (buf);
          return rc;
        }
      xfree (buf);
      buf = p;
    }

  rc = agent_write_private_key (grip, buf, len, force);
  xfree (buf);
  return rc;
}

/* Callback function to compare the first entered PIN with the one
   currently being entered. */
static int
reenter_compare_cb (struct pin_entry_info_s *pi)
{
  const char *pin1 = pi->check_cb_arg;

  if (!strcmp (pin1, pi->pin))
    return 0; /* okay */
  pi->cb_errtext = _("does not match - try again");
  return -1;
}



/* Generate a new keypair according to the parameters given in
   KEYPARAM */
int
agent_genkey (CTRL ctrl, const char *keyparam, size_t keyparamlen,
              FILE *outfp) 
{
  GCRY_SEXP s_keyparam, s_key, s_private, s_public;
  struct pin_entry_info_s *pi, *pi2;
  int rc;
  size_t len;
  char *buf;

  rc = gcry_sexp_sscan (&s_keyparam, NULL, keyparam, keyparamlen);
  if (rc)
    {
      log_error ("failed to convert keyparam: %s\n", gcry_strerror (rc));
      return gpg_error (GPG_ERR_INV_DATA);
    }

  /* Get the passphrase now, cause key generation may take a while. */
  {
    const char *text1 = _("Please enter the passphrase to%0A"
                               "to protect your new key");
    const char *text2 = _("Please re-enter this passphrase");

    pi = gcry_calloc_secure (2, sizeof (*pi) + 100);
    pi2 = pi + (sizeof *pi + 100);
    pi->max_length = 100;
    pi->max_tries = 3;
    pi2->max_length = 100;
    pi2->max_tries = 3;
    pi2->check_cb = reenter_compare_cb;
    pi2->check_cb_arg = pi->pin;

    rc = agent_askpin (ctrl, text1, pi);
    if (!rc)
      rc = agent_askpin (ctrl, text2, pi2);
    if (rc)
      return rc;
    if (!*pi->pin)
      {
        xfree (pi);
        pi = NULL; /* User does not want a passphrase. */
      }
  }

  rc = gcry_pk_genkey (&s_key, s_keyparam );
  gcry_sexp_release (s_keyparam);
  if (rc)
    {
      log_error ("key generation failed: %s\n", gcry_strerror (rc));
      xfree (pi);
      return map_gcry_err (rc);
    }

  /* break out the parts */
  s_private = gcry_sexp_find_token (s_key, "private-key", 0);
  if (!s_private)
    {
      log_error ("key generation failed: invalid return value\n");
      gcry_sexp_release (s_key);
      xfree (pi);
      return gpg_error (GPG_ERR_INV_DATA);
    }
  s_public = gcry_sexp_find_token (s_key, "public-key", 0);
  if (!s_public)
    {
      log_error ("key generation failed: invalid return value\n");
      gcry_sexp_release (s_private);
      gcry_sexp_release (s_key);
      xfree (pi);
      return gpg_error (GPG_ERR_INV_DATA);
    }
  gcry_sexp_release (s_key); s_key = NULL;
  
  /* store the secret key */
  log_debug ("storing private key\n");
  rc = store_key (s_private, pi? pi->pin:NULL, 0);
  xfree (pi); pi = NULL;
  gcry_sexp_release (s_private);
  if (rc)
    {
      gcry_sexp_release (s_public);
      return rc;
    }

  /* return the public key */
  log_debug ("returning public key\n");
  len = gcry_sexp_sprint (s_public, GCRYSEXP_FMT_CANON, NULL, 0);
  assert (len);
  buf = xtrymalloc (len);
  if (!buf)
    {
      gpg_error_t tmperr = out_of_core ();
      gcry_sexp_release (s_private);
      gcry_sexp_release (s_public);
      return tmperr;
    }
  len = gcry_sexp_sprint (s_public, GCRYSEXP_FMT_CANON, buf, len);
  assert (len);
  if (fwrite (buf, len, 1, outfp) != 1)
    {
      gpg_error_t tmperr = gpg_error (gpg_err_code_from_errno (errno));
      log_error ("error writing public key: %s\n", strerror (errno));
      gcry_sexp_release (s_private);
      gcry_sexp_release (s_public);
      xfree (buf);
      return tmperr;
    }
  gcry_sexp_release (s_public);
  xfree (buf);

  return 0;
}



/* Apply a new passpahrse to the key S_SKEY and store it. */
int
agent_protect_and_store (CTRL ctrl, GCRY_SEXP s_skey) 
{
  struct pin_entry_info_s *pi, *pi2;
  int rc;

  {
    const char *text1 = _("Please enter the new passphrase");
    const char *text2 = _("Please re-enter this passphrase");

    pi = gcry_calloc_secure (2, sizeof (*pi) + 100);
    pi2 = pi + (sizeof *pi + 100);
    pi->max_length = 100;
    pi->max_tries = 3;
    pi2->max_length = 100;
    pi2->max_tries = 3;
    pi2->check_cb = reenter_compare_cb;
    pi2->check_cb_arg = pi->pin;

    rc = agent_askpin (ctrl, text1, pi);
    if (!rc)
      rc = agent_askpin (ctrl, text2, pi2);
    if (rc)
      return rc;
    if (!*pi->pin)
      {
        xfree (pi);
        pi = NULL; /* User does not want a passphrase. */
      }
  }

  rc = store_key (s_skey, pi? pi->pin:NULL, 1);
  xfree (pi);
  return 0;
}
