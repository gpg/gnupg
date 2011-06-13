/* pkglue.c - public key operations glue code
 *	Copyright (C) 2000, 2003 Free Software Foundation, Inc.
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
#include <assert.h>

#include "gpg.h"
#include "util.h"
#include "pkglue.h"


static gcry_mpi_t
mpi_from_sexp (gcry_sexp_t sexp, const char * item)
{
  gcry_sexp_t list;
  gcry_mpi_t data;

  list = gcry_sexp_find_token (sexp, item, 0);
  assert (list);
  data = gcry_sexp_nth_mpi (list, 1, GCRYMPI_FMT_USG);
  assert (data);
  gcry_sexp_release (list);
  return data;
}


/****************
 * Emulate our old PK interface here - sometime in the future we might
 * change the internal design to directly fit to libgcrypt.
 */
int
pk_sign (int algo, gcry_mpi_t * data, gcry_mpi_t hash, gcry_mpi_t * skey)
{
  gcry_sexp_t s_sig, s_hash, s_skey;
  int rc;

  /* make a sexp from skey */
  if (algo == GCRY_PK_DSA)
    {
      rc = gcry_sexp_build (&s_skey, NULL,
			    "(private-key(dsa(p%m)(q%m)(g%m)(y%m)(x%m)))",
			    skey[0], skey[1], skey[2], skey[3], skey[4]);
    }
  else if (algo == GCRY_PK_RSA || algo == GCRY_PK_RSA_S)
    {
      rc = gcry_sexp_build (&s_skey, NULL,
			    "(private-key(rsa(n%m)(e%m)(d%m)(p%m)(q%m)(u%m)))",
			    skey[0], skey[1], skey[2], skey[3], skey[4],
			    skey[5]);
    }
  else if (algo == GCRY_PK_ELG || algo == GCRY_PK_ELG_E)
    {
      rc = gcry_sexp_build (&s_skey, NULL,
			    "(private-key(elg(p%m)(g%m)(y%m)(x%m)))",
			    skey[0], skey[1], skey[2], skey[3]);
    }
  else
    return GPG_ERR_PUBKEY_ALGO;

  if (rc)
    BUG ();

  /* put hash into a S-Exp s_hash */
  if (gcry_sexp_build (&s_hash, NULL, "%m", hash))
    BUG ();

  rc = gcry_pk_sign (&s_sig, s_hash, s_skey);
  gcry_sexp_release (s_hash);
  gcry_sexp_release (s_skey);

  if (rc)
    ;
  else if (algo == GCRY_PK_RSA || algo == GCRY_PK_RSA_S)
    data[0] = mpi_from_sexp (s_sig, "s");
  else
    {
      data[0] = mpi_from_sexp (s_sig, "r");
      data[1] = mpi_from_sexp (s_sig, "s");
    }

  gcry_sexp_release (s_sig);
  return rc;
}

/****************
 * Emulate our old PK interface here - sometime in the future we might
 * change the internal design to directly fit to libgcrypt.
 */
int
pk_verify (int algo, gcry_mpi_t hash, gcry_mpi_t * data, gcry_mpi_t * pkey)
{
  gcry_sexp_t s_sig, s_hash, s_pkey;
  int rc;

  /* make a sexp from pkey */
  if (algo == GCRY_PK_DSA)
    {
      rc = gcry_sexp_build (&s_pkey, NULL,
			    "(public-key(dsa(p%m)(q%m)(g%m)(y%m)))",
			    pkey[0], pkey[1], pkey[2], pkey[3]);
    }
  else if (algo == GCRY_PK_ELG || algo == GCRY_PK_ELG_E)
    {
      rc = gcry_sexp_build (&s_pkey, NULL,
			    "(public-key(elg(p%m)(g%m)(y%m)))",
			    pkey[0], pkey[1], pkey[2]);
    }
  else if (algo == GCRY_PK_RSA || algo == GCRY_PK_RSA_S)
    {
      rc = gcry_sexp_build (&s_pkey, NULL,
			    "(public-key(rsa(n%m)(e%m)))", pkey[0], pkey[1]);
    }
  else
    return GPG_ERR_PUBKEY_ALGO;

  if (rc)
    BUG ();  /* gcry_sexp_build should never fail.  */

  /* put hash into a S-Exp s_hash */
  if (gcry_sexp_build (&s_hash, NULL, "%m", hash))
    BUG (); /* gcry_sexp_build should never fail.  */

  /* Put data into a S-Exp s_sig. */
  s_sig = NULL;
  if (algo == GCRY_PK_DSA)
    {
      if (!data[0] || !data[1])
        rc = gpg_error (GPG_ERR_BAD_MPI);
      else
        rc = gcry_sexp_build (&s_sig, NULL,
                              "(sig-val(dsa(r%m)(s%m)))", data[0], data[1]);
    }
  else if (algo == GCRY_PK_ELG || algo == GCRY_PK_ELG_E)
    {
      if (!data[0] || !data[1])
        rc = gpg_error (GPG_ERR_BAD_MPI);
      else
        rc = gcry_sexp_build (&s_sig, NULL,
                              "(sig-val(elg(r%m)(s%m)))", data[0], data[1]);
    }
  else if (algo == GCRY_PK_RSA || algo == GCRY_PK_RSA_S)
    {
      if (!data[0])
        rc = gpg_error (GPG_ERR_BAD_MPI);
      else
        rc = gcry_sexp_build (&s_sig, NULL, "(sig-val(rsa(s%m)))", data[0]);
    }
  else
    BUG ();

  if (!rc)
    rc = gcry_pk_verify (s_sig, s_hash, s_pkey);

  gcry_sexp_release (s_sig);
  gcry_sexp_release (s_hash);
  gcry_sexp_release (s_pkey);
  return rc;
}




/****************
 * Emulate our old PK interface here - sometime in the future we might
 * change the internal design to directly fit to libgcrypt.
 */
int
pk_encrypt (int algo, gcry_mpi_t * resarr, gcry_mpi_t data, gcry_mpi_t * pkey)
{
  gcry_sexp_t s_ciph, s_data, s_pkey;
  int rc;

  /* make a sexp from pkey */
  if (algo == GCRY_PK_ELG || algo == GCRY_PK_ELG_E)
    {
      rc = gcry_sexp_build (&s_pkey, NULL,
			    "(public-key(elg(p%m)(g%m)(y%m)))",
			    pkey[0], pkey[1], pkey[2]);
    }
  else if (algo == GCRY_PK_RSA || algo == GCRY_PK_RSA_E)
    {
      rc = gcry_sexp_build (&s_pkey, NULL,
			    "(public-key(rsa(n%m)(e%m)))",
			    pkey[0], pkey[1]);
    }
  else
    return GPG_ERR_PUBKEY_ALGO;

  if (rc)
    BUG ();

  /* put the data into a simple list */
  if (gcry_sexp_build (&s_data, NULL, "%m", data))
    BUG ();

  /* pass it to libgcrypt */
  rc = gcry_pk_encrypt (&s_ciph, s_data, s_pkey);
  gcry_sexp_release (s_data);
  gcry_sexp_release (s_pkey);

  if (rc)
    ;
  else
    { /* add better error handling or make gnupg use S-Exp directly */
      resarr[0] = mpi_from_sexp (s_ciph, "a");
      if (algo != GCRY_PK_RSA && algo != GCRY_PK_RSA_E)
        resarr[1] = mpi_from_sexp (s_ciph, "b");
    }

  gcry_sexp_release (s_ciph);
  return rc;
}



/****************
 * Emulate our old PK interface here - sometime in the future we might
 * change the internal design to directly fit to libgcrypt.
 */
int
pk_decrypt (int algo, gcry_mpi_t * result, gcry_mpi_t * data,
	    gcry_mpi_t * skey)
{
  gcry_sexp_t s_skey, s_data, s_plain;
  int rc;

  *result = NULL;
  /* make a sexp from skey */
  if (algo == GCRY_PK_ELG || algo == GCRY_PK_ELG_E)
    {
      rc = gcry_sexp_build (&s_skey, NULL,
			    "(private-key(elg(p%m)(g%m)(y%m)(x%m)))",
			    skey[0], skey[1], skey[2], skey[3]);
    }
  else if (algo == GCRY_PK_RSA || algo == GCRY_PK_RSA_E)
    {
      rc = gcry_sexp_build (&s_skey, NULL,
			    "(private-key(rsa(n%m)(e%m)(d%m)(p%m)(q%m)(u%m)))",
			    skey[0], skey[1], skey[2], skey[3], skey[4],
			    skey[5]);
    }
  else
    return GPG_ERR_PUBKEY_ALGO;

  if (rc)
    BUG ();

  /* put data into a S-Exp s_data */
  if (algo == GCRY_PK_ELG || algo == GCRY_PK_ELG_E)
    {
      if (!data[0] || !data[1])
        rc = gpg_error (GPG_ERR_BAD_MPI);
      else
        rc = gcry_sexp_build (&s_data, NULL,
                              "(enc-val(elg(a%m)(b%m)))", data[0], data[1]);
    }
  else if (algo == GCRY_PK_RSA || algo == GCRY_PK_RSA_E)
    {
      if (!data[0])
        rc = gpg_error (GPG_ERR_BAD_MPI);
      else
        rc = gcry_sexp_build (&s_data, NULL, "(enc-val(rsa(a%m)))", data[0]);
    }
  else
    BUG ();

  if (rc)
    BUG ();

  rc = gcry_pk_decrypt (&s_plain, s_data, s_skey);
  gcry_sexp_release (s_skey);
  gcry_sexp_release (s_data);
  if (rc)
    return rc;

  *result = gcry_sexp_nth_mpi (s_plain, 0, GCRYMPI_FMT_USG);
  gcry_sexp_release (s_plain);
  if (!*result)
    return -1;			/* oops */

  return 0;
}


/* Check whether SKEY is a suitable secret key. */
int
pk_check_secret_key (int algo, gcry_mpi_t *skey)
{
  gcry_sexp_t s_skey;
  int rc;

  if (algo == GCRY_PK_DSA)
    {
      rc = gcry_sexp_build (&s_skey, NULL,
			    "(private-key(dsa(p%m)(q%m)(g%m)(y%m)(x%m)))",
			    skey[0], skey[1], skey[2], skey[3], skey[4]);
    }
  else if (algo == GCRY_PK_ELG || algo == GCRY_PK_ELG_E)
    {
      rc = gcry_sexp_build (&s_skey, NULL,
			    "(private-key(elg(p%m)(g%m)(y%m)(x%m)))",
			    skey[0], skey[1], skey[2], skey[3]);
    }
  else if (algo == GCRY_PK_RSA
           || algo == GCRY_PK_RSA_S || algo == GCRY_PK_RSA_E)
    {
      rc = gcry_sexp_build (&s_skey, NULL,
			    "(private-key(rsa(n%m)(e%m)(d%m)(p%m)(q%m)(u%m)))",
			    skey[0], skey[1], skey[2], skey[3], skey[4],
			    skey[5]);
    }
  else
    return GPG_ERR_PUBKEY_ALGO;

  if (!rc)
    {
      rc = gcry_pk_testkey (s_skey);
      gcry_sexp_release (s_skey);
    }
  return rc;
}
