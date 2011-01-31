/* pkglue.c - public key operations glue code
 *	Copyright (C) 2000, 2003, 2010 Free Software Foundation, Inc.
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
#include "main.h"
#include "options.h"

/* FIXME: Better chnage the fucntion name because mpi_ is used by
   gcrypt macros.  */
gcry_mpi_t
mpi_from_sexp (gcry_sexp_t sexp, const char * item)
{
  gcry_sexp_t list;
  gcry_mpi_t data;
  
  list = gcry_sexp_find_token (sexp, item, 0);
  assert (list);
  data = gcry_sexp_nth_mpi (list, 1, 0);
  assert (data);
  gcry_sexp_release (list);
  return data;
}



/****************
 * Emulate our old PK interface here - sometime in the future we might
 * change the internal design to directly fit to libgcrypt.
 */
int
pk_verify (int algo, gcry_mpi_t hash, gcry_mpi_t *data, gcry_mpi_t *pkey)
{
  gcry_sexp_t s_sig, s_hash, s_pkey;
  int rc;
  const int pkalgo = map_pk_openpgp_to_gcry (algo);

  /* Make a sexp from pkey.  */
  if (pkalgo == GCRY_PK_DSA)
    {
      rc = gcry_sexp_build (&s_pkey, NULL,
			    "(public-key(dsa(p%m)(q%m)(g%m)(y%m)))",
			    pkey[0], pkey[1], pkey[2], pkey[3]);
    }
  else if (pkalgo == GCRY_PK_ELG || pkalgo == GCRY_PK_ELG_E)
    {
      rc = gcry_sexp_build (&s_pkey, NULL,
			    "(public-key(elg(p%m)(g%m)(y%m)))",
			    pkey[0], pkey[1], pkey[2]);
    }
  else if (pkalgo == GCRY_PK_RSA || pkalgo == GCRY_PK_RSA_S)
    {
      rc = gcry_sexp_build (&s_pkey, NULL,
			    "(public-key(rsa(n%m)(e%m)))", pkey[0], pkey[1]);
    }
  else if (pkalgo == GCRY_PK_ECDSA) /* Same as GCRY_PK_ECDH */
    {
      char *curve = openpgp_oid_to_str (pkey[0]);
      if (!curve)
        rc = gpg_error_from_syserror ();
      else
        {
          rc = gcry_sexp_build (&s_pkey, NULL,
                                "(public-key(ecdsa(curve %s)(q%m)))",
                                curve, pkey[1]);
          xfree (curve);
        }
    }
  else
    return GPG_ERR_PUBKEY_ALGO;

  if (rc)
    BUG ();  /* gcry_sexp_build should never fail.  */

  /* Put hash into a S-Exp s_hash. */
  if (gcry_sexp_build (&s_hash, NULL, "%m", hash))
    BUG (); /* gcry_sexp_build should never fail.  */

  /* Put data into a S-Exp s_sig. */
  s_sig = NULL;
  if (pkalgo == GCRY_PK_DSA)
    {
      if (!data[0] || !data[1])
        rc = gpg_error (GPG_ERR_BAD_MPI);
      else
        rc = gcry_sexp_build (&s_sig, NULL,
                              "(sig-val(dsa(r%m)(s%m)))", data[0], data[1]);
    }
  else if (pkalgo == GCRY_PK_ECDSA)
    {
      if (!data[0] || !data[1])
        rc = gpg_error (GPG_ERR_BAD_MPI);
      else
        rc = gcry_sexp_build (&s_sig, NULL,
                              "(sig-val(ecdsa(r%m)(s%m)))", data[0], data[1]);
    }
  else if (pkalgo == GCRY_PK_ELG || pkalgo == GCRY_PK_ELG_E)
    {
      if (!data[0] || !data[1])
        rc = gpg_error (GPG_ERR_BAD_MPI);
      else
        rc = gcry_sexp_build (&s_sig, NULL,
                              "(sig-val(elg(r%m)(s%m)))", data[0], data[1]);
    }
  else if (pkalgo == GCRY_PK_RSA || pkalgo == GCRY_PK_RSA_S)
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
pk_encrypt (int algo, gcry_mpi_t *resarr, gcry_mpi_t data,
            const byte pk_fp[MAX_FINGERPRINT_LEN], gcry_mpi_t *pkey)
{
  gcry_sexp_t s_ciph, s_data, s_pkey;
  int rc;

  /* Make a sexp from pkey.  */
  if (algo == GCRY_PK_ELG || algo == GCRY_PK_ELG_E)
    {
      rc = gcry_sexp_build (&s_pkey, NULL,
			    "(public-key(elg(p%m)(g%m)(y%m)))",
			    pkey[0], pkey[1], pkey[2]);
      /* Put DATA into a simplified S-expression.  */
      if (rc || gcry_sexp_build (&s_data, NULL, "%m", data))
        BUG ();

    }
  else if (algo == GCRY_PK_RSA || algo == GCRY_PK_RSA_E)
    {
      rc = gcry_sexp_build (&s_pkey, NULL,
			    "(public-key(rsa(n%m)(e%m)))",
			    pkey[0], pkey[1]);
      /* Put DATA into a simplified S-expression.  */
      if (rc || gcry_sexp_build (&s_data, NULL, "%m", data))
        BUG ();
    }
  else if (algo == PUBKEY_ALGO_ECDH)	
    {
      gcry_mpi_t k;
      char *curve;

      rc = pk_ecdh_generate_ephemeral_key (pkey, &k);
      if (rc)
        return rc;
      
      curve = openpgp_oid_to_str (pkey[0]);
      if (!curve)
        rc = gpg_error_from_syserror ();
      else
        {
          /* Now use the ephemeral secret to compute the shared point.  */
          rc = gcry_sexp_build (&s_pkey, NULL,
                                "(public-key(ecdh(curve%s)(q%m)))",
                                curve, pkey[1]);
          xfree (curve);
          /* FIXME: Take care of RC.  */
          /* Put K into a simplified S-expression.  */
          if (rc || gcry_sexp_build (&s_data, NULL, "%m", k))
            BUG ();
        }
    }
  else
    return gpg_error (GPG_ERR_PUBKEY_ALGO);


  /* Pass it to libgcrypt. */
  rc = gcry_pk_encrypt (&s_ciph, s_data, s_pkey);
  gcry_sexp_release (s_data);
  gcry_sexp_release (s_pkey);

  if (rc)
    ;
  else if (algo == PUBKEY_ALGO_ECDH)	
    {
      gcry_mpi_t shared, public, result;

      /* Get the shared point and the ephemeral public key.  */
      shared = mpi_from_sexp (s_ciph, "s"); 
      public = mpi_from_sexp (s_ciph, "e");
      gcry_sexp_release (s_ciph);
      s_ciph = NULL;
      if (DBG_CIPHER)
        {
          log_debug ("ECDH ephemeral key:");
          gcry_mpi_dump (public);
          log_printf ("\n");
        }
    
      result = NULL;
      rc = pk_ecdh_encrypt_with_shared_point (1 /*=encrypton*/, shared,
                                              pk_fp, data, pkey, &result);
      gcry_mpi_release (shared);
      if (!rc)
        {
          resarr[0] = public;
          resarr[1] = result;
        }
      else
        {
          gcry_mpi_release (public);
          gcry_mpi_release (result);
        }
    }
  else /* Elgamal or RSA case.  */
    { /* Fixme: Add better error handling or make gnupg use
         S-expressions directly.  */
      resarr[0] = mpi_from_sexp (s_ciph, "a");
      if (algo != GCRY_PK_RSA && algo != GCRY_PK_RSA_E)
        resarr[1] = mpi_from_sexp (s_ciph, "b");
    }

  gcry_sexp_release (s_ciph);
  return rc;
}


/* Check whether SKEY is a suitable secret key. */
int
pk_check_secret_key (int algo, gcry_mpi_t *skey)
{
  gcry_sexp_t s_skey;
  int rc;
  const int gcry_pkalgo = map_pk_openpgp_to_gcry( algo );

  if (gcry_pkalgo == GCRY_PK_DSA)
    {
      rc = gcry_sexp_build (&s_skey, NULL,
			    "(private-key(dsa(p%m)(q%m)(g%m)(y%m)(x%m)))",
			    skey[0], skey[1], skey[2], skey[3], skey[4]);
    }
  else if (gcry_pkalgo == GCRY_PK_ELG || gcry_pkalgo == GCRY_PK_ELG_E)
    {
      rc = gcry_sexp_build (&s_skey, NULL,
			    "(private-key(elg(p%m)(g%m)(y%m)(x%m)))",
			    skey[0], skey[1], skey[2], skey[3]);
    }
  else if (gcry_pkalgo == GCRY_PK_RSA
           || gcry_pkalgo == GCRY_PK_RSA_S || gcry_pkalgo == GCRY_PK_RSA_E)
    {
      rc = gcry_sexp_build (&s_skey, NULL,
			    "(private-key(rsa(n%m)(e%m)(d%m)(p%m)(q%m)(u%m)))",
			    skey[0], skey[1], skey[2], skey[3], skey[4],
			    skey[5]);
    }
  else if (gcry_pkalgo == GCRY_PK_ECDSA || gcry_pkalgo == GCRY_PK_ECDH)
    {
      char *curve = openpgp_oid_to_str (skey[0]);
      if (!curve)
        rc = gpg_error_from_syserror ();
      else
        {
          rc = gcry_sexp_build (&s_skey, NULL,
                                "(private-key(ecdsa(curve%s)(q%m)(d%m)))",
                                curve, skey[1], skey[2]);
          xfree (curve);
        }
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
