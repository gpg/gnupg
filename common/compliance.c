/* compliance.c - Functions for compliance modi
 * Copyright (C) 2017 g10 Code GmbH
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <gcrypt.h>

#include "openpgpdefs.h"
#include "logging.h"
#include "util.h"
#include "i18n.h"
#include "compliance.h"

/* Return true if ALGO with a key of KEYLENGTH is compliant to the
 * given COMPLIANCE mode.  If KEY is not NULL, various bits of
 * information will be extracted from it.  If CURVENAME is not NULL, it
 * is assumed to be the already computed.  ALGO may be either an
 * OpenPGP-style pubkey_algo_t, or a gcrypt-style enum gcry_pk_algos,
 * both are compatible from the point of view of this function.  */
int
gnupg_pk_is_compliant (enum gnupg_compliance_mode compliance, int algo,
		       gcry_mpi_t key[], unsigned int keylength, const char *curvename)
{
  enum { is_rsa, is_dsa, is_pgp5, is_elg_sign, is_ecc } algotype;
  int result = 0;

  switch (algo)
    {
    case PUBKEY_ALGO_RSA:
    case PUBKEY_ALGO_RSA_E:
    case PUBKEY_ALGO_RSA_S:
      algotype = is_rsa;
      break;

    case PUBKEY_ALGO_DSA:
      algotype = is_dsa;
      break;

    case PUBKEY_ALGO_ELGAMAL_E:
      algotype = is_pgp5;
      break;

    case PUBKEY_ALGO_ECDH:
    case PUBKEY_ALGO_ECDSA:
    case PUBKEY_ALGO_EDDSA:
      algotype = is_ecc;
      break;

    case PUBKEY_ALGO_ELGAMAL:
      algotype = is_elg_sign;
      break;

    default: /* Unknown.  */
      return 0;
    }

  if (compliance == CO_DE_VS)
    {
      char *curve = NULL;

      switch (algotype)
        {
        case is_pgp5:
          result = 0;
          break;

        case is_rsa:
          result = (keylength == 2048
                    || keylength == 3072
                    || keylength == 4096);
          break;

	case is_dsa:
	  if (key)
	    {
	      size_t L = gcry_mpi_get_nbits (key[0] /* p */);
	      size_t N = gcry_mpi_get_nbits (key[1] /* q */);
	      result = (L == 256
			&& (N == 2048 || N == 3072));
	    }
	  break;

        case is_ecc:
          if (!curvename && key)
            {
              curve = openpgp_oid_to_str (key[0]);
              curvename = openpgp_oid_to_curve (curve, 0);
              if (!curvename)
                curvename = curve;
            }

          result = (curvename
                    && algo != PUBKEY_ALGO_EDDSA
                    && (!strcmp (curvename, "brainpoolP256r1")
                        || !strcmp (curvename, "brainpoolP384r1")
                        || !strcmp (curvename, "brainpoolP512r1")));
          break;

        default:
          result = 0;
        }
      xfree (curve);
    }
  else if (algotype == is_elg_sign)
    {
      /* An Elgamal signing key is only RFC-2440 compliant.  */
      result = (compliance == CO_RFC2440);
    }
  else
    {
      result = 1; /* Assume compliance.  */
    }

  return result;
}


/* Return true if CIPHER is compliant to the given COMPLIANCE mode.  */
int
gnupg_cipher_is_compliant (enum gnupg_compliance_mode compliance, cipher_algo_t cipher)
{
  switch (compliance)
    {
    case CO_DE_VS:
      switch (cipher)
	{
	case CIPHER_ALGO_AES:
	case CIPHER_ALGO_AES192:
	case CIPHER_ALGO_AES256:
	case CIPHER_ALGO_3DES:
	  return 1;
	default:
	  return 0;
	}
      log_assert (!"reached");

    default:
      return 0;
    }

  log_assert (!"reached");
}


/* Return true if DIGEST is compliant to the given COMPLIANCE mode.  */
int
gnupg_digest_is_compliant (enum gnupg_compliance_mode compliance, digest_algo_t digest)
{
  switch (compliance)
    {
    case CO_DE_VS:
      switch (digest)
	{
	case DIGEST_ALGO_SHA256:
	case DIGEST_ALGO_SHA384:
	case DIGEST_ALGO_SHA512:
	  return 1;
	default:
	  return 0;
	}
      log_assert (!"reached");

    default:
      return 0;
    }

  log_assert (!"reached");
}


const char *
gnupg_status_compliance_flag (enum gnupg_compliance_mode compliance)
{
  switch (compliance)
    {
    case CO_GNUPG:
      return "8";
    case CO_RFC4880:
    case CO_RFC2440:
    case CO_PGP6:
    case CO_PGP7:
    case CO_PGP8:
      log_assert (!"no status code assigned for this compliance mode");
    case CO_DE_VS:
      return "23";
    }
  log_assert (!"invalid compliance mode");
}


/* Parse the value of --compliance.  Returns the value corresponding
 * to the given STRING according to OPTIONS of size LENGTH, or -1
 * indicating that the lookup was unsuccessful, or the list of options
 * was printed.  If quiet is false, an additional hint to use 'help'
 * is printed on unsuccessful lookups.  */
int
gnupg_parse_compliance_option (const char *string,
			       struct gnupg_compliance_option options[],
			       size_t length,
			       int quiet)
{
  size_t i;

  if (! ascii_strcasecmp (string, "help"))
    {
      log_info (_ ("valid values for option '%s':\n"), "--compliance");
      for (i = 0; i < length; i++)
        log_info ("  %s\n", options[i].keyword);
      return -1;
    }

  for (i = 0; i < length; i++)
    if (! ascii_strcasecmp (string, options[i].keyword))
      return options[i].value;

  log_error (_ ("invalid value for option '%s'\n"), "--compliance");
  if (! quiet)
    log_info (_ ("(use \"help\" to list choices)\n"));
  return -1;
}
