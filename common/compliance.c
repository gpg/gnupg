/* compliance.c - Functions for compliance modi
 * Copyright (C) 2017 g10 Code GmbH
 * Copyright (C) 2017 Bundesamt für Sicherheit in der Informationstechnik
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

static int initialized;
static int module;

/* This value is used by DSA and RSA checks in addition to the hard
 * coded length checks.  It allows to increase the required key length
 * using a confue file.  */
static unsigned int min_compliant_rsa_length;

/* Return the address of a compliance cache variable for COMPLIANCE.
 * If no such variable exists NULL is returned.  FOR_RNG returns the
 * cache variable for the RNG compliance check. */
static int *
get_compliance_cache (enum gnupg_compliance_mode compliance, int for_rng)
{
  static int r_gnupg   = -1, s_gnupg   = -1;
  static int r_rfc4880 = -1, s_rfc4880 = -1;
  static int r_rfc2440 = -1, s_rfc2440 = -1;
  static int r_pgp6    = -1, s_pgp6    = -1;
  static int r_pgp7    = -1, s_pgp7    = -1;
  static int r_pgp8    = -1, s_pgp8    = -1;
  static int r_de_vs   = -1, s_de_vs   = -1;

  int *ptr = NULL;

  switch (compliance)
    {
    case CO_GNUPG:   ptr = for_rng? &r_gnupg   : &s_gnupg  ; break;
    case CO_RFC4880: ptr = for_rng? &r_rfc4880 : &s_rfc4880; break;
    case CO_RFC2440: ptr = for_rng? &r_rfc2440 : &s_rfc2440; break;
    case CO_PGP6:    ptr = for_rng? &r_pgp6    : &s_pgp6   ; break;
    case CO_PGP7:    ptr = for_rng? &r_pgp7    : &s_pgp7   ; break;
    case CO_PGP8:    ptr = for_rng? &r_pgp8    : &s_pgp8   ; break;
    case CO_DE_VS:   ptr = for_rng? &r_de_vs   : &s_de_vs  ; break;
    }

  return ptr;
}


/* Initializes the module.  Must be called with the current
 * GNUPG_MODULE_NAME.  Checks a few invariants, and tunes the policies
 * for the given module.  */
void
gnupg_initialize_compliance (int gnupg_module_name)
{
  log_assert (! initialized);

  /* We accept both OpenPGP-style and gcrypt-style algorithm ids.
   * Assert that they are compatible.  */
  log_assert ((int) GCRY_PK_RSA          == (int) PUBKEY_ALGO_RSA);
  log_assert ((int) GCRY_PK_RSA_E        == (int) PUBKEY_ALGO_RSA_E);
  log_assert ((int) GCRY_PK_RSA_S        == (int) PUBKEY_ALGO_RSA_S);
  log_assert ((int) GCRY_PK_ELG_E        == (int) PUBKEY_ALGO_ELGAMAL_E);
  log_assert ((int) GCRY_PK_DSA          == (int) PUBKEY_ALGO_DSA);
  log_assert ((int) GCRY_PK_ECC          == (int) PUBKEY_ALGO_ECDH);
  log_assert ((int) GCRY_PK_ELG          == (int) PUBKEY_ALGO_ELGAMAL);
  log_assert ((int) GCRY_CIPHER_NONE     == (int) CIPHER_ALGO_NONE);
  log_assert ((int) GCRY_CIPHER_IDEA     == (int) CIPHER_ALGO_IDEA);
  log_assert ((int) GCRY_CIPHER_3DES     == (int) CIPHER_ALGO_3DES);
  log_assert ((int) GCRY_CIPHER_CAST5    == (int) CIPHER_ALGO_CAST5);
  log_assert ((int) GCRY_CIPHER_BLOWFISH == (int) CIPHER_ALGO_BLOWFISH);
  log_assert ((int) GCRY_CIPHER_AES      == (int) CIPHER_ALGO_AES);
  log_assert ((int) GCRY_CIPHER_AES192   == (int) CIPHER_ALGO_AES192);
  log_assert ((int) GCRY_CIPHER_AES256   == (int) CIPHER_ALGO_AES256);
  log_assert ((int) GCRY_CIPHER_TWOFISH  == (int) CIPHER_ALGO_TWOFISH);
  log_assert ((int) GCRY_MD_MD5          == (int) DIGEST_ALGO_MD5);
  log_assert ((int) GCRY_MD_SHA1         == (int) DIGEST_ALGO_SHA1);
  log_assert ((int) GCRY_MD_RMD160       == (int) DIGEST_ALGO_RMD160);
  log_assert ((int) GCRY_MD_SHA256       == (int) DIGEST_ALGO_SHA256);
  log_assert ((int) GCRY_MD_SHA384       == (int) DIGEST_ALGO_SHA384);
  log_assert ((int) GCRY_MD_SHA512       == (int) DIGEST_ALGO_SHA512);
  log_assert ((int) GCRY_MD_SHA224       == (int) DIGEST_ALGO_SHA224);

  switch (gnupg_module_name)
    {
    case GNUPG_MODULE_NAME_GPGSM:
    case GNUPG_MODULE_NAME_GPG:
      break;

    default:
      log_assert (!"no policies for this module");
    }

  module = gnupg_module_name;
  initialized = 1;
}

/* Return true if ALGO with a key of KEYLENGTH is compliant to the
 * given COMPLIANCE mode.  If KEY is not NULL, various bits of
 * information will be extracted from it.  If CURVENAME is not NULL, it
 * is assumed to be the already computed.  ALGO may be either an
 * OpenPGP-style pubkey_algo_t, or a gcrypt-style enum gcry_pk_algos,
 * both are compatible from the point of view of this function.  */
int
gnupg_pk_is_compliant (enum gnupg_compliance_mode compliance, int algo,
                       unsigned int algo_flags,
		       gcry_mpi_t key[], unsigned int keylength,
                       const char *curvename)
{
  enum { is_rsa, is_dsa, is_elg, is_ecc } algotype;
  int result = 0;

  if (! initialized)
    return 0;

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
      algotype = is_elg;
      break;

    case PUBKEY_ALGO_ECDH:
    case PUBKEY_ALGO_ECDSA:
    case PUBKEY_ALGO_EDDSA:
      algotype = is_ecc;
      break;

    case PUBKEY_ALGO_ELGAMAL:
      return 0; /* Signing with Elgamal is not at all supported.  */

    default: /* Unknown.  */
      return 0;
    }

  if (compliance == CO_DE_VS)
    {
      char *curve = NULL;

      switch (algotype)
        {
        case is_elg:
          result = 0;
          break;

        case is_rsa:
          result = ((keylength == 2048
                     || keylength == 3072
                     || keylength == 4096)
                    && keylength >= min_compliant_rsa_length);
          /* Although rsaPSS was not part of the original evaluation
           * we got word that we can claim compliance.  */
          (void)algo_flags;
          break;

	case is_dsa:
	  if (key)
	    {
	      size_t P = gcry_mpi_get_nbits (key[0]);
	      size_t Q = gcry_mpi_get_nbits (key[1]);
	      result = (Q == 256
			&& (P == 2048 || P == 3072)
                        && P >= min_compliant_rsa_length);
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
                    && (algo == PUBKEY_ALGO_ECDH
                        || algo == PUBKEY_ALGO_ECDSA)
                    && (!strcmp (curvename, "brainpoolP256r1")
                        || !strcmp (curvename, "brainpoolP384r1")
                        || !strcmp (curvename, "brainpoolP512r1")));
          break;

        default:
          result = 0;
        }
      xfree (curve);
    }
  else
    {
      result = 1; /* Assume compliance.  */
    }

  return result;
}


/* Return true if ALGO with the given KEYLENGTH is allowed in the
 * given COMPLIANCE mode.  USE specifies for which use case the
 * predicate is evaluated.  This way policies can be strict in what
 * they produce, and liberal in what they accept.  */
int
gnupg_pk_is_allowed (enum gnupg_compliance_mode compliance,
		     enum pk_use_case use, int algo,
                     unsigned int algo_flags, gcry_mpi_t key[],
		     unsigned int keylength, const char *curvename)
{
  int result = 0;

  if (! initialized)
    return 1;

  switch (compliance)
    {
    case CO_DE_VS:
      switch (algo)
	{
	case PUBKEY_ALGO_RSA:
	case PUBKEY_ALGO_RSA_E:
	case PUBKEY_ALGO_RSA_S:
	  switch (use)
	    {
	    case PK_USE_DECRYPTION:
	    case PK_USE_VERIFICATION:
	      result = 1;
              break;
	    case PK_USE_ENCRYPTION:
	    case PK_USE_SIGNING:
	      result = ((keylength == 2048
                         || keylength == 3072
                         || keylength == 4096)
                        && keylength >= min_compliant_rsa_length);
              break;
	    default:
	      log_assert (!"reached");
	    }
          (void)algo_flags;
	  break;

	case PUBKEY_ALGO_DSA:
          if (use == PK_USE_VERIFICATION)
            result = 1;
	  else if (use == PK_USE_SIGNING && key)
	    {
	      size_t P = gcry_mpi_get_nbits (key[0]);
	      size_t Q = gcry_mpi_get_nbits (key[1]);
	      result = (Q == 256
                        && (P == 2048 || P == 3072)
                        && keylength >= min_compliant_rsa_length);
            }
          break;

	case PUBKEY_ALGO_ELGAMAL:
	case PUBKEY_ALGO_ELGAMAL_E:
	  result = (use == PK_USE_DECRYPTION);
          break;

	case PUBKEY_ALGO_ECDH:
	  if (use == PK_USE_DECRYPTION)
            result = 1;
          else if (use == PK_USE_ENCRYPTION)
            {
              char *curve = NULL;

              if (!curvename && key)
                {
                  curve = openpgp_oid_to_str (key[0]);
                  curvename = openpgp_oid_to_curve (curve, 0);
                  if (!curvename)
                    curvename = curve;
                }

              result = (curvename
                        && (!strcmp (curvename, "brainpoolP256r1")
                            || !strcmp (curvename, "brainpoolP384r1")
                            || !strcmp (curvename, "brainpoolP512r1")));

              xfree (curve);
            }
          break;

	case PUBKEY_ALGO_ECDSA:
          if (use == PK_USE_VERIFICATION)
            result = 1;
          else
            {
              char *curve = NULL;

              if (! curvename && key)
	      {
		curve = openpgp_oid_to_str (key[0]);
		curvename = openpgp_oid_to_curve (curve, 0);
		if (!curvename)
		  curvename = curve;
	      }

              result = (use == PK_USE_SIGNING
                         && curvename
                         && (!strcmp (curvename, "brainpoolP256r1")
                             || !strcmp (curvename, "brainpoolP384r1")
                             || !strcmp (curvename, "brainpoolP512r1")));
              xfree (curve);
            }
          break;


	case PUBKEY_ALGO_EDDSA:
	  break;

	default:
	  break;
	}
      break;

    default:
      /* The default policy is to allow all algorithms.  */
      result = 1;
    }

  return result;
}


/* Return true if (CIPHER, MODE) is compliant to the given COMPLIANCE mode.  */
int
gnupg_cipher_is_compliant (enum gnupg_compliance_mode compliance,
			   cipher_algo_t cipher,
			   enum gcry_cipher_modes mode)
{
  if (! initialized)
    return 0;

  switch (compliance)
    {
    case CO_DE_VS:
      switch (cipher)
	{
	case CIPHER_ALGO_AES:
	case CIPHER_ALGO_AES192:
	case CIPHER_ALGO_AES256:
	case CIPHER_ALGO_3DES:
	  switch (module)
	    {
	    case GNUPG_MODULE_NAME_GPG:
	      return mode == GCRY_CIPHER_MODE_CFB;
	    case GNUPG_MODULE_NAME_GPGSM:
	      return mode == GCRY_CIPHER_MODE_CBC;
	    }
	  log_assert (!"reached");

	default:
	  return 0;
	}
      log_assert (!"reached");

    default:
      return 0;
    }

  log_assert (!"reached");
}


/* Return true if CIPHER is allowed in the given COMPLIANCE mode.  If
 * PRODUCER is true, the predicate is evaluated for the producer, if
 * false for the consumer.  This way policies can be strict in what
 * they produce, and liberal in what they accept.  */
int
gnupg_cipher_is_allowed (enum gnupg_compliance_mode compliance, int producer,
			 cipher_algo_t cipher,
			 enum gcry_cipher_modes mode)
{
  if (! initialized)
    return 1;

  switch (compliance)
    {
    case CO_DE_VS:
      switch (cipher)
	{
	case CIPHER_ALGO_AES:
	case CIPHER_ALGO_AES192:
	case CIPHER_ALGO_AES256:
	case CIPHER_ALGO_3DES:
	  switch (module)
	    {
	    case GNUPG_MODULE_NAME_GPG:
	      return (mode == GCRY_CIPHER_MODE_NONE
                      || mode == GCRY_CIPHER_MODE_CFB);
	    case GNUPG_MODULE_NAME_GPGSM:
	      return (mode == GCRY_CIPHER_MODE_NONE
                      || mode == GCRY_CIPHER_MODE_CBC
                      || (mode == GCRY_CIPHER_MODE_GCM && !producer));
	    }
	  log_assert (!"reached");

	case CIPHER_ALGO_BLOWFISH:
	case CIPHER_ALGO_CAMELLIA128:
	case CIPHER_ALGO_CAMELLIA192:
	case CIPHER_ALGO_CAMELLIA256:
	case CIPHER_ALGO_CAST5:
	case CIPHER_ALGO_IDEA:
	case CIPHER_ALGO_TWOFISH:
	  return (module == GNUPG_MODULE_NAME_GPG
		  && (mode == GCRY_CIPHER_MODE_NONE
                      || mode == GCRY_CIPHER_MODE_CFB)
		  && ! producer);
	default:
	  return 0;
	}
      log_assert (!"reached");

    default:
      /* The default policy is to allow all algorithms.  */
      return 1;
    }

  log_assert (!"reached");
}


/* Return true if DIGEST is compliant to the given COMPLIANCE mode.  */
int
gnupg_digest_is_compliant (enum gnupg_compliance_mode compliance,
                           digest_algo_t digest)
{
  if (! initialized)
    return 0;

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


/* Return true if DIGEST is allowed in the given COMPLIANCE mode.  If
 * PRODUCER is true, the predicate is evaluated for the producer, if
 * false for the consumer.  This way policies can be strict in what
 * they produce, and liberal in what they accept.  */
int
gnupg_digest_is_allowed (enum gnupg_compliance_mode compliance, int producer,
			 digest_algo_t digest)
{
  if (! initialized)
    return 1;

  switch (compliance)
    {
    case CO_DE_VS:
      switch (digest)
	{
	case DIGEST_ALGO_SHA256:
	case DIGEST_ALGO_SHA384:
	case DIGEST_ALGO_SHA512:
	  return 1;
	case DIGEST_ALGO_SHA1:
	case DIGEST_ALGO_SHA224:
	case DIGEST_ALGO_RMD160:
	  return ! producer;
	case DIGEST_ALGO_MD5:
	  return ! producer && module == GNUPG_MODULE_NAME_GPGSM;
	default:
	  return 0;
	}
      log_assert (!"reached");

    default:
      /* The default policy is to allow all algorithms.  */
      return 1;
    }

  log_assert (!"reached");
}


/* Return True if the random number generator is compliant in
 * COMPLIANCE mode.  */
int
gnupg_rng_is_compliant (enum gnupg_compliance_mode compliance)
{
  int *result;
  int res;

  result = get_compliance_cache (compliance, 1);

  if (result && *result != -1)
    res = *result; /* Use cached result.  */
  else if (compliance == CO_DE_VS)
    {
      /* We also check whether the library is at all compliant.  */
      res = gnupg_gcrypt_is_compliant (compliance);

      /* In DE_VS mode under Windows we also require that the JENT RNG
       * is active.  Check it here. */
#ifdef HAVE_W32_SYSTEM
      if (res == 1)
        {
          char *buf;
          char *fields[5];

          buf = gcry_get_config (0, "rng-type");
          if (buf
              && split_fields_colon (buf, fields, DIM (fields)) >= 5
              && atoi (fields[4]) > 0)
            ; /* Field 5 > 0 := Jent is active.  */
          else
            result = 0;  /* Force non-compliance.  */
          gcry_free (buf);
        }
#endif /*HAVE_W32_SYSTEM*/
    }
  else
    res = 1;

  if (result)
    *result = res;

  return res;
}


/* Return true if the used Libgcrypt is compliant in COMPLIANCE
 * mode.  */
int
gnupg_gcrypt_is_compliant (enum gnupg_compliance_mode compliance)
{
  int *result;
  int res;

  result = get_compliance_cache (compliance, 0);

  if (result && *result != -1)
    res = *result; /* Use cached result.  */
  else if (compliance == CO_DE_VS)
    {
      int is19orlater = !!gcry_check_version ("1.9.0");

      /* A compliant version of GnuPG requires Libgcrypt >= 1.8.1 and
       * less than 1.9.0.  Version 1.9.0 requires a re-evaluation and
       * can thus not be used for de-vs.  */
      if (gcry_check_version ("1.8.1") && !is19orlater)
        res = 1;  /* Compliant version of Libgcrypt.  */
      else if (is19orlater)
        {
          /* Libgcrypt might be nice enough to tell us whether it is
           * compliant.  */
          char *buf;
          char *fields[3];

          buf = gcry_get_config (0, "compliance");
          if (buf
              && split_fields_colon (buf, fields, DIM (fields)) >= 2
              && strstr (fields[1], "de-vs"))
            res = 1;  /* Compliant.  */
          else
            res = 0;  /* Non-compliant.  */
          gcry_free (buf);
        }
      else
        res = 0;  /* Non-compliant version of Libgcrypt.  */
    }
  else
    res = 1;

  if (result)
    *result = res;

  return res;
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
      log_info (_("valid values for option '%s':\n"), "--compliance");
      for (i = 0; i < length; i++)
        log_info ("  %s\n", options[i].keyword);
      return -1;
    }

  for (i = 0; i < length; i++)
    if (! ascii_strcasecmp (string, options[i].keyword))
      return options[i].value;

  log_error (_("invalid value for option '%s'\n"), "--compliance");
  if (! quiet)
    log_info (_("(use \"help\" to list choices)\n"));
  return -1;
}


/* Return the command line option for the given COMPLIANCE mode.  */
const char *
gnupg_compliance_option_string (enum gnupg_compliance_mode compliance)
{
  switch (compliance)
    {
    case CO_GNUPG:   return "--compliance=gnupg";
    case CO_RFC4880: return "--compliance=openpgp";
    case CO_RFC2440: return "--compliance=rfc2440";
    case CO_PGP6:    return "--compliance=pgp6";
    case CO_PGP7:    return "--compliance=pgp7";
    case CO_PGP8:    return "--compliance=pgp8";
    case CO_DE_VS:   return "--compliance=de-vs";
    }

  log_assert (!"invalid compliance mode");
}


/* Set additional infos for example taken from config files at startup.  */
void
gnupg_set_compliance_extra_info (unsigned int min_rsa)
{
  min_compliant_rsa_length = min_rsa;
}
