#include <config.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <assert.h>

#include "util.h"
#include "openpgpdefs.h"

gcry_mpi_t
openpgp_ecc_parse_pubkey (pubkey_algo_t pkalgo, const char *curve_oid,
			  gcry_mpi_t pubkey)
{
  unsigned int nbits = 0;
  unsigned char *buf = NULL;
  const char *curve = openpgp_oid_to_curve (curve_oid, 1);

  if (curve == NULL)
    curve = curve_oid;

  if ((pkalgo == PUBKEY_ALGO_EDDSA && !strcmp (curve, "Ed448"))
      || (pkalgo == PUBKEY_ALGO_ECDH && !strcmp (curve, "X448")))
    buf = gcry_mpi_get_opaque (pubkey, &nbits);

  if (nbits == 0
      || (pkalgo == PUBKEY_ALGO_EDDSA && (nbits+7)/8 == (448 + 8)/8)
      || (pkalgo == PUBKEY_ALGO_ECDH && (nbits+7)/8 == 448/8))
    return gcry_mpi_copy (pubkey);

  if (pkalgo == PUBKEY_ALGO_EDDSA)
    return gcry_mpi_set_opaque_copy (NULL, buf+1, 8 + 448);
  else
    return gcry_mpi_set_opaque_copy (NULL, buf+1, 448);
}


gcry_mpi_t
openpgp_ecc_parse_seckey (pubkey_algo_t pkalgo, const char *curve_oid,
			  gcry_mpi_t seckey)
{
  unsigned int nbits = 0;
  unsigned char *buf = NULL;
  const char *curve = openpgp_oid_to_curve (curve_oid, 1);

  if (curve == NULL)
    curve = curve_oid;

  if ((pkalgo == PUBKEY_ALGO_EDDSA && !strcmp (curve, "Ed448"))
      || (pkalgo == PUBKEY_ALGO_ECDH && !strcmp (curve, "X448")))
    buf = gcry_mpi_get_opaque (seckey, &nbits);

  if (nbits == 0
      || (pkalgo == PUBKEY_ALGO_EDDSA && (nbits+7)/8 == (448 + 8)/8)
      || (pkalgo == PUBKEY_ALGO_ECDH && (nbits+7)/8 == 448/8))
    return gcry_mpi_copy (seckey);

  if (pkalgo == PUBKEY_ALGO_EDDSA)
    return gcry_mpi_set_opaque_copy (NULL, buf+1, 8 + 448);
  else
    return gcry_mpi_set_opaque_copy (NULL, buf+1, 448);
}
