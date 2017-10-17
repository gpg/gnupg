/* pkscreening.c - Screen public keys for vulnerabilities
 * Copyright (C) 2017 Werner Koch
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdlib.h>

#include "util.h"
#include "pkscreening.h"


/* Helper */
static inline gpg_error_t
my_error (gpg_err_code_t ec)
{
  return gpg_err_make (default_errsource, ec);
}


/* Emulation of the new gcry_mpi_get_ui function.  */
static gpg_error_t
my_mpi_get_ui (unsigned int *v, gcry_mpi_t a)
{
  gpg_error_t err;
  unsigned char buf[8];
  size_t n;
  int i, mul;

  if (gcry_mpi_cmp_ui (a, 16384) > 0)
    return my_error (GPG_ERR_ERANGE); /* Clearly too large for our purpose.  */

  err = gcry_mpi_print (GCRYMPI_FMT_USG, buf, sizeof buf, &n, a);
  if (err)
    return err;

  *v = 0;
  for (i = n - 1, mul = 1; i >= 0; i--, mul *= 256)
    *v += mul * buf[i];

  return 0;
}


/* Detect whether the MODULUS of a public RSA key is affected by the
 * ROCA vulnerability as found in the Infinion RSA library
 * (CVE-2017-15361).  Returns 0 if not affected, GPG_ERR_TRUE if
 * affected, GPG_ERR_BAD_MPI if an opaque RSA was passed, or other
 * error codes if something weird happened  */
gpg_error_t
screen_key_for_roca (gcry_mpi_t modulus)
{
  static struct {
    unsigned int prime_ui;
    const char *print_hex;
    gcry_mpi_t prime;
    gcry_mpi_t print;
  } table[] = {
   { 3,   "0x6" },
   { 5,   "0x1E" },
   { 7,   "0x7E" },
   { 11,  "0x402" },
   { 13,  "0x161A" },
   { 17,  "0x1A316" },
   { 19,  "0x30AF2" },
   { 23,  "0x7FFFFE" },
   { 29,  "0x1FFFFFFE" },
   { 31,  "0x7FFFFFFE" },
   { 37,  "0x4000402"  },
   { 41,  "0x1FFFFFFFFFE" },
   { 43,  "0x7FFFFFFFFFE" },
   { 47,  "0x7FFFFFFFFFFE" },
   { 53,  "0x12DD703303AED2" },
   { 59,  "0x7FFFFFFFFFFFFFE" },
   { 61,  "0x1434026619900B0A" },
   { 67,  "0x7FFFFFFFFFFFFFFFE" },
   { 71,  "0x1164729716B1D977E" },
   { 73,  "0x147811A48004962078A" },
   { 79,  "0xB4010404000640502"   },
   { 83,  "0x7FFFFFFFFFFFFFFFFFFFE" },
   { 89,  "0x1FFFFFFFFFFFFFFFFFFFFFE" },
   { 97,  "0x1000000006000001800000002" },
   { 101, "0x1FFFFFFFFFFFFFFFFFFFFFFFFE" },
   { 103, "0x16380E9115BD964257768FE396" },
   { 107, "0x27816EA9821633397BE6A897E1A" },
   { 109, "0x1752639F4E85B003685CBE7192BA" },
   { 113, "0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFE" },
   { 127, "0x6CA09850C2813205A04C81430A190536" },
   { 131, "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE" },
   { 137, "0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE" },
   { 139, "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE" },
   { 149, "0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE" },
   { 151, "0x50C018BC00482458DAC35B1A2412003D18030A" },
   { 157, "0x161FB414D76AF63826461899071BD5BACA0B7E1A" },
   { 163, "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE" },
   { 167, "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE" }
  };
  gpg_error_t err;
  int i;
  gcry_mpi_t rem;
  unsigned int bitno;

  /* Initialize on the first call. */
  if (!table[0].prime)
    {
      /* We pass primes[i] to the call so that in case of a concurrent
       * second thread the already allocated space is reused.  */
      for (i = 0; i < DIM (table); i++)
        {
          table[i].prime = gcry_mpi_set_ui (table[i].prime, table[i].prime_ui);
          if (gcry_mpi_scan (&table[i].print, GCRYMPI_FMT_HEX,
                             table[i].print_hex, 0, NULL))
            BUG ();
        }
    }

  /* Check that it is not NULL or an opaque MPI.  */
  if (!modulus || gcry_mpi_get_flag (modulus, GCRYMPI_FLAG_OPAQUE))
    return my_error (GPG_ERR_BAD_MPI);

  /* We divide the modulus of an RSA public key by a set of small
   * PRIMEs and examine all the remainders.  If all the bits at the
   * index given by the remainder are set in the corresponding PRINT
   * masks the key is very likely vulnerable.  If any of the tested
   * bits is zero, the key is not vulnerable.  */
  rem = gcry_mpi_new (0);
  for (i = 0; i < DIM (table); i++)
    {
      gcry_mpi_mod (rem, modulus, table[i].prime);
      err = my_mpi_get_ui (&bitno, rem);
      if (gpg_err_code (err) == GPG_ERR_ERANGE)
        continue;
      if (err)
        goto leave;
      if (!gcry_mpi_test_bit (table[i].print, bitno))
        goto leave;  /* Not vulnerable.  */
    }

  /* Very likely vulnerable */
  err = my_error (GPG_ERR_TRUE);

 leave:
  gcry_mpi_release (rem);
  return err;
}
