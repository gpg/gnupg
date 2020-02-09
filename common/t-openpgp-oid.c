/* t-openpgp-oid.c - Module test for openpgp-oid.c
 *	Copyright (C) 2011 Free Software Foundation, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "util.h"

#define pass()  do { ; } while(0)
#define fail(a,e)                                                       \
  do { fprintf (stderr, "%s:%d: test %d failed (%s)\n",                 \
                __func__, __LINE__, (a), gpg_strerror (e));             \
    exit (1);                                                           \
  } while(0)


#define BADOID "1.3.6.1.4.1.11591.2.12242973"


static int verbose;



static void
test_openpgp_oid_from_str (void)
{
   static char *sample_oids[] =
    {
      "0.0",
      "1.0",
      "1.2.3",
      "1.2.840.10045.3.1.7",
      "1.3.132.0.34",
      "1.3.132.0.35",
      NULL
    };
  gpg_error_t err;
  gcry_mpi_t a;
  int idx;
  char *string;
  unsigned char *p;
  unsigned int nbits;
  size_t length;

  err = openpgp_oid_from_str ("", &a);
  if (gpg_err_code (err) != GPG_ERR_INV_VALUE)
    fail (0, err);
  gcry_mpi_release (a);

  err = openpgp_oid_from_str (".", &a);
  if (gpg_err_code (err) != GPG_ERR_INV_OID_STRING)
    fail (0, err);
  gcry_mpi_release (a);

  err = openpgp_oid_from_str ("0", &a);
  if (gpg_err_code (err) != GPG_ERR_INV_OID_STRING)
    fail (0, err);
  gcry_mpi_release (a);

  for (idx=0; sample_oids[idx]; idx++)
    {
      err = openpgp_oid_from_str (sample_oids[idx], &a);
      if (err)
        fail (idx, err);

      string = openpgp_oid_to_str (a);
      if (!string)
        fail (idx, gpg_error_from_syserror ());
      if (strcmp (string, sample_oids[idx]))
        fail (idx, 0);
      xfree (string);

      p = gcry_mpi_get_opaque (a, &nbits);
      length = (nbits+7)/8;
      if (!p || !length || p[0] != length - 1)
        fail (idx, 0);

      gcry_mpi_release (a);
    }

}


static void
test_openpgp_oid_to_str (void)
{
  static struct {
    const char *string;
    unsigned char der[10];
  } samples[] = {
    { "1.2.840.10045.3.1.7",
      {8, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 }},

    { "1.3.132.0.34",
      {5, 0x2B, 0x81, 0x04, 0x00, 0x22 }},

    { "1.3.132.0.35",
      { 5, 0x2B, 0x81, 0x04, 0x00, 0x23 }},

    { BADOID,
      { 9, 0x80, 0x02, 0x70, 0x50, 0x25, 0x46, 0xfd, 0x0c, 0xc0 }},

    { BADOID,
      { 1, 0x80 }},

    { NULL }};
  gcry_mpi_t a;
  int idx;
  char *string;
  unsigned char *p;

  for (idx=0; samples[idx].string; idx++)
    {
      p = xmalloc (samples[idx].der[0]+1);
      memcpy (p, samples[idx].der, samples[idx].der[0]+1);
      a = gcry_mpi_set_opaque (NULL, p, (samples[idx].der[0]+1)*8);
      if (!a)
        fail (idx, gpg_error_from_syserror ());

      string = openpgp_oid_to_str (a);
      if (!string)
        fail (idx, gpg_error_from_syserror ());
      if (strcmp (string, samples[idx].string))
        fail (idx, 0);
      xfree (string);
      gcry_mpi_release (a);

      /* Again using the buffer variant. */
      string = openpgp_oidbuf_to_str (samples[idx].der, samples[idx].der[0]+1);
      if (!string)
        fail (idx, gpg_error_from_syserror ());
      if (strcmp (string, samples[idx].string))
        fail (idx, 0);
      xfree (string);
    }

}


static void
test_openpgp_oid_is_ed25519 (void)
{
  static struct
  {
    int yes;
    const char *oidstr;
  } samples[] = {
    { 0, "0.0" },
    { 0, "1.3.132.0.35" },
    { 0, "1.3.6.1.4.1.3029.1.5.0" },
    { 0, "1.3.6.1.4.1.3029.1.5.1" }, /* Used during Libgcrypt development. */
    { 0, "1.3.6.1.4.1.3029.1.5.2" },
    { 0, "1.3.6.1.4.1.3029.1.5.1.0" },
    { 0, "1.3.6.1.4.1.3029.1.5" },
    { 0, "1.3.6.1.4.1.11591.15.0" },
    { 1, "1.3.6.1.4.1.11591.15.1" }, /* Your the one we want.  */
    { 0, "1.3.6.1.4.1.11591.15.2" },
    { 0, "1.3.6.1.4.1.11591.15.1.0" },
    { 0, "1.3.6.1.4.1.11591.15" },
    { 0, NULL },
  };
  gpg_error_t err;
  gcry_mpi_t a;
  int idx;

  for (idx=0; samples[idx].oidstr; idx++)
    {
      err = openpgp_oid_from_str (samples[idx].oidstr, &a);
      if (err)
        fail (idx, err);

      if (openpgp_oid_is_ed25519 (a) != samples[idx].yes)
        fail (idx, 0);

      gcry_mpi_release (a);
    }

}


static void
test_openpgp_enum_curves (void)
{
  int iter = 0;
  const char *name;
  int p256 = 0;
  int p384 = 0;
  int p521 = 0;

  while ((name = openpgp_enum_curves (&iter)))
    {
      if (verbose)
        printf ("curve: %s\n", name);
      if (!strcmp (name, "nistp256"))
        p256++;
      else if (!strcmp (name, "nistp384"))
        p384++;
      else if (!strcmp (name, "nistp521"))
        p521++;
    }

  if (p256 != 1 || p384 != 1 || p521 != 1)
    {
      /* We can only check the basic RFC-6637 requirements.  */
      fputs ("standard ECC curve missing\n", stderr);
      exit (1);
    }
}


static void
test_get_keyalgo_string (void)
{
  static struct
  {
    int algo;
    unsigned int nbits;
    const char *curve;
    const char *name;
  } samples[] =
      {
       { GCRY_PK_RSA, 1024, NULL, "rsa1024" },
       { GCRY_PK_RSA, 1536, NULL, "rsa1536" },
       { GCRY_PK_RSA, 768,  NULL, "rsa768"  },
       { GCRY_PK_DSA, 3072, NULL, "dsa3072" },
       { GCRY_PK_DSA, 1024, NULL, "dsa1024" },
       { GCRY_PK_ELG, 2048, NULL, "elg2048" },
       { GCRY_PK_ELG, 0,    NULL, "unknown_20" },
       { 47114711,    1000, NULL, "unknown_47114711" },
       /* Note that we don't care about the actual ECC algorithm.  */
       { GCRY_PK_EDDSA,  0, "1.3.6.1.4.1.11591.15.1", "ed25519" },
       { GCRY_PK_ECDSA,  0, "1.3.6.1.4.1.11591.15.1", "ed25519" },
       { GCRY_PK_ECDH,   0, "1.3.6.1.4.1.11591.15.1", "ed25519" },
       { GCRY_PK_ECDH,   0, "1.3.6.1.4.1.3029.1.5.1", "cv25519" },
       { GCRY_PK_ECDH,   0, "1.3.36.3.3.2.8.1.1.7",   "brainpoolP256r1" },
       { GCRY_PK_ECDH,   0, "1.3.36.3.3.2.8.1.1.11",  "brainpoolP384r1" },
       { GCRY_PK_ECDH,   0, "1.3.36.3.3.2.8.1.1.13",  "brainpoolP512r1" },
       { GCRY_PK_ECDH,   0, "1.3.132.0.10",           "secp256k1" },
       { GCRY_PK_ECDH,   0, "1.2.840.10045.3.1.7",    "nistp256"  },
       { GCRY_PK_ECDH,   0, "1.3.132.0.34",           "nistp384"  },
       { GCRY_PK_ECDH,   0, "1.3.132.0.35",           "nistp521"  },
       { GCRY_PK_ECDH,   0, "1.2.3.4.5.6",            "E_1.2.3.4.5.6" },
       { GCRY_PK_ECDH,   0, BADOID,    "E_1.3.6.1.4.1.11591.2.12242973" },

       /* Some again to test existing lookups.  */
       { GCRY_PK_RSA, 768,  NULL, "rsa768"  },
       { GCRY_PK_DSA, 3072, NULL, "dsa3072" },
       { GCRY_PK_DSA, 1024, NULL, "dsa1024" },
       { GCRY_PK_ECDH,   0, "1.3.6.1.4.1.11591.15.1", "ed25519" },
       { GCRY_PK_ECDH,   0, "1.3.6.1.4.1.3029.1.5.1", "cv25519" },
       { GCRY_PK_ECDH,   0, "1.3.36.3.3.2.8.1.1.7",   "brainpoolP256r1" },
       { 47114711,    1000, NULL, "unknown_47114711" }
      };
  int idx;
  const char *name;
  int oops = 0;
  int pass;

  /* We do several passes becuase that is how the function is
   * called.  */
  for (pass=0; pass < 3; pass++)
    for (idx=0; idx < DIM (samples); idx++)
      {
        name = get_keyalgo_string (samples[idx].algo,
                                   samples[idx].nbits,
                                   samples[idx].curve);
        if (strcmp (samples[idx].name, name))
          {
            fprintf (stderr, "%s:test %d.%d: want '%s' got '%s'\n",
                     __func__, pass, idx, samples[idx].name, name);
            oops = 1;
          }
    }
  if (oops)
    exit (1);
}


int
main (int argc, char **argv)
{
  if (argc)
    { argc--; argv++; }
  if (argc && !strcmp (argv[0], "--verbose"))
    {
      verbose = 1;
      argc--; argv++;
    }

  test_openpgp_oid_from_str ();
  test_openpgp_oid_to_str ();
  test_openpgp_oid_is_ed25519 ();
  test_openpgp_enum_curves ();
  test_get_keyalgo_string ();

  return 0;
}
