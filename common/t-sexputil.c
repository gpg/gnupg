/* t-sexputil.c - Module test for sexputil.c
 *	Copyright (C) 2007 Free Software Foundation, Inc.
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

#include "util.h"

#define pass()  do { ; } while(0)
#define fail(a)  do { fprintf (stderr, "%s:%d: test %d failed\n",\
                               __FILE__,__LINE__, (a));          \
                     exit (1);                                   \
                   } while(0)
#define fail2(a,e) do { fprintf (stderr, "%s:%d: test %d failed: %s\n", \
                        __FILE__,__LINE__, (a), gpg_strerror ((e)));    \
                     exit (1);                                          \
                   } while(0)


static void
test_hash_algo_from_sigval (void)
{
  int algo;
  /* A real world example.  */
  unsigned char example1_rsa_sha1[] =
    ("\x28\x37\x3A\x73\x69\x67\x2D\x76\x61\x6C\x28\x33\x3A\x72\x73\x61"
     "\x28\x31\x3A\x73\x31\x32\x38\x3A\x17\xD2\xE9\x5F\xB4\x24\xD4\x1E"
     "\x8C\xEE\x94\xDA\x41\x42\x1F\x26\x5E\xF4\x6D\xEC\x5B\xBD\x5B\x89"
     "\x7A\x69\x11\x43\xE9\xD2\x23\x21\x25\x64\xA6\xB0\x56\xEF\xB4\xE9"
     "\x06\xB2\x44\xF6\x80\x1E\xFF\x41\x23\xEB\xC9\xFA\xFD\x09\xBF\x9C"
     "\x8E\xCF\x7F\xC3\x7F\x3A\x40\x48\x89\xDC\xBA\xB7\xDB\x9E\xF1\xBA"
     "\x7C\x08\xEA\x74\x1D\x49\xE7\x65\xEF\x67\x79\xBC\x23\xD9\x49\xCD"
     "\x05\x99\xD3\xD8\xB7\x7B\xC7\x0E\xF2\xB3\x01\x48\x0F\xC8\xEB\x05"
     "\x7B\xFB\x61\xCC\x41\x04\x74\x6D\x33\x84\xB1\xE6\x6A\xD8\x0F\xBC"
     "\x27\xAC\x43\x45\xFA\x04\xD1\x22\x29\x29\x28\x34\x3A\x68\x61\x73"
     "\x68\x34\x3A\x73\x68\x61\x31\x29\x29");
  /* The same but without the hash algo. */
  unsigned char example1_rsa[] =
    ("\x28\x37\x3A\x73\x69\x67\x2D\x76\x61\x6C\x28\x33\x3A\x72\x73\x61"
     "\x28\x31\x3A\x73\x31\x32\x38\x3A\x17\xD2\xE9\x5F\xB4\x24\xD4\x1E"
     "\x8C\xEE\x94\xDA\x41\x42\x1F\x26\x5E\xF4\x6D\xEC\x5B\xBD\x5B\x89"
     "\x7A\x69\x11\x43\xE9\xD2\x23\x21\x25\x64\xA6\xB0\x56\xEF\xB4\xE9"
     "\x06\xB2\x44\xF6\x80\x1E\xFF\x41\x23\xEB\xC9\xFA\xFD\x09\xBF\x9C"
     "\x8E\xCF\x7F\xC3\x7F\x3A\x40\x48\x89\xDC\xBA\xB7\xDB\x9E\xF1\xBA"
     "\x7C\x08\xEA\x74\x1D\x49\xE7\x65\xEF\x67\x79\xBC\x23\xD9\x49\xCD"
     "\x05\x99\xD3\xD8\xB7\x7B\xC7\x0E\xF2\xB3\x01\x48\x0F\xC8\xEB\x05"
     "\x7B\xFB\x61\xCC\x41\x04\x74\x6D\x33\x84\xB1\xE6\x6A\xD8\x0F\xBC"
     "\x27\xAC\x43\x45\xFA\x04\xD1\x22\x29\x29\x29");

  algo = hash_algo_from_sigval (example1_rsa_sha1);
  if (algo != GCRY_MD_SHA1)
    fail (0);
  algo = hash_algo_from_sigval (example1_rsa);
  if (algo)
    fail (0);
}


static void
test_make_canon_sexp_from_rsa_pk (void)
{
  struct {
    unsigned char *m;
    size_t mlen;
    unsigned char *e;
    size_t elen;
    unsigned char *result;
    size_t resultlen;
    gpg_err_code_t reverr;  /* Expected error from the reverse function.  */
  } tests[] = {
    {
      "\x82\xB4\x12\x48\x08\x48\xC0\x76\xAA\x8E\xF1\xF8\x7F\x5E\x9B\x89"
      "\xA9\x62\x92\xA2\x16\x1B\xF5\x9F\xE1\x41\xF3\xF0\x42\xB5\x5C\x46"
      "\xB8\x83\x9F\x39\x97\x73\xFF\xC5\xB2\xF4\x59\x5F\xBA\xC7\x0E\x03"
      "\x9D\x27\xC0\x86\x37\x31\x46\xE0\xA1\xFE\xA1\x41\xD4\xE3\xE9\xB3"
      "\x9B\xD5\x84\x65\xA5\x37\x35\x34\x07\x58\xB6\xBA\x21\xCA\x21\x72"
      "\x4C\xF3\xFC\x91\x47\xD1\x3C\x1D\xA5\x9C\x38\x4D\x58\x39\x92\x16"
      "\xB1\xE5\x43\xFE\xB5\x46\x4B\x43\xD1\x47\xB0\xE8\x2A\xDB\xF8\x34"
      "\xB0\x5A\x22\x3D\x14\xBB\xEA\x63\x65\xA7\xF1\xF2\xF8\x97\x74\xA7",
      128,
      "\x40\x00\x00\x81",
      4,
      "\x28\x31\x30\x3a\x70\x75\x62\x6c\x69\x63\x2d\x6b\x65\x79\x28\x33"
      "\x3a\x72\x73\x61\x28\x31\x3a\x6e\x31\x32\x39\x3a\x00\x82\xb4\x12"
      "\x48\x08\x48\xc0\x76\xaa\x8e\xf1\xf8\x7f\x5e\x9b\x89\xa9\x62\x92"
      "\xa2\x16\x1b\xf5\x9f\xe1\x41\xf3\xf0\x42\xb5\x5c\x46\xb8\x83\x9f"
      "\x39\x97\x73\xff\xc5\xb2\xf4\x59\x5f\xba\xc7\x0e\x03\x9d\x27\xc0"
      "\x86\x37\x31\x46\xe0\xa1\xfe\xa1\x41\xd4\xe3\xe9\xb3\x9b\xd5\x84"
      "\x65\xa5\x37\x35\x34\x07\x58\xb6\xba\x21\xca\x21\x72\x4c\xf3\xfc"
      "\x91\x47\xd1\x3c\x1d\xa5\x9c\x38\x4d\x58\x39\x92\x16\xb1\xe5\x43"
      "\xfe\xb5\x46\x4b\x43\xd1\x47\xb0\xe8\x2a\xdb\xf8\x34\xb0\x5a\x22"
      "\x3d\x14\xbb\xea\x63\x65\xa7\xf1\xf2\xf8\x97\x74\xa7\x29\x28\x31"
      "\x3a\x65\x34\x3a\x40\x00\x00\x81\x29\x29\x29",
      171
    },
    {
      "\x63\xB4\x12\x48\x08\x48\xC0\x76\xAA\x8E\xF1\xF8\x7F\x5E\x9B\x89",
      16,
      "\x03",
      1,
      "\x28\x31\x30\x3a\x70\x75\x62\x6c\x69\x63\x2d\x6b\x65\x79\x28\x33"
      "\x3a\x72\x73\x61\x28\x31\x3a\x6e\x31\x36\x3a\x63\xb4\x12\x48\x08"
      "\x48\xc0\x76\xaa\x8e\xf1\xf8\x7f\x5e\x9b\x89\x29\x28\x31\x3a\x65"
      "\x31\x3a\x03\x29\x29\x29",
      54,
    },
    {
      "",
      0,
      "",
      0,
      "\x28\x31\x30\x3a\x70\x75\x62\x6c\x69\x63\x2d\x6b\x65\x79\x28\x33"
      "\x3a\x72\x73\x61\x28\x31\x3a\x6e\x31\x3a\x00\x29\x28\x31\x3a\x65"
      "\x31\x3a\x00\x29\x29\x29",
      38,
      GPG_ERR_BAD_PUBKEY
    },
    {
      NULL
    }
  };
  int idx;
  gpg_error_t err;
  unsigned char *sexp;
  size_t length;
  const unsigned char *rsa_n, *rsa_e;
  size_t rsa_n_len, rsa_e_len;

  for (idx=0; tests[idx].m; idx++)
    {
      sexp = make_canon_sexp_from_rsa_pk (tests[idx].m, tests[idx].mlen,
                                          tests[idx].e, tests[idx].elen,
                                          &length);
      if (!sexp)
        {
          fprintf (stderr, "%s:%d: out of core\n", __FILE__, __LINE__);
          exit (1);
        }

      if (length != tests[idx].resultlen)
        fail (idx);
      if (memcmp (sexp, tests[idx].result, tests[idx].resultlen))
        fail (idx);

      /* Test the reverse function.  */
      err = get_rsa_pk_from_canon_sexp (sexp, length,
                                        &rsa_n, &rsa_n_len,
                                        &rsa_e, &rsa_e_len);
      if (gpg_err_code (err) != tests[idx].reverr)
        fail (idx);
      if (!err)
        {
          if (tests[idx].mlen != rsa_n_len)
            fail (idx);
          if (memcmp (tests[idx].m, rsa_n, rsa_n_len))
            fail (idx);
          if (tests[idx].elen != rsa_e_len)
            fail (idx);
          if (memcmp (tests[idx].e, rsa_e, rsa_e_len))
            fail (idx);
        }

      xfree (sexp);
    }
}


/* Communiacation object for tcmp.  */
struct tcmp_parm_s {
  int curve_seen;
};

/* Helper for test_cmp_canon_sexp.  */
static int
tcmp1 (void *opaque, int depth,
       const unsigned char *aval, size_t alen,
       const unsigned char *bval, size_t blen)
{
  struct tcmp_parm_s *parm = opaque;

  (void)depth;

  if (parm->curve_seen)
    {
      /* Last token was "curve", canonicalize its argument.  */
      parm->curve_seen = 0;

      if (alen == 8 && !memcmp (aval, "nistp256", alen))
        {
          alen = 19;
          aval = "1.2.840.10045.3.1.7";
        }

      if (blen == 8 && !memcmp (bval, "nistp256", blen))
        {
          blen = 19;
          bval = "1.2.840.10045.3.1.7";
        }
    }
  else if (alen == 5 && !memcmp (aval, "curve", 5))
    parm->curve_seen = 1;
  else
    parm->curve_seen = 0;

  if (alen > blen)
    return 1;
  else if (alen < blen)
    return -1;
  else
    return memcmp (aval, bval, alen);
}


static void
test_cmp_canon_sexp (void)
{
  struct {
    unsigned char *a;
    unsigned char *b;
    int expected0;  /* Expected result without compare function.    */
    int expected1;  /* Expected result with compare function tcmp1. */
  }
  tests[] = {
  {
   "(10:public-key(3:ecc(5:curve8:nistp256)(1:q10:qqqqqqqqqq)))",
   "(10:public-key(3:ecc(5:curve8:nistp256)(1:q10:qqqqqqqqqq)))",
   0, 0
  },
  {
   "(10:public-key(3:ecc(5:curve19:1.2.840.10045.3.1.7)(1:q10:qqqqqqqqqq)))",
   "(10:public-key(3:ecc(5:curve19:1.2.840.10045.3.1.7)(1:q10:qqqqqqqqqq)))",
   0, 0
  },
  {
   "(10:public-key(3:ecc(5:curve8:nistp256)(1:q10:qqqqqqqqqq)))",
   "(10:public-key(3:ecc(5:curve19:1.2.840.10045.3.1.7)(1:q10:qqqqqqqqqq)))",
   -1, 0
  },
  {
   "(10:public-key(3:ecc(5:curve19:1.2.840.10045.3.1.7)(1:q10:qqqqqqqqqq)))",
   "(10:public-key(3:ecc(5:curve8:nistp256)(1:q10:qqqqqqqqqq)))",
   1, 0
  },
  {
   NULL
  }
  };
  struct tcmp_parm_s parm = {0};
  int idx;
  int res;

  for (idx=0; tests[idx].a; idx++)
    {
      res = cmp_canon_sexp (tests[idx].a, strlen (tests[idx].a),
                            tests[idx].b, strlen (tests[idx].b),
                            NULL, NULL);
      if (res != tests[idx].expected0)
        fail (idx);
      res = cmp_canon_sexp (tests[idx].a, strlen (tests[idx].a),
                            tests[idx].b, strlen (tests[idx].b),
                            tcmp1, &parm);
      if (res != tests[idx].expected1)
        fail (idx);
    }
}


static void
test_ecc_uncompress (void)
{
  struct {
    const char *a;  /* Uncompressed.  */
    const char *b;  /* Compressed.    */
  }
  tests[] = {
  {
    "(public-key"
    " (ecc"
    " (curve brainpoolP256r1)"
    " (q #042ECD8679930BE2DB4AD42B8600BA3F80"
    /*   */"2D4D539BFF2F69B83EC9B7BBAA7F3406"
    /*   */"436DD11A1756AFE56CD93408410FCDA9"
    /*   */"BA95024EB613BD481A14FCFEC27A448A#)))",
    /* The same in compressed form.  */
    "(public-key"
    " (ecc"
    " (curve brainpoolP256r1)"
    " (q #022ECD8679930BE2DB4AD42B8600BA3F80"
    /*   */"2D4D539BFF2F69B83EC9B7BBAA7F3406#)))"
  },
  {
    "(public-key"
    " (ecc"
    " (curve brainpoolP256r1)"
    " (q #045B784CA008EE64AB3D85017EE0D2BE87"
    /*   */"558762C7300E0C8E06B1F9AF7C031458"
    /*   */"9EBBA41915313417BA54218EB0569C59"
    /*   */"0B156C76DBCAB6E84575E6EF68CE7B87#)))",
    /* The same in compressed form.  */
    "(public-key"
    " (ecc"
    " (curve brainpoolP256r1)"
    " (q #035B784CA008EE64AB3D85017EE0D2BE87"
    /*   */"558762C7300E0C8E06B1F9AF7C031458#)))"
  },
  { /* A key which does not require a conversion.  */
    "(public-key"
    " (ecdsa"
    " (p #00FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF#)"
    " (curve \"NIST P-256\")"
    " (b #5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B#)"
    " (g #046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5#)"
    " (n #00FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551#)"
    " (h #000000000000000000000000000000000000000000000000000000000000000001#)"
    " (q #04C8A4CEC2E9A9BC8E173531A67B0840DF345C32E261ADD780E6D83D56EFADFD5DE872F8B854819B59543CE0B7F822330464FBC4E6324DADDCD9D059554F63B344#)))"
  },
  {  /* Nothing to do for an RSA private key.  */
    "(private-key"
    " (rsa"
    "  (n #00B6B509596A9ECABC939212F891E656A626BA07DA8521A9CAD4C08E640C04052FBB87F424EF1A0275A48A9299AC9DB69ABE3D0124E6C756B1F7DFB9B842D6251AEA6EE85390495CADA73D671537FCE5850A932F32BAB60AB1AC1F852C1F83C625E7A7D70CDA9EF16D5C8E47739D77DF59261ABE8454807FF441E143FBD37F8545#)"
    "  (e #010001#)"
    "  (d #077AD3DE284245F4806A1B82B79E616FBDE821C82D691A65665E57B5FAD3F34E67F401E7BD2E28699E89D9C496CF821945AE83AC7A1231176A196BA6027E77D85789055D50404A7A2A95B1512F91F190BBAEF730ED550D227D512F89C0CDB31AC06FA9A19503DDF6B66D0B42B9691BFD6140EC1720FFC48AE00C34796DC899E5#)"
    "  (p #00D586C78E5F1B4BF2E7CD7A04CA091911706F19788B93E44EE20AAF462E8363E98A72253ED845CCBF2481BB351E8557C85BCFFF0DABDBFF8E26A79A0938096F27#)"
    "  (q #00DB0CDF60F26F2A296C88D6BF9F8E5BE45C0DDD713C96CC73EBCB48B061740943F21D2A93D6E42A7211E7F02A95DCED6C390A67AD21ECF739AE8A0CA46FF2EBB3#)"
    "  (u #33149195F16912DB20A48D020DBC3B9E3881B39D722BF79378F6340F43148A6E9FC5F53E2853B7387BA4443BA53A52FCA8173DE6E85B42F9783D4A7817D0680B#)))"
  },
  { /* Nothing to do dor a DSA key.  */
    " (public-key"
    " (dsa"
    "  (p #0084E4C626E16005770BD9509ABF7354492E85B8C0060EFAAAEC617F725B592FAA59DF5460575F41022776A9718CE62EDD542AB73C7720869EBDBC834D174ADCD7136827DF51E2613545A25CA573BC502A61B809000B6E35F5EB7FD6F18C35678C23EA1C3638FB9CFDBA2800EE1B62F41A4479DE824F2834666FBF8DC5B53C2617#)"
    "  (q #00B0E6F710051002A9F425D98A677B18E0E5B038AB#)"
    "  (g #44370CEE0FE8609994183DBFEBA7EEA97D466838BCF65EFF506E35616DA93FA4E572A2F08886B74977BC00CA8CD3DBEA7AEB7DB8CBB180E6975E0D2CA76E023E6DE9F8CCD8826EBA2F72B8516532F6001DEFFAE76AA5E59E0FA33DBA3999B4E92D1703098CDEDCC416CF008801964084CDE1980132B2B78CB4CE9C15A559528B#)"
    "  (y #3D5DD14AFA2BF24A791E285B90232213D0E3BA74AB1109E768AED19639A322F84BB7D959E2BA92EF73DE4C7F381AA9F4053CFA3CD4527EF9043E304E5B95ED0A3A5A9D590AA641C13DB2B6E32B9B964A6A2C730DD3EA7C8E13F7A140AFF1A91CE375E9B9B960384779DC4EA180FA1F827C52288F366C0770A220F50D6D8FD6F6#)))"
  },
  { /* Nothing to do for an ECDSA key w/o curvename.  */
    "(public-key"
    " (ecdsa(flags param)"
    " (p #00FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF#)"
    " (a #00FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC#)"
    " (b #5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B#)"
    " (g #046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5#)"
    " (n #00FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551#)"
    " (h #000000000000000000000000000000000000000000000000000000000000000001#)"
    " (q #04C8A4CEC2E9A9BC8E173531A67B0840DF345C32E261ADD780E6D83D56EFADFD5DE872F8B854819B59543CE0B7F822330464FBC4E6324DADDCD9D059554F63B344#)))"
  },
  { /* Nothing to do for Ed25519 key.  */
    "(public-key"
    " (ecc"
    " (curve Ed25519)"
    " (q #04"
    "     1CC662926E7EFF4982B7FB8B928E61CD74CCDD85277CC57196C3AD20B611085F"
    "     47BD24842905C049257673B3F5249524E0A41FAA17B25B818D0F97E625F1A1D0#)"
    "     ))"
  },
  { /* Nothing to do for Ed25519 with EdDSA key.  */
    "(public-key"
    " (ecc"
    " (curve Ed25519)(flags eddsa)"
    " (q #773E72848C1FD5F9652B29E2E7AF79571A04990E96F2016BF4E0EC1890C2B7DB#)"
    " ))"
  },
  { /* Nothing to do for Ed25519 with EdDSA key with prefix.  */
    "(public-key"
    " (ecc"
    " (curve Ed25519)(flags eddsa)"
    " (q #40"
    "     773E72848C1FD5F9652B29E2E7AF79571A04990E96F2016BF4E0EC1890C2B7DB#)"
    " ))"
  },
  { /* Nothing to do for Ed25519 with EdDSA key with uncompress prefix.  */
    "(public-key"
    " (ecc"
    " (curve Ed25519)(flags eddsa)"
    " (q #04"
    "     629ad237d1ed04dcd4abe1711dd699a1cf51b1584c4de7a4ef8b8a640180b26f"
    "     5bb7c29018ece0f46b01f2960e99041a5779afe7e2292b65f9d51f8c84723e77#)"
    " ))"
  },
  { /* Noting to do for a Cv25519 tweaked key.  */
    "(public-key"
    " (ecc"
    " (curve Curve25519)(flags djb-tweak)"
    " (q #40"
    "     918C1733127F6BF2646FAE3D081A18AE77111C903B906310B077505EFFF12740#)"
    " ))"
  },
  { /* Nothing to do for a shadowed key.  */
    "(shadowed-private-key"
    " (rsa"
    " (n #00B493C79928398DA9D99AC0E949FE6EB62F683CB974FFFBFBC01066F5C9A89B"
    "     D3DC48EAD7C65F36EA943C2B2C865C26C4884FF9EDFDA8C99C855B737D77EEF6"
    "     B85DBC0CCEC0E900C1F89A6893A2A93E8B31028469B6927CEB2F08687E547C68"
    "     6B0A2F7E50A194FF7AB7637E03DE0912EF7F6E5F1EC37625BD1620CCC2E7A564"
    "     31E168CDAFBD1D9E61AE47A69A6FA03EF22F844528A710B2392F262B95A3078C"
    "     F321DC8325F92A5691EF69F34FD0DE0B22C79D29DC87723FCADE463829E8E5F7"
    "     D196D73D6C9C180F6A6A0DDBF7B9D8F7FA293C36163B12199EF6A1A95CAE4051"
    "     E3069C522CC6C4A7110F663A5DAD20F66C13A1674D050088208FAE4F33B3AB51"
    "     03#)"
    " (e #00010001#)"
    " (shadowed t1-v1"
    " (#D2760001240102000005000123350000# OPENPGP.1)"
    ")))"
  },
  {
    NULL
  }};
  gpg_error_t err;
  int idx;
  gcry_sexp_t sexp;
  unsigned char *abuf, *bbuf, *rbuf;
  size_t abuflen, bbuflen, rbuflen;


  for (idx=0; tests[idx].a; idx++)
    {
      err = gcry_sexp_new (&sexp, tests[idx].a, 0, 1);
      if (err)
        fail2 (idx,err);
      err = make_canon_sexp (sexp, &abuf, &abuflen);
      if (err)
        fail2 (idx,err);
      gcry_sexp_release (sexp);

      if (tests[idx].b)
        {
          err = gcry_sexp_new (&sexp, tests[idx].b, 0, 1);
          if (err)
            fail2 (idx,err);
          err = make_canon_sexp (sexp, &bbuf, &bbuflen);
          if (err)
            fail2 (idx,err);
          gcry_sexp_release (sexp);
        }
      else
        bbuf = NULL;

      err = uncompress_ecc_q_in_canon_sexp (abuf, abuflen, &rbuf, &rbuflen);
      if (err)
        fail2 (idx,err);
      if (rbuf)
        fail (idx);  /* Converted without a need.  */

      if (bbuf)
        {
          err = uncompress_ecc_q_in_canon_sexp (bbuf, bbuflen, &rbuf, &rbuflen);
          if (gpg_err_code (err) == GPG_ERR_UNKNOWN_CURVE)
            {
              static int shown;
              fprintf (stderr, "%s:%d: test %d failed: %s - ignored\n",
                       __FILE__,__LINE__, idx, gpg_strerror (err));
              if (!shown)
                {
                  shown = 1;
                  fprintf (stderr, "This is likely due to a patched"
                           " version of Libgcrypt with removed support"
                           " for Brainpool curves\n");
                }
            }
          else
            {
              if (err)
                fail2 (idx,err);
              if (!rbuf)
                fail (idx);  /* Not converted despite a need for it. */

              /* log_printcanon ("  orig:", abuf, abuflen); */
              /* log_printcanon ("  comp:", bbuf, bbuflen); */
              /* log_printcanon ("uncomp:", rbuf, rbuflen); */

              if (rbuflen != abuflen || memcmp (rbuf, abuf, abuflen))
                fail (idx);
            }
        }

      xfree (abuf);
      xfree (bbuf);
      xfree (rbuf);
    }
}


int
main (int argc, char **argv)
{
  (void)argc;
  (void)argv;

  test_hash_algo_from_sigval ();
  test_make_canon_sexp_from_rsa_pk ();
  test_cmp_canon_sexp ();
  test_ecc_uncompress ();

  return 0;
}
