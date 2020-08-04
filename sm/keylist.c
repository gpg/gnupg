/* keylist.c - Print certificates in various formats.
 * Copyright (C) 1998, 1999, 2000, 2001, 2003, 2004, 2005, 2008, 2009,
 *               2010, 2011 Free Software Foundation, Inc.
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
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>

#include "gpgsm.h"

#include <gcrypt.h>
#include <ksba.h>

#include "keydb.h"
#include "../kbx/keybox.h" /* for KEYBOX_FLAG_* */
#include "../common/i18n.h"
#include "../common/tlv.h"
#include "../common/compliance.h"

struct list_external_parm_s
{
  ctrl_t ctrl;
  estream_t fp;
  int print_header;
  int with_colons;
  int with_chain;
  int raw_mode;
};


/* This table is to map Extended Key Usage OIDs to human readable
   names.  */
struct
{
  const char *oid;
  const char *name;
} key_purpose_map[] = {
  { "1.3.6.1.5.5.7.3.1",  "serverAuth" },
  { "1.3.6.1.5.5.7.3.2",  "clientAuth" },
  { "1.3.6.1.5.5.7.3.3",  "codeSigning" },
  { "1.3.6.1.5.5.7.3.4",  "emailProtection" },
  { "1.3.6.1.5.5.7.3.5",  "ipsecEndSystem" },
  { "1.3.6.1.5.5.7.3.6",  "ipsecTunnel" },
  { "1.3.6.1.5.5.7.3.7",  "ipsecUser" },
  { "1.3.6.1.5.5.7.3.8",  "timeStamping" },
  { "1.3.6.1.5.5.7.3.9",  "ocspSigning" },
  { "1.3.6.1.5.5.7.3.10", "dvcs" },
  { "1.3.6.1.5.5.7.3.11", "sbgpCertAAServerAuth" },
  { "1.3.6.1.5.5.7.3.13", "eapOverPPP" },
  { "1.3.6.1.5.5.7.3.14", "wlanSSID" },

  { "2.16.840.1.113730.4.1", "serverGatedCrypto.ns" }, /* Netscape. */
  { "1.3.6.1.4.1.311.10.3.3", "serverGatedCrypto.ms"}, /* Microsoft. */

  { "1.3.6.1.5.5.7.48.1.5", "ocspNoCheck" },

  { NULL, NULL }
};


/* Do not print this extension in the list of extensions.  This is set
   for oids which are already available via ksba functions. */
#define OID_FLAG_SKIP 1
/* The extension is a simple UTF8String and should be printed.  */
#define OID_FLAG_UTF8 2
/* The extension can be trnted as a hex string.  */
#define OID_FLAG_HEX  4

/* A table mapping OIDs to a descriptive string. */
static struct
{
  char *oid;
  char *name;
  unsigned int flag; /* A flag as described above.  */
} oidtranstbl[] = {

  /* Algorithms. */
  { "1.2.840.10040.4.1", "dsa" },
  { "1.2.840.10040.4.3", "dsaWithSha1" },

  { "1.2.840.113549.1.1.1", "rsaEncryption" },
  { "1.2.840.113549.1.1.2", "md2WithRSAEncryption" },
  { "1.2.840.113549.1.1.3", "md4WithRSAEncryption" },
  { "1.2.840.113549.1.1.4", "md5WithRSAEncryption" },
  { "1.2.840.113549.1.1.5", "sha1WithRSAEncryption" },
  { "1.2.840.113549.1.1.7", "rsaOAEP" },
  { "1.2.840.113549.1.1.8", "rsaOAEP-MGF" },
  { "1.2.840.113549.1.1.9", "rsaOAEP-pSpecified" },
  { "1.2.840.113549.1.1.10", "rsaPSS" },
  { "1.2.840.113549.1.1.11", "sha256WithRSAEncryption" },
  { "1.2.840.113549.1.1.12", "sha384WithRSAEncryption" },
  { "1.2.840.113549.1.1.13", "sha512WithRSAEncryption" },

  { "1.3.14.3.2.26", "sha1" },
  { "1.3.14.3.2.29",  "sha-1WithRSAEncryption" },
  { "1.3.36.3.3.1.2", "rsaSignatureWithripemd160" },


  /* Telesec extensions. */
  { "0.2.262.1.10.12.0", "certExtensionLiabilityLimitationExt" },
  { "0.2.262.1.10.12.1", "telesecCertIdExt" },
  { "0.2.262.1.10.12.2", "telesecPolicyIdentifier" },
  { "0.2.262.1.10.12.3", "telesecPolicyQualifierID" },
  { "0.2.262.1.10.12.4", "telesecCRLFilteredExt" },
  { "0.2.262.1.10.12.5", "telesecCRLFilterExt"},
  { "0.2.262.1.10.12.6", "telesecNamingAuthorityExt" },
#define OIDSTR_restriction \
    "1.3.36.8.3.8"
  { OIDSTR_restriction,      "restriction", OID_FLAG_UTF8 },


  /* PKIX private extensions. */
  { "1.3.6.1.5.5.7.1.1", "authorityInfoAccess" },
  { "1.3.6.1.5.5.7.1.2", "biometricInfo" },
  { "1.3.6.1.5.5.7.1.3", "qcStatements" },
  { "1.3.6.1.5.5.7.1.4", "acAuditIdentity" },
  { "1.3.6.1.5.5.7.1.5", "acTargeting" },
  { "1.3.6.1.5.5.7.1.6", "acAaControls" },
  { "1.3.6.1.5.5.7.1.7", "sbgp-ipAddrBlock" },
  { "1.3.6.1.5.5.7.1.8", "sbgp-autonomousSysNum" },
  { "1.3.6.1.5.5.7.1.9", "sbgp-routerIdentifier" },
  { "1.3.6.1.5.5.7.1.10", "acProxying" },
  { "1.3.6.1.5.5.7.1.11", "subjectInfoAccess" },

  { "1.3.6.1.5.5.7.48.1", "ocsp" },
  { "1.3.6.1.5.5.7.48.2", "caIssuers" },
  { "1.3.6.1.5.5.7.48.3", "timeStamping" },
  { "1.3.6.1.5.5.7.48.5", "caRepository" },

  /* X.509 id-ce */
  { "2.5.29.14", "subjectKeyIdentifier", OID_FLAG_SKIP},
  { "2.5.29.15", "keyUsage", OID_FLAG_SKIP},
  { "2.5.29.16", "privateKeyUsagePeriod" },
  { "2.5.29.17", "subjectAltName", OID_FLAG_SKIP},
  { "2.5.29.18", "issuerAltName", OID_FLAG_SKIP},
  { "2.5.29.19", "basicConstraints", OID_FLAG_SKIP},
  { "2.5.29.20", "cRLNumber" },
  { "2.5.29.21", "cRLReason" },
  { "2.5.29.22", "expirationDate" },
  { "2.5.29.23", "instructionCode" },
  { "2.5.29.24", "invalidityDate" },
  { "2.5.29.27", "deltaCRLIndicator" },
  { "2.5.29.28", "issuingDistributionPoint" },
  { "2.5.29.29", "certificateIssuer" },
  { "2.5.29.30", "nameConstraints" },
  { "2.5.29.31", "cRLDistributionPoints", OID_FLAG_SKIP},
  { "2.5.29.32", "certificatePolicies", OID_FLAG_SKIP},
  { "2.5.29.32.0", "anyPolicy" },
  { "2.5.29.33", "policyMappings" },
  { "2.5.29.35", "authorityKeyIdentifier", OID_FLAG_SKIP},
  { "2.5.29.36", "policyConstraints" },
  { "2.5.29.37", "extKeyUsage", OID_FLAG_SKIP},
  { "2.5.29.46", "freshestCRL" },
  { "2.5.29.54", "inhibitAnyPolicy" },

  /* Netscape certificate extensions. */
  { "2.16.840.1.113730.1.1", "netscape-cert-type" },
  { "2.16.840.1.113730.1.2", "netscape-base-url" },
  { "2.16.840.1.113730.1.3", "netscape-revocation-url" },
  { "2.16.840.1.113730.1.4", "netscape-ca-revocation-url" },
  { "2.16.840.1.113730.1.7", "netscape-cert-renewal-url" },
  { "2.16.840.1.113730.1.8", "netscape-ca-policy-url" },
  { "2.16.840.1.113730.1.9", "netscape-homePage-url" },
  { "2.16.840.1.113730.1.10", "netscape-entitylogo" },
  { "2.16.840.1.113730.1.11", "netscape-userPicture" },
  { "2.16.840.1.113730.1.12", "netscape-ssl-server-name" },
  { "2.16.840.1.113730.1.13", "netscape-comment" },

  /* GnuPG extensions */
  { "1.3.6.1.4.1.11591.2.1.1", "pkaAddress" },
  { "1.3.6.1.4.1.11591.2.2.1", "standaloneCertificate" },
  { "1.3.6.1.4.1.11591.2.2.2", "wellKnownPrivateKey" },

  /* Extensions used by the Bundesnetzagentur.  */
  { "1.3.6.1.4.1.8301.3.5", "validityModel" },

  /* Yubikey extensions for attestation certificates.  */
  { "1.3.6.1.4.1.41482.3.3", "yubikey-firmware-version", OID_FLAG_HEX },
  { "1.3.6.1.4.1.41482.3.7", "yubikey-serial-number", OID_FLAG_HEX },
  { "1.3.6.1.4.1.41482.3.8", "yubikey-pin-touch-policy", OID_FLAG_HEX },
  { "1.3.6.1.4.1.41482.3.9", "yubikey-formfactor", OID_FLAG_HEX },

  { NULL }
};


/* Return the description for OID; if no description is available
   NULL is returned. */
static const char *
get_oid_desc (const char *oid, unsigned int *flag)
{
  int i;

  if (oid)
    for (i=0; oidtranstbl[i].oid; i++)
      if (!strcmp (oidtranstbl[i].oid, oid))
        {
          if (flag)
            *flag = oidtranstbl[i].flag;
          return oidtranstbl[i].name;
        }
  if (flag)
    *flag = 0;
  return NULL;
}


static void
print_key_data (ksba_cert_t cert, estream_t fp)
{
#if 0
  int n = pk ? pubkey_get_npkey( pk->pubkey_algo ) : 0;
  int i;

  for(i=0; i < n; i++ )
    {
      es_fprintf (fp, "pkd:%d:%u:", i, mpi_get_nbits( pk->pkey[i] ) );
      mpi_print(stdout, pk->pkey[i], 1 );
      putchar(':');
      putchar('\n');
    }
#else
  (void)cert;
  (void)fp;
#endif
}

static void
print_capabilities (ksba_cert_t cert, estream_t fp)
{
  gpg_error_t err;
  unsigned int use;
  size_t buflen;
  char buffer[1];

  err = ksba_cert_get_user_data (cert, "is_qualified",
                                 &buffer, sizeof (buffer), &buflen);
  if (!err && buflen)
    {
      if (*buffer)
        es_putc ('q', fp);
    }
  else if (gpg_err_code (err) == GPG_ERR_NOT_FOUND)
    ; /* Don't know - will not get marked as 'q' */
  else
    log_debug ("get_user_data(is_qualified) failed: %s\n",
               gpg_strerror (err));

  err = ksba_cert_get_key_usage (cert, &use);
  if (gpg_err_code (err) == GPG_ERR_NO_DATA)
    {
      es_putc ('e', fp);
      es_putc ('s', fp);
      es_putc ('c', fp);
      es_putc ('E', fp);
      es_putc ('S', fp);
      es_putc ('C', fp);
      return;
    }
  if (err)
    {
      log_error (_("error getting key usage information: %s\n"),
                 gpg_strerror (err));
      return;
    }

  if ((use & (KSBA_KEYUSAGE_KEY_ENCIPHERMENT|KSBA_KEYUSAGE_DATA_ENCIPHERMENT)))
    es_putc ('e', fp);
  if ((use & (KSBA_KEYUSAGE_DIGITAL_SIGNATURE|KSBA_KEYUSAGE_NON_REPUDIATION)))
    es_putc ('s', fp);
  if ((use & KSBA_KEYUSAGE_KEY_CERT_SIGN))
    es_putc ('c', fp);
  if ((use & (KSBA_KEYUSAGE_KEY_ENCIPHERMENT|KSBA_KEYUSAGE_DATA_ENCIPHERMENT)))
    es_putc ('E', fp);
  if ((use & (KSBA_KEYUSAGE_DIGITAL_SIGNATURE|KSBA_KEYUSAGE_NON_REPUDIATION)))
    es_putc ('S', fp);
  if ((use & KSBA_KEYUSAGE_KEY_CERT_SIGN))
    es_putc ('C', fp);
}


static void
print_time (gnupg_isotime_t t, estream_t fp)
{
  if (!t || !*t)
    ;
  else
    es_fputs (t, fp);
}


/* Return an allocated string with the email address extracted from a
   DN.  Note hat we use this code also in ../kbx/keybox-blob.c.  */
static char *
email_kludge (const char *name)
{
  const char *p, *string;
  unsigned char *buf;
  int n;

  string = name;
  for (;;)
    {
      p = strstr (string, "1.2.840.113549.1.9.1=#");
      if (!p)
        return NULL;
      if (p == name || (p > string+1 && p[-1] == ',' && p[-2] != '\\'))
        {
          name = p + 22;
          break;
        }
      string = p + 22;
    }


  /* This looks pretty much like an email address in the subject's DN
     we use this to add an additional user ID entry.  This way,
     OpenSSL generated keys get a nicer and usable listing.  */
  for (n=0, p=name; hexdigitp (p) && hexdigitp (p+1); p +=2, n++)
    ;
  if (!n)
    return NULL;
  buf = xtrymalloc (n+3);
  if (!buf)
    return NULL; /* oops, out of core */
  *buf = '<';
  for (n=1, p=name; hexdigitp (p); p +=2, n++)
    buf[n] = xtoi_2 (p);
  buf[n++] = '>';
  buf[n] = 0;
  return (char*)buf;
}


/* Print the compliance flags to field 18.  ALGO is the gcrypt algo
 * number.  NBITS is the length of the key in bits.  */
static void
print_compliance_flags (ksba_cert_t cert, int algo, unsigned int nbits,
                        estream_t fp)
{
  int hashalgo;

  /* Note that we do not need to test for PK_ALGO_FLAG_RSAPSS because
   * that is not a property of the key but one of the created
   * signature.  */
  if (gnupg_pk_is_compliant (CO_DE_VS, algo, 0, NULL, nbits, NULL))
    {
      hashalgo = gcry_md_map_name (ksba_cert_get_digest_algo (cert));
      if (gnupg_digest_is_compliant (CO_DE_VS, hashalgo))
        {
          es_fputs (gnupg_status_compliance_flag (CO_DE_VS), fp);
        }
    }
}


/* List one certificate in colon mode */
static void
list_cert_colon (ctrl_t ctrl, ksba_cert_t cert, unsigned int validity,
                 estream_t fp, int have_secret)
{
  int rc;
  int idx;
  char truststring[2];
  char *p;
  ksba_sexp_t sexp;
  char *fpr;
  ksba_isotime_t t;
  gpg_error_t valerr;
  int algo;
  unsigned int nbits;
  const char *chain_id;
  char *chain_id_buffer = NULL;
  int is_root = 0;
  char *kludge_uid;

  if (ctrl->with_validation)
    valerr = gpgsm_validate_chain (ctrl, cert, "", NULL, 1, NULL, 0, NULL);
  else
    valerr = 0;


  /* We need to get the fingerprint and the chaining ID in advance. */
  fpr = gpgsm_get_fingerprint_hexstring (cert, GCRY_MD_SHA1);
  {
    ksba_cert_t next;

    rc = gpgsm_walk_cert_chain (ctrl, cert, &next);
    if (!rc) /* We known the issuer's certificate. */
      {
        p = gpgsm_get_fingerprint_hexstring (next, GCRY_MD_SHA1);
        chain_id_buffer = p;
        chain_id = chain_id_buffer;
        ksba_cert_release (next);
      }
    else if (rc == -1)  /* We have reached the root certificate. */
      {
        chain_id = fpr;
        is_root = 1;
      }
    else
      chain_id = NULL;
  }


  es_fputs (have_secret? "crs:":"crt:", fp);

  /* Note: We can't use multiple flags, like "ei", because the
     validation check does only return one error.  */
  truststring[0] = 0;
  truststring[1] = 0;
  if ((validity & VALIDITY_REVOKED)
      || gpg_err_code (valerr) == GPG_ERR_CERT_REVOKED)
    *truststring = 'r';
  else if (gpg_err_code (valerr) == GPG_ERR_CERT_EXPIRED)
    *truststring = 'e';
  else
    {
      /* Lets also check whether the certificate under question
         expired.  This is merely a hack until we found a proper way
         to store the expiration flag in the keybox. */
      ksba_isotime_t current_time, not_after;

      gnupg_get_isotime (current_time);
      if (!opt.ignore_expiration
          && !ksba_cert_get_validity (cert, 1, not_after)
          && *not_after && strcmp (current_time, not_after) > 0 )
        *truststring = 'e';
      else if (valerr)
        {
          if (gpgsm_cert_has_well_known_private_key (cert))
            *truststring = 'w';  /* Well, this is dummy CA.  */
          else
            *truststring = 'i';
        }
      else if (ctrl->with_validation && !is_root)
        *truststring = 'f';
    }

  /* If we have no truststring yet (i.e. the certificate might be
     good) and this is a root certificate, we ask the agent whether
     this is a trusted root certificate. */
  if (!*truststring && is_root)
    {
      struct rootca_flags_s dummy_flags;

      if (gpgsm_cert_has_well_known_private_key (cert))
        *truststring = 'w';  /* Well, this is dummy CA.  */
      else
        {
          rc = gpgsm_agent_istrusted (ctrl, cert, NULL, &dummy_flags);
          if (!rc)
            *truststring = 'u';  /* Yes, we trust this one (ultimately). */
          else if (gpg_err_code (rc) == GPG_ERR_NOT_TRUSTED)
            *truststring = 'n';  /* No, we do not trust this one. */
          /* (in case of an error we can't tell anything.) */
        }
    }

  if (*truststring)
    es_fputs (truststring, fp);

  algo = gpgsm_get_key_algo_info (cert, &nbits);
  es_fprintf (fp, ":%u:%d:%s:", nbits, algo, fpr+24);

  ksba_cert_get_validity (cert, 0, t);
  print_time (t, fp);
  es_putc (':', fp);
  ksba_cert_get_validity (cert, 1, t);
  print_time ( t, fp);
  es_putc (':', fp);
  /* Field 8, serial number: */
  if ((sexp = ksba_cert_get_serial (cert)))
    {
      int len;
      const unsigned char *s = sexp;

      if (*s == '(')
        {
          s++;
          for (len=0; *s && *s != ':' && digitp (s); s++)
            len = len*10 + atoi_1 (s);
          if (*s == ':')
            for (s++; len; len--, s++)
              es_fprintf (fp,"%02X", *s);
        }
      xfree (sexp);
    }
  es_putc (':', fp);
  /* Field 9, ownertrust - not used here */
  es_putc (':', fp);
  /* field 10, old user ID - we use it here for the issuer DN */
  if ((p = ksba_cert_get_issuer (cert,0)))
    {
      es_write_sanitized (fp, p, strlen (p), ":", NULL);
      xfree (p);
    }
  es_putc (':', fp);
  /* Field 11, signature class - not used */
  es_putc (':', fp);
  /* Field 12, capabilities: */
  print_capabilities (cert, fp);
  es_putc (':', fp);
  /* Field 13, not used: */
  es_putc (':', fp);
  /* Field 14, not used: */
  es_putc (':', fp);
  if (have_secret || ctrl->with_secret)
    {
      char *cardsn;

      p = gpgsm_get_keygrip_hexstring (cert);
      if (!gpgsm_agent_keyinfo (ctrl, p, &cardsn)
          && (cardsn || ctrl->with_secret))
        {
          /* Field 15:  Token serial number or secret key indicator.  */
          if (cardsn)
            es_fputs (cardsn, fp);
          else if (ctrl->with_secret)
            es_putc ('+', fp);
        }
      xfree (cardsn);
      xfree (p);
    }
  es_putc (':', fp);  /* End of field 15. */
  es_putc (':', fp);  /* End of field 16. */
  es_putc (':', fp);  /* End of field 17. */
  print_compliance_flags (cert, algo, nbits, fp);
  es_putc (':', fp);  /* End of field 18. */
  es_putc ('\n', fp);

  /* FPR record */
  es_fprintf (fp, "fpr:::::::::%s:::", fpr);
  /* Print chaining ID (field 13)*/
  if (chain_id)
    es_fputs (chain_id, fp);
  es_putc (':', fp);
  es_putc ('\n', fp);
  xfree (fpr); fpr = NULL; chain_id = NULL;
  xfree (chain_id_buffer); chain_id_buffer = NULL;
  /* SHA256 FPR record */
  fpr = gpgsm_get_fingerprint_hexstring (cert, GCRY_MD_SHA256);
  es_fprintf (fp, "fp2:::::::::%s::::\n", fpr);
  xfree (fpr); fpr = NULL;

  /* Always print the keygrip.  */
  if ( (p = gpgsm_get_keygrip_hexstring (cert)))
    {
      es_fprintf (fp, "grp:::::::::%s:\n", p);
      xfree (p);
    }

  if (opt.with_key_data)
    print_key_data (cert, fp);

  kludge_uid = NULL;
  for (idx=0; (p = ksba_cert_get_subject (cert,idx)); idx++)
    {
      /* In the case that the same email address is in the subject DN
         as well as in an alternate subject name we avoid printing it
         a second time. */
      if (kludge_uid && !strcmp (kludge_uid, p))
        continue;

      es_fprintf (fp, "uid:%s::::::::", truststring);
      es_write_sanitized (fp, p, strlen (p), ":", NULL);
      es_putc (':', fp);
      es_putc (':', fp);
      es_putc ('\n', fp);
      if (!idx)
        {
          /* It would be better to get the faked email address from
             the keydb.  But as long as we don't have a way to pass
             the meta data back, we just check it the same way as the
             code used to create the keybox meta data does */
          kludge_uid = email_kludge (p);
          if (kludge_uid)
            {
              es_fprintf (fp, "uid:%s::::::::", truststring);
              es_write_sanitized (fp, kludge_uid, strlen (kludge_uid),
                                  ":", NULL);
              es_putc (':', fp);
              es_putc (':', fp);
              es_putc ('\n', fp);
            }
        }
      xfree (p);
    }
  xfree (kludge_uid);
}


static void
print_name_raw (estream_t fp, const char *string)
{
  if (!string)
    es_fputs ("[error]", fp);
  else
    es_write_sanitized (fp, string, strlen (string), NULL, NULL);
}

static void
print_names_raw (estream_t fp, int indent, ksba_name_t name)
{
  int idx;
  const char *s;
  int indent_all;

  if ((indent_all = (indent < 0)))
    indent = - indent;

  if (!name)
    {
      es_fputs ("none\n", fp);
      return;
    }

  for (idx=0; (s = ksba_name_enum (name, idx)); idx++)
    {
      char *p = ksba_name_get_uri (name, idx);
      es_fprintf (fp, "%*s", idx||indent_all?indent:0, "");
      es_write_sanitized (fp, p?p:s, strlen (p?p:s), NULL, NULL);
      es_putc ('\n', fp);
      xfree (p);
    }
}


static void
print_utf8_extn_raw (estream_t fp, int indent,
                     const unsigned char *der, size_t derlen)
{
  gpg_error_t err;
  int class, tag, constructed, ndef;
  size_t objlen, hdrlen;

  if (indent < 0)
    indent = - indent;

  err = parse_ber_header (&der, &derlen, &class, &tag, &constructed,
                          &ndef, &objlen, &hdrlen);
  if (!err && (objlen > derlen || tag != TAG_UTF8_STRING))
    err = gpg_error (GPG_ERR_INV_OBJ);
  if (err)
    {
      es_fprintf (fp, "%*s[%s]\n", indent, "", gpg_strerror (err));
      return;
    }
  es_fprintf (fp, "%*s(%.*s)\n", indent, "", (int)objlen, der);
}


static void
print_utf8_extn (estream_t fp, int indent,
                 const unsigned char *der, size_t derlen)
{
  gpg_error_t err;
  int class, tag, constructed, ndef;
  size_t objlen, hdrlen;
  int indent_all;

  if ((indent_all = (indent < 0)))
    indent = - indent;

  err = parse_ber_header (&der, &derlen, &class, &tag, &constructed,
                          &ndef, &objlen, &hdrlen);
  if (!err && (objlen > derlen || tag != TAG_UTF8_STRING))
    err = gpg_error (GPG_ERR_INV_OBJ);
  if (err)
    {
      es_fprintf (fp, "%*s[%s%s]\n",
                  indent_all? indent:0, "", _("Error - "), gpg_strerror (err));
      return;
    }
  es_fprintf (fp, "%*s\"", indent_all? indent:0, "");
  /* Fixme: we should implement word wrapping */
  es_write_sanitized (fp, der, objlen, "\"", NULL);
  es_fputs ("\"\n", fp);
}


/* Print the extension described by (DER,DERLEN) in hex.  */
static void
print_hex_extn (estream_t fp, int indent,
                const unsigned char *der, size_t derlen)
{
  if (indent < 0)
    indent = - indent;

  es_fprintf (fp, "%*s(", indent, "");
  for (; derlen; der++, derlen--)
    es_fprintf (fp, "%02X%s", *der, derlen > 1? " ":"");
  es_fprintf (fp, ")\n");
}


/* List one certificate in raw mode useful to have a closer look at
   the certificate.  This one does no beautification and only minimal
   output sanitation.  It is mainly useful for debugging. */
static void
list_cert_raw (ctrl_t ctrl, KEYDB_HANDLE hd,
               ksba_cert_t cert, estream_t fp, int have_secret,
               int with_validation)
{
  gpg_error_t err;
  size_t off, len;
  ksba_sexp_t sexp, keyid;
  char *dn;
  ksba_isotime_t t;
  int idx, i;
  int is_ca, chainlen;
  unsigned int kusage;
  char *string, *p, *pend;
  const char *oid, *s;
  ksba_name_t name, name2;
  unsigned int reason;
  const unsigned char *cert_der = NULL;

  (void)have_secret;

  es_fprintf (fp, "           ID: 0x%08lX\n",
              gpgsm_get_short_fingerprint (cert, NULL));

  sexp = ksba_cert_get_serial (cert);
  es_fputs ("          S/N: ", fp);
  gpgsm_print_serial (fp, sexp);
  es_putc ('\n', fp);
  es_fputs ("        (dec): ", fp);
  gpgsm_print_serial_decimal (fp, sexp);
  es_putc ('\n', fp);
  ksba_free (sexp);

  dn = ksba_cert_get_issuer (cert, 0);
  es_fputs ("       Issuer: ", fp);
  print_name_raw (fp, dn);
  ksba_free (dn);
  es_putc ('\n', fp);
  for (idx=1; (dn = ksba_cert_get_issuer (cert, idx)); idx++)
    {
      es_fputs ("          aka: ", fp);
      print_name_raw (fp, dn);
      ksba_free (dn);
      es_putc ('\n', fp);
    }

  dn = ksba_cert_get_subject (cert, 0);
  es_fputs ("      Subject: ", fp);
  print_name_raw (fp, dn);
  ksba_free (dn);
  es_putc ('\n', fp);
  for (idx=1; (dn = ksba_cert_get_subject (cert, idx)); idx++)
    {
      es_fputs ("          aka: ", fp);
      print_name_raw (fp, dn);
      ksba_free (dn);
      es_putc ('\n', fp);
    }

  dn = gpgsm_get_fingerprint_string (cert, GCRY_MD_SHA256);
  es_fprintf (fp, "     sha2_fpr: %s\n", dn?dn:"error");
  xfree (dn);

  dn = gpgsm_get_fingerprint_string (cert, 0);
  es_fprintf (fp, "     sha1_fpr: %s\n", dn?dn:"error");
  xfree (dn);

  dn = gpgsm_get_fingerprint_string (cert, GCRY_MD_MD5);
  es_fprintf (fp, "      md5_fpr: %s\n", dn?dn:"error");
  xfree (dn);

  dn = gpgsm_get_certid (cert);
  es_fprintf (fp, "       certid: %s\n", dn?dn:"error");
  xfree (dn);

  dn = gpgsm_get_keygrip_hexstring (cert);
  es_fprintf (fp, "      keygrip: %s\n", dn?dn:"error");
  xfree (dn);

  ksba_cert_get_validity (cert, 0, t);
  es_fputs ("    notBefore: ", fp);
  gpgsm_print_time (fp, t);
  es_putc ('\n', fp);
  es_fputs ("     notAfter: ", fp);
  ksba_cert_get_validity (cert, 1, t);
  gpgsm_print_time (fp, t);
  es_putc ('\n', fp);

  oid = ksba_cert_get_digest_algo (cert);
  s = get_oid_desc (oid, NULL);
  es_fprintf (fp, "     hashAlgo: %s%s%s%s\n", oid, s?" (":"",s?s:"",s?")":"");

  {
    const char *algoname;
    unsigned int nbits;

    algoname = gcry_pk_algo_name (gpgsm_get_key_algo_info (cert, &nbits));
    es_fprintf (fp, "      keyType: %u bit %s\n",
                nbits, algoname? algoname:"?");
  }

  /* subjectKeyIdentifier */
  es_fputs ("    subjKeyId: ", fp);
  err = ksba_cert_get_subj_key_id (cert, NULL, &keyid);
  if (!err || gpg_err_code (err) == GPG_ERR_NO_DATA)
    {
      if (gpg_err_code (err) == GPG_ERR_NO_DATA)
        es_fputs ("[none]\n", fp);
      else
        {
          gpgsm_print_serial (fp, keyid);
          ksba_free (keyid);
          es_putc ('\n', fp);
        }
    }
  else
    es_fputs ("[?]\n", fp);


  /* authorityKeyIdentifier */
  es_fputs ("    authKeyId: ", fp);
  err = ksba_cert_get_auth_key_id (cert, &keyid, &name, &sexp);
  if (!err || gpg_err_code (err) == GPG_ERR_NO_DATA)
    {
      if (gpg_err_code (err) == GPG_ERR_NO_DATA || !name)
        es_fputs ("[none]\n", fp);
      else
        {
          gpgsm_print_serial (fp, sexp);
          ksba_free (sexp);
          es_putc ('\n', fp);
          print_names_raw (fp, -15, name);
          ksba_name_release (name);
        }
      if (keyid)
        {
          es_fputs (" authKeyId.ki: ", fp);
          gpgsm_print_serial (fp, keyid);
          ksba_free (keyid);
          es_putc ('\n', fp);
        }
    }
  else
    es_fputs ("[?]\n", fp);

  es_fputs ("     keyUsage:", fp);
  err = ksba_cert_get_key_usage (cert, &kusage);
  if (gpg_err_code (err) != GPG_ERR_NO_DATA)
    {
      if (err)
        es_fprintf (fp, " [error: %s]", gpg_strerror (err));
      else
        {
          if ( (kusage & KSBA_KEYUSAGE_DIGITAL_SIGNATURE))
            es_fputs (" digitalSignature", fp);
          if ( (kusage & KSBA_KEYUSAGE_NON_REPUDIATION))
            es_fputs (" nonRepudiation", fp);
          if ( (kusage & KSBA_KEYUSAGE_KEY_ENCIPHERMENT))
            es_fputs (" keyEncipherment", fp);
          if ( (kusage & KSBA_KEYUSAGE_DATA_ENCIPHERMENT))
            es_fputs (" dataEncipherment", fp);
          if ( (kusage & KSBA_KEYUSAGE_KEY_AGREEMENT))
            es_fputs (" keyAgreement", fp);
          if ( (kusage & KSBA_KEYUSAGE_KEY_CERT_SIGN))
            es_fputs (" certSign", fp);
          if ( (kusage & KSBA_KEYUSAGE_CRL_SIGN))
            es_fputs (" crlSign", fp);
          if ( (kusage & KSBA_KEYUSAGE_ENCIPHER_ONLY))
            es_fputs (" encipherOnly", fp);
          if ( (kusage & KSBA_KEYUSAGE_DECIPHER_ONLY))
            es_fputs (" decipherOnly", fp);
        }
      es_putc ('\n', fp);
    }
  else
    es_fputs (" [none]\n", fp);

  es_fputs ("  extKeyUsage: ", fp);
  err = ksba_cert_get_ext_key_usages (cert, &string);
  if (gpg_err_code (err) != GPG_ERR_NO_DATA)
    {
      if (err)
        es_fprintf (fp, "[error: %s]", gpg_strerror (err));
      else
        {
          p = string;
          while (p && (pend=strchr (p, ':')))
            {
              *pend++ = 0;
              for (i=0; key_purpose_map[i].oid; i++)
                if ( !strcmp (key_purpose_map[i].oid, p) )
                  break;
              es_fputs (key_purpose_map[i].oid?key_purpose_map[i].name:p, fp);
              p = pend;
              if (*p != 'C')
                es_fputs (" (suggested)", fp);
              if ((p = strchr (p, '\n')))
                {
                  p++;
                  es_fputs ("\n               ", fp);
                }
            }
          xfree (string);
        }
      es_putc ('\n', fp);
    }
  else
    es_fputs ("[none]\n", fp);


  es_fputs ("     policies: ", fp);
  err = ksba_cert_get_cert_policies (cert, &string);
  if (gpg_err_code (err) != GPG_ERR_NO_DATA)
    {
      if (err)
        es_fprintf (fp, "[error: %s]", gpg_strerror (err));
      else
        {
          p = string;
          while (p && (pend=strchr (p, ':')))
            {
              *pend++ = 0;
              for (i=0; key_purpose_map[i].oid; i++)
                if ( !strcmp (key_purpose_map[i].oid, p) )
                  break;
              es_fputs (p, fp);
              p = pend;
              if (*p == 'C')
                es_fputs (" (critical)", fp);
              if ((p = strchr (p, '\n')))
                {
                  p++;
                  es_fputs ("\n               ", fp);
                }
            }
          xfree (string);
        }
      es_putc ('\n', fp);
    }
  else
    es_fputs ("[none]\n", fp);

  es_fputs ("  chainLength: ", fp);
  err = ksba_cert_is_ca (cert, &is_ca, &chainlen);
  if (err || is_ca)
    {
      if (gpg_err_code (err) == GPG_ERR_NO_VALUE )
        es_fprintf (fp, "[none]");
      else if (err)
        es_fprintf (fp, "[error: %s]", gpg_strerror (err));
      else if (chainlen == -1)
        es_fputs ("unlimited", fp);
      else
        es_fprintf (fp, "%d", chainlen);
      es_putc ('\n', fp);
    }
  else
    es_fputs ("not a CA\n", fp);


  /* CRL distribution point */
  for (idx=0; !(err=ksba_cert_get_crl_dist_point (cert, idx, &name, &name2,
                                                  &reason)) ;idx++)
    {
      es_fputs ("        crlDP: ", fp);
      print_names_raw (fp, 15, name);
      if (reason)
        {
          es_fputs ("               reason: ", fp);
          if ( (reason & KSBA_CRLREASON_UNSPECIFIED))
            es_fputs (" unused", fp);
          if ( (reason & KSBA_CRLREASON_KEY_COMPROMISE))
            es_fputs (" keyCompromise", fp);
          if ( (reason & KSBA_CRLREASON_CA_COMPROMISE))
            es_fputs (" caCompromise", fp);
          if ( (reason & KSBA_CRLREASON_AFFILIATION_CHANGED))
            es_fputs (" affiliationChanged", fp);
          if ( (reason & KSBA_CRLREASON_SUPERSEDED))
            es_fputs (" superseded", fp);
          if ( (reason & KSBA_CRLREASON_CESSATION_OF_OPERATION))
            es_fputs (" cessationOfOperation", fp);
          if ( (reason & KSBA_CRLREASON_CERTIFICATE_HOLD))
            es_fputs (" certificateHold", fp);
          es_putc ('\n', fp);
        }
      es_fputs ("               issuer: ", fp);
      print_names_raw (fp, 23, name2);
      ksba_name_release (name);
      ksba_name_release (name2);
    }
  if (err && gpg_err_code (err) != GPG_ERR_EOF
      && gpg_err_code (err) != GPG_ERR_NO_VALUE)
    es_fputs ("        crlDP: [error]\n", fp);
  else if (!idx)
    es_fputs ("        crlDP: [none]\n", fp);


  /* authorityInfoAccess. */
  for (idx=0; !(err=ksba_cert_get_authority_info_access (cert, idx, &string,
                                                         &name)); idx++)
    {
      es_fputs ("     authInfo: ", fp);
      s = get_oid_desc (string, NULL);
      es_fprintf (fp, "%s%s%s%s\n", string, s?" (":"", s?s:"", s?")":"");
      print_names_raw (fp, -15, name);
      ksba_name_release (name);
      ksba_free (string);
    }
  if (err && gpg_err_code (err) != GPG_ERR_EOF
      && gpg_err_code (err) != GPG_ERR_NO_VALUE)
    es_fputs ("     authInfo: [error]\n", fp);
  else if (!idx)
    es_fputs ("     authInfo: [none]\n", fp);

  /* subjectInfoAccess. */
  for (idx=0; !(err=ksba_cert_get_subject_info_access (cert, idx, &string,
                                                         &name)); idx++)
    {
      es_fputs ("  subjectInfo: ", fp);
      s = get_oid_desc (string, NULL);
      es_fprintf (fp, "%s%s%s%s\n", string, s?" (":"", s?s:"", s?")":"");
      print_names_raw (fp, -15, name);
      ksba_name_release (name);
      ksba_free (string);
    }
  if (err && gpg_err_code (err) != GPG_ERR_EOF
      && gpg_err_code (err) != GPG_ERR_NO_VALUE)
    es_fputs ("     subjInfo: [error]\n", fp);
  else if (!idx)
    es_fputs ("     subjInfo: [none]\n", fp);


  for (idx=0; !(err=ksba_cert_get_extension (cert, idx,
                                             &oid, &i, &off, &len));idx++)
    {
      unsigned int flag;

      s = get_oid_desc (oid, &flag);
      if ((flag & OID_FLAG_SKIP))
        continue;

      es_fprintf (fp, "     %s: %s%s%s%s",
                  i? "critExtn":"    extn",
                  oid, s?" (":"", s?s:"", s?")":"");
      if ((flag & OID_FLAG_UTF8))
        {
          if (!cert_der)
            cert_der = ksba_cert_get_image (cert, NULL);
          log_assert (cert_der);
          es_fprintf (fp, "\n");
          print_utf8_extn_raw (fp, -15, cert_der+off, len);
        }
      else if ((flag & OID_FLAG_HEX))
        {
          if (!cert_der)
            cert_der = ksba_cert_get_image (cert, NULL);
          log_assert (cert_der);
          es_fprintf (fp, "\n");
          print_hex_extn (fp, -15, cert_der+off, len);
        }
      else
        es_fprintf (fp, "  [%d octets]\n", (int)len);
    }


  if (with_validation)
    {
      err = gpgsm_validate_chain (ctrl, cert, "", NULL, 1, fp, 0, NULL);
      if (!err)
        es_fprintf (fp, "  [certificate is good]\n");
      else
        es_fprintf (fp, "  [certificate is bad: %s]\n", gpg_strerror (err));
    }

  if (hd)
    {
      unsigned int blobflags;

      err = keydb_get_flags (hd, KEYBOX_FLAG_BLOB, 0, &blobflags);
      if (err)
        es_fprintf (fp, "  [error getting keyflags: %s]\n",gpg_strerror (err));
      else if ((blobflags & KEYBOX_FLAG_BLOB_EPHEMERAL))
        es_fprintf (fp, "  [stored as ephemeral]\n");
    }

}




/* List one certificate in standard mode */
static void
list_cert_std (ctrl_t ctrl, ksba_cert_t cert, estream_t fp, int have_secret,
               int with_validation)
{
  gpg_error_t err;
  ksba_sexp_t sexp;
  char *dn;
  ksba_isotime_t t;
  int idx, i;
  int is_ca, chainlen;
  unsigned int kusage;
  char *string, *p, *pend;
  size_t off, len;
  const char *oid;
  const unsigned char *cert_der = NULL;


  es_fprintf (fp, "           ID: 0x%08lX\n",
              gpgsm_get_short_fingerprint (cert, NULL));

  sexp = ksba_cert_get_serial (cert);
  es_fputs ("          S/N: ", fp);
  gpgsm_print_serial (fp, sexp);
  es_putc ('\n', fp);
  es_fputs ("        (dec): ", fp);
  gpgsm_print_serial_decimal (fp, sexp);
  es_putc ('\n', fp);
  ksba_free (sexp);

  dn = ksba_cert_get_issuer (cert, 0);
  es_fputs ("       Issuer: ", fp);
  gpgsm_es_print_name (fp, dn);
  ksba_free (dn);
  es_putc ('\n', fp);
  for (idx=1; (dn = ksba_cert_get_issuer (cert, idx)); idx++)
    {
      es_fputs ("          aka: ", fp);
      gpgsm_es_print_name (fp, dn);
      ksba_free (dn);
      es_putc ('\n', fp);
    }

  dn = ksba_cert_get_subject (cert, 0);
  es_fputs ("      Subject: ", fp);
  gpgsm_es_print_name (fp, dn);
  ksba_free (dn);
  es_putc ('\n', fp);
  for (idx=1; (dn = ksba_cert_get_subject (cert, idx)); idx++)
    {
      es_fputs ("          aka: ", fp);
      gpgsm_es_print_name (fp, dn);
      ksba_free (dn);
      es_putc ('\n', fp);
    }

  ksba_cert_get_validity (cert, 0, t);
  es_fputs ("     validity: ", fp);
  gpgsm_print_time (fp, t);
  es_fputs (" through ", fp);
  ksba_cert_get_validity (cert, 1, t);
  gpgsm_print_time (fp, t);
  es_putc ('\n', fp);


  {
    const char *algoname;
    unsigned int nbits;

    algoname = gcry_pk_algo_name (gpgsm_get_key_algo_info (cert, &nbits));
    es_fprintf (fp, "     key type: %u bit %s\n",
                nbits, algoname? algoname:"?");
  }


  err = ksba_cert_get_key_usage (cert, &kusage);
  if (gpg_err_code (err) != GPG_ERR_NO_DATA)
    {
      es_fputs ("    key usage:", fp);
      if (err)
        es_fprintf (fp, " [error: %s]", gpg_strerror (err));
      else
        {
          if ( (kusage & KSBA_KEYUSAGE_DIGITAL_SIGNATURE))
            es_fputs (" digitalSignature", fp);
          if ( (kusage & KSBA_KEYUSAGE_NON_REPUDIATION))
            es_fputs (" nonRepudiation", fp);
          if ( (kusage & KSBA_KEYUSAGE_KEY_ENCIPHERMENT))
            es_fputs (" keyEncipherment", fp);
          if ( (kusage & KSBA_KEYUSAGE_DATA_ENCIPHERMENT))
            es_fputs (" dataEncipherment", fp);
          if ( (kusage & KSBA_KEYUSAGE_KEY_AGREEMENT))
            es_fputs (" keyAgreement", fp);
          if ( (kusage & KSBA_KEYUSAGE_KEY_CERT_SIGN))
            es_fputs (" certSign", fp);
          if ( (kusage & KSBA_KEYUSAGE_CRL_SIGN))
            es_fputs (" crlSign", fp);
          if ( (kusage & KSBA_KEYUSAGE_ENCIPHER_ONLY))
            es_fputs (" encipherOnly", fp);
          if ( (kusage & KSBA_KEYUSAGE_DECIPHER_ONLY))
            es_fputs (" decipherOnly", fp);
        }
      es_putc ('\n', fp);
    }

  err = ksba_cert_get_ext_key_usages (cert, &string);
  if (gpg_err_code (err) != GPG_ERR_NO_DATA)
    {
      es_fputs ("ext key usage: ", fp);
      if (err)
        es_fprintf (fp, "[error: %s]", gpg_strerror (err));
      else
        {
          p = string;
          while (p && (pend=strchr (p, ':')))
            {
              *pend++ = 0;
              for (i=0; key_purpose_map[i].oid; i++)
                if ( !strcmp (key_purpose_map[i].oid, p) )
                  break;
              es_fputs (key_purpose_map[i].oid?key_purpose_map[i].name:p, fp);
              p = pend;
              if (*p != 'C')
                es_fputs (" (suggested)", fp);
              if ((p = strchr (p, '\n')))
                {
                  p++;
                  es_fputs (", ", fp);
                }
            }
          xfree (string);
        }
      es_putc ('\n', fp);
    }

  /* Print restrictions.  */
  for (idx=0; !(err=ksba_cert_get_extension (cert, idx,
                                             &oid, NULL, &off, &len));idx++)
    {
      if (!strcmp (oid, OIDSTR_restriction) )
        {
          if (!cert_der)
            cert_der = ksba_cert_get_image (cert, NULL);
          assert (cert_der);
          es_fputs ("  restriction: ", fp);
          print_utf8_extn (fp, 15, cert_der+off, len);
        }
    }

  /* Print policies.  */
  err = ksba_cert_get_cert_policies (cert, &string);
  if (gpg_err_code (err) != GPG_ERR_NO_DATA)
    {
      es_fputs ("     policies: ", fp);
      if (err)
        es_fprintf (fp, "[error: %s]", gpg_strerror (err));
      else
        {
          for (p=string; *p; p++)
            {
              if (*p == '\n')
                *p = ',';
            }
          es_write_sanitized (fp, string, strlen (string), NULL, NULL);
          xfree (string);
        }
      es_putc ('\n', fp);
    }

  err = ksba_cert_is_ca (cert, &is_ca, &chainlen);
  if (err || is_ca)
    {
      es_fputs (" chain length: ", fp);
      if (gpg_err_code (err) == GPG_ERR_NO_VALUE )
        es_fprintf (fp, "none");
      else if (err)
        es_fprintf (fp, "[error: %s]", gpg_strerror (err));
      else if (chainlen == -1)
        es_fputs ("unlimited", fp);
      else
        es_fprintf (fp, "%d", chainlen);
      es_putc ('\n', fp);
    }

  if (opt.with_md5_fingerprint)
    {
      dn = gpgsm_get_fingerprint_string (cert, GCRY_MD_MD5);
      es_fprintf (fp, "      md5 fpr: %s\n", dn?dn:"error");
      xfree (dn);
    }

  dn = gpgsm_get_fingerprint_string (cert, 0);
  es_fprintf (fp, "  fingerprint: %s\n", dn?dn:"error");
  xfree (dn);

  dn = gpgsm_get_fingerprint_string (cert, GCRY_MD_SHA256);
  es_fprintf (fp, "     sha2 fpr: %s\n", dn?dn:"error");
  xfree (dn);

  if (opt.with_keygrip)
    {
      dn = gpgsm_get_keygrip_hexstring (cert);
      if (dn)
        {
          es_fprintf (fp, "      keygrip: %s\n", dn);
          xfree (dn);
        }
    }

  if (have_secret)
    {
      char *cardsn;

      p = gpgsm_get_keygrip_hexstring (cert);
      if (!gpgsm_agent_keyinfo (ctrl, p, &cardsn) && cardsn)
        es_fprintf (fp, "     card s/n: %s\n", cardsn);
      xfree (cardsn);
      xfree (p);
    }

  if (with_validation)
    {
      gpg_error_t tmperr;
      size_t buflen;
      char buffer[1];

      err = gpgsm_validate_chain (ctrl, cert, "", NULL, 1, fp, 0, NULL);
      tmperr = ksba_cert_get_user_data (cert, "is_qualified",
                                        &buffer, sizeof (buffer), &buflen);
      if (!tmperr && buflen)
        {
          if (*buffer)
            es_fputs ("  [qualified]\n", fp);
        }
      else if (gpg_err_code (tmperr) == GPG_ERR_NOT_FOUND)
        ; /* Don't know - will not get marked as 'q' */
      else
        log_debug ("get_user_data(is_qualified) failed: %s\n",
                   gpg_strerror (tmperr));

      if (!err)
        es_fprintf (fp, "  [certificate is good]\n");
      else
        es_fprintf (fp, "  [certificate is bad: %s]\n", gpg_strerror (err));
    }
}


/* Same as standard mode list all certifying certs too. */
static void
list_cert_chain (ctrl_t ctrl, KEYDB_HANDLE hd,
                 ksba_cert_t cert, int raw_mode,
                 estream_t fp, int with_validation)
{
  ksba_cert_t next = NULL;

  if (raw_mode)
    list_cert_raw (ctrl, hd, cert, fp, 0, with_validation);
  else
    list_cert_std (ctrl, cert, fp, 0, with_validation);
  ksba_cert_ref (cert);
  while (!gpgsm_walk_cert_chain (ctrl, cert, &next))
    {
      ksba_cert_release (cert);
      es_fputs ("Certified by\n", fp);
      if (raw_mode)
        list_cert_raw (ctrl, hd, next, fp, 0, with_validation);
      else
        list_cert_std (ctrl, next, fp, 0, with_validation);
      cert = next;
    }
  ksba_cert_release (cert);
  es_putc ('\n', fp);
}



/* List all internal keys or just the keys given as NAMES.  MODE is a
   bit vector to specify what keys are to be included; see
   gpgsm_list_keys (below) for details.  If RAW_MODE is true, the raw
   output mode will be used instead of the standard beautified one.
 */
static gpg_error_t
list_internal_keys (ctrl_t ctrl, strlist_t names, estream_t fp,
                    unsigned int mode, int raw_mode)
{
  KEYDB_HANDLE hd;
  KEYDB_SEARCH_DESC *desc = NULL;
  strlist_t sl;
  int ndesc;
  ksba_cert_t cert = NULL;
  ksba_cert_t lastcert = NULL;
  gpg_error_t rc = 0;
  const char *lastresname, *resname;
  int have_secret;
  int want_ephemeral = ctrl->with_ephemeral_keys;

  hd = keydb_new ();
  if (!hd)
    {
      log_error ("keydb_new failed\n");
      rc = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }

  if (!names)
    ndesc = 1;
  else
    {
      for (sl=names, ndesc=0; sl; sl = sl->next, ndesc++)
        ;
    }

  desc = xtrycalloc (ndesc, sizeof *desc);
  if (!ndesc)
    {
      rc = gpg_error_from_syserror ();
      log_error ("out of core\n");
      goto leave;
    }

  if (!names)
    desc[0].mode = KEYDB_SEARCH_MODE_FIRST;
  else
    {
      for (ndesc=0, sl=names; sl; sl = sl->next)
        {
          rc = classify_user_id (sl->d, desc+ndesc, 0);
          if (rc)
            {
              log_error ("key '%s' not found: %s\n",
                         sl->d, gpg_strerror (rc));
              rc = 0;
            }
          else
            ndesc++;
        }

    }

  /* If all specifications are done by fingerprint or keygrip, we
     switch to ephemeral mode so that _all_ currently available and
     matching certificates are listed.  */
  if (!want_ephemeral && names && ndesc)
    {
      int i;

      for (i=0; (i < ndesc
                 && (desc[i].mode == KEYDB_SEARCH_MODE_FPR
                     || desc[i].mode == KEYDB_SEARCH_MODE_FPR20
                     || desc[i].mode == KEYDB_SEARCH_MODE_FPR16
                     || desc[i].mode == KEYDB_SEARCH_MODE_KEYGRIP)); i++)
        ;
      if (i == ndesc)
        want_ephemeral = 1;
    }

  if (want_ephemeral)
    keydb_set_ephemeral (hd, 1);

  /* It would be nice to see which of the given users did actually
     match one in the keyring.  To implement this we need to have a
     found flag for each entry in desc and to set this we must check
     all those entries after a match to mark all matched one -
     currently we stop at the first match.  To do this we need an
     extra flag to enable this feature so */

  /* Suppress duplicates at least when they follow each other.  */
  lastresname = NULL;
  while (!(rc = keydb_search (ctrl, hd, desc, ndesc)))
    {
      unsigned int validity;

      if (!names)
        desc[0].mode = KEYDB_SEARCH_MODE_NEXT;

      rc = keydb_get_flags (hd, KEYBOX_FLAG_VALIDITY, 0, &validity);
      if (rc)
        {
          log_error ("keydb_get_flags failed: %s\n", gpg_strerror (rc));
          goto leave;
        }
      rc = keydb_get_cert (hd, &cert);
      if (rc)
        {
          log_error ("keydb_get_cert failed: %s\n", gpg_strerror (rc));
          goto leave;
        }
      /* Skip duplicated certificates, at least if they follow each
	 others.  This works best if a single key is searched for and
	 expected.  FIXME: Non-sequential duplicates remain.  */
      if (gpgsm_certs_identical_p (cert, lastcert))
	{
	  ksba_cert_release (cert);
          cert = NULL;
	  continue;
	}

      resname = keydb_get_resource_name (hd);

      if (lastresname != resname )
        {
          int i;

          if (ctrl->no_server)
            {
              es_fprintf (fp, "%s\n", resname );
              for (i=strlen(resname); i; i-- )
                es_putc ('-', fp);
              es_putc ('\n', fp);
              lastresname = resname;
            }
        }

      have_secret = 0;
      if (mode)
        {
          char *p = gpgsm_get_keygrip_hexstring (cert);
          if (p)
            {
              rc = gpgsm_agent_havekey (ctrl, p);
              if (!rc)
                have_secret = 1;
              else if ( gpg_err_code (rc) != GPG_ERR_NO_SECKEY)
                goto leave;
              rc = 0;
              xfree (p);
            }
        }

      if (!mode          || ((mode & 1) && !have_secret)
          || ((mode & 2) && have_secret)  )
        {
          if (ctrl->with_colons)
            list_cert_colon (ctrl, cert, validity, fp, have_secret);
          else if (ctrl->with_chain)
            list_cert_chain (ctrl, hd, cert,
                             raw_mode, fp, ctrl->with_validation);
          else
            {
              if (raw_mode)
                list_cert_raw (ctrl, hd, cert, fp, have_secret,
                               ctrl->with_validation);
              else
                list_cert_std (ctrl, cert, fp, have_secret,
                               ctrl->with_validation);
              es_putc ('\n', fp);
            }
        }

      ksba_cert_release (lastcert);
      lastcert = cert;
      cert = NULL;
    }
  if (gpg_err_code (rc) == GPG_ERR_EOF || rc == -1 )
    rc = 0;
  if (rc)
    log_error ("keydb_search failed: %s\n", gpg_strerror (rc));

 leave:
  ksba_cert_release (cert);
  ksba_cert_release (lastcert);
  xfree (desc);
  keydb_release (hd);
  return rc;
}



static void
list_external_cb (void *cb_value, ksba_cert_t cert)
{
  struct list_external_parm_s *parm = cb_value;

  if (keydb_store_cert (parm->ctrl, cert, 1, NULL))
    log_error ("error storing certificate as ephemeral\n");

  if (parm->print_header)
    {
      const char *resname = "[external keys]";
      int i;

      es_fprintf (parm->fp, "%s\n", resname );
      for (i=strlen(resname); i; i-- )
        es_putc('-', parm->fp);
      es_putc ('\n', parm->fp);
      parm->print_header = 0;
    }

  if (parm->with_colons)
    list_cert_colon (parm->ctrl, cert, 0, parm->fp, 0);
  else if (parm->with_chain)
    list_cert_chain (parm->ctrl, NULL, cert, parm->raw_mode, parm->fp, 0);
  else
    {
      if (parm->raw_mode)
        list_cert_raw (parm->ctrl, NULL, cert, parm->fp, 0, 0);
      else
        list_cert_std (parm->ctrl, cert, parm->fp, 0, 0);
      es_putc ('\n', parm->fp);
    }
}


/* List external keys similar to internal one.  Note: mode does not
   make sense here because it would be unwise to list external secret
   keys */
static gpg_error_t
list_external_keys (ctrl_t ctrl, strlist_t names, estream_t fp, int raw_mode)
{
  int rc;
  struct list_external_parm_s parm;

  parm.fp = fp;
  parm.ctrl = ctrl,
  parm.print_header = ctrl->no_server;
  parm.with_colons = ctrl->with_colons;
  parm.with_chain = ctrl->with_chain;
  parm.raw_mode  = raw_mode;

  rc = gpgsm_dirmngr_lookup (ctrl, names, NULL, 0, list_external_cb, &parm);
  if (gpg_err_code (rc) == GPG_ERR_EOF || rc == -1
      || gpg_err_code (rc) == GPG_ERR_NOT_FOUND)
    rc = 0; /* "Not found" is not an error here. */
  if (rc)
    log_error ("listing external keys failed: %s\n", gpg_strerror (rc));
  return rc;
}

/* List all keys or just the key given as NAMES.
   MODE controls the operation mode:
    Bit 0-2:
      0 = list all public keys but don't flag secret ones
      1 = list only public keys
      2 = list only secret keys
      3 = list secret and public keys
    Bit 6: list internal keys
    Bit 7: list external keys
    Bit 8: Do a raw format dump.
 */
gpg_error_t
gpgsm_list_keys (ctrl_t ctrl, strlist_t names, estream_t fp,
                 unsigned int mode)
{
  gpg_error_t err = 0;

  if ((mode & (1<<6)))
    err = list_internal_keys (ctrl, names, fp, (mode & 3), (mode&256));
  if (!err && (mode & (1<<7)))
    err = list_external_keys (ctrl, names, fp, (mode&256));
  return err;
}
