/* keylist.c - Print certificates in various formats.
 * Copyright (C) 1998, 1999, 2000, 2001, 2003,
 *               2004, 2005 Free Software Foundation, Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
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
#include "i18n.h"

struct list_external_parm_s {
  ctrl_t ctrl;
  FILE *fp;
  int print_header;
  int with_colons;
  int with_chain;
  int raw_mode;
};


/* This table is to map Extended Key Usage OIDs to human readable
   names.  */
struct {
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


/* A table mapping OIDs to a descriptive string. */
static struct {
  char *oid;
  char *name;
  unsigned int flag;
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
  { "2.5.29.14", "subjectKeyIdentifier", 1},
  { "2.5.29.15", "keyUsage", 1 },
  { "2.5.29.16", "privateKeyUsagePeriod" },
  { "2.5.29.17", "subjectAltName", 1 },
  { "2.5.29.18", "issuerAltName", 1 },
  { "2.5.29.19", "basicConstraints", 1},
  { "2.5.29.20", "cRLNumber" },
  { "2.5.29.21", "cRLReason" },
  { "2.5.29.22", "expirationDate" },
  { "2.5.29.23", "instructionCode" }, 
  { "2.5.29.24", "invalidityDate" },
  { "2.5.29.27", "deltaCRLIndicator" },
  { "2.5.29.28", "issuingDistributionPoint" },
  { "2.5.29.29", "certificateIssuer" },
  { "2.5.29.30", "nameConstraints" },
  { "2.5.29.31", "cRLDistributionPoints", 1 },
  { "2.5.29.32", "certificatePolicies", 1 },
  { "2.5.29.32.0", "anyPolicy" },
  { "2.5.29.33", "policyMappings" },
  { "2.5.29.35", "authorityKeyIdentifier", 1 },
  { "2.5.29.36", "policyConstraints" },
  { "2.5.29.37", "extKeyUsage", 1 },
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
print_key_data (ksba_cert_t cert, FILE *fp)
{
#if 0  
  int n = pk ? pubkey_get_npkey( pk->pubkey_algo ) : 0;
  int i;

  for(i=0; i < n; i++ ) 
    {
      fprintf (fp, "pkd:%d:%u:", i, mpi_get_nbits( pk->pkey[i] ) );
      mpi_print(stdout, pk->pkey[i], 1 );
      putchar(':');
      putchar('\n');
    }
#endif
}

static void
print_capabilities (ksba_cert_t cert, FILE *fp)
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
        putc ('q', fp);
    }    
  else if (gpg_err_code (err) == GPG_ERR_NOT_FOUND)
    ; /* Don't know - will not get marked as 'q' */
  else
    log_debug ("get_user_data(is_qualified) failed: %s\n",
               gpg_strerror (err)); 

  err = ksba_cert_get_key_usage (cert, &use);
  if (gpg_err_code (err) == GPG_ERR_NO_DATA)
    {
      putc ('e', fp);
      putc ('s', fp);
      putc ('c', fp);
      putc ('E', fp);
      putc ('S', fp);
      putc ('C', fp);
      return;
    }
  if (err)
    { 
      log_error (_("error getting key usage information: %s\n"),
                 gpg_strerror (err));
      return;
    } 

  if ((use & (KSBA_KEYUSAGE_KEY_ENCIPHERMENT|KSBA_KEYUSAGE_DATA_ENCIPHERMENT)))
    putc ('e', fp);
  if ((use & (KSBA_KEYUSAGE_DIGITAL_SIGNATURE|KSBA_KEYUSAGE_NON_REPUDIATION)))
    putc ('s', fp);
  if ((use & KSBA_KEYUSAGE_KEY_CERT_SIGN))
    putc ('c', fp);
  if ((use & (KSBA_KEYUSAGE_KEY_ENCIPHERMENT|KSBA_KEYUSAGE_DATA_ENCIPHERMENT)))
    putc ('E', fp);
  if ((use & (KSBA_KEYUSAGE_DIGITAL_SIGNATURE|KSBA_KEYUSAGE_NON_REPUDIATION)))
    putc ('S', fp);
  if ((use & KSBA_KEYUSAGE_KEY_CERT_SIGN))
    putc ('C', fp);
}


static void
print_time (gnupg_isotime_t t, FILE *fp)
{
  if (!t || !*t)
    ;
  else 
    fputs (t, fp);
}


/* Return an allocated string with the email address extracted from a
   DN */
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
     openSSL generated keys get a nicer and usable listing */
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




/* List one certificate in colon mode */
static void
list_cert_colon (ctrl_t ctrl, ksba_cert_t cert, unsigned int validity,
                 FILE *fp, int have_secret)
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

  if (ctrl->with_validation)
    valerr = gpgsm_validate_chain (ctrl, cert, NULL, 1, NULL, 0);
  else
    valerr = 0;


  /* We need to get the fingerprint and the chaining ID in advance. */
  fpr = gpgsm_get_fingerprint_hexstring (cert, GCRY_MD_SHA1);
  {
    ksba_cert_t next;

    rc = gpgsm_walk_cert_chain (cert, &next);
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


  fputs (have_secret? "crs:":"crt:", fp);

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
        *truststring = 'i';
    }

  /* Is we have no truststring yet (i.e. the certificate might be
     good) and this is a root certificate, we ask the agent whether
     this is a trusted root certificate. */
  if (!*truststring && is_root)
    {
      rc = gpgsm_agent_istrusted (ctrl, cert);
      if (!rc)
        *truststring = 'u';  /* Yes, we trust this one (ultimately). */
      else if (gpg_err_code (rc) == GPG_ERR_NOT_TRUSTED)
        *truststring = 'n';  /* No, we do not trust this one. */
      /* (in case of an error we can't tell anything.) */
    }
  
  if (*truststring)
    fputs (truststring, fp);

  algo = gpgsm_get_key_algo_info (cert, &nbits);
  fprintf (fp, ":%u:%d:%s:", nbits, algo, fpr+24);

  /* We assume --fixed-list-mode for gpgsm */
  ksba_cert_get_validity (cert, 0, t);
  print_time (t, fp);
  putc (':', fp);
  ksba_cert_get_validity (cert, 1, t);
  print_time ( t, fp);
  putc (':', fp);
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
              fprintf (fp,"%02X", *s);
        }
      xfree (sexp);
    }
  putc (':', fp);
  /* Field 9, ownertrust - not used here */
  putc (':', fp);
  /* field 10, old user ID - we use it here for the issuer DN */
  if ((p = ksba_cert_get_issuer (cert,0)))
    {
      print_sanitized_string (fp, p, ':');
      xfree (p);
    }
  putc (':', fp);
  /* Field 11, signature class - not used */ 
  putc (':', fp);
  /* Field 12, capabilities: */ 
  print_capabilities (cert, fp);
  putc (':', fp);
  putc ('\n', fp);

  /* FPR record */
  fprintf (fp, "fpr:::::::::%s:::", fpr);
  /* Print chaining ID (field 13)*/
  if (chain_id)
    fputs (chain_id, fp);
  putc (':', fp);
  putc ('\n', fp);
  xfree (fpr); fpr = NULL; chain_id = NULL;
  xfree (chain_id_buffer); chain_id_buffer = NULL;

  if (opt.with_key_data)
    {
      if ( (p = gpgsm_get_keygrip_hexstring (cert)))
        {
          fprintf (fp, "grp:::::::::%s:\n", p);
          xfree (p);
        }
      print_key_data (cert, fp);
    }

  for (idx=0; (p = ksba_cert_get_subject (cert,idx)); idx++)
    {
      fprintf (fp, "uid:%s::::::::", truststring);
      print_sanitized_string (fp, p, ':');
      putc (':', fp);
      putc (':', fp);
      putc ('\n', fp);
      if (!idx)
        {
          /* It would be better to get the faked email address from
             the keydb.  But as long as we don't have a way to pass
             the meta data back, we just check it the same way as the
             code used to create the keybox meta data does */
          char *pp = email_kludge (p);
          if (pp)
            {
              fprintf (fp, "uid:%s::::::::", truststring);
              print_sanitized_string (fp, pp, ':');
              putc (':', fp);
              putc (':', fp);
              putc ('\n', fp);
              xfree (pp);
            }
        }
      xfree (p);
    }
}


static void
print_name_raw (FILE *fp, const char *string)
{
  if (!string)
    fputs ("[error]", fp);
  else
    print_sanitized_string (fp, string, 0);
}

static void
print_names_raw (FILE *fp, int indent, ksba_name_t name)
{
  int idx;
  const char *s;
  int indent_all;

  if ((indent_all = (indent < 0)))
    indent = - indent;

  if (!name)
    {
      fputs ("none\n", fp);
      return;
    }
  
  for (idx=0; (s = ksba_name_enum (name, idx)); idx++)
    {
      char *p = ksba_name_get_uri (name, idx);
      printf ("%*s", idx||indent_all?indent:0, "");
      print_sanitized_string (fp, p?p:s, 0);
      putc ('\n', fp);
      xfree (p);
    }
}


/* List one certificate in raw mode useful to have a closer look at
   the certificate.  This one does no beautification and only minimal
   output sanitation.  It is mainly useful for debugging. */
static void
list_cert_raw (ctrl_t ctrl, KEYDB_HANDLE hd,
               ksba_cert_t cert, FILE *fp, int have_secret,
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

  sexp = ksba_cert_get_serial (cert);
  fputs ("Serial number: ", fp);
  gpgsm_print_serial (fp, sexp);
  ksba_free (sexp);
  putc ('\n', fp);

  dn = ksba_cert_get_issuer (cert, 0);
  fputs ("       Issuer: ", fp);
  print_name_raw (fp, dn);
  ksba_free (dn);
  putc ('\n', fp);
  for (idx=1; (dn = ksba_cert_get_issuer (cert, idx)); idx++)
    {
      fputs ("          aka: ", fp);
      print_name_raw (fp, dn);
      ksba_free (dn);
      putc ('\n', fp);
    }

  dn = ksba_cert_get_subject (cert, 0);
  fputs ("      Subject: ", fp);
  print_name_raw (fp, dn);
  ksba_free (dn);
  putc ('\n', fp);
  for (idx=1; (dn = ksba_cert_get_subject (cert, idx)); idx++)
    {
      fputs ("          aka: ", fp);
      print_name_raw (fp, dn);
      ksba_free (dn);
      putc ('\n', fp);
    }

  dn = gpgsm_get_fingerprint_string (cert, 0);
  fprintf (fp, "     sha1_fpr: %s\n", dn?dn:"error");
  xfree (dn);

  dn = gpgsm_get_fingerprint_string (cert, GCRY_MD_MD5);
  fprintf (fp, "      md5_fpr: %s\n", dn?dn:"error");
  xfree (dn);

  dn = gpgsm_get_certid (cert);
  fprintf (fp, "       certid: %s\n", dn?dn:"error");
  xfree (dn);

  dn = gpgsm_get_keygrip_hexstring (cert);
  fprintf (fp, "      keygrip: %s\n", dn?dn:"error");
  xfree (dn);

  ksba_cert_get_validity (cert, 0, t);
  fputs ("    notBefore: ", fp);
  gpgsm_print_time (fp, t);
  putc ('\n', fp);
  fputs ("     notAfter: ", fp);
  ksba_cert_get_validity (cert, 1, t);
  gpgsm_print_time (fp, t);
  putc ('\n', fp);

  oid = ksba_cert_get_digest_algo (cert);
  s = get_oid_desc (oid, NULL);
  fprintf (fp, "     hashAlgo: %s%s%s%s\n", oid, s?" (":"",s?s:"",s?")":"");

  {
    const char *algoname;
    unsigned int nbits;

    algoname = gcry_pk_algo_name (gpgsm_get_key_algo_info (cert, &nbits));
    fprintf (fp, "      keyType: %u bit %s\n",  nbits, algoname? algoname:"?");
  }

  /* subjectKeyIdentifier */
  fputs ("    subjKeyId: ", fp);
  err = ksba_cert_get_subj_key_id (cert, NULL, &keyid);
  if (!err || gpg_err_code (err) == GPG_ERR_NO_DATA)
    {
      if (gpg_err_code (err) == GPG_ERR_NO_DATA)
        fputs ("[none]\n", fp);
      else
        {
          gpgsm_print_serial (fp, keyid);
          ksba_free (keyid);
          putc ('\n', fp);
        }
    }
  else
    fputs ("[?]\n", fp);


  /* authorityKeyIdentifier */
  fputs ("    authKeyId: ", fp);
  err = ksba_cert_get_auth_key_id (cert, &keyid, &name, &sexp);
  if (!err || gpg_err_code (err) == GPG_ERR_NO_DATA)
    {
      if (gpg_err_code (err) == GPG_ERR_NO_DATA || !name)
        fputs ("[none]\n", fp);
      else
        {
          gpgsm_print_serial (fp, sexp);
          ksba_free (sexp);
          putc ('\n', fp);
          print_names_raw (fp, -15, name);
          ksba_name_release (name);
        }
      if (keyid)
        {
          fputs (" authKeyId.ki: ", fp);
          gpgsm_print_serial (fp, keyid);
          ksba_free (keyid);
          putc ('\n', fp);
        }
    }
  else
    fputs ("[?]\n", fp);

  fputs ("     keyUsage: ", fp);
  err = ksba_cert_get_key_usage (cert, &kusage);
  if (gpg_err_code (err) != GPG_ERR_NO_DATA)
    {
      if (err)
        fprintf (fp, " [error: %s]", gpg_strerror (err));
      else
        {
          if ( (kusage & KSBA_KEYUSAGE_DIGITAL_SIGNATURE))
            fputs (" digitalSignature", fp);
          if ( (kusage & KSBA_KEYUSAGE_NON_REPUDIATION))  
            fputs (" nonRepudiation", fp);
          if ( (kusage & KSBA_KEYUSAGE_KEY_ENCIPHERMENT)) 
            fputs (" keyEncipherment", fp);
          if ( (kusage & KSBA_KEYUSAGE_DATA_ENCIPHERMENT))
            fputs (" dataEncipherment", fp);
          if ( (kusage & KSBA_KEYUSAGE_KEY_AGREEMENT))    
            fputs (" keyAgreement", fp);
          if ( (kusage & KSBA_KEYUSAGE_KEY_CERT_SIGN))
            fputs (" certSign", fp);
          if ( (kusage & KSBA_KEYUSAGE_CRL_SIGN))  
            fputs (" crlSign", fp);
          if ( (kusage & KSBA_KEYUSAGE_ENCIPHER_ONLY))
            fputs (" encipherOnly", fp);
          if ( (kusage & KSBA_KEYUSAGE_DECIPHER_ONLY))  
            fputs (" decipherOnly", fp);
        }
      putc ('\n', fp);
    }
  else
    fputs ("[none]\n", fp);

  fputs ("  extKeyUsage: ", fp);
  err = ksba_cert_get_ext_key_usages (cert, &string);
  if (gpg_err_code (err) != GPG_ERR_NO_DATA)
    { 
      if (err)
        fprintf (fp, "[error: %s]", gpg_strerror (err));
      else
        {
          p = string;
          while (p && (pend=strchr (p, ':')))
            {
              *pend++ = 0;
              for (i=0; key_purpose_map[i].oid; i++)
                if ( !strcmp (key_purpose_map[i].oid, p) )
                  break;
              fputs (key_purpose_map[i].oid?key_purpose_map[i].name:p, fp);
              p = pend;
              if (*p != 'C')
                fputs (" (suggested)", fp);
              if ((p = strchr (p, '\n')))
                {
                  p++;
                  fputs ("\n               ", fp);
                }
            }
          xfree (string);
        }
      putc ('\n', fp);
    }
  else
    fputs ("[none]\n", fp);


  fputs ("     policies: ", fp);
  err = ksba_cert_get_cert_policies (cert, &string);
  if (gpg_err_code (err) != GPG_ERR_NO_DATA)
    {
      if (err)
        fprintf (fp, "[error: %s]", gpg_strerror (err));
      else
        {
          p = string;
          while (p && (pend=strchr (p, ':')))
            {
              *pend++ = 0;
              for (i=0; key_purpose_map[i].oid; i++)
                if ( !strcmp (key_purpose_map[i].oid, p) )
                  break;
              fputs (p, fp);
              p = pend;
              if (*p == 'C')
                fputs (" (critical)", fp);
              if ((p = strchr (p, '\n')))
                {
                  p++;
                  fputs ("\n               ", fp);
                }
            }
          xfree (string);
        }
      putc ('\n', fp);
    }
  else
    fputs ("[none]\n", fp);

  fputs ("  chainLength: ", fp);
  err = ksba_cert_is_ca (cert, &is_ca, &chainlen);
  if (err || is_ca)
    {
      if (err)
        fprintf (fp, "[error: %s]", gpg_strerror (err));
      else if (chainlen == -1)
        fputs ("unlimited", fp);
      else
        fprintf (fp, "%d", chainlen);
      putc ('\n', fp);
    }
  else
    fputs ("not a CA\n", fp);


  /* CRL distribution point */
  for (idx=0; !(err=ksba_cert_get_crl_dist_point (cert, idx, &name, &name2,
                                                  &reason)) ;idx++)
    {
      fputs ("        crlDP: ", fp);
      print_names_raw (fp, 15, name);
      if (reason)
        {
          fputs ("               reason: ", fp);
          if ( (reason & KSBA_CRLREASON_UNSPECIFIED))
            fputs (" unused", stdout);
          if ( (reason & KSBA_CRLREASON_KEY_COMPROMISE))
            fputs (" keyCompromise", stdout);
          if ( (reason & KSBA_CRLREASON_CA_COMPROMISE))
            fputs (" caCompromise", stdout);
          if ( (reason & KSBA_CRLREASON_AFFILIATION_CHANGED))
            fputs (" affiliationChanged", stdout);
          if ( (reason & KSBA_CRLREASON_SUPERSEDED))
            fputs (" superseded", stdout);
          if ( (reason & KSBA_CRLREASON_CESSATION_OF_OPERATION))
            fputs (" cessationOfOperation", stdout);
          if ( (reason & KSBA_CRLREASON_CERTIFICATE_HOLD))
            fputs (" certificateHold", stdout);
          putchar ('\n');
        }
      fputs ("               issuer: ", fp);
      print_names_raw (fp, 23, name2);
      ksba_name_release (name);
      ksba_name_release (name2);
    }
  if (err && gpg_err_code (err) != GPG_ERR_EOF)
    fputs ("        crlDP: [error]\n", fp);
  else if (!idx)
    fputs ("        crlDP: [none]\n", fp);


  /* authorityInfoAccess. */
  for (idx=0; !(err=ksba_cert_get_authority_info_access (cert, idx, &string,
                                                         &name)); idx++)
    {
      fputs ("     authInfo: ", fp);
      s = get_oid_desc (string, NULL);
      fprintf (fp, "%s%s%s%s\n", string, s?" (":"", s?s:"", s?")":"");
      print_names_raw (fp, -15, name);
      ksba_name_release (name);
      ksba_free (string);
    }
  if (err && gpg_err_code (err) != GPG_ERR_EOF)
    fputs ("     authInfo: [error]\n", fp);
  else if (!idx)
    fputs ("     authInfo: [none]\n", fp);

  /* subjectInfoAccess. */
  for (idx=0; !(err=ksba_cert_get_subject_info_access (cert, idx, &string,
                                                         &name)); idx++)
    {
      fputs ("  subjectInfo: ", fp);
      s = get_oid_desc (string, NULL);
      fprintf (fp, "%s%s%s%s\n", string, s?" (":"", s?s:"", s?")":"");
      print_names_raw (fp, -15, name);
      ksba_name_release (name);
      ksba_free (string);
    }
  if (err && gpg_err_code (err) != GPG_ERR_EOF)
    fputs ("     subjInfo: [error]\n", fp);
  else if (!idx)
    fputs ("     subjInfo: [none]\n", fp);


  for (idx=0; !(err=ksba_cert_get_extension (cert, idx,
                                             &oid, &i, &off, &len));idx++)
    {
      unsigned int flag;

      s = get_oid_desc (oid, &flag);

      if (!(flag & 1))
        fprintf (fp, "     %s: %s%s%s%s  [%d octets]\n",
                 i? "critExtn":"    extn",
                 oid, s?" (":"", s?s:"", s?")":"", (int)len);
    }


  if (with_validation)
    {
      err = gpgsm_validate_chain (ctrl, cert, NULL, 1, fp, 0);
      if (!err)
        fprintf (fp, "  [certificate is good]\n");
      else
        fprintf (fp, "  [certificate is bad: %s]\n", gpg_strerror (err));
    }

  if (opt.with_ephemeral_keys && hd)
    {
      unsigned int blobflags;

      err = keydb_get_flags (hd, KEYBOX_FLAG_BLOB, 0, &blobflags);
      if (err)
        fprintf (fp, "  [error getting keyflags: %s]\n", gpg_strerror (err));
      else if ((blobflags & 2))
        fprintf (fp, "  [stored as ephemeral]\n");
    }

}




/* List one certificate in standard mode */
static void
list_cert_std (ctrl_t ctrl, ksba_cert_t cert, FILE *fp, int have_secret,
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

  sexp = ksba_cert_get_serial (cert);
  fputs ("Serial number: ", fp);
  gpgsm_print_serial (fp, sexp);
  ksba_free (sexp);
  putc ('\n', fp);

  dn = ksba_cert_get_issuer (cert, 0);
  fputs ("       Issuer: ", fp);
  gpgsm_print_name (fp, dn);
  ksba_free (dn);
  putc ('\n', fp);
  for (idx=1; (dn = ksba_cert_get_issuer (cert, idx)); idx++)
    {
      fputs ("          aka: ", fp);
      gpgsm_print_name (fp, dn);
      ksba_free (dn);
      putc ('\n', fp);
    }

  dn = ksba_cert_get_subject (cert, 0);
  fputs ("      Subject: ", fp);
  gpgsm_print_name (fp, dn);
  ksba_free (dn);
  putc ('\n', fp);
  for (idx=1; (dn = ksba_cert_get_subject (cert, idx)); idx++)
    {
      fputs ("          aka: ", fp);
      gpgsm_print_name (fp, dn);
      ksba_free (dn);
      putc ('\n', fp);
    }

  ksba_cert_get_validity (cert, 0, t);
  fputs ("     validity: ", fp);
  gpgsm_print_time (fp, t);
  fputs (" through ", fp);
  ksba_cert_get_validity (cert, 1, t);
  gpgsm_print_time (fp, t);
  putc ('\n', fp);


  {
    const char *algoname;
    unsigned int nbits;

    algoname = gcry_pk_algo_name (gpgsm_get_key_algo_info (cert, &nbits));
    fprintf (fp, "     key type: %u bit %s\n", nbits, algoname? algoname:"?");
  }


  err = ksba_cert_get_key_usage (cert, &kusage);
  if (gpg_err_code (err) != GPG_ERR_NO_DATA)
    {
      fputs ("    key usage:", fp);
      if (err)
        fprintf (fp, " [error: %s]", gpg_strerror (err));
      else
        {
          if ( (kusage & KSBA_KEYUSAGE_DIGITAL_SIGNATURE))
            fputs (" digitalSignature", fp);
          if ( (kusage & KSBA_KEYUSAGE_NON_REPUDIATION))  
            fputs (" nonRepudiation", fp);
          if ( (kusage & KSBA_KEYUSAGE_KEY_ENCIPHERMENT)) 
            fputs (" keyEncipherment", fp);
          if ( (kusage & KSBA_KEYUSAGE_DATA_ENCIPHERMENT))
            fputs (" dataEncipherment", fp);
          if ( (kusage & KSBA_KEYUSAGE_KEY_AGREEMENT))    
            fputs (" keyAgreement", fp);
          if ( (kusage & KSBA_KEYUSAGE_KEY_CERT_SIGN))
            fputs (" certSign", fp);
          if ( (kusage & KSBA_KEYUSAGE_CRL_SIGN))  
            fputs (" crlSign", fp);
          if ( (kusage & KSBA_KEYUSAGE_ENCIPHER_ONLY))
            fputs (" encipherOnly", fp);
          if ( (kusage & KSBA_KEYUSAGE_DECIPHER_ONLY))  
            fputs (" decipherOnly", fp);
        }
      putc ('\n', fp);
    }

  err = ksba_cert_get_ext_key_usages (cert, &string);
  if (gpg_err_code (err) != GPG_ERR_NO_DATA)
    { 
      fputs ("ext key usage: ", fp);
      if (err)
        fprintf (fp, "[error: %s]", gpg_strerror (err));
      else
        {
          p = string;
          while (p && (pend=strchr (p, ':')))
            {
              *pend++ = 0;
              for (i=0; key_purpose_map[i].oid; i++)
                if ( !strcmp (key_purpose_map[i].oid, p) )
                  break;
              fputs (key_purpose_map[i].oid?key_purpose_map[i].name:p, fp);
              p = pend;
              if (*p != 'C')
                fputs (" (suggested)", fp);
              if ((p = strchr (p, '\n')))
                {
                  p++;
                  fputs (", ", fp);
                }
            }
          xfree (string);
        }
      putc ('\n', fp);
    }

  err = ksba_cert_get_cert_policies (cert, &string);
  if (gpg_err_code (err) != GPG_ERR_NO_DATA)
    {
      fputs ("     policies: ", fp);
      if (err)
        fprintf (fp, "[error: %s]", gpg_strerror (err));
      else
        {
          for (p=string; *p; p++)
            {
              if (*p == '\n')
                *p = ',';
            }
          print_sanitized_string (fp, string, 0);
          xfree (string);
        }
      putc ('\n', fp);
    }

  err = ksba_cert_is_ca (cert, &is_ca, &chainlen);
  if (err || is_ca)
    {
      fputs (" chain length: ", fp);
      if (err)
        fprintf (fp, "[error: %s]", gpg_strerror (err));
      else if (chainlen == -1)
        fputs ("unlimited", fp);
      else
        fprintf (fp, "%d", chainlen);
      putc ('\n', fp);
    }

  if (opt.with_md5_fingerprint)
    {
      dn = gpgsm_get_fingerprint_string (cert, GCRY_MD_MD5);
      fprintf (fp, "      md5 fpr: %s\n", dn?dn:"error");
      xfree (dn);
    }

  dn = gpgsm_get_fingerprint_string (cert, 0);
  fprintf (fp, "  fingerprint: %s\n", dn?dn:"error");
  xfree (dn);



  if (with_validation)
    {
      gpg_error_t tmperr;
      size_t buflen;
      char buffer[1];
      
      err = gpgsm_validate_chain (ctrl, cert, NULL, 1, fp, 0);
      tmperr = ksba_cert_get_user_data (cert, "is_qualified", 
                                        &buffer, sizeof (buffer), &buflen);
      if (!tmperr && buflen)
        {
          if (*buffer)
            fputs ("  [qualified]\n", fp);
        }    
      else if (gpg_err_code (tmperr) == GPG_ERR_NOT_FOUND)
        ; /* Don't know - will not get marked as 'q' */
      else
        log_debug ("get_user_data(is_qualified) failed: %s\n",
                   gpg_strerror (tmperr)); 

      if (!err)
        fprintf (fp, "  [certificate is good]\n");
      else
        fprintf (fp, "  [certificate is bad: %s]\n", gpg_strerror (err));
    }
}


/* Same as standard mode mode list all certifying certs too. */
static void
list_cert_chain (ctrl_t ctrl, KEYDB_HANDLE hd,
                 ksba_cert_t cert, int raw_mode,
                 FILE *fp, int with_validation)
{
  ksba_cert_t next = NULL;

  if (raw_mode)
    list_cert_raw (ctrl, hd, cert, fp, 0, with_validation);
  else
    list_cert_std (ctrl, cert, fp, 0, with_validation);
  ksba_cert_ref (cert);
  while (!gpgsm_walk_cert_chain (cert, &next))
    {
      ksba_cert_release (cert);
      fputs ("Certified by\n", fp);
      if (raw_mode)
        list_cert_raw (ctrl, hd, next, fp, 0, with_validation);
      else
        list_cert_std (ctrl, next, fp, 0, with_validation);
      cert = next;
    }
  ksba_cert_release (cert);
  putc ('\n', fp);
}



/* List all internal keys or just the keys given as NAMES.  MODE is a
   bit vector to specify what keys are to be included; see
   gpgsm_list_keys (below) for details.  If RAW_MODE is true, the raw
   output mode will be used intead of the standard beautified one.
 */
static gpg_error_t
list_internal_keys (ctrl_t ctrl, STRLIST names, FILE *fp,
                    unsigned int mode, int raw_mode)
{
  KEYDB_HANDLE hd;
  KEYDB_SEARCH_DESC *desc = NULL;
  STRLIST sl;
  int ndesc;
  ksba_cert_t cert = NULL;
  gpg_error_t rc = 0;
  const char *lastresname, *resname;
  int have_secret;

  hd = keydb_new (0);
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
      rc = gpg_error_from_errno (errno);
      log_error ("out of core\n");
      goto leave;
    }

  if (!names)
    desc[0].mode = KEYDB_SEARCH_MODE_FIRST;
  else 
    {
      for (ndesc=0, sl=names; sl; sl = sl->next) 
        {
          rc = keydb_classify_name (sl->d, desc+ndesc);
          if (rc)
            {
              log_error ("key `%s' not found: %s\n",
                         sl->d, gpg_strerror (rc));
              rc = 0;
            }
          else
            ndesc++;
        }
      
    }

  if (opt.with_ephemeral_keys)
    keydb_set_ephemeral (hd, 1);

  /* It would be nice to see which of the given users did actually
     match one in the keyring.  To implement this we need to have a
     found flag for each entry in desc and to set this we must check
     all those entries after a match to mark all matched one -
     currently we stop at the first match.  To do this we need an
     extra flag to enable this feature so */

  lastresname = NULL;
  while (!(rc = keydb_search (hd, desc, ndesc)))
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
      
      resname = keydb_get_resource_name (hd);
      
      if (lastresname != resname ) 
        {
          int i;
          
          if (ctrl->no_server)
            {
              fprintf (fp, "%s\n", resname );
              for (i=strlen(resname); i; i-- )
                putchar('-');
              putc ('\n', fp);
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

      if (!mode
          || ((mode & 1) && !have_secret)
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
              putc ('\n', fp);
            }
        }
      ksba_cert_release (cert); 
      cert = NULL;
    }
  if (gpg_err_code (rc) == GPG_ERR_EOF || rc == -1 )
    rc = 0;
  if (rc)
    log_error ("keydb_search failed: %s\n", gpg_strerror (rc));
  
 leave:
  ksba_cert_release (cert);
  xfree (desc);
  keydb_release (hd);
  return rc;
}



static void
list_external_cb (void *cb_value, ksba_cert_t cert)
{
  struct list_external_parm_s *parm = cb_value;

  if (keydb_store_cert (cert, 1, NULL))
    log_error ("error storing certificate as ephemeral\n");

  if (parm->print_header)
    {
      const char *resname = "[external keys]";
      int i;

      fprintf (parm->fp, "%s\n", resname );
      for (i=strlen(resname); i; i-- )
        putchar('-');
      putc ('\n', parm->fp);
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
      putc ('\n', parm->fp);
    }
}


/* List external keys similar to internal one.  Note: mode does not
   make sense here because it would be unwise to list external secret
   keys */
static gpg_error_t
list_external_keys (ctrl_t ctrl, STRLIST names, FILE *fp, int raw_mode)
{
  int rc;
  struct list_external_parm_s parm;

  parm.fp = fp;
  parm.ctrl = ctrl,
  parm.print_header = ctrl->no_server;
  parm.with_colons = ctrl->with_colons;
  parm.with_chain = ctrl->with_chain;
  parm.raw_mode  = raw_mode;

  rc = gpgsm_dirmngr_lookup (ctrl, names, list_external_cb, &parm);
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
gpgsm_list_keys (ctrl_t ctrl, STRLIST names, FILE *fp, unsigned int mode)
{
  gpg_error_t err = 0;

  if ((mode & (1<<6)))
    err = list_internal_keys (ctrl, names, fp, (mode & 3), (mode&256));
  if (!err && (mode & (1<<7)))
    err = list_external_keys (ctrl, names, fp, (mode&256)); 
  return err;
}
