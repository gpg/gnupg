/* keylist.c
 * Copyright (C) 1998, 1999, 2000, 2001, 2003 Free Software Foundation, Inc.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
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
  FILE *fp;
  int print_header;
  int with_colons;
  int with_chain;
};



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


/* return an allocated string with the email address extracted from a
   DN */
static char *
email_kludge (const char *name)
{
  const unsigned char *p;
  unsigned char *buf;
  int n;

  if (strncmp (name, "1.2.840.113549.1.9.1=#", 22))
    return NULL;
  /* This looks pretty much like an email address in the subject's DN
     we use this to add an additional user ID entry.  This way,
     openSSL generated keys get a nicer and usable listing */
  name += 22;    
  for (n=0, p=name; hexdigitp (p) && hexdigitp (p+1); p +=2, n++)
    ;
  if (*p != '#' || !n)
    return NULL;
  buf = xtrymalloc (n+3);
  if (!buf)
    return NULL; /* oops, out of core */
  *buf = '<';
  for (n=1, p=name; *p != '#'; p +=2, n++)
    buf[n] = xtoi_2 (p);
  buf[n++] = '>';
  buf[n] = 0;
  return buf;
}




/* List one certificate in colon mode */
static void
list_cert_colon (ksba_cert_t cert, unsigned int validity,
                 FILE *fp, int have_secret)
{
  int idx, trustletter = 0;
  char *p;
  ksba_sexp_t sexp;
  char *fpr;
  ksba_isotime_t t;

  fputs (have_secret? "crs:":"crt:", fp);
  trustletter = 0;
  if ((validity & VALIDITY_REVOKED))
    trustletter = 'r';
#if 0
  else if (is_not_valid (cert))
    putc ('i', fp);
  else if ( has_expired (cert))
    putcr ('e', fp);
#endif
  else
    trustletter = '?';
  putc (trustletter, fp);

  fpr = gpgsm_get_fingerprint_hexstring (cert, GCRY_MD_SHA1);
  fprintf (fp, ":%u:%d:%s:",
           /*keylen_of_cert (cert)*/1024,
           /* pubkey_algo_of_cert (cert)*/1,
           fpr+24);

  /* we assume --fixed-list-mode for gpgsm */
  ksba_cert_get_validity (cert, 0, t);
  print_time (t, fp);
  putc (':', fp);
  ksba_cert_get_validity (cert, 1, t);
  print_time ( t, fp);
  putc (':', fp);
  /* field 8, serial number: */
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
  /* field 9, ownertrust - not used here */
  putc (':', fp);
  /* field 10, old user ID - we use it here for the issuer DN */
  if ((p = ksba_cert_get_issuer (cert,0)))
    {
      print_sanitized_string (fp, p, ':');
      xfree (p);
    }
  putc (':', fp);
  /* field 11, signature class - not used */ 
  putc (':', fp);
  /* field 12, capabilities: */ 
  print_capabilities (cert, fp);
  putc (':', fp);
  putc ('\n', fp);

  /* FPR record */
  fprintf (fp, "fpr:::::::::%s:::", fpr);
  xfree (fpr); fpr = NULL;
  /* print chaining ID (field 13)*/
  {
    ksba_cert_t next;
    
    if (!gpgsm_walk_cert_chain (cert, &next))
      {
        p = gpgsm_get_fingerprint_hexstring (next, GCRY_MD_SHA1);
        fputs (p, fp);
        xfree (p);
        ksba_cert_release (next);
      }
  }
  putc (':', fp);
  putc ('\n', fp);


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
      fprintf (fp, "uid:%c::::::::", trustletter);
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
              fprintf (fp, "uid:%c::::::::", trustletter);
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


/* List one certificate in standard mode */
static void
list_cert_std (ksba_cert_t cert, FILE *fp, int have_secret)
{
  gpg_error_t kerr;
  ksba_sexp_t sexp;
  char *dn;
  ksba_isotime_t t;
  int idx;
  int is_ca, chainlen;
  unsigned int kusage;
  char *string, *p;

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

  kerr = ksba_cert_get_key_usage (cert, &kusage);
  if (gpg_err_code (kerr) != GPG_ERR_NO_DATA)
    {
      fputs ("    key usage:", fp);
      if (kerr)
        fprintf (fp, " [error: %s]", gpg_strerror (kerr));
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

  kerr = ksba_cert_get_cert_policies (cert, &string);
  if (gpg_err_code (kerr) != GPG_ERR_NO_DATA)
    {
      fputs ("     policies: ", fp);
      if (kerr)
        fprintf (fp, "[error: %s]", gpg_strerror (kerr));
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

  kerr = ksba_cert_is_ca (cert, &is_ca, &chainlen);
  if (kerr || is_ca)
    {
      fputs (" chain length: ", fp);
      if (kerr)
        fprintf (fp, "[error: %s]", gpg_strerror (kerr));
      else if (chainlen == -1)
        fputs ("unlimited", fp);
      else
        fprintf (fp, "%d", chainlen);
      putc ('\n', fp);
    }


  dn = gpgsm_get_fingerprint_string (cert, 0);
  fprintf (fp, "  fingerprint: %s\n", dn?dn:"error");
  xfree (dn);
}

/* Same as standard mode mode list all certifying certts too */
static void
list_cert_chain (ksba_cert_t cert, FILE *fp)
{
  ksba_cert_t next = NULL;

  list_cert_std (cert, fp, 0);
  ksba_cert_ref (cert);
  while (!gpgsm_walk_cert_chain (cert, &next))
    {
      ksba_cert_release (cert);
      fputs ("Certified by\n", fp);
      list_cert_std (next, fp, 0);
      cert = next;
    }
  ksba_cert_release (cert);
  putc ('\n', fp);
}



/* List all internal keys or just the key given as NAMES.
 */
static void
list_internal_keys (CTRL ctrl, STRLIST names, FILE *fp, unsigned int mode)
{
  KEYDB_HANDLE hd;
  KEYDB_SEARCH_DESC *desc = NULL;
  STRLIST sl;
  int ndesc;
  ksba_cert_t cert = NULL;
  int rc=0;
  const char *lastresname, *resname;
  int have_secret;

  hd = keydb_new (0);
  if (!hd)
    {
      log_error ("keydb_new failed\n");
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

  /* it would be nice to see which of the given users did actually
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
              if (!gpgsm_agent_havekey (p))
                have_secret = 1;
              xfree (p);
            }
        }

      if (!mode
          || ((mode & 1) && !have_secret)
          || ((mode & 2) && have_secret)  )
        {
          if (ctrl->with_colons)
            list_cert_colon (cert, validity, fp, have_secret);
          else if (ctrl->with_chain)
            list_cert_chain (cert, fp);
          else
            {
              list_cert_std (cert, fp, have_secret);
              putc ('\n', fp);
            }
        }
      ksba_cert_release (cert); 
      cert = NULL;
    }
  if (rc && rc != -1)
    log_error ("keydb_search failed: %s\n", gpg_strerror (rc));
  
 leave:
  ksba_cert_release (cert);
  xfree (desc);
  keydb_release (hd);
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
    list_cert_colon (cert, 0, parm->fp, 0);
  else if (parm->with_chain)
    list_cert_chain (cert, parm->fp);
  else
    {
      list_cert_std (cert, parm->fp, 0);
      putc ('\n', parm->fp);
    }
}


/* List external keys similar to internal one.  Note: mode does not
   make sense here because it would be unwise to list external secret
   keys */
static void
list_external_keys (CTRL ctrl, STRLIST names, FILE *fp)
{
  int rc;
  struct list_external_parm_s parm;

  parm.fp = fp;
  parm.print_header = ctrl->no_server;
  parm.with_colons = ctrl->with_colons;
  parm.with_chain = ctrl->with_chain;

  rc = gpgsm_dirmngr_lookup (ctrl, names, list_external_cb, &parm);
  if (rc)
    log_error ("listing external keys failed: %s\n", gpg_strerror (rc));
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
 */
void
gpgsm_list_keys (CTRL ctrl, STRLIST names, FILE *fp, unsigned int mode)
{
  if ((mode & (1<<6)))
      list_internal_keys (ctrl, names, fp, (mode & 3));
  if ((mode & (1<<7)))
      list_external_keys (ctrl, names, fp); 
}
