/* certreqgen.c - Generate a key and a certification request
 * Copyright (C) 2002, 2003, 2005, 2007 Free Software Foundation, Inc.
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

/*
The format of the native parameter file is follows:
  o Text only, line length is limited to about 1000 chars.
  o You must use UTF-8 encoding to specify non-ascii characters.
  o Empty lines are ignored.
  o Leading and trailing spaces are ignored.
  o A hash sign as the first non white space character is a comment line.
  o Control statements are indicated by a leading percent sign, the
    arguments are separated by white space from the keyword.
  o Parameters are specified by a keyword, followed by a colon.  Arguments
    are separated by white space.
  o The first parameter must be "Key-Type", control statements
    may be placed anywhere.
  o Key generation takes place when either the end of the parameter file
    is reached, the next "Key-Type" parameter is encountered or at the
    controlstatement "%commit"
  o Control statements:
    %echo <text>
	Print <text>.
    %dry-run
	Suppress actual key generation (useful for syntax checking).
    %commit
	Perform the key generation.  Note that an implicit commit is done
	at the next "Key-Type" parameter.
    %certfile <filename>
	Do not write the certificate to the keyDB but to <filename>.
        This must be given before the first
	commit to take place, duplicate specification of the same filename
	is ignored, the last filename before a commit is used.
	The filename is used until a new filename is used (at commit points)
	and all keys are written to that file.	If a new filename is given,
	this file is created (and overwrites an existing one).
	Both control statements must be given.
   o The order of the parameters does not matter except for "Key-Type"
     which must be the first parameter.  The parameters are only for the
     generated keyblock and parameters from previous key generations are not
     used. Some syntactically checks may be performed.
     The currently defined parameters are:
     Key-Type: <algo>
	Starts a new parameter block by giving the type of the
	primary key. The algorithm must be capable of signing.
	This is a required parameter.  For now the only supported
        algorithm is "rsa".
     Key-Length: <length-in-bits>
	Length of the key in bits.  Default is 2048.
     Key-Grip: hexstring
        This is optional and used to generate a request for an already
        existing key.  Key-Length will be ignored when given,
     Key-Usage: <usage-list>
        Space or comma delimited list of key usage, allowed values are
        "encrypt" and "sign".  This is used to generate the KeyUsage extension.
        Please make sure that the algorithm is capable of this usage.  Default
        is to allow encrypt and sign.
     Name-DN: subject name
        This is the DN name of the subject in rfc2253 format.
     Name-Email: <string>
	The is an email address for the altSubjectName
     Name-DNS: <string>
	The is an DNS name for the altSubjectName
     Name-URI: <string>
	The is an URI for the altSubjectName

Here is an example:
$ cat >foo <<EOF
%echo Generating a standard key
Key-Type: RSA
Key-Length: 2048
Name-DN: CN=test cert 1,OU=Aegypten Project,O=g10 Code GmbH,L=Düsseldorf,C=DE
Name-Email: joe@foo.bar
# Do a commit here, so that we can later print "done" :-)
%commit
%echo done
EOF
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
#include "i18n.h"


enum para_name {
  pKEYTYPE,
  pKEYLENGTH,
  pKEYGRIP,
  pKEYUSAGE,
  pNAMEDN,
  pNAMEEMAIL,
  pNAMEDNS,
  pNAMEURI
};

struct para_data_s {
  struct para_data_s *next;
  int lnr;
  enum para_name key;
  union {
    unsigned int usage;
    char value[1];
  } u;
};

struct reqgen_ctrl_s {
  int lnr;
  int dryrun;
  ksba_writer_t writer;
};


static const char oidstr_keyUsage[] = "2.5.29.15";


static int proc_parameters (ctrl_t ctrl,
                            struct para_data_s *para,
                            struct reqgen_ctrl_s *outctrl);
static int create_request (ctrl_t ctrl,
                           struct para_data_s *para,
                           const char *carddirect,
                           ksba_const_sexp_t public,
                           struct reqgen_ctrl_s *outctrl);



static void
release_parameter_list (struct para_data_s *r)
{
  struct para_data_s *r2;

  for (; r ; r = r2)
    {
      r2 = r->next;
      xfree(r);
    }
}

static struct para_data_s *
get_parameter (struct para_data_s *para, enum para_name key, int seq)
{
  struct para_data_s *r;

  for (r = para; r ; r = r->next)
    if ( r->key == key && !seq--)
      return r;
  return NULL;
}

static const char *
get_parameter_value (struct para_data_s *para, enum para_name key, int seq)
{
  struct para_data_s *r = get_parameter (para, key, seq);
  return (r && *r->u.value)? r->u.value : NULL;
}

static int
get_parameter_algo (struct para_data_s *para, enum para_name key)
{
  struct para_data_s *r = get_parameter (para, key, 0);
  if (!r)
    return -1;
  if (digitp (r->u.value))
    return atoi( r->u.value );
  return gcry_pk_map_name (r->u.value);
}

/* Parse the usage parameter.  Returns 0 on success.  Note that we
   only care about sign and encrypt and don't (yet) allow all the
   other X.509 usage to be specified; instead we will use a fixed
   mapping to the X.509 usage flags. */
static int
parse_parameter_usage (struct para_data_s *para, enum para_name key)
{
  struct para_data_s *r = get_parameter (para, key, 0);
  char *p, *pn;
  unsigned int use;

  if (!r)
    return 0; /* none (this is an optional parameter)*/

  use = 0;
  pn = r->u.value;
  while ( (p = strsep (&pn, " \t,")) )
    {
      if (!*p)
        ;
      else if ( !ascii_strcasecmp (p, "sign") )
        use |= GCRY_PK_USAGE_SIGN;
      else if ( !ascii_strcasecmp (p, "encrypt") )
        use |= GCRY_PK_USAGE_ENCR;
      else
        {
          log_error ("line %d: invalid usage list\n", r->lnr);
          return -1; /* error */
        }
    }
  r->u.usage = use;
  return 0;
}


static unsigned int
get_parameter_uint (struct para_data_s *para, enum para_name key)
{
  struct para_data_s *r = get_parameter (para, key, 0);

  if (!r)
    return 0;

  if (r->key == pKEYUSAGE)
    return r->u.usage;

  return (unsigned int)strtoul (r->u.value, NULL, 10);
}



/* Read the certificate generation parameters from FP and generate
   (all) certificate requests.  */
static int
read_parameters (ctrl_t ctrl, estream_t fp, ksba_writer_t writer)
{
  static struct {
    const char *name;
    enum para_name key;
    int allow_dups;
  } keywords[] = {
    { "Key-Type",       pKEYTYPE},
    { "Key-Length",     pKEYLENGTH },
    { "Key-Grip",       pKEYGRIP },
    { "Key-Usage",      pKEYUSAGE },
    { "Name-DN",        pNAMEDN },
    { "Name-Email",     pNAMEEMAIL, 1 },
    { "Name-DNS",       pNAMEDNS, 1 },
    { "Name-URI",       pNAMEURI, 1 },
    { NULL, 0 }
  };
  char line[1024], *p;
  const char *err = NULL;
  struct para_data_s *para, *r;
  int i, rc = 0, any = 0;
  struct reqgen_ctrl_s outctrl;

  memset (&outctrl, 0, sizeof (outctrl));
  outctrl.writer = writer;

  err = NULL;
  para = NULL;
  while (es_fgets (line, DIM(line)-1, fp) )
    {
      char *keyword, *value;

      outctrl.lnr++;
      if (*line && line[strlen(line)-1] != '\n')
        {
          err = "line too long";
          break;
	}
      for (p=line; spacep (p); p++)
        ;
      if (!*p || *p == '#')
        continue;

      keyword = p;
      if (*keyword == '%')
        {
          for (; *p && !spacep (p); p++)
            ;
          if (*p)
            *p++ = 0;
          for (; spacep (p); p++)
            ;
          value = p;
          trim_trailing_spaces (value);

          if (!ascii_strcasecmp (keyword, "%echo"))
            log_info ("%s\n", value);
          else if (!ascii_strcasecmp (keyword, "%dry-run"))
            outctrl.dryrun = 1;
          else if (!ascii_strcasecmp( keyword, "%commit"))
            {
              rc = proc_parameters (ctrl, para, &outctrl);
              if (rc)
                goto leave;
              any = 1;
              release_parameter_list (para);
              para = NULL;
	    }
          else
            log_info ("skipping control `%s' (%s)\n", keyword, value);

          continue;
	}


      if (!(p = strchr (p, ':')) || p == keyword)
        {
          err = "missing colon";
          break;
	}
      if (*p)
        *p++ = 0;
      for (; spacep (p); p++)
        ;
      if (!*p)
        {
          err = "missing argument";
          break;
	}
      value = p;
      trim_trailing_spaces (value);

      for (i=0; (keywords[i].name
                 && ascii_strcasecmp (keywords[i].name, keyword)); i++)
        ;
      if (!keywords[i].name)
        {
          err = "unknown keyword";
          break;
	}
      if (keywords[i].key != pKEYTYPE && !para)
        {
          err = "parameter block does not start with \"Key-Type\"";
          break;
	}

      if (keywords[i].key == pKEYTYPE && para)
        {
          rc = proc_parameters (ctrl, para, &outctrl);
          if (rc)
            goto leave;
          any = 1;
          release_parameter_list (para);
          para = NULL;
	}
      else if (!keywords[i].allow_dups)
        {
          for (r = para; r && r->key != keywords[i].key; r = r->next)
            ;
          if (r)
            {
              err = "duplicate keyword";
              break;
	    }
	}

      r = xtrycalloc (1, sizeof *r + strlen( value ));
      if (!r)
        {
          err = "out of core";
          break;
        }
      r->lnr = outctrl.lnr;
      r->key = keywords[i].key;
      strcpy (r->u.value, value);
      r->next = para;
      para = r;
    }

  if (err)
    {
      log_error ("line %d: %s\n", outctrl.lnr, err);
      rc = gpg_error (GPG_ERR_GENERAL);
    }
  else if (es_ferror(fp))
    {
      log_error ("line %d: read error: %s\n", outctrl.lnr, strerror(errno) );
      rc = gpg_error (GPG_ERR_GENERAL);
    }
  else if (para)
    {
      rc = proc_parameters (ctrl, para, &outctrl);
      if (rc)
        goto leave;
      any = 1;
    }

  if (!rc && !any)
    rc = gpg_error (GPG_ERR_NO_DATA);

 leave:
  release_parameter_list (para);
  return rc;
}

/* check whether there are invalid characters in the email address S */
static int
has_invalid_email_chars (const char *s)
{
  int at_seen=0;
  static char valid_chars[] = "01234567890_-."
                              "abcdefghijklmnopqrstuvwxyz"
			      "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  for (; *s; s++)
    {
      if (*s & 0x80)
        return 1;
      if (*s == '@')
        at_seen++;
      else if (!at_seen && !( !!strchr (valid_chars, *s) || *s == '+'))
        return 1;
      else if (at_seen && !strchr (valid_chars, *s))
        return 1;
    }
  return at_seen != 1;
}


/* Check that all required parameters are given and perform the action */
static int
proc_parameters (ctrl_t ctrl,
                 struct para_data_s *para, struct reqgen_ctrl_s *outctrl)
{
  gpg_error_t err;
  struct para_data_s *r;
  const char *s;
  int i;
  unsigned int nbits;
  char numbuf[20];
  unsigned char keyparms[100];
  int rc;
  ksba_sexp_t public;
  int seq;
  size_t erroff, errlen;
  char *cardkeyid = NULL;

  /* Check that we have all required parameters; */
  assert (get_parameter (para, pKEYTYPE, 0));

  /* We can only use RSA for now.  There is a problem with pkcs-10 on
     how to use ElGamal because it is expected that a PK algorithm can
     always be used for signing. Another problem is that on-card
     generated encryption keys may not be used for signing.  */
  i = get_parameter_algo (para, pKEYTYPE);
  if (!i && (s = get_parameter_value (para, pKEYTYPE, 0)) && *s)
    {
      /* Hack to allow creation of certificates directly from a smart
         card.  For example: "Key-Type: card:OPENPGP.3".  */
      if (!strncmp (s, "card:", 5) && s[5])
        cardkeyid = xtrystrdup (s+5);
    }
  if ( (i < 1 || i != GCRY_PK_RSA) && !cardkeyid )
    {
      r = get_parameter (para, pKEYTYPE, 0);
      log_error (_("line %d: invalid algorithm\n"), r->lnr);
      return gpg_error (GPG_ERR_INV_PARAMETER);
    }

  /* Check the keylength. */
  if (!get_parameter (para, pKEYLENGTH, 0))
    nbits = 2048;
  else
    nbits = get_parameter_uint (para, pKEYLENGTH);
  if ((nbits < 1024 || nbits > 4096) && !cardkeyid)
    {
      /* The BSI specs dated 2002-11-25 don't allow lengths below 1024. */
      r = get_parameter (para, pKEYLENGTH, 0);
      log_error (_("line %d: invalid key length %u (valid are %d to %d)\n"),
                 r->lnr, nbits, 1024, 4096);
      xfree (cardkeyid);
      return gpg_error (GPG_ERR_INV_PARAMETER);
    }

  /* Check the usage. */
  if (parse_parameter_usage (para, pKEYUSAGE))
    {
      xfree (cardkeyid);
      return gpg_error (GPG_ERR_INV_PARAMETER);
    }

  /* Check that there is a subject name and that this DN fits our
     requirements. */
  if (!(s=get_parameter_value (para, pNAMEDN, 0)))
    {
      r = get_parameter (para, pNAMEDN, 0);
      log_error (_("line %d: no subject name given\n"), r->lnr);
      xfree (cardkeyid);
      return gpg_error (GPG_ERR_INV_PARAMETER);
    }
  err = ksba_dn_teststr (s, 0, &erroff, &errlen);
  if (err)
    {
      r = get_parameter (para, pNAMEDN, 0);
      if (gpg_err_code (err) == GPG_ERR_UNKNOWN_NAME)
        log_error (_("line %d: invalid subject name label `%.*s'\n"),
                   r->lnr, (int)errlen, s+erroff);
      else
        log_error (_("line %d: invalid subject name `%s' at pos %d\n"),
                   r->lnr, s, (int)erroff);

      xfree (cardkeyid);
      return gpg_error (GPG_ERR_INV_PARAMETER);
    }

  /* Check that the optional email address is okay. */
  for (seq=0; (s=get_parameter_value (para, pNAMEEMAIL, seq)); seq++)
    {
      if (has_invalid_email_chars (s)
          || *s == '@'
          || s[strlen(s)-1] == '@'
          || s[strlen(s)-1] == '.'
          || strstr(s, ".."))
        {
          r = get_parameter (para, pNAMEEMAIL, seq);
          log_error (_("line %d: not a valid email address\n"), r->lnr);
          xfree (cardkeyid);
          return gpg_error (GPG_ERR_INV_PARAMETER);
        }
    }

  if (cardkeyid) /* Take the key from the current smart card. */
    {
      rc = gpgsm_agent_readkey (ctrl, 1, cardkeyid, &public);
      if (rc)
        {
          r = get_parameter (para, pKEYTYPE, 0);
          log_error (_("line %d: error reading key `%s' from card: %s\n"),
                     r->lnr, cardkeyid, gpg_strerror (rc));
          xfree (cardkeyid);
          return rc;
        }
    }
  else if ((s=get_parameter_value (para, pKEYGRIP, 0))) /* Use existing key.*/
    {
      rc = gpgsm_agent_readkey (ctrl, 0, s, &public);
      if (rc)
        {
          r = get_parameter (para, pKEYTYPE, 0);
          log_error (_("line %d: error getting key by keygrip `%s': %s\n"),
                     r->lnr, s, gpg_strerror (rc));
          xfree (cardkeyid);
          return rc;
        }
    }
  else /* Generate new key.  */
    {
      sprintf (numbuf, "%u", nbits);
      snprintf ((char*)keyparms, DIM (keyparms)-1,
                "(6:genkey(3:rsa(5:nbits%d:%s)))",
                (int)strlen (numbuf), numbuf);
      rc = gpgsm_agent_genkey (ctrl, keyparms, &public);
      if (rc)
        {
          r = get_parameter (para, pKEYTYPE, 0);
          log_error (_("line %d: key generation failed: %s <%s>\n"),
                     r->lnr, gpg_strerror (rc), gpg_strsource (rc));
          xfree (cardkeyid);
          return rc;
        }
    }

  rc = create_request (ctrl, para, cardkeyid, public, outctrl);
  xfree (public);
  xfree (cardkeyid);

  return rc;
}


/* Parameters are checked, the key pair has been created.  Now
   generate the request and write it out */
static int
create_request (ctrl_t ctrl,
                struct para_data_s *para,
                const char *carddirect,
                ksba_const_sexp_t public,
                struct reqgen_ctrl_s *outctrl)
{
  ksba_certreq_t cr;
  gpg_error_t err;
  gcry_md_hd_t md;
  ksba_stop_reason_t stopreason;
  int rc = 0;
  const char *s;
  unsigned int use;
  int seq;
  char *buf, *p;
  size_t len;
  char numbuf[30];

  err = ksba_certreq_new (&cr);
  if (err)
    return err;

  rc = gcry_md_open (&md, GCRY_MD_SHA1, 0);
  if (rc)
    {
      log_error ("md_open failed: %s\n", gpg_strerror (rc));
      goto leave;
    }
  if (DBG_HASHING)
    gcry_md_debug (md, "cr.cri");

  ksba_certreq_set_hash_function (cr, HASH_FNC, md);
  ksba_certreq_set_writer (cr, outctrl->writer);

  err = ksba_certreq_add_subject (cr, get_parameter_value (para, pNAMEDN, 0));
  if (err)
    {
      log_error ("error setting the subject's name: %s\n",
                 gpg_strerror (err));
      rc = err;
      goto leave;
    }

  for (seq=0; (s = get_parameter_value (para, pNAMEEMAIL, seq)); seq++)
    {
      buf = xtrymalloc (strlen (s) + 3);
      if (!buf)
        {
          rc = out_of_core ();
          goto leave;
        }
      *buf = '<';
      strcpy (buf+1, s);
      strcat (buf+1, ">");
      err = ksba_certreq_add_subject (cr, buf);
      xfree (buf);
      if (err)
        {
          log_error ("error setting the subject's alternate name: %s\n",
                     gpg_strerror (err));
          rc = err;
          goto leave;
        }
    }

  for (seq=0; (s = get_parameter_value (para, pNAMEDNS, seq)); seq++)
    {
      len = strlen (s);
      assert (len);
      snprintf (numbuf, DIM(numbuf), "%u:", (unsigned int)len);
      buf = p = xtrymalloc (11 + strlen (numbuf) + len + 3);
      if (!buf)
        {
          rc = out_of_core ();
          goto leave;
        }
      p = stpcpy (p, "(8:dns-name");
      p = stpcpy (p, numbuf);
      p = stpcpy (p, s);
      strcpy (p, ")");

      err = ksba_certreq_add_subject (cr, buf);
      xfree (buf);
      if (err)
        {
          log_error ("error setting the subject's alternate name: %s\n",
                     gpg_strerror (err));
          rc = err;
          goto leave;
        }
    }

  for (seq=0; (s = get_parameter_value (para, pNAMEURI, seq)); seq++)
    {
      len = strlen (s);
      assert (len);
      snprintf (numbuf, DIM(numbuf), "%u:", (unsigned int)len);
      buf = p = xtrymalloc (6 + strlen (numbuf) + len + 3);
      if (!buf)
        {
          rc = out_of_core ();
          goto leave;
        }
      p = stpcpy (p, "(3:uri");
      p = stpcpy (p, numbuf);
      p = stpcpy (p, s);
      strcpy (p, ")");

      err = ksba_certreq_add_subject (cr, buf);
      xfree (buf);
      if (err)
        {
          log_error ("error setting the subject's alternate name: %s\n",
                     gpg_strerror (err));
          rc = err;
          goto leave;
        }
    }


  err = ksba_certreq_set_public_key (cr, public);
  if (err)
    {
      log_error ("error setting the public key: %s\n",
                 gpg_strerror (err));
      rc = err;
      goto leave;
    }


  use = get_parameter_uint (para, pKEYUSAGE);
  if (use == GCRY_PK_USAGE_SIGN)
    {
      /* For signing only we encode the bits:
         KSBA_KEYUSAGE_DIGITAL_SIGNATURE
         KSBA_KEYUSAGE_NON_REPUDIATION */
      err = ksba_certreq_add_extension (cr, oidstr_keyUsage, 1,
                                        "\x03\x02\x06\xC0", 4);
    }
  else if (use == GCRY_PK_USAGE_ENCR)
    {
      /* For encrypt only we encode the bits:
         KSBA_KEYUSAGE_KEY_ENCIPHERMENT
         KSBA_KEYUSAGE_DATA_ENCIPHERMENT */
      err = ksba_certreq_add_extension (cr, oidstr_keyUsage, 1,
                                        "\x03\x02\x04\x30", 4);
    }
  else
    err = 0; /* Both or none given: don't request one. */
  if (err)
    {
      log_error ("error setting the key usage: %s\n",
                 gpg_strerror (err));
      rc = err;
      goto leave;
    }


  do
    {
      err = ksba_certreq_build (cr, &stopreason);
      if (err)
        {
          log_error ("ksba_certreq_build failed: %s\n", gpg_strerror (err));
          rc = err;
          goto leave;
        }
      if (stopreason == KSBA_SR_NEED_SIG)
        {
          gcry_sexp_t s_pkey;
          size_t n;
          unsigned char grip[20];
          char hexgrip[41];
          unsigned char *sigval;
          size_t siglen;

          n = gcry_sexp_canon_len (public, 0, NULL, NULL);
          if (!n)
            {
              log_error ("libksba did not return a proper S-Exp\n");
              rc = gpg_error (GPG_ERR_BUG);
              goto leave;
            }
          rc = gcry_sexp_sscan (&s_pkey, NULL, (const char*)public, n);
          if (rc)
            {
              log_error ("gcry_sexp_scan failed: %s\n", gpg_strerror (rc));
              goto leave;
            }
          if ( !gcry_pk_get_keygrip (s_pkey, grip) )
            {
              rc = gpg_error (GPG_ERR_GENERAL);
              log_error ("can't figure out the keygrip\n");
              gcry_sexp_release (s_pkey);
              goto leave;
            }
          gcry_sexp_release (s_pkey);
          bin2hex (grip, 20, hexgrip);

          log_info ("about to sign CSR for key: &%s\n", hexgrip);

          if (carddirect)
            rc = gpgsm_scd_pksign (ctrl, carddirect, NULL,
                                     gcry_md_read(md, GCRY_MD_SHA1),
                                     gcry_md_get_algo_dlen (GCRY_MD_SHA1),
                                     GCRY_MD_SHA1,
                                     &sigval, &siglen);
          else
            {
              char *orig_codeset;
              char *desc;

              orig_codeset = i18n_switchto_utf8 ();
              desc = percent_plus_escape
                (_("To complete this certificate request please enter"
                   " the passphrase for the key you just created once"
                   " more.\n"));
              i18n_switchback (orig_codeset);
              rc = gpgsm_agent_pksign (ctrl, hexgrip, desc,
                                       gcry_md_read(md, GCRY_MD_SHA1),
                                       gcry_md_get_algo_dlen (GCRY_MD_SHA1),
                                       GCRY_MD_SHA1,
                                       &sigval, &siglen);
              xfree (desc);
            }
          if (rc)
            {
              log_error ("signing failed: %s\n", gpg_strerror (rc));
              goto leave;
            }

          err = ksba_certreq_set_sig_val (cr, sigval);
          xfree (sigval);
          if (err)
            {
              log_error ("failed to store the sig_val: %s\n",
                         gpg_strerror (err));
              rc = err;
              goto leave;
            }
        }
    }
  while (stopreason != KSBA_SR_READY);


 leave:
  gcry_md_close (md);
  ksba_certreq_release (cr);
  return rc;
}



/* Create a new key by reading the parameters from IN_FP.  Multiple
   keys may be created */
int
gpgsm_genkey (ctrl_t ctrl, estream_t in_stream, FILE *out_fp)
{
  int rc;
  Base64Context b64writer = NULL;
  ksba_writer_t writer;

  ctrl->pem_name = "CERTIFICATE REQUEST";
  rc = gpgsm_create_writer (&b64writer, ctrl, out_fp, NULL, &writer);
  if (rc)
    {
      log_error ("can't create writer: %s\n", gpg_strerror (rc));
      goto leave;
    }

  rc = read_parameters (ctrl, in_stream, writer);
  if (rc)
    {
      log_error ("error creating certificate request: %s <%s>\n",
                 gpg_strerror (rc), gpg_strsource (rc));
      goto leave;
    }

  rc = gpgsm_finish_writer (b64writer);
  if (rc)
    {
      log_error ("write failed: %s\n", gpg_strerror (rc));
      goto leave;
    }

  gpgsm_status (ctrl, STATUS_KEY_CREATED, "P");
  log_info ("certificate request created\n");

 leave:
  gpgsm_destroy_writer (b64writer);
  return rc;
}

