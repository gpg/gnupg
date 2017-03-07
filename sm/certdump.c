/* certdump.c - Dump a certificate for debugging
 * Copyright (C) 2001-2010, 2014-2015  g10 Code GmbH
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
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif
#ifdef HAVE_LANGINFO_CODESET
#include <langinfo.h>
#endif

#include "gpgsm.h"
#include <gcrypt.h>
#include <ksba.h>

#include "keydb.h"
#include "../common/i18n.h"


struct dn_array_s {
  char *key;
  char *value;
  int   multivalued;
  int   done;
};


/* Print the first element of an S-Expression. */
void
gpgsm_print_serial (estream_t fp, ksba_const_sexp_t sn)
{
  const char *p = (const char *)sn;
  unsigned long n;
  char *endp;

  if (!p)
    es_fputs (_("none"), fp);
  else if (*p != '(')
    es_fputs ("[Internal error - not an S-expression]", fp);
  else
    {
      p++;
      n = strtoul (p, &endp, 10);
      p = endp;
      if (*p++ != ':')
        es_fputs ("[Internal Error - invalid S-expression]", fp);
      else
        es_write_hexstring (fp, p, n, 0, NULL);
    }
}


/* Dump the serial number or any other simple S-expression. */
void
gpgsm_dump_serial (ksba_const_sexp_t sn)
{
  const char *p = (const char *)sn;
  unsigned long n;
  char *endp;

  if (!p)
    log_printf ("none");
  else if (*p != '(')
    log_printf ("ERROR - not an S-expression");
  else
    {
      p++;
      n = strtoul (p, &endp, 10);
      p = endp;
      if (*p!=':')
        log_printf ("ERROR - invalid S-expression");
      else
        {
          for (p++; n; n--, p++)
            log_printf ("%02X", *(const unsigned char *)p);
        }
    }
}


char *
gpgsm_format_serial (ksba_const_sexp_t sn)
{
  const char *p = (const char *)sn;
  unsigned long n;
  char *endp;
  char *buffer;
  int i;

  if (!p)
    return NULL;

  if (*p != '(')
    BUG (); /* Not a valid S-expression. */

  p++;
  n = strtoul (p, &endp, 10);
  p = endp;
  if (*p!=':')
    BUG (); /* Not a valid S-expression. */
  p++;

  buffer = xtrymalloc (n*2+1);
  if (buffer)
    {
      for (i=0; n; n--, p++, i+=2)
        sprintf (buffer+i, "%02X", *(unsigned char *)p);
      buffer[i] = 0;
    }
  return buffer;
}




void
gpgsm_print_time (estream_t fp, ksba_isotime_t t)
{
  if (!t || !*t)
    es_fputs (_("none"), fp);
  else
    es_fprintf (fp, "%.4s-%.2s-%.2s %.2s:%.2s:%s",
                t, t+4, t+6, t+9, t+11, t+13);
}


void
gpgsm_dump_string (const char *string)
{

  if (!string)
    log_printf ("[error]");
  else
    {
      const unsigned char *s;

      for (s=(const unsigned char*)string; *s; s++)
        {
          if (*s < ' ' || (*s >= 0x7f && *s <= 0xa0))
            break;
        }
      if (!*s && *string != '[')
        log_printf ("%s", string);
      else
        {
          log_printf ( "[ ");
          log_printhex (NULL, string, strlen (string));
          log_printf ( " ]");
        }
    }
}


/* This simple dump function is mainly used for debugging purposes. */
void
gpgsm_dump_cert (const char *text, ksba_cert_t cert)
{
  ksba_sexp_t sexp;
  char *p;
  char *dn;
  ksba_isotime_t t;

  log_debug ("BEGIN Certificate '%s':\n", text? text:"");
  if (cert)
    {
      sexp = ksba_cert_get_serial (cert);
      log_debug ("     serial: ");
      gpgsm_dump_serial (sexp);
      ksba_free (sexp);
      log_printf ("\n");

      ksba_cert_get_validity (cert, 0, t);
      log_debug ("  notBefore: ");
      dump_isotime (t);
      log_printf ("\n");
      ksba_cert_get_validity (cert, 1, t);
      log_debug ("   notAfter: ");
      dump_isotime (t);
      log_printf ("\n");

      dn = ksba_cert_get_issuer (cert, 0);
      log_debug ("     issuer: ");
      gpgsm_dump_string (dn);
      ksba_free (dn);
      log_printf ("\n");

      dn = ksba_cert_get_subject (cert, 0);
      log_debug ("    subject: ");
      gpgsm_dump_string (dn);
      ksba_free (dn);
      log_printf ("\n");

      log_debug ("  hash algo: %s\n", ksba_cert_get_digest_algo (cert));

      p = gpgsm_get_fingerprint_string (cert, 0);
      log_debug ("  SHA1 Fingerprint: %s\n", p);
      xfree (p);
    }
  log_debug ("END Certificate\n");
}


/* Return a new string holding the format serial number and issuer
   ("#SN/issuer").  No filtering on invalid characters is done.
   Caller must release the string.  On memory failure NULL is
   returned.  */
char *
gpgsm_format_sn_issuer (ksba_sexp_t sn, const char *issuer)
{
  char *p, *p1;

  if (sn && issuer)
    {
      p1 = gpgsm_format_serial (sn);
      if (!p1)
        p = xtrystrdup ("[invalid SN]");
      else
        {
          p = xtrymalloc (strlen (p1) + strlen (issuer) + 2 + 1);
          if (p)
            {
              *p = '#';
              strcpy (stpcpy (stpcpy (p+1, p1),"/"), issuer);
            }
          xfree (p1);
        }
    }
  else
    p = xtrystrdup ("[invalid SN/issuer]");
  return p;
}


/* Log the certificate's name in "#SN/ISSUERDN" format along with
   TEXT. */
void
gpgsm_cert_log_name (const char *text, ksba_cert_t cert)
{
  log_info ("%s", text? text:"certificate" );
  if (cert)
    {
      ksba_sexp_t sn;
      char *p;

      p = ksba_cert_get_issuer (cert, 0);
      sn = ksba_cert_get_serial (cert);
      if (p && sn)
        {
          log_printf (" #");
          gpgsm_dump_serial (sn);
          log_printf ("/");
          gpgsm_dump_string (p);
        }
      else
        log_printf (" [invalid]");
      ksba_free (sn);
      xfree (p);
    }
  log_printf ("\n");
}






/* helper for the rfc2253 string parser */
static const unsigned char *
parse_dn_part (struct dn_array_s *array, const unsigned char *string)
{
  static struct {
    const char *label;
    const char *oid;
  } label_map[] = {
    /* Warning: When adding new labels, make sure that the buffer
       below we be allocated large enough. */
    {"EMail",        "1.2.840.113549.1.9.1" },
    {"T",            "2.5.4.12" },
    {"GN",           "2.5.4.42" },
    {"SN",           "2.5.4.4" },
    {"NameDistinguisher", "0.2.262.1.10.7.20"},
    {"ADDR",         "2.5.4.16" },
    {"BC",           "2.5.4.15" },
    {"D",            "2.5.4.13" },
    {"PostalCode",   "2.5.4.17" },
    {"Pseudo",       "2.5.4.65" },
    {"SerialNumber", "2.5.4.5" },
    {NULL, NULL}
  };
  const unsigned char *s, *s1;
  size_t n;
  char *p;
  int i;

  /* Parse attributeType */
  for (s = string+1; *s && *s != '='; s++)
    ;
  if (!*s)
    return NULL; /* error */
  n = s - string;
  if (!n)
    return NULL; /* empty key */

  /* We need to allocate a few bytes more due to the possible mapping
     from the shorter OID to the longer label. */
  array->key = p = xtrymalloc (n+10);
  if (!array->key)
    return NULL;
  memcpy (p, string, n);
  p[n] = 0;
  trim_trailing_spaces (p);

  if (digitp (p))
    {
      for (i=0; label_map[i].label; i++ )
        if ( !strcmp (p, label_map[i].oid) )
          {
            strcpy (p, label_map[i].label);
            break;
          }
    }
  string = s + 1;

  if (*string == '#')
    { /* hexstring */
      string++;
      for (s=string; hexdigitp (s); s++)
        s++;
      n = s - string;
      if (!n || (n & 1))
        return NULL; /* Empty or odd number of digits. */
      n /= 2;
      array->value = p = xtrymalloc (n+1);
      if (!p)
        return NULL;
      for (s1=string; n; s1 += 2, n--, p++)
        {
          *(unsigned char *)p = xtoi_2 (s1);
          if (!*p)
            *p = 0x01; /* Better print a wrong value than truncating
                          the string. */
        }
      *p = 0;
   }
  else
    { /* regular v3 quoted string */
      for (n=0, s=string; *s; s++)
        {
          if (*s == '\\')
            { /* pair */
              s++;
              if (*s == ',' || *s == '=' || *s == '+'
                  || *s == '<' || *s == '>' || *s == '#' || *s == ';'
                  || *s == '\\' || *s == '\"' || *s == ' ')
                n++;
              else if (hexdigitp (s) && hexdigitp (s+1))
                {
                  s++;
                  n++;
                }
              else
                return NULL; /* invalid escape sequence */
            }
          else if (*s == '\"')
            return NULL; /* invalid encoding */
          else if (*s == ',' || *s == '=' || *s == '+'
                   || *s == '<' || *s == '>' || *s == ';' )
            break;
          else
            n++;
        }

      array->value = p = xtrymalloc (n+1);
      if (!p)
        return NULL;
      for (s=string; n; s++, n--)
        {
          if (*s == '\\')
            {
              s++;
              if (hexdigitp (s))
                {
                  *(unsigned char *)p++ = xtoi_2 (s);
                  s++;
                }
              else
                *p++ = *s;
            }
          else
            *p++ = *s;
        }
      *p = 0;
    }
  return s;
}


/* Parse a DN and return an array-ized one.  This is not a validating
   parser and it does not support any old-stylish syntax; KSBA is
   expected to return only rfc2253 compatible strings. */
static struct dn_array_s *
parse_dn (const unsigned char *string)
{
  struct dn_array_s *array;
  size_t arrayidx, arraysize;
  int i;

  arraysize = 7; /* C,ST,L,O,OU,CN,email */
  arrayidx = 0;
  array = xtrymalloc ((arraysize+1) * sizeof *array);
  if (!array)
    return NULL;
  while (*string)
    {
      while (*string == ' ')
        string++;
      if (!*string)
        break; /* ready */
      if (arrayidx >= arraysize)
        {
          struct dn_array_s *a2;

          arraysize += 5;
          a2 = xtryrealloc (array, (arraysize+1) * sizeof *array);
          if (!a2)
            goto failure;
          array = a2;
        }
      array[arrayidx].key = NULL;
      array[arrayidx].value = NULL;
      string = parse_dn_part (array+arrayidx, string);
      if (!string)
        goto failure;
      while (*string == ' ')
        string++;
      array[arrayidx].multivalued = (*string == '+');
      array[arrayidx].done = 0;
      arrayidx++;
      if (*string && *string != ',' && *string != ';' && *string != '+')
        goto failure; /* invalid delimiter */
      if (*string)
        string++;
    }
  array[arrayidx].key = NULL;
  array[arrayidx].value = NULL;
  return array;

 failure:
  for (i=0; i < arrayidx; i++)
    {
      xfree (array[i].key);
      xfree (array[i].value);
    }
  xfree (array);
  return NULL;
}


/* Print a DN part to STREAM. */
static void
print_dn_part (estream_t stream,
               struct dn_array_s *dn, const char *key, int translate)
{
  struct dn_array_s *first_dn = dn;

  for (; dn->key; dn++)
    {
      if (!dn->done && !strcmp (dn->key, key))
        {
          /* Forward to the last multi-valued RDN, so that we can
             print them all in reverse in the correct order.  Note
             that this overrides the standard sequence but that
             seems to a reasonable thing to do with multi-valued
             RDNs. */
          while (dn->multivalued && dn[1].key)
            dn++;
        next:
          if (!dn->done && dn->value && *dn->value)
            {
              es_fprintf (stream, "/%s=", dn->key);
              if (translate)
                print_utf8_buffer3 (stream, dn->value, strlen (dn->value),
                                    "/");
              else
                es_write_sanitized (stream, dn->value, strlen (dn->value),
                                    "/", NULL);
            }
          dn->done = 1;
          if (dn > first_dn && dn[-1].multivalued)
            {
              dn--;
              goto next;
            }
        }
    }
}

/* Print all parts of a DN in a "standard" sequence.  We first print
   all the known parts, followed by the uncommon ones */
static void
print_dn_parts (estream_t stream,
                struct dn_array_s *dn, int translate)
{
  const char *stdpart[] = {
    "CN", "OU", "O", "STREET", "L", "ST", "C", "EMail", NULL
  };
  int i;

  for (i=0; stdpart[i]; i++)
      print_dn_part (stream, dn, stdpart[i], translate);

  /* Now print the rest without any specific ordering */
  for (; dn->key; dn++)
    print_dn_part (stream, dn, dn->key, translate);
}


/* Print the S-Expression in BUF to extended STREAM, which has a valid
   length of BUFLEN, as a human readable string in one line to FP. */
static void
pretty_es_print_sexp (estream_t fp, const unsigned char *buf, size_t buflen)
{
  size_t len;
  gcry_sexp_t sexp;
  char *result, *p;

  if ( gcry_sexp_sscan (&sexp, NULL, (const char*)buf, buflen) )
    {
      es_fputs (_("[Error - invalid encoding]"), fp);
      return;
    }
  len = gcry_sexp_sprint (sexp, GCRYSEXP_FMT_ADVANCED, NULL, 0);
  assert (len);
  result = xtrymalloc (len);
  if (!result)
    {
      es_fputs (_("[Error - out of core]"), fp);
      gcry_sexp_release (sexp);
      return;
    }
  len = gcry_sexp_sprint (sexp, GCRYSEXP_FMT_ADVANCED, result, len);
  assert (len);
  for (p = result; len; len--, p++)
    {
      if (*p == '\n')
        {
          if (len > 1) /* Avoid printing the trailing LF. */
            es_fputs ("\\n", fp);
        }
      else if (*p == '\r')
        es_fputs ("\\r", fp);
      else if (*p == '\v')
        es_fputs ("\\v", fp);
      else if (*p == '\t')
        es_fputs ("\\t", fp);
      else
        es_putc (*p, fp);
    }
  xfree (result);
  gcry_sexp_release (sexp);
}


/* This is a variant of gpgsm_print_name sending it output to an estream. */
void
gpgsm_es_print_name2 (estream_t fp, const char *name, int translate)
{
  const unsigned char *s = (const unsigned char *)name;
  int i;

  if (!s)
    {
      es_fputs (_("[Error - No name]"), fp);
    }
  else if (*s == '<')
    {
      const char *s2 = strchr ( (char*)s+1, '>');

      if (s2)
        {
          if (translate)
            print_utf8_buffer (fp, s + 1, s2 - (char*)s - 1);
          else
            es_write_sanitized (fp, s + 1, s2 - (char*)s - 1, NULL, NULL);
        }
    }
  else if (*s == '(')
    {
      pretty_es_print_sexp (fp, s, gcry_sexp_canon_len (s, 0, NULL, NULL));
    }
  else if (!((*s >= '0' && *s < '9')
             || (*s >= 'A' && *s <= 'Z')
             || (*s >= 'a' && *s <= 'z')))
    es_fputs (_("[Error - invalid encoding]"), fp);
  else
    {
      struct dn_array_s *dn = parse_dn (s);

      if (!dn)
        es_fputs (_("[Error - invalid DN]"), fp);
      else
        {
          print_dn_parts (fp, dn, translate);
          for (i=0; dn[i].key; i++)
            {
              xfree (dn[i].key);
              xfree (dn[i].value);
            }
          xfree (dn);
        }
    }
}


void
gpgsm_es_print_name (estream_t fp, const char *name)
{
  gpgsm_es_print_name2 (fp, name, 1);
}


/* A cookie structure used for the memory stream. */
struct format_name_cookie
{
  char *buffer;         /* Malloced buffer with the data to deliver. */
  size_t size;          /* Allocated size of this buffer. */
  size_t len;           /* strlen (buffer). */
  int error;            /* system error code if any. */
};

/* The writer function for the memory stream. */
static gpgrt_ssize_t
format_name_writer (void *cookie, const void *buffer, size_t size)
{
  struct format_name_cookie *c = cookie;
  char *p;

  if (!c->buffer)
    {
      p = xtrymalloc (size + 1 + 1);
      if (p)
        {
          c->size = size + 1;
          c->buffer = p;
          c->len = 0;
        }
    }
  else if (c->len + size < c->len)
    {
      p = NULL;
      gpg_err_set_errno (ENOMEM);
    }
  else if (c->size < c->len + size)
    {
      p = xtryrealloc (c->buffer, c->len + size + 1);
      if (p)
        {
          c->size = c->len + size;
          c->buffer = p;
        }
    }
  else
    p = c->buffer;
  if (!p)
    {
      c->error = errno;
      xfree (c->buffer);
      c->buffer = NULL;
      gpg_err_set_errno (c->error);
      return -1;
    }
  memcpy (p + c->len, buffer, size);
  c->len += size;
  p[c->len] = 0; /* Terminate string. */

  return (gpgrt_ssize_t)size;
}


/* Format NAME which is expected to be in rfc2253 format into a better
   human readable format. Caller must free the returned string.  NULL
   is returned in case of an error.  With TRANSLATE set to true the
   name will be translated to the native encoding.  Note that NAME is
   internally always UTF-8 encoded. */
char *
gpgsm_format_name2 (const char *name, int translate)
{
  estream_t fp;
  struct format_name_cookie cookie;
  es_cookie_io_functions_t io = { NULL };

  memset (&cookie, 0, sizeof cookie);

  io.func_write = format_name_writer;
  fp = es_fopencookie (&cookie, "w", io);
  if (!fp)
    {
      int save_errno = errno;
      log_error ("error creating memory stream: %s\n", strerror (save_errno));
      gpg_err_set_errno (save_errno);
      return NULL;
    }
  gpgsm_es_print_name2 (fp, name, translate);
  es_fclose (fp);
  if (cookie.error || !cookie.buffer)
    {
      xfree (cookie.buffer);
      gpg_err_set_errno (cookie.error);
      return NULL;
    }
  return cookie.buffer;
}


char *
gpgsm_format_name (const char *name)
{
  return gpgsm_format_name2 (name, 1);
}


/* Return fingerprint and a percent escaped name in a human readable
   format suitable for status messages like GOODSIG.  May return NULL
   on error (out of core). */
char *
gpgsm_fpr_and_name_for_status (ksba_cert_t cert)
{
  char *fpr, *name, *p;
  char *buffer;

  fpr = gpgsm_get_fingerprint_hexstring (cert, GCRY_MD_SHA1);
  if (!fpr)
    return NULL;

  name = ksba_cert_get_subject (cert, 0);
  if (!name)
    {
      xfree (fpr);
      return NULL;
    }

  p = gpgsm_format_name2 (name, 0);
  ksba_free (name);
  name = p;
  if (!name)
    {
      xfree (fpr);
      return NULL;
    }

  buffer = xtrymalloc (strlen (fpr) + 1 + 3*strlen (name) + 1);
  if (buffer)
    {
      const char *s;

      p = stpcpy (stpcpy (buffer, fpr), " ");
      for (s = name; *s; s++)
        {
          if (*s < ' ')
            {
              sprintf (p, "%%%02X", *(const unsigned char*)s);
              p += 3;
            }
          else
            *p++ = *s;
        }
      *p = 0;
    }
  xfree (fpr);
  xfree (name);
  return buffer;
}


/* Create a key description for the CERT, this may be passed to the
   pinentry.  The caller must free the returned string.  NULL may be
   returned on error. */
char *
gpgsm_format_keydesc (ksba_cert_t cert)
{
  char *name, *subject, *buffer;
  ksba_isotime_t t;
  char created[20];
  char expires[20];
  char *sn;
  ksba_sexp_t sexp;
  char *orig_codeset;

  name = ksba_cert_get_subject (cert, 0);
  subject = name? gpgsm_format_name2 (name, 0) : NULL;
  ksba_free (name); name = NULL;

  sexp = ksba_cert_get_serial (cert);
  sn = sexp? gpgsm_format_serial (sexp) : NULL;
  ksba_free (sexp);

  ksba_cert_get_validity (cert, 0, t);
  if (*t)
    sprintf (created, "%.4s-%.2s-%.2s", t, t+4, t+6);
  else
    *created = 0;
  ksba_cert_get_validity (cert, 1, t);
  if (*t)
    sprintf (expires, "%.4s-%.2s-%.2s", t, t+4, t+6);
  else
    *expires = 0;

  orig_codeset = i18n_switchto_utf8 ();

  name = xtryasprintf (_("Please enter the passphrase to unlock the"
                         " secret key for the X.509 certificate:\n"
                         "\"%s\"\n"
                         "S/N %s, ID 0x%08lX,\n"
                         "created %s, expires %s.\n" ),
                       subject? subject:"?",
                       sn? sn: "?",
                       gpgsm_get_short_fingerprint (cert, NULL),
                       created, expires);

  i18n_switchback (orig_codeset);

  if (!name)
    {
      xfree (subject);
      xfree (sn);
      return NULL;
    }

  xfree (subject);
  xfree (sn);

  buffer = percent_plus_escape (name);
  xfree (name);
  return buffer;
}
