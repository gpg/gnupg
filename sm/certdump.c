/* certdump.c - Dump a certificate for debugging
 *	Copyright (C) 2001 Free Software Foundation, Inc.
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

#include <gcrypt.h>
#include <ksba.h>

#include "gpgsm.h"
#include "keydb.h"
#include "i18n.h"

struct dn_array_s {
  char *key;
  char *value;
};


/* print the first element of an S-Expression */
void
gpgsm_print_serial (FILE *fp, KsbaConstSexp p)
{
  unsigned long n;
  KsbaConstSexp endp;

  if (!p)
    fputs (_("none"), fp);
  else if (*p != '(')
    fputs ("[Internal error - not an S-expression]", fp);
  else
    {
      p++;
      n = strtoul (p, (char**)&endp, 10);
      p = endp;
      if (*p!=':')
        fputs ("[Internal Error - invalid S-expression]", fp);
      else
        {
          for (p++; n; n--, p++)
            fprintf (fp, "%02X", *p);
        }
    }
}


void
gpgsm_dump_serial (KsbaConstSexp p)
{
  unsigned long n;
  KsbaConstSexp endp;

  if (!p)
    log_printf ("none");
  else if (*p != '(')
    log_printf ("ERROR - not an S-expression");
  else
    {
      p++;
      n = strtoul (p, (char**)&endp, 10);
      p = endp;
      if (*p!=':')
        log_printf ("ERROR - invalid S-expression");
      else
        {
          for (p++; n; n--, p++)
            log_printf ("%02X", *p);
        }
    }
}

void
gpgsm_print_time (FILE *fp, time_t t)
{
  if (!t)
    fputs (_("none"), fp);
  else if ( t == (time_t)(-1) )
    fputs ("[Error - Invalid time]", fp);
  else
    {
      struct tm *tp;

      tp = gmtime (&t);
      fprintf (fp, "%04d-%02d-%02d %02d:%02d:%02d Z",
               1900+tp->tm_year, tp->tm_mon+1, tp->tm_mday,
               tp->tm_hour, tp->tm_min, tp->tm_sec);
      assert (!tp->tm_isdst);
    }
}

void
gpgsm_dump_time (time_t t)
{

  if (!t)
    log_printf (_("[none]"));
  else if ( t == (time_t)(-1) )
    log_printf (_("[error]"));
  else
    {
      struct tm *tp;

      tp = gmtime (&t);
      log_printf ("%04d-%02d-%02d %02d:%02d:%02d",
                  1900+tp->tm_year, tp->tm_mon+1, tp->tm_mday,
                  tp->tm_hour, tp->tm_min, tp->tm_sec);
      assert (!tp->tm_isdst);
    }
}




void
gpgsm_dump_string (const char *string)
{

  if (!string)
    log_printf ("[error]");
  else
    {
      const unsigned char *s;

      for (s=string; *s; s++)
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


void 
gpgsm_dump_cert (const char *text, KsbaCert cert)
{
  KsbaSexp sexp;
  unsigned char *p;
  char *dn;
  time_t t;

  log_debug ("BEGIN Certificate `%s':\n", text? text:"");
  if (cert)
    {
      sexp = ksba_cert_get_serial (cert);
      log_debug ("     serial: ");
      gpgsm_dump_serial (sexp);
      ksba_free (sexp);
      log_printf ("\n");

      t = ksba_cert_get_validity (cert, 0);
      log_debug ("  notBefore: ");
      gpgsm_dump_time (t);
      log_printf ("\n");
      t = ksba_cert_get_validity (cert, 1);
      log_debug ("   notAfter: ");
      gpgsm_dump_time (t);
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



/* helper for the rfc2253 string parser */
static const unsigned char *
parse_dn_part (struct dn_array_s *array, const unsigned char *string)
{
  const unsigned char *s, *s1;
  size_t n;
  unsigned char *p;

  /* parse attributeType */
  for (s = string+1; *s && *s != '='; s++)
    ;
  if (!*s)
    return NULL; /* error */
  n = s - string;
  if (!n)
    return NULL; /* empty key */
  array->key = p = xtrymalloc (n+1);
  if (!array->key)
    return NULL;
  memcpy (p, string, n); 
  p[n] = 0;
  trim_trailing_spaces (p);
  if ( !strcmp (p, "1.2.840.113549.1.9.1") )
    strcpy (p, "EMail");
  string = s + 1;

  if (*string == '#')
    { /* hexstring */
      string++;
      for (s=string; hexdigitp (s); s++)
        s++;
      n = s - string;
      if (!n || (n & 1))
        return NULL; /* empty or odd number of digits */
      n /= 2;
      array->value = p = xtrymalloc (n+1);
      if (!p)
        return NULL;
      for (s1=string; n; s1 += 2, n--)
        *p++ = xtoi_2 (s1);
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
                   || *s == '<' || *s == '>' || *s == '#' || *s == ';' )
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
                  *p++ = xtoi_2 (s);
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
      arrayidx++;
      if (!string)
        goto failure;
      while (*string == ' ')
        string++;
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


static void
print_dn_part (FILE *fp, struct dn_array_s *dn, const char *key)
{
  int any = 0;

  for (; dn->key; dn++)
    {
      if (!strcmp (dn->key, key) && dn->value && *dn->value)
        {
          putc ('/', fp);
          if (any)
            fputs (" + ", fp);
          else
            fprintf (fp, "%s=", key);
          print_sanitized_utf8_string (fp, dn->value, '/');
          any = 1;
        }
    }
}

/* Print all parts of a DN in a "standard" sequence.  We first print
   all the known parts, followed by the uncommon ones */
static void
print_dn_parts (FILE *fp, struct dn_array_s *dn)
{
  const char *stdpart[] = {
    "CN", "OU", "O", "STREET", "L", "ST", "C", "EMail", NULL 
  };
  int i;
  
  for (i=0; stdpart[i]; i++)
    print_dn_part (fp, dn, stdpart[i]);

  /* now print the rest without any specific ordering */
  for (; dn->key; dn++)
    {
      for (i=0; stdpart[i]; i++)
        {
          if (!strcmp (dn->key, stdpart[i]))
            break;
        }
      if (!stdpart[i])
        print_dn_part (fp, dn, dn->key);
    }
}



void
gpgsm_print_name (FILE *fp, const char *name)
{
  const unsigned char *s;
  int i;

  s = name;
  if (!s)
    {
      fputs (_("[Error - No name]"), fp);
    }
  else if (*s == '<')
    {
      const unsigned char *s2 = strchr (s+1, '>');
      if (s2)
        print_sanitized_utf8_buffer (fp, s + 1, s2 - s - 1, 0);
    }
  else if (*s == '(')
    fputs (_("[Error - unknown encoding]"), fp);
  else if (!((*s >= '0' && *s < '9')
             || (*s >= 'A' && *s <= 'Z')
             || (*s >= 'a' && *s <= 'z')))
    fputs (_("[Error - invalid encoding]"), fp);
  else
    {
      struct dn_array_s *dn = parse_dn (s);
      if (!dn)
        fputs (_("[Error - invalid DN]"), fp);
      else 
        {
          print_dn_parts (fp, dn);          
          for (i=0; dn[i].key; i++)
            {
              xfree (dn[i].key);
              xfree (dn[i].value);
            }
          xfree (dn);
        }
    }
}



