/* misc.c - miscellaneous
 *	Copyright (C) 2002 Klarälvdalens Datakonsult AB
 *      Copyright (C) 2002, 2003, 2004, 2010 Free Software Foundation, Inc.
 *
 * This file is part of DirMngr.
 *
 * DirMngr is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * DirMngr is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include "dirmngr.h"
#include "../common/util.h"
#include "misc.h"


/* Convert the hex encoded STRING back into binary and store the
   result into the provided buffer RESULT.  The actual size of that
   buffer will be returned.  The caller should provide RESULT of at
   least strlen(STRING)/2 bytes.  There is no error detection, the
   parsing stops at the first non hex character.  With RESULT given as
   NULL, the function does only return the size of the buffer which
   would be needed.  */
size_t
unhexify (unsigned char *result, const char *string)
{
  const char *s;
  size_t n;

  for (s=string,n=0; hexdigitp (s) && hexdigitp(s+1); s += 2)
    {
      if (result)
        result[n] = xtoi_2 (s);
      n++;
    }
  return n;
}


char*
hashify_data( const char* data, size_t len )
{
  unsigned char buf[20];
  gcry_md_hash_buffer (GCRY_MD_SHA1, buf, data, len);
  return hexify_data (buf, 20, 0);
}


/* FIXME: Replace this by hextobin.  */
char*
hexify_data (const unsigned char* data, size_t len, int with_prefix)
{
  int i;
  char *result = xmalloc (2*len + (with_prefix?2:0) + 1);
  char *p;

  if (with_prefix)
    p = stpcpy (result, "0x");
  else
    p = result;

  for (i = 0; i < 2*len; i+=2 )
    snprintf (p+i, 3, "%02X", *data++);
  return result;
}

char *
serial_hex (ksba_sexp_t serial )
{
  unsigned char* p = serial;
  char *endp;
  unsigned long n;
  char *certid;

  if (!p)
    return NULL;
  else {
    p++; /* ignore initial '(' */
    n = strtoul (p, (char**)&endp, 10);
    p = endp;
    if (*p!=':')
      return NULL;
    else {
      int i = 0;
      certid = xmalloc( sizeof( char )*(2*n + 1 ) );
      for (p++; n; n--, p++) {
	sprintf ( certid+i , "%02X", *p);
	i += 2;
      }
    }
  }
  return certid;
}


/* Take an S-Expression encoded blob and return a pointer to the
   actual data as well as its length.  Return NULL for an invalid
   S-Expression.*/
const unsigned char *
serial_to_buffer (const ksba_sexp_t serial, size_t *length)
{
  unsigned char *p = serial;
  char *endp;
  unsigned long n;

  if (!p || *p != '(')
    return NULL;
  p++;
  n = strtoul (p, &endp, 10);
  p = endp;
  if (*p != ':')
    return NULL;
  p++;
  *length = n;
  return p;
}


/* Do an in-place percent unescaping of STRING. Returns STRING. Note
   that this function does not do a '+'-to-space unescaping.*/
char *
unpercent_string (char *string)
{
  char *s = string;
  char *d = string;

  while (*s)
    {
      if (*s == '%' && s[1] && s[2])
        {
          s++;
          *d++ = xtoi_2 ( s);
          s += 2;
        }
      else
        *d++ = *s++;
    }
  *d = 0;
  return string;
}

/* Convert a canonical encoded S-expression in CANON into the GCRY
   type. */
gpg_error_t
canon_sexp_to_gcry (const unsigned char *canon, gcry_sexp_t *r_sexp)
{
  gpg_error_t err;
  size_t n;
  gcry_sexp_t sexp;

  *r_sexp = NULL;
  n = gcry_sexp_canon_len (canon, 0, NULL, NULL);
  if (!n)
    {
      log_error (_("invalid canonical S-expression found\n"));
      err = gpg_error (GPG_ERR_INV_SEXP);
    }
  else if ((err = gcry_sexp_sscan (&sexp, NULL, canon, n)))
    log_error (_("converting S-expression failed: %s\n"), gcry_strerror (err));
  else
    *r_sexp = sexp;
  return err;
}


/* Return an allocated buffer with the formatted fingerprint as one
   large hexnumber */
char *
get_fingerprint_hexstring (ksba_cert_t cert)
{
  unsigned char digest[20];
  gcry_md_hd_t md;
  int rc;
  char *buf;
  int i;

  rc = gcry_md_open (&md, GCRY_MD_SHA1, 0);
  if (rc)
    log_fatal (_("gcry_md_open failed: %s\n"), gpg_strerror (rc));

  rc = ksba_cert_hash (cert, 0, HASH_FNC, md);
  if (rc)
    {
      log_error (_("oops: ksba_cert_hash failed: %s\n"), gpg_strerror (rc));
      memset (digest, 0xff, 20); /* Use a dummy value. */
    }
  else
    {
      gcry_md_final (md);
      memcpy (digest, gcry_md_read (md, GCRY_MD_SHA1), 20);
    }
  gcry_md_close (md);
  buf = xmalloc (41);
  *buf = 0;
  for (i=0; i < 20; i++ )
    sprintf (buf+strlen(buf), "%02X", digest[i]);
  return buf;
}

/* Return an allocated buffer with the formatted fingerprint as one
   large hexnumber.  This version inserts the usual colons. */
char *
get_fingerprint_hexstring_colon (ksba_cert_t cert)
{
  unsigned char digest[20];
  gcry_md_hd_t md;
  int rc;
  char *buf;
  int i;

  rc = gcry_md_open (&md, GCRY_MD_SHA1, 0);
  if (rc)
    log_fatal (_("gcry_md_open failed: %s\n"), gpg_strerror (rc));

  rc = ksba_cert_hash (cert, 0, HASH_FNC, md);
  if (rc)
    {
      log_error (_("oops: ksba_cert_hash failed: %s\n"), gpg_strerror (rc));
      memset (digest, 0xff, 20); /* Use a dummy value. */
    }
  else
    {
      gcry_md_final (md);
      memcpy (digest, gcry_md_read (md, GCRY_MD_SHA1), 20);
    }
  gcry_md_close (md);
  buf = xmalloc (61);
  *buf = 0;
  for (i=0; i < 20; i++ )
    sprintf (buf+strlen(buf), "%02X:", digest[i]);
  buf[strlen(buf)-1] = 0; /* Remove railing colon. */
  return buf;
}


/* Dump the serial number SERIALNO to the log stream.  */
void
dump_serial (ksba_sexp_t serialno)
{
  char *p;

  p = serial_hex (serialno);
  log_printf ("%s", p?p:"?");
  xfree (p);
}


/* Dump STRING to the log file but choose the best readable
   format.  */
void
dump_string (const char *string)
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
          log_printhex (string, strlen (string), NULL);
          log_printf ( " ]");
        }
    }
}

/* Dump an KSBA cert object to the log stream. Prefix the output with
   TEXT.  This is used for debugging. */
void
dump_cert (const char *text, ksba_cert_t cert)
{
  ksba_sexp_t sexp;
  char *p;
  ksba_isotime_t t;
  int idx;

  log_debug ("BEGIN Certificate '%s':\n", text? text:"");
  if (cert)
    {
      sexp = ksba_cert_get_serial (cert);
      p = serial_hex (sexp);
      log_debug ("     serial: %s\n", p?p:"?");
      xfree (p);
      ksba_free (sexp);

      ksba_cert_get_validity (cert, 0, t);
      log_debug ("  notBefore: ");
      dump_isotime (t);
      log_printf ("\n");
      ksba_cert_get_validity (cert, 1, t);
      log_debug ("   notAfter: ");
      dump_isotime (t);
      log_printf ("\n");

      p = ksba_cert_get_issuer (cert, 0);
      log_debug ("     issuer: ");
      dump_string (p);
      ksba_free (p);
      log_printf ("\n");

      p = ksba_cert_get_subject (cert, 0);
      log_debug ("    subject: ");
      dump_string (p);
      ksba_free (p);
      log_printf ("\n");
      for (idx=1; (p = ksba_cert_get_subject (cert, idx)); idx++)
        {
          log_debug ("        aka: ");
          dump_string (p);
          ksba_free (p);
          log_printf ("\n");
        }

      log_debug ("  hash algo: %s\n", ksba_cert_get_digest_algo (cert));

      p = get_fingerprint_hexstring (cert);
      log_debug ("  SHA1 fingerprint: %s\n", p);
      xfree (p);
    }
  log_debug ("END Certificate\n");
}



/* Log the certificate's name in "#SN/ISSUERDN" format along with
   TEXT. */
void
cert_log_name (const char *text, ksba_cert_t cert)
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
          dump_serial (sn);
          log_printf ("/");
          dump_string (p);
        }
      else
        log_printf (" [invalid]");
      ksba_free (sn);
      xfree (p);
    }
  log_printf ("\n");
}


/* Log the certificate's subject DN along with TEXT. */
void
cert_log_subject (const char *text, ksba_cert_t cert)
{
  log_info ("%s", text? text:"subject" );
  if (cert)
    {
      char *p;

      p = ksba_cert_get_subject (cert, 0);
      if (p)
        {
          log_printf (" /");
          dump_string (p);
          xfree (p);
        }
      else
        log_printf (" [invalid]");
    }
  log_printf ("\n");
}


/* Callback to print infos about the TLS certificates.  */
void
cert_log_cb (http_session_t sess, gpg_error_t err,
             const char *hostname, const void **certs, size_t *certlens)
{
  ksba_cert_t cert;
  size_t n;

  (void)sess;

  if (!err)
    return; /* No error - no need to log anything  */

  log_debug ("expected hostname: %s\n", hostname);
  for (n=0; certs[n]; n++)
    {
      err = ksba_cert_new (&cert);
      if (!err)
        err = ksba_cert_init_from_mem (cert, certs[n], certlens[n]);
      if (err)
        log_error ("error parsing cert for logging: %s\n", gpg_strerror (err));
      else
        {
          char textbuf[20];
          snprintf (textbuf, sizeof textbuf, "server[%u]", (unsigned int)n);
          dump_cert (textbuf, cert);
        }

      ksba_cert_release (cert);
    }
}


/****************
 * Remove all %xx escapes; this is done inplace.
 * Returns: New length of the string.
 */
static int
remove_percent_escapes (unsigned char *string)
{
  int n = 0;
  unsigned char *p, *s;

  for (p = s = string; *s; s++)
    {
      if (*s == '%')
        {
          if (s[1] && s[2] && hexdigitp (s+1) && hexdigitp (s+2))
            {
              s++;
              *p = xtoi_2 (s);
              s++;
              p++;
              n++;
            }
          else
            {
              *p++ = *s++;
              if (*s)
                *p++ = *s++;
              if (*s)
                *p++ = *s++;
              if (*s)
                *p = 0;
              return -1;   /* Bad URI. */
            }
        }
      else
        {
          *p++ = *s;
          n++;
        }
    }
  *p = 0;  /* Always keep a string terminator. */
  return n;
}


/* Return the host name and the port (0 if none was given) from the
   URL.  Return NULL on error or if host is not included in the
   URL.  */
char *
host_and_port_from_url (const char *url, int *port)
{
  const char *s, *s2;
  char *buf, *p;
  int n;

  s = url;

  *port = 0;

  /* Find the scheme */
  if ( !(s2 = strchr (s, ':')) || s2 == s )
    return NULL;  /* No scheme given. */
  s = s2+1;

  /* Find the hostname */
  if (*s != '/')
    return NULL; /* Does not start with a slash. */

  s++;
  if (*s != '/')
    return NULL; /* No host name.  */
  s++;

  buf = xtrystrdup (s);
  if (!buf)
    {
      log_error (_("malloc failed: %s\n"), strerror (errno));
      return NULL;
    }
  if ((p = strchr (buf, '/')))
    *p++ = 0;
  strlwr (buf);
  if ((p = strchr (buf, ':')))
    {
      *p++ = 0;
      *port = atoi (p);
    }

  /* Remove quotes and make sure that no Nul has been encoded. */
  if ((n = remove_percent_escapes (buf)) < 0
      || n != strlen (buf) )
    {
      log_error (_("bad URL encoding detected\n"));
      xfree (buf);
      return NULL;
    }

  return buf;
}


/* A KSBA reader callback to read from an estream.  */
static int
my_estream_ksba_reader_cb (void *cb_value, char *buffer, size_t count,
                           size_t *r_nread)
{
  estream_t fp = cb_value;

  if (!fp)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!buffer && !count && !r_nread)
    {
      es_rewind (fp);
      return 0;
    }

  *r_nread = es_fread (buffer, 1, count, fp);
  if (!*r_nread)
    return -1; /* EOF or error.  */
  return 0; /* Success.  */
}


/* Create a KSBA reader object and connect it to the estream FP.  */
gpg_error_t
create_estream_ksba_reader (ksba_reader_t *r_reader, estream_t fp)
{
  gpg_error_t err;
  ksba_reader_t reader;

  *r_reader = NULL;
  err = ksba_reader_new (&reader);
  if (!err)
    err = ksba_reader_set_cb (reader, my_estream_ksba_reader_cb, fp);
  if (err)
    {
      log_error (_("error initializing reader object: %s\n"),
                 gpg_strerror (err));
      ksba_reader_release (reader);
      return err;
    }
  *r_reader = reader;
  return 0;
}

gpg_error_t
armor_data (char **r_string, const void *data, size_t datalen)
{
  gpg_error_t err;
  struct b64state b64state;
  estream_t fp;
  long length;
  char *buffer;
  size_t nread;

  *r_string = NULL;

  fp = es_fopenmem (0, "rw,samethread");
  if (!fp)
    return gpg_error_from_syserror ();

  if ((err=b64enc_start_es (&b64state, fp, "PGP PUBLIC KEY BLOCK"))
      || (err=b64enc_write (&b64state, data, datalen))
      || (err = b64enc_finish (&b64state)))
    {
      es_fclose (fp);
      return err;
    }

  /* FIXME: To avoid the extra buffer allocation estream should
     provide a function to snatch the internal allocated memory from
     such a memory stream.  */
  length = es_ftell (fp);
  if (length < 0)
    {
      err = gpg_error_from_syserror ();
      es_fclose (fp);
      return err;
    }

  buffer = xtrymalloc (length+1);
  if (!buffer)
    {
      err = gpg_error_from_syserror ();
      es_fclose (fp);
      return err;
    }

  es_rewind (fp);
  if (es_read (fp, buffer, length, &nread))
    {
      err = gpg_error_from_syserror ();
      es_fclose (fp);
      return err;
    }
  buffer[nread] = 0;
  es_fclose (fp);

  *r_string = buffer;
  return 0;
}


/* Copy all data from IN to OUT.  OUT may be NULL to use this fucntion
 * as a dummy reader.  */
gpg_error_t
copy_stream (estream_t in, estream_t out)
{
  char buffer[512];
  size_t nread;

  while (!es_read (in, buffer, sizeof buffer, &nread))
    {
      if (!nread)
        return 0; /* EOF */
      if (out && es_write (out, buffer, nread, NULL))
        break;
    }
  return gpg_error_from_syserror ();
}
