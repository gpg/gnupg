/* findkey.c - locate the secret key
 * Copyright (C) 2001, 2002, 2003, 2004, 2005 Free Software Foundation, Inc.
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>
#include <assert.h>

#include "agent.h"

/* Helper to pass data to the check callback of the unprotect function. */
struct try_unprotect_arg_s {
  const unsigned char *protected_key;
  unsigned char *unprotected_key;
};


/* Write an S-expression formatted key to our key storage.  With FORCE
   pased as true an existsing key with the given GRIP will get
   overwritten.  */
int
agent_write_private_key (const unsigned char *grip,
                         const void *buffer, size_t length, int force)
{
  int i;
  char *fname;
  FILE *fp;
  char hexgrip[40+4+1];
  int fd;
  
  for (i=0; i < 20; i++)
    sprintf (hexgrip+2*i, "%02X", grip[i]);
  strcpy (hexgrip+40, ".key");

  fname = make_filename (opt.homedir, GNUPG_PRIVATE_KEYS_DIR, hexgrip, NULL);

  if (!force && !access (fname, F_OK))
    {
      log_error ("secret key file `%s' already exists\n", fname);
      xfree (fname);
      return gpg_error (GPG_ERR_GENERAL);
    }

  /* In FORCE mode we would like to create FNAME but only if it does
     not already exist.  We cannot make this guarantee just using
     POSIX (GNU provides the "x" opentype for fopen, however, this is
     not portable).  Thus, we use the more flexible open function and
     then use fdopen to obtain a stream. */
  fd = open (fname, force? (O_CREAT | O_TRUNC | O_WRONLY)
                         : (O_CREAT | O_EXCL | O_WRONLY),
             S_IRUSR | S_IWUSR 
#ifndef HAVE_W32_SYSTEM
                 | S_IRGRP 
#endif
                 );
  if (fd < 0)
    fp = NULL;
  else
    {
      fp = fdopen (fd, "wb");
      if (!fp)
        { 
          int save_e = errno;
          close (fd);
          errno = save_e;
        }
    }

  if (!fp) 
    { 
      gpg_error_t tmperr = gpg_error (gpg_err_code_from_errno (errno));
      log_error ("can't create `%s': %s\n", fname, strerror (errno));
      xfree (fname);
      return tmperr;
    }

  if (fwrite (buffer, length, 1, fp) != 1)
    {
      gpg_error_t tmperr = gpg_error (gpg_err_code_from_errno (errno));
      log_error ("error writing `%s': %s\n", fname, strerror (errno));
      fclose (fp);
      remove (fname);
      xfree (fname);
      return tmperr;
    }
  if ( fclose (fp) )
    {
      gpg_error_t tmperr = gpg_error (gpg_err_code_from_errno (errno));
      log_error ("error closing `%s': %s\n", fname, strerror (errno));
      remove (fname);
      xfree (fname);
      return tmperr;
    }

  xfree (fname);
  return 0;
}


/* Callback function to try the unprotection from the passpharse query
   code. */
static int
try_unprotect_cb (struct pin_entry_info_s *pi)
{
  struct try_unprotect_arg_s *arg = pi->check_cb_arg;
  size_t dummy;

  assert (!arg->unprotected_key);
  return agent_unprotect (arg->protected_key, pi->pin,
                          &arg->unprotected_key, &dummy);
}


/* Modify a Key description, replacing certain special format
   characters.  List of currently supported replacements:

   %% - Replaced by a single %
   %c - Replaced by the content of COMMENT.

   The functions returns 0 on success or an error code.  On success a
   newly allocated string is stored at the address of RESULT.
 */
static gpg_error_t
modify_description (const char *in, const char *comment, char **result)
{
  size_t comment_length;
  size_t in_len;
  size_t out_len;
  char *out;
  size_t i;
  int special, pass;

  comment_length = strlen (comment);
  in_len  = strlen (in);

  /* First pass calculates the length, second pass does the actual
     copying.  */
  out = NULL;
  out_len = 0;
  for (pass=0; pass < 2; pass++)
    {
      special = 0;
      for (i = 0; i < in_len; i++)
        {
          if (in[i] == '%')
            special = 1;
          else if (special)
            {
              special = 0;
              switch (in[i])
                {
                case '%':
                  if (out)
                    *out++ = '%';
                  else
                    out_len++;
                  break;

                case 'c': /* Comment.  */
                  if (out)
                    {
                      memcpy (out, comment, comment_length);
                      out += comment_length;
                    }
                  else
                    out_len += comment_length;
                  break;

                default: /* Invalid special sequences are ignored.  */
                  break;
                }
            }
          else
            {
              if (out)
                *out++ = in[i];
              else
                out_len++;
            }
        }
      
      if (!pass)
        {
          *result = out = xtrymalloc (out_len + 1);
          if (!out)
            return gpg_error_from_errno (errno);
        }
    }

  *out = 0;
  assert (*result + out_len == out);
  return 0;
}

  

/* Unprotect the canconical encoded S-expression key in KEYBUF.  GRIP
   should be the hex encoded keygrip of that key to be used with the
   caching mechanism. DESC_TEXT may be set to override the default
   description used for the pinentry. */
static int
unprotect (CTRL ctrl, const char *desc_text,
           unsigned char **keybuf, const unsigned char *grip, int ignore_cache)
{
  struct pin_entry_info_s *pi;
  struct try_unprotect_arg_s arg;
  int rc, i;
  unsigned char *result;
  size_t resultlen;
  char hexgrip[40+1];
  
  for (i=0; i < 20; i++)
    sprintf (hexgrip+2*i, "%02X", grip[i]);
  hexgrip[40] = 0;

  /* First try to get it from the cache - if there is none or we can't
     unprotect it, we fall back to ask the user */
  if (!ignore_cache)
    {
      void *cache_marker;
      const char *pw = agent_get_cache (hexgrip, &cache_marker);
      if (pw)
        {
          rc = agent_unprotect (*keybuf, pw, &result, &resultlen);
          agent_unlock_cache_entry (&cache_marker);
          if (!rc)
            {
              xfree (*keybuf);
              *keybuf = result;
              return 0;
            }
          rc  = 0;
        }
    }
  
  pi = gcry_calloc_secure (1, sizeof (*pi) + 100);
  if (!pi)
    return gpg_error_from_errno (errno);
  pi->max_length = 100;
  pi->min_digits = 0;  /* we want a real passphrase */
  pi->max_digits = 8;
  pi->max_tries = 3;
  pi->check_cb = try_unprotect_cb;
  arg.protected_key = *keybuf;
  arg.unprotected_key = NULL;
  pi->check_cb_arg = &arg;

  rc = agent_askpin (ctrl, desc_text, NULL, pi);
  if (!rc)
    {
      assert (arg.unprotected_key);
      agent_put_cache (hexgrip, pi->pin, 0);
      xfree (*keybuf);
      *keybuf = arg.unprotected_key;
    }
  xfree (pi);
  return rc;
}


/* Read the key identified by GRIP from the private key directory and
   return it as an gcrypt S-expression object in RESULT.  On failure
   returns an error code and stores NULL at RESULT. */
static gpg_error_t
read_key_file (const unsigned char *grip, gcry_sexp_t *result)
{
  int i, rc;
  char *fname;
  FILE *fp;
  struct stat st;
  unsigned char *buf;
  size_t buflen, erroff;
  gcry_sexp_t s_skey;
  char hexgrip[40+4+1];
  
  *result = NULL;

  for (i=0; i < 20; i++)
    sprintf (hexgrip+2*i, "%02X", grip[i]);
  strcpy (hexgrip+40, ".key");

  fname = make_filename (opt.homedir, GNUPG_PRIVATE_KEYS_DIR, hexgrip, NULL);
  fp = fopen (fname, "rb");
  if (!fp)
    {
      rc = gpg_error_from_errno (errno);
      log_error ("can't open `%s': %s\n", fname, strerror (errno));
      xfree (fname);
      return rc;
    }
  
  if (fstat (fileno(fp), &st))
    {
      rc = gpg_error_from_errno (errno);
      log_error ("can't stat `%s': %s\n", fname, strerror (errno));
      xfree (fname);
      fclose (fp);
      return rc;
    }

  buflen = st.st_size;
  buf = xtrymalloc (buflen+1);
  if (!buf || fread (buf, buflen, 1, fp) != 1)
    {
      rc = gpg_error_from_errno (errno);
      log_error ("error reading `%s': %s\n", fname, strerror (errno));
      xfree (fname);
      fclose (fp);
      xfree (buf);
      return rc;
    }

  /* Convert the file into a gcrypt S-expression object.  */
  rc = gcry_sexp_sscan (&s_skey, &erroff, buf, buflen);
  xfree (fname);
  fclose (fp);
  xfree (buf);
  if (rc)
    {
      log_error ("failed to build S-Exp (off=%u): %s\n",
                 (unsigned int)erroff, gpg_strerror (rc));
      return rc;
    }
  *result = s_skey;
  return 0;
}


/* Return the secret key as an S-Exp in RESULT after locating it using
   the grip.  Returns NULL in RESULT if the operation should be
   diverted to a token; SHADOW_INFO will point then to an allocated
   S-Expression with the shadow_info part from the file.  With
   IGNORE_CACHE passed as true the passphrase is not taken from the
   cache.  DESC_TEXT may be set to present a custom description for the
   pinentry. */
gpg_error_t
agent_key_from_file (ctrl_t ctrl, const char *desc_text,
                     const unsigned char *grip, unsigned char **shadow_info,
                     int ignore_cache, gcry_sexp_t *result)
{
  int rc;
  unsigned char *buf;
  size_t len, buflen, erroff;
  gcry_sexp_t s_skey;
  int got_shadow_info = 0;
  
  *result = NULL;
  if (shadow_info)
      *shadow_info = NULL;

  rc = read_key_file (grip, &s_skey);
  if (rc)
    return rc;

  /* For use with the protection functions we also need the key as an
     canonical encoded S-expression in abuffer.  Create this buffer
     now.  */
  len = gcry_sexp_sprint (s_skey, GCRYSEXP_FMT_CANON, NULL, 0);
  assert (len);
  buf = xtrymalloc (len);
  if (!buf)
    {
      rc = gpg_error_from_errno (errno);
      gcry_sexp_release (s_skey);
      return rc;
    }
  len = gcry_sexp_sprint (s_skey, GCRYSEXP_FMT_CANON, buf, len);
  assert (len);


  switch (agent_private_key_type (buf))
    {
    case PRIVATE_KEY_CLEAR:
      break; /* no unprotection needed */
    case PRIVATE_KEY_PROTECTED:
      {
	gcry_sexp_t comment_sexp;
	size_t comment_length;
	char *desc_text_final;
	const char *comment = NULL;

        /* Note, that we will take the comment as a C string for
           display purposes; i.e. all stuff beyond a Nul character is
           ignored.  */
	comment_sexp = gcry_sexp_find_token (s_skey, "comment", 0);
	if (comment_sexp)
	  comment = gcry_sexp_nth_data (comment_sexp, 1, &comment_length);
	if (!comment)
	  {
	    comment = "";
	    comment_length = 0;
	  }

        desc_text_final = NULL;
	if (desc_text)
	  {
            if (comment[comment_length])
              {
                /* Not a C-string; create one.  We might here allocate
                   more than actually displayed but well, that
                   shouldn't be a problem.  */
                char *tmp = xtrymalloc (comment_length+1);
                if (!tmp)
                  rc = gpg_error_from_errno (errno);
                else
                  {
                    memcpy (tmp, comment, comment_length);
                    tmp[comment_length] = 0;
                    rc = modify_description (desc_text, tmp, &desc_text_final);
                    xfree (tmp);
                  }
              }
            else
              rc = modify_description (desc_text, comment, &desc_text_final);
	  }

	if (!rc)
	  {
	    rc = unprotect (ctrl, desc_text_final, &buf, grip, ignore_cache);
	    if (rc)
	      log_error ("failed to unprotect the secret key: %s\n",
			 gpg_strerror (rc));
	  }
        
	gcry_sexp_release (comment_sexp);
	xfree (desc_text_final);
      }
      break;
    case PRIVATE_KEY_SHADOWED:
      if (shadow_info)
        {
          const unsigned char *s;
          size_t n;

          rc = agent_get_shadow_info (buf, &s);
          if (!rc)
            {
              n = gcry_sexp_canon_len (s, 0, NULL,NULL);
              assert (n);
              *shadow_info = xtrymalloc (n);
              if (!*shadow_info)
                rc = out_of_core ();
              else
                {
                  memcpy (*shadow_info, s, n);
                  rc = 0;
                  got_shadow_info = 1;
                }
            }
          if (rc)
            log_error ("get_shadow_info failed: %s\n", gpg_strerror (rc));
        }
      else
        rc = gpg_error (GPG_ERR_UNUSABLE_SECKEY);
      break;
    default:
      log_error ("invalid private key format\n");
      rc = gpg_error (GPG_ERR_BAD_SECKEY);
      break;
    }
  gcry_sexp_release (s_skey);
  s_skey = NULL;
  if (rc || got_shadow_info)
    {
      xfree (buf);
      return rc;
    }

  buflen = gcry_sexp_canon_len (buf, 0, NULL, NULL);
  rc = gcry_sexp_sscan (&s_skey, &erroff, buf, buflen);
  wipememory (buf, buflen);
  xfree (buf);
  if (rc)
    {
      log_error ("failed to build S-Exp (off=%u): %s\n",
                 (unsigned int)erroff, gpg_strerror (rc));
      return rc;
    }

  *result = s_skey;
  return 0;
}



/* Return the public key for the keygrip GRIP.  The result is stored
   at RESULT.  This function extracts the public key from the private
   key database.  On failure an error code is returned and NULL stored
   at RESULT. */
gpg_error_t
agent_public_key_from_file (ctrl_t ctrl, 
                            const unsigned char *grip,
                            gcry_sexp_t *result)
{
  int i, idx, rc;
  gcry_sexp_t s_skey;
  const char *algoname;
  gcry_sexp_t uri_sexp, comment_sexp;
  const char *uri, *comment;
  size_t uri_length, comment_length;
  char *format, *p;
  void *args[4+2+2+1]; /* Size is max. # of elements + 2 for uri + 2
                           for comment + end-of-list.  */
  int argidx;
  gcry_sexp_t list, l2;
  const char *name;
  const char *s;
  size_t n;
  const char *elems;
  gcry_mpi_t *array;

  *result = NULL;

  rc = read_key_file (grip, &s_skey);
  if (rc)
    return rc;

  list = gcry_sexp_find_token (s_skey, "shadowed-private-key", 0 );
  if (!list)
    list = gcry_sexp_find_token (s_skey, "protected-private-key", 0 );
  if (!list)
    list = gcry_sexp_find_token (s_skey, "private-key", 0 );
  if (!list)
    {
      log_error ("invalid private key format\n");
      gcry_sexp_release (s_skey);
      return gpg_error (GPG_ERR_BAD_SECKEY);
    }

  l2 = gcry_sexp_cadr (list);
  gcry_sexp_release (list);
  list = l2;
  name = gcry_sexp_nth_data (list, 0, &n);
  if (n==3 && !memcmp (name, "rsa", 3))
    {
      algoname = "rsa";
      elems = "ne";
    }
  else if (n==3 && !memcmp (name, "dsa", 3))
    {
      algoname = "dsa";
      elems = "pqgy";
    }
  else if (n==3 && !memcmp (name, "elg", 3))
    {
      algoname = "elg";
      elems = "pgy";
    }
  else
    {
      log_error ("unknown private key algorithm\n");
      gcry_sexp_release (list);
      gcry_sexp_release (s_skey);
      return gpg_error (GPG_ERR_BAD_SECKEY);
    }

  /* Allocate an array for the parameters and copy them out of the
     secret key.   FIXME: We should have a generic copy function. */
  array = xtrycalloc (strlen(elems) + 1, sizeof *array);
  if (!array)
    {
      rc = gpg_error_from_errno (errno);
      gcry_sexp_release (list);
      gcry_sexp_release (s_skey);
      return rc;
    }

  for (idx=0, s=elems; *s; s++, idx++ ) 
    {
      l2 = gcry_sexp_find_token (list, s, 1);
      if (!l2)
        {
          /* Required parameter not found.  */
          for (i=0; i<idx; i++)
            gcry_mpi_release (array[i]);
          xfree (array);
          gcry_sexp_release (list);
          gcry_sexp_release (s_skey);
          return gpg_error (GPG_ERR_BAD_SECKEY);
	}
      array[idx] = gcry_sexp_nth_mpi (l2, 1, GCRYMPI_FMT_USG);
      gcry_sexp_release (l2);
      if (!array[idx])
        {
          /* Required parameter is invalid. */
          for (i=0; i<idx; i++)
            gcry_mpi_release (array[i]);
          xfree (array);
          gcry_sexp_release (list);
          gcry_sexp_release (s_skey);
          return gpg_error (GPG_ERR_BAD_SECKEY);
	}
    }
  gcry_sexp_release (list);
  list = NULL;

  uri = NULL;
  uri_length = 0;
  uri_sexp = gcry_sexp_find_token (s_skey, "uri", 0);
  if (uri_sexp)
    uri = gcry_sexp_nth_data (uri_sexp, 1, &uri_length);

  comment = NULL;
  comment_length = 0;
  comment_sexp = gcry_sexp_find_token (s_skey, "comment", 0);
  if (comment_sexp)
    comment = gcry_sexp_nth_data (comment_sexp, 1, &comment_length);

  gcry_sexp_release (s_skey);
  s_skey = NULL;


  /* FIXME: The following thing is pretty ugly code; we should
     investigate how to make it cleaner. Probably code to handle
     canonical S-expressions in a memory buffer is better suioted for
     such a task.  After all that is what we do in protect.c.  Neeed
     to find common patterns and write a straightformward API to use
     them.  */
  assert (sizeof (size_t) <= sizeof (void*));

  format = xtrymalloc (15+7*strlen (elems)+10+15+1+1);
  if (!format)
    {
      rc = gpg_error_from_errno (errno);
      for (i=0; array[i]; i++)
        gcry_mpi_release (array[i]);
      xfree (array);
      gcry_sexp_release (uri_sexp);
      gcry_sexp_release (comment_sexp);
      return rc;
    }

  argidx = 0;
  p = stpcpy (stpcpy (format, "(public-key("), algoname);
  for (idx=0, s=elems; *s; s++, idx++ ) 
    {
      *p++ = '(';
      *p++ = *s;
      p = stpcpy (p, " %m)");
      assert (argidx < DIM (args));
      args[argidx++] = array[idx];
    }
  *p++ = ')';
  if (uri)
    {
      p = stpcpy (p, "(uri %b)");
      assert (argidx+1 < DIM (args));
      args[argidx++] = (void *)uri_length;
      args[argidx++] = (void *)uri;
    }
  if (comment)
    {
      p = stpcpy (p, "(comment %b)");
      assert (argidx+1 < DIM (args));
      args[argidx++] = (void *)comment_length;
      args[argidx++] = (void*)comment;
    }
  *p++ = ')';
  *p = 0;
  assert (argidx < DIM (args));
  args[argidx] = NULL;
    
  rc = gcry_sexp_build_array (&list, NULL, format, args);
  xfree (format);
  for (i=0; array[i]; i++)
    gcry_mpi_release (array[i]);
  xfree (array);
  gcry_sexp_release (uri_sexp);
  gcry_sexp_release (comment_sexp);

  if (!rc)
    *result = list;
  return rc;
}



/* Return the secret key as an S-Exp after locating it using the grip.
   Returns NULL if key is not available. 0 = key is available */
int
agent_key_available (const unsigned char *grip)
{
  int i;
  char *fname;
  char hexgrip[40+4+1];
  
  for (i=0; i < 20; i++)
    sprintf (hexgrip+2*i, "%02X", grip[i]);
  strcpy (hexgrip+40, ".key");

  fname = make_filename (opt.homedir, GNUPG_PRIVATE_KEYS_DIR, hexgrip, NULL);
  i = !access (fname, R_OK)? 0 : -1;
  xfree (fname);
  return i;
}



