/* command-ssh.c - gpg-agent's ssh-agent emulation layer
 * Copyright (C) 2004, 2005 Free Software Foundation, Inc.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA
 */

#include <config.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdio.h>

#include "agent.h"

#include <gcrypt.h>

#include "estream.h"



/* Request types. */
#define SSH_REQUEST_REQUEST_IDENTITIES    11
#define SSH_REQUEST_SIGN_REQUEST          13
#define SSH_REQUEST_ADD_IDENTITY          17
#define SSH_REQUEST_REMOVE_IDENTITY       18
#define SSH_REQUEST_REMOVE_ALL_IDENTITIES 19
#define SSH_REQUEST_LOCK                  22
#define SSH_REQUEST_UNLOCK                23
#define SSH_REQUEST_ADD_ID_CONSTRAINED    25

/* Options. */
#define	SSH_OPT_CONSTRAIN_LIFETIME	   1
#define	SSH_OPT_CONSTRAIN_CONFIRM	   2

/* Response types. */
#define SSH_RESPONSE_SUCCESS               6
#define SSH_RESPONSE_FAILURE               5
#define SSH_RESPONSE_IDENTITIES_ANSWER    12
#define SSH_RESPONSE_SIGN_RESPONSE        14




/* Basic types.  */

/* A "byte".  */
typedef unsigned char byte_t;

typedef int (*ssh_request_handler_t) (ctrl_t ctrl,
				      estream_t request, estream_t response);

typedef struct ssh_request_spec
{
  byte_t type;
  ssh_request_handler_t handler;
} ssh_request_spec_t;

typedef gpg_error_t (*ssh_key_modifier_t) (const char *elems, gcry_mpi_t *mpis);
typedef gpg_error_t (*ssh_signature_encoder_t) (estream_t signature_blob,
						gcry_mpi_t *mpis);

typedef struct ssh_key_type_spec
{
  const char *ssh_identifier;
  const char *identifier;
  const char *elems_key_secret;
  const char *elems_key_public;
  const char *elems_secret;
  const char *elems_signature;
  const char *elems_sexp_order;
  ssh_key_modifier_t key_modifier;
  ssh_signature_encoder_t signature_encoder;
  unsigned int flags;
} ssh_key_type_spec_t;



static uint32_t lifetime_default;

/* General utility functions.  */

static void *
realloc_secure (void *a, size_t n)
{
  void *p;
  
  if (a)
    p = gcry_realloc (a, n);
  else
    p = gcry_malloc_secure (n);
  
  return p;
}

/* Primitive I/O functions.  */

static gpg_error_t
es_read_byte (estream_t stream, byte_t *b)
{
  gpg_error_t err;
  int ret;

  ret = es_fgetc (stream);
  if (ret == EOF)
    {
      if (es_ferror (stream))
	err = gpg_error_from_errno (errno);
      else
	err = gpg_error (GPG_ERR_EOF);
    }
  else
    {
      *b = ret & 0xFF;
      err = 0;
    }

  return err;
}

static gpg_error_t
es_write_byte (estream_t stream, byte_t b)
{
  gpg_error_t err;
  int ret;

  ret = es_fputc (b, stream);
  if (ret == EOF)
    err = gpg_error_from_errno (errno);
  else
    err = 0;

  return err;
}

static gpg_error_t
es_read_uint32 (estream_t stream, uint32_t *uint32)
{
  unsigned char buffer[4];
  size_t bytes_read;
  gpg_error_t err;
  int ret;

  ret = es_read (stream, buffer, sizeof (buffer), &bytes_read);
  if (ret)
    err = gpg_error_from_errno (errno);
  else
    {
      if (bytes_read != sizeof (buffer))
	err = gpg_error (GPG_ERR_EOF);
      else
	{
	  uint32_t n;

	  n = (0
	       | ((uint32_t) (buffer[0] << 24))
	       | ((uint32_t) (buffer[1] << 16))
	       | ((uint32_t) (buffer[2] <<  8))
	       | ((uint32_t) (buffer[3] <<  0)));
	  *uint32 = n;
	  err = 0;
	}
    }

  return err;
}

static gpg_error_t
es_write_uint32 (estream_t stream, uint32_t uint32)
{
  unsigned char buffer[4];
  gpg_error_t err;
  int ret;

  buffer[0] = (uint32 >> 24) & 0xFF;
  buffer[1] = (uint32 >> 16) & 0xFF;
  buffer[2] = (uint32 >>  8) & 0xFF;
  buffer[3] = (uint32 >>  0) & 0xFF;

  ret = es_write (stream, buffer, sizeof (buffer), NULL);
  if (ret)
    err = gpg_error_from_errno (errno);
  else
    err = 0;

  return err;
}

static gpg_error_t
es_read_data (estream_t stream, unsigned char *buffer, size_t size)
{
  gpg_error_t err;
  size_t bytes_read;
  int ret;

  ret = es_read (stream, buffer, size, &bytes_read);
  if (ret)
    err = gpg_error_from_errno (errno);
  else
    {
      if (bytes_read != size)
	err = gpg_error (GPG_ERR_EOF);
      else
	err = 0;
    }

  return err;
}

static gpg_error_t
es_write_data (estream_t stream, const unsigned char *buffer, size_t size)
{
  gpg_error_t err;
  int ret;

  ret = es_write (stream, buffer, size, NULL);
  if (ret)
    err = gpg_error_from_errno (errno);
  else
    err = 0;

  return err;
}

static gpg_error_t
es_read_string (estream_t stream, unsigned int secure,
		unsigned char **string, uint32_t *string_size)
{
  gpg_error_t err;
  unsigned char *buffer;
  uint32_t length;

  buffer = NULL;

  /* Read string length.  */
  err = es_read_uint32 (stream, &length);
  if (err)
    goto out;

  /* Allocate space.  */
  if (secure)
    buffer = xtrymalloc_secure (length + 1);
  else
    buffer = xtrymalloc (length + 1);
  if (! buffer)
    {
      /* FIXME: xtrymalloc_secure does not set errno, does it?  */
      err = gpg_error_from_errno (errno);
      abort ();
      goto out;
    }

  /* Read data.  */
  err = es_read_data (stream, buffer, length);
  if (err)
    goto out;

  /* Finalize string object.  */
  buffer[length] = 0;
  *string = buffer;
  if (string_size)
    *string_size = length;

 out:

  if (err)
    xfree (buffer);

  return err;
}

static gpg_error_t
es_read_cstring (estream_t stream, char **string)
{
  unsigned char *buffer;
  gpg_error_t err;

  err = es_read_string (stream, 0, &buffer, NULL);
  if (err)
    goto out;
  
  *string = (char *) buffer;

 out:

  return err;
}

static gpg_error_t
es_write_string (estream_t stream,
		 const unsigned char *string, uint32_t string_n)
{
  gpg_error_t err;

  err = es_write_uint32 (stream, string_n);
  if (err)
    goto out;

  err = es_write_data (stream, string, string_n);

 out:

  return err;
}

static gpg_error_t
es_write_cstring (estream_t stream, const char *string)
{
  gpg_error_t err;

  err = es_write_string (stream,
			 (const unsigned char *) string, strlen (string));

  return err;
}			  

static gpg_error_t
es_read_mpi (estream_t stream, unsigned int secure, gcry_mpi_t *mpint)
{
  unsigned char *mpi_data;
  uint32_t mpi_data_size;
  gpg_error_t err;
  gcry_mpi_t mpi;

  mpi_data = NULL;

  err = es_read_string (stream, secure, &mpi_data, &mpi_data_size);
  if (err)
    goto out;

  err = gcry_mpi_scan (&mpi, GCRYMPI_FMT_STD, mpi_data, mpi_data_size, NULL);
  if (err)
    goto out;

  *mpint = mpi;

 out:

  xfree (mpi_data);

  return err;
}

static gpg_error_t
es_write_mpi (estream_t stream, gcry_mpi_t mpint)
{
  unsigned char *mpi_buffer;
  size_t mpi_buffer_n;
  gpg_error_t err;

  mpi_buffer = NULL;

  err = gcry_mpi_aprint (GCRYMPI_FMT_STD, &mpi_buffer, &mpi_buffer_n, mpint);
  if (err)
    goto out;

  err = es_write_string (stream, mpi_buffer, mpi_buffer_n);

 out:

  xfree (mpi_buffer);

  return err;
}

static gpg_error_t
es_read_file (const char *filename, unsigned char **buffer, size_t *buffer_n)
{
  unsigned char *buffer_new;
  struct stat statbuf;
  estream_t stream;
  gpg_error_t err;
  int ret;

  buffer_new = NULL;
  err = 0;
  
  stream = es_fopen (filename, "r");
  if (! stream)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  ret = fstat (es_fileno (stream), &statbuf);
  if (ret)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  buffer_new = xtrymalloc (statbuf.st_size);
  if (! buffer_new)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  err = es_read_data (stream, buffer_new, statbuf.st_size);
  if (err)
    goto out;

  *buffer = buffer_new;
  *buffer_n = statbuf.st_size;

 out:

  if (stream)
    es_fclose (stream);

  if (err)
    xfree (buffer_new);

  return err;
}

static gpg_error_t
es_copy (estream_t dst, estream_t src)
{
  char buffer[BUFSIZ];
  size_t bytes_read;
  gpg_error_t err;
  int ret;

  err = 0;
  while (1)
    {
      ret = es_read (src, buffer, sizeof (buffer), &bytes_read);
      if (ret || (! bytes_read))
	{
	  if (ret)
	    err = gpg_error_from_errno (errno);
	  break;
	}
      ret = es_write (dst, buffer, bytes_read, NULL);
      if (ret)
	{
	  err = gpg_error_from_errno (errno);
	  break;
	}
    }

  return err;
}



/* MPI lists.  */

static void
mpint_list_free (gcry_mpi_t *mpi_list)
{
  if (mpi_list)
    {
      unsigned int i;

      for (i = 0; mpi_list[i]; i++)
	gcry_mpi_release (mpi_list[i]);
      xfree (mpi_list);
    }
}

static gpg_error_t
ssh_receive_mpint_list (estream_t stream, int secret,
			ssh_key_type_spec_t key_spec, gcry_mpi_t **mpi_list)
{
  const char *elems_secret;
  const char *elems;
  unsigned int elems_n;
  gcry_mpi_t *mpis;
  unsigned int i;
  gpg_error_t err;
  int elem_is_secret;

  mpis = NULL;
  err = 0;
  
  if (secret)
    {
      elems = key_spec.elems_key_secret;
      elems_secret = key_spec.elems_secret;
    }
  else
    {
      elems = key_spec.elems_key_public;
      elems_secret = "";
    }
  elems_n = strlen (elems);

  mpis = xtrymalloc (sizeof (*mpis) * (elems_n + 1));
  if (! mpis)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }
  
  memset (mpis, 0, sizeof (*mpis) * (elems_n + 1));
  
  for (i = 0; i < elems_n; i++)
    {
      elem_is_secret = strchr (elems_secret, elems[i]) ? 1 : 0;
      err = es_read_mpi (stream, elem_is_secret, &mpis[i]);
      if (err)
	break;
    }
  if (err)
    goto out;

  *mpi_list = mpis;

 out:

  if (err)
    mpint_list_free (mpis);

  return err;
}



static gpg_error_t
ssh_key_modifier_rsa (const char *elems, gcry_mpi_t *mpis)
{
  gcry_mpi_t p;
  gcry_mpi_t q;
  gcry_mpi_t u;

  if (strcmp (elems, "nedupq"))
    /* Modifying only necessary for secret keys.  */
    goto out;

  u = mpis[3];
  p = mpis[4];
  q = mpis[5];

  if (gcry_mpi_cmp (p, q) > 0)
    {
      /* P shall be smaller then Q!  Swap primes.  iqmp becomes u.  */
      gcry_mpi_t tmp;

      tmp = mpis[4];
      mpis[4] = mpis[5];
      mpis[5] = tmp;
    }
  else
    /* U needs to be recomputed.  */
    gcry_mpi_invm (u, p, q);

 out:

  return 0;
}

static gpg_error_t
ssh_signature_encoder_rsa (estream_t signature_blob, gcry_mpi_t *mpis)
{
  unsigned char *data;
  size_t data_n;
  gpg_error_t err;
  gcry_mpi_t s;

  s = mpis[0];

  err = gcry_mpi_aprint (GCRYMPI_FMT_USG, &data, &data_n, s);
  if (err)
    goto out;

  err = es_write_string (signature_blob, data, data_n);
  xfree (data);

 out:

  return err;
}

#define SSH_DSA_SIGNATURE_PADDING 20
#define SSH_DSA_SIGNATURE_ELEMS    2

static gpg_error_t
ssh_signature_encoder_dsa (estream_t signature_blob, gcry_mpi_t *mpis)
{
  unsigned char buffer[SSH_DSA_SIGNATURE_PADDING * SSH_DSA_SIGNATURE_ELEMS];
  unsigned char *data;
  size_t data_n;
  gpg_error_t err;
  int i;

  data = NULL;

  for (i = 0; i < 2; i++)
    {
      err = gcry_mpi_aprint (GCRYMPI_FMT_USG, &data, &data_n, mpis[i]);
      if (err)
	break;

      if (data_n > SSH_DSA_SIGNATURE_PADDING)
	{
	  err = gpg_error (GPG_ERR_INTERNAL); /* FIXME?  */
	  break;
	}
      
      memset (buffer + (i * SSH_DSA_SIGNATURE_PADDING), 0,
	      SSH_DSA_SIGNATURE_PADDING - data_n);
      memcpy (buffer + (i * SSH_DSA_SIGNATURE_PADDING)
	      + (SSH_DSA_SIGNATURE_PADDING - data_n), data, data_n);

      xfree (data);
      data = NULL;
    }
  if (err)
    goto out;

  err = es_write_string (signature_blob, buffer, sizeof (buffer));

 out:

  xfree (data);

  return err;
}

#define SPEC_FLAG_USE_PKCS1V2 (1 << 0)


/* Table holding key type specifications.  */
static ssh_key_type_spec_t ssh_key_types[] =
  {
    {
      "ssh-rsa", "rsa", "nedupq", "en",   "dupq", "s",  "nedpqu",
      ssh_key_modifier_rsa, ssh_signature_encoder_rsa,
      SPEC_FLAG_USE_PKCS1V2
    },
    {
      "ssh-dss", "dsa", "pqgyx",  "pqgy", "x",    "rs", "pqgyx",
      NULL,                 ssh_signature_encoder_dsa,
      0
    },
  };



/* S-Expressions.  */

static gpg_error_t
ssh_sexp_construct (gcry_sexp_t *sexp,
		    ssh_key_type_spec_t key_spec, int secret,
		    gcry_mpi_t *mpis, const char *comment)
{
  gcry_sexp_t sexp_new;
  char *sexp_template;
  size_t sexp_template_n;
  gpg_error_t err;
  const char *elems;
  size_t elems_n;
  unsigned int i;
  unsigned int j;
  void **arg_list;

  err = 0;
  sexp_new = NULL;
  arg_list = NULL;
  if (secret)
    elems = key_spec.elems_sexp_order;
  else
    elems = key_spec.elems_key_public;
  elems_n = strlen (elems);

  sexp_template_n = 33 + strlen (key_spec.identifier) + (elems_n * 6) - (! secret);
  sexp_template = xtrymalloc (sexp_template_n);
  if (! sexp_template)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  arg_list = xtrymalloc (sizeof (*arg_list) * (elems_n + 1));
  if (! arg_list)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  sprintf (sexp_template, "(%s-key (%s ",
	   secret ? "private" : "public", key_spec.identifier);
  for (i = 0; i < elems_n; i++)
    {
      sprintf (strchr (sexp_template, 0), "(%c %%m)", elems[i]);
      if (secret)
	{
	  for (j = 0; j < elems_n; j++)
	    if (key_spec.elems_key_secret[j] == elems[i])
	      break;
	}
      else
	j = i;
      arg_list[i] = &mpis[j];
    }
  arg_list[i] = &comment;
  sprintf (strchr (sexp_template, 0), ") (comment %%s))");

  err = gcry_sexp_build_array (&sexp_new, NULL, sexp_template, arg_list);
  if (err)
    goto out;

  *sexp = sexp_new;

 out:

  xfree (arg_list);
  xfree (sexp_template);

  return err;
}

static gpg_error_t
ssh_sexp_extract (gcry_sexp_t sexp,
		  ssh_key_type_spec_t key_spec, int *secret,
		  gcry_mpi_t **mpis, const char **comment)
{
  gpg_error_t err;
  gcry_sexp_t value_list;
  gcry_sexp_t value_pair;
  gcry_sexp_t comment_list;
  unsigned int i;
  char *comment_new;
  const char *data;
  size_t data_n;
  int is_secret;
  size_t elems_n;
  const char *elems;
  gcry_mpi_t *mpis_new;
  gcry_mpi_t mpi;

  err = 0;
  value_list = NULL;
  value_pair = NULL;
  comment_list = NULL;
  comment_new = NULL;
  mpis_new = NULL;

  data = gcry_sexp_nth_data (sexp, 0, &data_n);
  if (! data)
    {
      err = gpg_error (GPG_ERR_INV_SEXP);
      goto out;
    }

  if ((data_n == 10) && (! strncmp (data, "public-key", 10)))
    {
      is_secret = 0;
      elems = key_spec.elems_key_public;
    }
  else if (((data_n == 11) && (! strncmp (data, "private-key", 11)))
	   || ((data_n == 21) && (! strncmp (data, "protected-private-key", 21))))
    {
      is_secret = 1;
      elems = key_spec.elems_key_secret;
    }
  else
    {
      err = gpg_error (GPG_ERR_INV_SEXP);
      goto out;
    }

  elems_n = strlen (elems);
  mpis_new = xtrymalloc (sizeof (*mpis_new) * (elems_n + 1));
  if (! mpis_new)
    {
      err = gpg_error_from_errno (errno); /* FIXME, xtrymalloc+errno.  */
      goto out;
    }
  memset (mpis_new, 0, sizeof (*mpis_new) * (elems_n + 1));

  value_list = gcry_sexp_find_token (sexp, key_spec.identifier, 0);
  if (! value_list)
    {
      err = gpg_error (GPG_ERR_INV_SEXP);
      goto out;
    }

  for (i = 0; i < elems_n; i++)
    {
      value_pair = gcry_sexp_find_token (value_list, elems + i, 1);
      if (! value_pair)
	{
	  err = gpg_error (GPG_ERR_INV_SEXP);
	  break;
	}

      mpi = gcry_sexp_nth_mpi (value_pair, 1, GCRYMPI_FMT_USG);
      if (! mpi)
	{
	  err = gpg_error (GPG_ERR_INV_SEXP);
	  break;
	}
      mpis_new[i] = mpi;
      gcry_sexp_release (value_pair);
      value_pair = NULL;
    }
  if (err)
    goto out;

  /* We do not require a comment sublist to be present here.  */
  data = NULL;
  data_n = 0;

  comment_list = gcry_sexp_find_token (sexp, "comment", 0);
  if (comment_list)
    data = gcry_sexp_nth_data (comment_list, 1, &data_n);
  if (! data)
    {
      data = "(none)";
      data_n = 6;
    }

  comment_new = xtrymalloc (data_n + 1);
  if (! comment_new)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }
  strncpy (comment_new, data, data_n);
  comment_new[data_n] = 0;

  if (secret)
    *secret = is_secret;
  *mpis = mpis_new;
  *comment = comment_new;

 out:

  gcry_sexp_release (value_list);
  gcry_sexp_release (value_pair);
  gcry_sexp_release (comment_list);
  
  if (err)
    {
      xfree (comment_new);
      mpint_list_free (mpis_new);
    }

  return err;
}

static gpg_error_t
ssh_sexp_extract_key_type (gcry_sexp_t sexp, const char **key_type)
{
  gcry_sexp_t sublist;
  char *key_type_new;
  const char *data;
  size_t data_n;
  gpg_error_t err;

  err = 0;
  key_type_new = NULL;
  
  sublist = gcry_sexp_nth (sexp, 1);
  if (! sublist)
    {
      err = gpg_error (GPG_ERR_INV_SEXP);
      goto out;
    }

  data = gcry_sexp_nth_data (sublist, 0, &data_n);
  if (! data)
    {
      err = gpg_error (GPG_ERR_INV_SEXP);
      goto out;
    }

  key_type_new = xtrymalloc (data_n + 1);
  if (! key_type_new)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  strncpy (key_type_new, data, data_n);
  key_type_new[data_n] = 0;
  *key_type = key_type_new;

 out:

  gcry_sexp_release (sublist);

  return err;
}



/* Key I/O.  */

static gpg_error_t
ssh_key_type_lookup (const char *ssh_name, const char *name,
		     ssh_key_type_spec_t *spec)
{
  gpg_error_t err;
  unsigned int i;

  for (i = 0; i < DIM (ssh_key_types); i++)
    if ((ssh_name && (! strcmp (ssh_name, ssh_key_types[i].ssh_identifier)))
	|| (name && (! strcmp (name, ssh_key_types[i].identifier))))
      break;
  
  if (i == DIM (ssh_key_types))
    err = gpg_error (GPG_ERR_NOT_FOUND);
  else
    {
      *spec = ssh_key_types[i];
      err = 0;
    }

  return err;
}

static gpg_error_t
ssh_receive_key (estream_t stream, gcry_sexp_t *key_new, int secret, int read_comment,
		 ssh_key_type_spec_t *key_spec)
{
  gpg_error_t err;
  char *key_type;
  char *comment;
  gcry_sexp_t key;
  ssh_key_type_spec_t spec;
  gcry_mpi_t *mpi_list;
  const char *elems;

  mpi_list = NULL;
  key_type = NULL;
  comment = "";
  key = NULL;
  	
  err = es_read_cstring (stream, &key_type);
  if (err)
    goto out;

  err = ssh_key_type_lookup (key_type, NULL, &spec);
  if (err)
    goto out;

  err = ssh_receive_mpint_list (stream, secret, spec, &mpi_list);
  if (err)
    goto out;

  if (read_comment)
    {
      err = es_read_cstring (stream, &comment);
      if (err)
	goto out;
    }

  if (secret)
    elems = spec.elems_key_secret;
  else
    elems = spec.elems_key_public;

  if (spec.key_modifier)
    {
      err = (*spec.key_modifier) (elems, mpi_list);
      if (err)
	goto out;
    }

  err = ssh_sexp_construct (&key, spec, secret, mpi_list, comment);
  if (err)
    goto out;

  if (key_spec)
    *key_spec = spec;
  *key_new = key;
  
 out:

  mpint_list_free (mpi_list);
  xfree (key_type);
  if (read_comment)
    xfree (comment);

  return err;
}

static gpg_error_t
ssh_convert_key_to_blob (unsigned char **blob, size_t *blob_size,
			 const char *type, gcry_mpi_t *mpis)
{
  unsigned char *blob_new;
  long int blob_size_new;
  estream_t stream;
  gpg_error_t err;
  unsigned int i;

  blob_new = NULL;
  stream = NULL;
  err = 0;

  stream = es_mopen (NULL, 0, 0, 1, NULL, NULL, "r+");
  if (! stream)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  err = es_write_cstring (stream, type);
  if (err)
    goto out;

  for (i = 0; mpis[i] && (! err); i++)
    err = es_write_mpi (stream, mpis[i]);
  if (err)
    goto out;

  blob_size_new = es_ftell (stream);
  if (blob_size_new == -1)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }
  
  err = es_fseek (stream, 0, SEEK_SET);
  if (err)
    goto out;

  blob_new = xtrymalloc (blob_size_new);
  if (! blob_new)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  err = es_read_data (stream, blob_new, blob_size_new);
  if (err)
    goto out;

  *blob = blob_new;
  *blob_size = blob_size_new;

 out:

  if (stream)
    es_fclose (stream);
  if (err)
    xfree (blob_new);

  return err;
}
			      

static gpg_error_t
ssh_send_key_public (estream_t stream, gcry_sexp_t key_public)
{
  ssh_key_type_spec_t spec;
  gcry_mpi_t *mpi_list;
  const char *key_type;
  const char *comment;
  unsigned char *blob;
  size_t blob_n;
  gpg_error_t err;

  key_type = NULL;
  mpi_list = NULL;
  comment = NULL;
  blob = NULL;

  err = ssh_sexp_extract_key_type (key_public, &key_type);
  if (err)
    goto out;

  err = ssh_key_type_lookup (NULL, key_type, &spec);
  if (err)
    goto out;

  err = ssh_sexp_extract (key_public, spec, NULL, &mpi_list, &comment);
  if (err)
    goto out;

  err = ssh_convert_key_to_blob (&blob, &blob_n, spec.ssh_identifier, mpi_list);
  if (err)
    goto out;
  
  err = es_write_string (stream, blob, blob_n);
  if (err)
    goto out;

  err = es_write_cstring (stream, comment);
  
 out:

  mpint_list_free (mpi_list);
  xfree ((void *) key_type);
  xfree ((void *) comment);
  xfree (blob);

  return err;
}

static gpg_error_t
ssh_read_key_public_from_blob (unsigned char *blob, size_t blob_size,
			       gcry_sexp_t *key_public,
			       ssh_key_type_spec_t *key_spec)
{
  estream_t blob_stream;
  gpg_error_t err;

  err = 0;
  
  blob_stream = es_mopen (NULL, 0, 0, 1, NULL, NULL, "r+");
  if (! blob_stream)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  err = es_write_data (blob_stream, blob, blob_size);
  if (err)
    goto out;

  err = es_fseek (blob_stream, 0, SEEK_SET);
  if (err)
    goto out;

  err = ssh_receive_key (blob_stream, key_public, 0, 0, key_spec);

 out:

  if (blob_stream)
    es_fclose (blob_stream);

  return err;
}



static gpg_error_t
key_secret_to_public (gcry_sexp_t *key_public,
		      ssh_key_type_spec_t spec, gcry_sexp_t key_secret)
{
  gpg_error_t err;
  gcry_sexp_t value_pair;
  unsigned int i;
  gcry_mpi_t *mpis;
  gcry_mpi_t mpi;
  void **arglist;
  size_t elems_n;
  char *template;
  size_t template_n;
  const char *elems;
  char *comment;
  const char *data;
  size_t data_n;

  err = 0;
  mpis = NULL;
  arglist = NULL;
  comment = NULL;
  template = NULL;
  value_pair = NULL;

  elems = spec.elems_key_public;
  elems_n = strlen (elems);

  data = NULL;
  value_pair  = gcry_sexp_find_token (key_secret, "comment", 0);
  if (value_pair)
    data = gcry_sexp_nth_data (value_pair, 1, &data_n);
  if (! data)
    {
      data = "";
      data_n = 0;
    }

  comment = xtrymalloc (data_n + 1);
  if (! comment)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }
  strncpy (comment, data, data_n);
  comment[data_n] = 0;

  gcry_sexp_release (value_pair);
  value_pair = NULL;
  
  template_n = 29 + strlen (spec.identifier) + (elems_n * 7) + 1;
  template = xtrymalloc (template_n);
  if (! template)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  mpis = xtrymalloc (sizeof (*mpis) * (elems_n + 1));
  if (! mpis)
    {
      err = gpg_error_from_errno (errno);	/* FIXME: errno.  */
      goto out;
    }
  memset (mpis, 0, sizeof (*mpis) * (elems_n + 1));

  arglist = xtrymalloc (sizeof (*arglist) * (elems_n + 1));
  if (! arglist)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  for (i = 0; i < elems_n; i++)
    {
      value_pair = gcry_sexp_find_token (key_secret, elems + i, 1);
      if (! value_pair)
	{
	  err = gpg_error (GPG_ERR_INV_SEXP);
	  break;
	}
      mpi = gcry_sexp_nth_mpi (value_pair, 1, GCRYMPI_FMT_USG);
      if (! mpi)
	{
	  err = gpg_error (GPG_ERR_INV_SEXP);
	  break;
	}
      gcry_sexp_release (value_pair);
      value_pair = NULL;

      mpis[i] = mpi;
      arglist[i] = &mpis[i];
      mpi = NULL;
    }
  if (err)
    goto out;

  sprintf (template, "(public-key (%s", spec.identifier);
  for (i = 0; i < elems_n; i++)
    sprintf (strchr (template, 0)," (%c %%m)", elems[i]);
  sprintf (strchr (template, 0), ") (comment %%s))");
  arglist[i] = &comment;

  err = gcry_sexp_build_array (key_public, NULL, template, arglist);
  
 out:

  gcry_sexp_release (value_pair);
  xfree (template);
  mpint_list_free (mpis);
  xfree (arglist);
  xfree (comment);

  return err;
}



static char *
make_cstring (const char *data, size_t data_n)
{
  char *s;

  s = xtrymalloc (data_n + 1);
  if (s)
    {
      strncpy (s, data, data_n);
      s[data_n] = 0;
    }

  return s;
}



/* Request handler.  */

static int
ssh_handler_request_identities (ctrl_t ctrl, estream_t request, estream_t response)
{
  const char *key_type;
  ssh_key_type_spec_t spec;
  struct dirent *dir_entry;
  char *key_directory;
  size_t key_directory_n;
  char *key_path;
  unsigned char *buffer;
  size_t buffer_n;
  uint32_t key_counter;
  estream_t key_blobs;
  gcry_sexp_t key_secret;
  gcry_sexp_t key_public;
  DIR *dir;
  gpg_error_t err;
  int ret;
  int bad;

  if (DBG_COMMAND)
    log_debug ("[ssh-agent] request identities\n");

  /* Prepare buffer stream.  */

  key_directory = NULL;
  key_secret = NULL;
  key_public = NULL;
  key_type = NULL;
  key_path = NULL;
  key_counter = 0;
  buffer = NULL;
  dir = NULL;
  bad = 0;
  err = 0;

  key_blobs = es_mopen (NULL, 0, 0, 1, NULL, NULL, "r+");
  if (! key_blobs)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  /* Open key directory.  */
  key_directory = make_filename (opt.homedir, GNUPG_PRIVATE_KEYS_DIR, NULL);
  if (! key_directory)
    {
      err = gpg_err_code_from_errno (errno);
      goto out;
    }
  key_directory_n = strlen (key_directory);
  
  key_path = xtrymalloc (key_directory_n + 46);
  if (! key_path)
    {
      err = gpg_err_code_from_errno (errno);
      goto out;
    }

  sprintf (key_path, "%s/", key_directory);
  sprintf (key_path + key_directory_n + 41, ".key");

  dir = opendir (key_directory);
  if (! dir)
    {
      err = gpg_err_code_from_errno (errno);
      goto out;
    }

  /* Iterate over key files.  */

  /* FIXME: make sure that buffer gets deallocated properly.  */

  while (1)
    {
      dir_entry = readdir (dir);
      if (dir_entry)
	{
	  if ((strlen (dir_entry->d_name) == 44)
	      && (! strncmp (dir_entry->d_name + 40, ".key", 4)))
	    {
	      strncpy (key_path + key_directory_n + 1, dir_entry->d_name, 40);

	      /* Read file content.  */
	      err = es_read_file (key_path, &buffer, &buffer_n);
	      if (err)
		break;
	      
	      err = gcry_sexp_sscan (&key_secret, NULL, buffer, buffer_n);
	      if (err)
		break;

	      xfree (buffer);
	      buffer = NULL;

	      err = ssh_sexp_extract_key_type (key_secret, &key_type);
	      if (err)
		break;

	      err = ssh_key_type_lookup (NULL, key_type, &spec);
	      if (err)
		break;

	      xfree ((void *) key_type);
	      key_type = NULL;

	      err = key_secret_to_public (&key_public, spec, key_secret);
	      if (err)
		break;

	      gcry_sexp_release (key_secret);
	      key_secret = NULL;
	      
	      err = ssh_send_key_public (key_blobs, key_public);
	      if (err)
		break;

	      gcry_sexp_release (key_public);
	      key_public = NULL;

	      key_counter++;
	    }
	}
      else
	break;
    }
  if (err)
    goto out;
  
  ret = es_fseek (key_blobs, 0, SEEK_SET);
  if (ret)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

 out:

  /* Send response.  */

  gcry_sexp_release (key_secret);
  gcry_sexp_release (key_public);

  es_write_byte (response, SSH_RESPONSE_IDENTITIES_ANSWER);
  if (! es_ferror (response))
    es_write_uint32 (response, err ? 0 : key_counter);
  if (! (err || es_ferror (response)))
    es_copy (response, key_blobs);

  if (key_blobs)
    es_fclose (key_blobs);
  if (dir)
    closedir (dir);

  free (key_directory);
  xfree (key_path);
  xfree (buffer);
  xfree ((void *) key_type);		/* FIXME? */

  return bad;
}

static gpg_error_t
data_hash (unsigned char *data, size_t data_n,
	   int md_algorithm, unsigned char *hash)
{
  gcry_md_hash_buffer (md_algorithm, hash, data, data_n);

  return 0;
}

static gpg_error_t
data_sign (CTRL ctrl, ssh_signature_encoder_t sig_encoder,
	   unsigned char **sig, size_t *sig_n)
{
  char description[] = "Please provide the passphrase for key `%c':";
  gpg_error_t err;
  gcry_sexp_t signature_sexp;
  estream_t stream;
  gcry_sexp_t valuelist;
  gcry_sexp_t sublist;
  gcry_mpi_t sig_value;
  unsigned char *sig_blob;
  size_t sig_blob_n;
  const char *identifier;
  const char *identifier_raw;
  size_t identifier_n;
  ssh_key_type_spec_t spec;
  int ret;
  unsigned int i;
  const char *elems;
  size_t elems_n;
  gcry_mpi_t *mpis;

  signature_sexp = NULL;
  identifier = NULL;
  valuelist = NULL;
  sublist = NULL;
  sig_blob = NULL;
  sig_blob_n = 0;
  stream = NULL;
  sig_value = NULL;
  mpis = NULL;

  err = agent_pksign_do (ctrl, description, &signature_sexp, 0);
  if (err)
    goto out;

  valuelist = gcry_sexp_nth (signature_sexp, 1);
  if (! valuelist)
    {
      err = gpg_error (GPG_ERR_INV_SEXP);
      goto out;
    }

  stream = es_mopen (NULL, 0, 0, 1, NULL, NULL, "r+");
  if (! stream)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  identifier_raw = gcry_sexp_nth_data (valuelist, 0, &identifier_n);
  if (! identifier_raw)
    {
      err = gpg_error (GPG_ERR_INV_SEXP);
      goto out;
    }

  identifier = make_cstring (identifier_raw, identifier_n);
  if (! identifier)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  err = ssh_key_type_lookup (NULL, identifier, &spec);
  if (err)
    goto out;

  err = es_write_cstring (stream, spec.ssh_identifier);
  if (err)
    goto out;

  elems = spec.elems_signature;
  elems_n = strlen (elems);

  mpis = xtrymalloc (sizeof (*mpis) * (elems_n + 1));
  if (! mpis)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }
  memset (mpis, 0, sizeof (*mpis) * (elems_n + 1));

  for (i = 0; i < elems_n; i++)
    {
      sublist = gcry_sexp_find_token (valuelist, spec.elems_signature + i, 1);
      if (! sublist)
	{
	  err = gpg_error (GPG_ERR_INV_SEXP);
	  break;
	}

      sig_value = gcry_sexp_nth_mpi (sublist, 1, GCRYMPI_FMT_USG);
      if (! sig_value)
	{
	  err = gpg_error (GPG_ERR_INTERNAL); /* FIXME?  */
	  break;
	}
      gcry_sexp_release (sublist);
      sublist = NULL;

      mpis[i] = sig_value;
    }
  if (err)
    goto out;

  err = (*sig_encoder) (stream, mpis);
  if (err)
    goto out;

  sig_blob_n = es_ftell (stream);
  if (sig_blob_n == -1)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  sig_blob = xtrymalloc (sig_blob_n);
  if (! sig_blob)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  ret = es_fseek (stream, 0, SEEK_SET);
  if (ret)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }    

  err = es_read_data (stream, sig_blob, sig_blob_n);
  if (err)
    goto out;
  
  *sig = (char *) sig_blob;
  *sig_n = sig_blob_n;
  
 out:

  if (err)
    xfree (sig_blob);

  if (stream)
    es_fclose (stream);
  gcry_sexp_release (valuelist);
  gcry_sexp_release (signature_sexp);
  gcry_sexp_release (sublist);
  mpint_list_free (mpis);
  xfree ((void *) identifier);

  return err;
}

static int
ssh_handler_sign_request (ctrl_t ctrl, estream_t request, estream_t response)
{
  gcry_sexp_t key;
  ssh_key_type_spec_t spec;
  unsigned char hash[MAX_DIGEST_LEN];
  unsigned int hash_n;
  unsigned char key_grip[20];
  unsigned char *key_blob;
  uint32_t key_blob_size;
  unsigned char *data;
  unsigned char *sig;
  size_t sig_n;
  uint32_t data_size;
  uint32_t flags;
  const void *p;
  gpg_error_t err;
  int bad;

  key_blob = NULL;
  data = NULL;
  sig = NULL;
  key = NULL;
  bad = 0;

  if (DBG_COMMAND)
    log_debug ("[ssh-agent] sign request\n");

  /* Receive key.  */
  
  err = es_read_string (request, 0, &key_blob, &key_blob_size);
  if (err)
    {
      bad = 1;
      goto out;
    }

  err = ssh_read_key_public_from_blob (key_blob, key_blob_size, &key, &spec);
  if (err)
    {
      bad = 1;
      goto out;
    }

  /* Receive data to sign.  */
  err = es_read_string (request, 0, &data, &data_size);
  if (err)
    {
      bad = 1;
      goto out;
    }

  /* FIXME?  */
  err = es_read_uint32 (request, &flags);
  if (err)
    {
      bad = 1;
      goto out;
    }

  /* Hash data.  */
  hash_n = gcry_md_get_algo_dlen (GCRY_MD_SHA1);
  if (! hash_n)
    {
      err = gpg_error (GPG_ERR_INTERNAL);
      goto out;
    }
  err = data_hash (data, data_size, GCRY_MD_SHA1, hash);
  if (err)
    goto out;

  /* Calculate key grip.  */
  p = gcry_pk_get_keygrip (key, key_grip);
  if (! p)
    {
      err = gpg_error (GPG_ERR_INTERNAL); /* FIXME?  */
      goto out;
    }

  /* Sign data.  */

  ctrl->digest.algo = GCRY_MD_SHA1;
  memcpy (ctrl->digest.value, hash, hash_n);
  ctrl->digest.valuelen = hash_n;
  ctrl->digest.raw_value = ! (spec.flags & SPEC_FLAG_USE_PKCS1V2);
  ctrl->have_keygrip = 1;
  memcpy (ctrl->keygrip, key_grip, 20);

  err = data_sign (ctrl, spec.signature_encoder, &sig, &sig_n);
  
 out:

  if (! bad)
    {
      /* Done.  */
      es_write_byte (response, SSH_RESPONSE_SIGN_RESPONSE);
      if (! es_ferror (response))
	{
	  if (! err)
	    es_write_string (response, sig, sig_n);
	  else
	    es_write_byte (response, SSH_RESPONSE_FAILURE);
	}
    }
  
  gcry_sexp_release (key);
  xfree (key_blob);
  xfree (data);
  xfree (sig);

  return bad;
}

static gpg_error_t
get_passphrase (const char *description, size_t passphrase_n, char *passphrase)
{
  struct pin_entry_info_s *pi;
  gpg_error_t err;

  err = 0;
  pi = gcry_calloc_secure (1, sizeof (*pi) + passphrase_n + 1);
  if (! pi)
    {
      err = gpg_error (GPG_ERR_ENOMEM);
      goto out;
    }

  pi->min_digits = 0;		/* We want a real passphrase.  */
  pi->max_digits = 8;
  pi->max_tries = 1;
  pi->failed_tries = 0;
  pi->check_cb = NULL;
  pi->check_cb_arg = NULL;
  pi->cb_errtext = NULL;
  pi->max_length = 100;

  err = agent_askpin (NULL, description, NULL, pi);
  if (err)
    goto out;

  memcpy (passphrase, pi->pin, passphrase_n);
  passphrase[passphrase_n] = 0;

 out:

  xfree (pi);
  
  return err;
}

static gpg_error_t
ssh_key_extract_comment (gcry_sexp_t key, char **comment)
{
  gcry_sexp_t comment_list;
  char *comment_new;
  const char *data;
  size_t data_n;
  gpg_error_t err;

  comment_list = gcry_sexp_find_token (key, "comment", 0);
  if (! comment_list)
    {
      err = gpg_error (GPG_ERR_INV_SEXP);
      goto out;
    }
  
  data = gcry_sexp_nth_data (comment_list, 1, &data_n);
  if (! data)
    {
      err = gpg_error (GPG_ERR_INV_SEXP);
      goto out;
    }

  comment_new = xtrymalloc (data_n + 1);
  if (! comment_new)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  strncpy (comment_new, data, data_n);
  comment_new[data_n] = 0;
  *comment = comment_new;
  err = 0;

 out:

  gcry_sexp_release (comment_list);

  return err;
}

static gpg_error_t
ssh_key_grip (gcry_sexp_t key, char *buffer)
{
  gpg_error_t err;
  char *p;

  /* FIXME: unsigned vs. signed.  */
  
  p = gcry_pk_get_keygrip (key, buffer);
  if (! p)
    err = gpg_error (GPG_ERR_INTERNAL);	/* FIXME?  */
  else
    err = 0;

  return err;
}

static gpg_error_t
ssh_key_to_buffer (gcry_sexp_t key, const char *passphrase,
		   unsigned char **buffer, size_t *buffer_n)
{
  unsigned char *buffer_new;
  unsigned int buffer_new_n;
  gpg_error_t err;

  err = 0;
  buffer_new_n = gcry_sexp_sprint (key, GCRYSEXP_FMT_CANON, NULL, 0);
  buffer_new = xtrymalloc (buffer_new_n);
  /* FIXME: secmem? */
  if (! buffer_new)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }
  
  gcry_sexp_sprint (key, GCRYSEXP_FMT_CANON, buffer_new, buffer_new_n);
  /* FIXME: guarantee?  */

  err = agent_protect (buffer_new, passphrase, buffer, buffer_n);

 out:

  xfree (buffer_new);

  return err;
}

static gpg_error_t
ssh_identity_register (gcry_sexp_t key, int ttl)
{
  unsigned char key_grip_raw[21];
  unsigned char *buffer;
  unsigned int buffer_n;
  char passphrase[100];
  size_t description_length;
  char *description;
  char key_grip[41];
  char *comment;
  gpg_error_t err;
  
  int ret;

  if (DBG_COMMAND)
    log_debug ("[ssh-agent] registering identity `%s'\n", key_grip);

  description = NULL;
  comment = NULL;
  buffer = NULL;

  err = ssh_key_grip (key, key_grip_raw);
  if (err)
    goto out;

  key_grip_raw[sizeof (key_grip_raw) - 1] = 0;
  ret = agent_key_available (key_grip_raw);
  if (! ret)
    goto out;

  err = ssh_key_extract_comment (key, &comment);
  if (err)
    goto out;

  description_length = 95 + (comment ? strlen (comment) : 0);
  description = malloc (description_length);
  if (! description)
    {
      err = gpg_err_code_from_errno (errno);
      goto out;
    }
  else
    sprintf (description,
	     "Please provide the passphrase, which should be used "
	     "for protecting the received secret key `%s':",
	     comment ? comment : "");

  err = get_passphrase (description, sizeof (passphrase), passphrase);
  if (err)
    goto out;

  err = ssh_key_to_buffer (key, passphrase, &buffer, &buffer_n);
  if (err)
    goto out;

  err = agent_write_private_key (key_grip_raw, buffer, buffer_n, 0);
  if (err)
    goto out;

  err = agent_put_cache (key_grip_raw, passphrase, ttl);
  if (err)
    goto out;

 out:

  xfree (buffer);
  xfree (comment);
  xfree (description);
  /* FIXME: verify xfree vs free.  */

  return err;
}

static gpg_error_t
ssh_identity_drop (gcry_sexp_t key)
{
  unsigned char key_grip[21] = { 0 };
  gpg_error_t err;

  err = ssh_key_grip (key, key_grip);
  if (err)
    goto out;

  key_grip[sizeof (key_grip) - 1] = 0;

  /* FIXME: What to do here - forgetting the passphrase or deleting
     the key from key cache?  */

  if (DBG_COMMAND)
    log_debug ("[ssh-agent] dropping identity `%s'\n", key_grip);

 out:

  return err;
}

static int
ssh_handler_add_identity (ctrl_t ctrl, estream_t request, estream_t response)
{
  gpg_error_t err;
  gcry_sexp_t key;
  byte_t b;
  int confirm;
  int death;
  int bad;
  
  if (DBG_COMMAND)
    log_debug ("[ssh-agent] add identity\n");

  confirm = 0;
  death = 0;
  key = NULL;
  bad = 0;

  /* FIXME?  */
  err = ssh_receive_key (request, &key, 1, 1, NULL);
  if (err)
    {
      bad = 1;
      goto out;
    }

  while (1)
    {
      err = es_read_byte (request, &b);
      if (gpg_err_code (err) == GPG_ERR_EOF)
	{
	  err = 0;
	  break;
	}

      switch (b)
	{
	case SSH_OPT_CONSTRAIN_LIFETIME:
	  {
	    uint32_t n = 0;

	    err = es_read_uint32 (request, &n);
	    if (! err)
	      death = time (NULL) + n;
	    break;
	  }

	case SSH_OPT_CONSTRAIN_CONFIRM:
	  {
	    confirm = 1;
	    break;
	  }

	default:
	  /* FIXME: log/bad?  */
	  break;
	}
    }
  if (err)
    goto out;

  if (lifetime_default && (! death))
    death = time (NULL) + lifetime_default;

  /* FIXME: are constraints used correctly?  */

  err = ssh_identity_register (key, death);

 out:

  gcry_sexp_release (key);

  if (! bad)
    es_write_byte (response, err ? SSH_RESPONSE_FAILURE : SSH_RESPONSE_SUCCESS);

  return bad;
}

static int
ssh_handler_remove_identity (ctrl_t ctrl, estream_t request, estream_t response)
{
  unsigned char *key_blob;
  uint32_t key_blob_size;
  gcry_sexp_t key;
  gpg_error_t err;
  int bad;

  /* Receive key.  */

  if (DBG_COMMAND)
    log_debug ("[ssh-agent] remove identity\n");

  key_blob = NULL;
  key = NULL;
  bad = 0;
  
  err = es_read_string (request, 0, &key_blob, &key_blob_size);
  if (err)
    {
      bad = 1;
      goto out;
    }

  err = ssh_read_key_public_from_blob (key_blob, key_blob_size, &key, NULL);
  if (err)
    {
      bad = 1;
      goto out;
    }
  
  err = ssh_identity_drop (key);

 out:

  xfree (key_blob);
  gcry_sexp_release (key);

  if (! bad)
    es_write_byte (response, err ? SSH_RESPONSE_FAILURE : SSH_RESPONSE_SUCCESS);

  return bad;
}

static gpg_error_t
ssh_identities_remove_all (void)
{
  gpg_error_t err;

  if (DBG_COMMAND)
    log_debug ("[ssh-agent] remove all identities\n");

  err = 0;

  /* FIXME: shall we remove _all_ cache entries or only those
     registered through the ssh emulation?  */
  
  return err;
}

static int
ssh_handler_remove_all_identities (ctrl_t ctrl, estream_t request, estream_t response)
{
  gpg_error_t err;
  
  err = ssh_identities_remove_all ();
  es_write_byte (response, err ? SSH_RESPONSE_FAILURE : SSH_RESPONSE_SUCCESS);

  return 0;
}

static gpg_error_t
ssh_lock (void)
{
  gpg_error_t err;

  if (DBG_COMMAND)
    log_debug ("[ssh-agent] lock\n");

  err = 0;

  return err;
}

static gpg_error_t
ssh_unlock (void)
{
  gpg_error_t err;

  if (DBG_COMMAND)
    log_debug ("[ssh-agent] unlock\n");

  err = 0;

  return err;
}

static int
ssh_handler_lock (ctrl_t ctrl, estream_t request, estream_t response)
{
  gpg_error_t err;
  
  err = ssh_lock ();
  es_write_byte (response, err ? SSH_RESPONSE_FAILURE : SSH_RESPONSE_SUCCESS);

  return 0;
}

static int
ssh_handler_unlock (ctrl_t ctrl, estream_t request, estream_t response)
{
  gpg_error_t err;
  
  err =  ssh_unlock ();
  es_write_byte (response, err ? SSH_RESPONSE_FAILURE : SSH_RESPONSE_SUCCESS);

  return 0;
}



/* Associating request types with the corresponding request
   handlers.  */

static ssh_request_spec_t request_specs[] =
  {
    { SSH_REQUEST_REQUEST_IDENTITIES,    ssh_handler_request_identities },
    { SSH_REQUEST_SIGN_REQUEST,          ssh_handler_sign_request },
    { SSH_REQUEST_ADD_IDENTITY,          ssh_handler_add_identity },
    { SSH_REQUEST_ADD_ID_CONSTRAINED,    ssh_handler_add_identity },
    { SSH_REQUEST_REMOVE_IDENTITY,       ssh_handler_remove_identity },
    { SSH_REQUEST_REMOVE_ALL_IDENTITIES, ssh_handler_remove_all_identities },
    { SSH_REQUEST_LOCK,                  ssh_handler_lock },
    { SSH_REQUEST_UNLOCK,                ssh_handler_unlock },
  };



static gpg_error_t
ssh_request_process (ctrl_t ctrl, estream_t request, estream_t response)
{
  byte_t request_type;
  gpg_error_t err;
  unsigned int i;
  int bad;

  err = es_read_byte (request, &request_type);
  if (err)
    goto out;

  if (DBG_COMMAND)
    log_debug ("[ssh-agent] request: %u\n", request_type);

  for (i = 0; i < DIM (request_specs); i++)
    if (request_specs[i].type == request_type)
      break;
  if (i == DIM (request_specs))
    {
      err = es_write_byte (response, SSH_RESPONSE_FAILURE);
      goto out;
    }

  
  bad = (*request_specs[i].handler) (ctrl, request, response);
  if (bad)
    err = GPG_ERR_PROTOCOL_VIOLATION;

 out:

  return err;
}

void
start_command_handler_ssh (int sock_client)
{
  struct server_control_s ctrl;
  gpg_error_t err;
  estream_t stream_response;
  estream_t stream_request;
  estream_t stream_sock;
  unsigned char *request;
  uint32_t request_size;
  size_t size;
  int ret;

  /* Setup control structure.  */

  if (DBG_COMMAND)
    log_debug ("[ssh-agent] Starting command handler\n");

  memset (&ctrl, 0, sizeof (ctrl));
  ctrl.connection_fd = sock_client;

  stream_response = NULL;
  stream_request = NULL;
  stream_sock = NULL;
  request = NULL;

  stream_sock = es_fdopen (sock_client, "r+");
  if (! stream_sock)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }
  ret = es_setvbuf (stream_sock, NULL, _IONBF, 0);
  if (ret)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  while (1)
    {
      /* Create memory streams for request/response data.  The entire
	 request will be stored in secure memory, since it might
	 contain secret key material.  The response does not have to
	 be stored in secure memory, since we never give out secret
	 keys.  FIXME: wrong place.  */
      
      /* Retrieve request.  */
      err = es_read_string (stream_sock, 1, &request, &request_size);
      if (err)
	break;

      if (DBG_COMMAND)
	log_debug ("[ssh-agent] Received request of length: %u\n",
		   request_size);

      stream_request = es_mopen (NULL, 0, 0, 1,
				 realloc_secure, gcry_free, "r+");
      if (! stream_request)
	{
	  err = gpg_error_from_errno (errno);
	  break;
	}
      ret = es_setvbuf (stream_request, NULL, _IONBF, 0);
      if (ret)
	{
	  err = gpg_error_from_errno (errno);
	  break;
	}
      err = es_write_data (stream_request, request, request_size);
      if (err)
	break;
      es_rewind (stream_request);

      stream_response = es_mopen (NULL, 0, 0, 1, NULL, NULL, "r+");
      if (! stream_response)
	{
	  err = gpg_error_from_errno (errno);
	  break;
	}

      /* Process request.  */
      err = ssh_request_process (&ctrl, stream_request, stream_response);
      if (err)
	break;
 
      /* Figure out size of response data.  */
      size = es_ftell (stream_response);
      err = es_fseek (stream_response, 0, SEEK_SET);
      if (err)
	break;

      /* Write response data to socket stream.  */
      err = es_write_uint32 (stream_sock, size);
      if (err)
	break;
      err = es_copy (stream_sock, stream_response);
      if (err)
	break;
      
      err = es_fflush (stream_sock);
      if (err)
	break;

      es_fclose (stream_request);
      stream_request = NULL;
      es_fclose (stream_response);
      stream_response = NULL;
      xfree (request);
      request = NULL;
    };

 out:

  /* FIXME: logging.  */

  if (stream_sock)
    es_fclose (stream_sock);
  if (stream_request)
    es_fclose (stream_request);
  if (stream_response)
    es_fclose (stream_response);
  xfree (request);		/* FIXME?  */

  if (DBG_COMMAND)
    log_debug ("[ssh-agent] Leaving ssh command handler: %s\n", gpg_strerror (err));
}
