/* command-ssh.c - gpg-agent's ssh-agent emulation
 * Copyright (C) 2004 Free Software Foundation, Inc.
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
#include <dirent.h>
//#include <stdio.h>

#include "agent.h"

#include <gcrypt.h>

#include "gpg-stream.h"



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

/* A "mpint".  */
typedef gcry_mpi_t mpint_t;



/* SSH specific types.  */

typedef byte_t ssh_request_type_t;
typedef byte_t ssh_response_type_t;

/* A "Packet header"; part of a Request/Response.  */
typedef struct ssh_packet_header
{
  uint32_t length;
  byte_t type;
} ssh_packet_header_t;

/* A "Key type".  */
typedef enum ssh_key_type
  {
    SSH_KEY_TYPE_NONE,
    SSH_KEY_TYPE_RSA,
  } ssh_key_type_t;

/* Type used for associating Key types with their string
   representation.  */
typedef struct ssh_key_type_spec
{
  ssh_key_type_t type;
  const char *name;
} ssh_key_type_spec_t;

/* Secret RSA key material.  */
typedef struct ssh_key_secret_rsa
{
  mpint_t n;
  mpint_t e;
  mpint_t d;
  mpint_t p;
  mpint_t q;
  mpint_t u;
} ssh_key_secret_rsa_t;

/* Public RSA key material.  */
typedef struct ssh_key_public_rsa
{
  mpint_t e;
  mpint_t n;
} ssh_key_public_rsa_t;

/* A secret key.  */
typedef struct ssh_key_secret
{
  ssh_key_type_t type;
  union
  {
    ssh_key_secret_rsa_t rsa;
  } material;
} ssh_key_secret_t;

/* A public key.  */
typedef struct ssh_key_public
{
  ssh_key_type_t type;
  union
  {
    ssh_key_public_rsa_t rsa;
  } material;
} ssh_key_public_t;

typedef void (*ssh_request_handler_t) (ctrl_t ctrl,
				       gpg_stream_t request,
				       gpg_stream_t response);

typedef struct ssh_request_spec
{
  ssh_request_type_t type;
  ssh_request_handler_t handler;
} ssh_request_spec_t;



/* Table associating numeric key types with their string
   representation.  */
static ssh_key_type_spec_t ssh_key_types[] =
  {
    { SSH_KEY_TYPE_RSA, "ssh-rsa" }
  };

static uint32_t lifetime_default;



/* Primitive I/O functions.  */

static gpg_err_code_t
gpg_stream_read_byte (gpg_stream_t stream, byte_t *b)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;
  unsigned char buffer[1];
  size_t bytes_read = 0;

  err = gpg_stream_read (stream, buffer, sizeof (buffer), &bytes_read);
  if ((! err) && (bytes_read != sizeof (buffer)))
    err = GPG_ERR_EOF;

  if (! err)
    *b = buffer[0];

  return err;
}

static gpg_err_code_t
gpg_stream_write_byte (gpg_stream_t stream, byte_t b)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;

  err = gpg_stream_write (stream, &b, sizeof (b), NULL);

  return err;
}

static gpg_err_code_t
gpg_stream_read_uint32 (gpg_stream_t stream, uint32_t *uint32)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;
  unsigned char buffer[4] = { 0 };
  size_t bytes_read = 0;
  uint32_t n = 0;

  err = gpg_stream_read (stream, buffer, sizeof (buffer), &bytes_read);
  if ((! err) && (bytes_read != sizeof (buffer)))
    err = GPG_ERR_EOF;

  if (! err)
    {
      n = (0
	   | ((uint32_t) (buffer[0] << 24))
	   | ((uint32_t) (buffer[1] << 16))
	   | ((uint32_t) (buffer[2] <<  8))
	   | ((uint32_t) (buffer[3] <<  0)));
      *uint32 = n;
    }

  return err;
}

static gpg_err_code_t
gpg_stream_write_uint32 (gpg_stream_t stream, uint32_t uint32)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;
  unsigned char buffer[4] = { 0 };

  buffer[0] = uint32 >> 24;
  buffer[1] = uint32 >> 16;
  buffer[2] = uint32 >>  8;
  buffer[3] = uint32 >>  0;

  err = gpg_stream_write (stream, buffer, sizeof (buffer), NULL);

  return err;
}

static gpg_err_code_t
gpg_stream_read_string (gpg_stream_t stream,
			unsigned char **string, uint32_t *string_size)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;
  unsigned char *buffer = NULL;
  size_t bytes_read = 0;
  uint32_t length = 0;

  /* Read string length.  */
  err = gpg_stream_read_uint32 (stream, &length);
  if (err)
    goto out;

  /* Allocate space.  */
  buffer = malloc (length + 1);
  if (! buffer)
    {
      err = gpg_err_code_from_errno (errno);
      goto out;
    }

  /* Read data.  */
  err = gpg_stream_read (stream, buffer, length, &bytes_read);
  if ((! err) && (bytes_read != length))
    err = GPG_ERR_EOF;
  if (err)
    goto out;

  /* Finalize string object.  */
  buffer[length] = 0;

 out:

  if (! err)
    {
      *string = buffer;
      if (string_size)
	*string_size = length;
    }
  else
    if (buffer)
      free (buffer);

  return err;
}

static gpg_err_code_t
gpg_stream_write_string (gpg_stream_t stream,
			 const unsigned char *string, uint32_t string_n)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;

  err = gpg_stream_write_uint32 (stream, string_n);
  if (err)
    goto out;

  err = gpg_stream_write (stream, string, string_n, NULL);
  if (err)
    goto out;

 out:

  return err;
}

static gpg_err_code_t
gpg_stream_write_cstring (gpg_stream_t stream, char *string)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;

  err = gpg_stream_write_string (stream, (char *) string, strlen (string));

  return err;
}			  

static gpg_err_code_t
gpg_stream_read_mpint (gpg_stream_t stream, mpint_t *mpint,
		       unsigned int mpi_type)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;
  unsigned char *mpi_data = NULL;
  uint32_t mpi_data_size = 0;
  gcry_mpi_t mpi = NULL;

  if (! mpi_type)
    mpi_type = GCRYMPI_FMT_STD;

  err = gpg_stream_read_string (stream, &mpi_data, &mpi_data_size);
  if (err)
    goto out;

  err = gcry_mpi_scan (&mpi, mpi_type, mpi_data, mpi_data_size, NULL);
  if (err)
    goto out;

 out:

  free (mpi_data);

  if (! err)
    *mpint = mpi;

  return err;
}

static gpg_err_code_t
gpg_stream_write_mpint (gpg_stream_t stream, mpint_t mpint,
			unsigned int mpi_type)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;
  unsigned char *mpi_buffer = NULL;
  size_t mpi_buffer_n = 0;

  if (! mpi_type)
    mpi_type = GCRYMPI_FMT_STD;

  err = gcry_mpi_aprint (mpi_type, &mpi_buffer, &mpi_buffer_n, mpint);
  if (err)
    goto out;

  err = gpg_stream_write_string (stream, mpi_buffer, mpi_buffer_n);
  if (err)
    goto out;

 out:

  free (mpi_buffer);

  return err;
}

static gpg_err_code_t
gpg_stream_read_file (const char *filename,
		      unsigned char **buffer, size_t *buffer_n)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;
  unsigned char *buffer_new = NULL;
  size_t buffer_new_n = 0;
  gpg_stream_t stream = NULL;
  size_t bytes_read = 0;

  err = gpg_stream_create_file (&stream, filename, GPG_STREAM_FLAG_READ);
  if (err)
    goto out;

  err = gpg_stream_stat (stream, &buffer_new_n);
  if (err)
    goto out;

  buffer_new = malloc (buffer_new_n);
  if (! buffer_new)
    {
      err = gpg_err_code_from_errno (errno);
      goto out;
    }

  err = gpg_stream_read (stream, buffer_new, buffer_new_n, &bytes_read);
  if ((! err) && (bytes_read != buffer_new_n))
    err = GPG_ERR_INTERNAL;	/* FIXME? */
  if (err)
    goto out;

 out:

  gpg_stream_destroy (stream);

  if (! err)
    {
      *buffer = buffer_new;
      *buffer_n = buffer_new_n;
    }
  else
    {
      free (buffer_new);
    }

  return err;
}



/* Key I/O.  */

static gpg_err_code_t
ssh_key_type_lookup (const char *key_type_identifier, ssh_key_type_t *key_type)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;
  unsigned int i = 0;

  for (i = 0; i < DIM (ssh_key_types); i++)
    if (! strcmp (key_type_identifier, ssh_key_types[i].name))
      break;
  
  if (i == DIM (ssh_key_types))
    err = GPG_ERR_NOT_FOUND;
  else
    *key_type = ssh_key_types[i].type;

  return err;
}

static gpg_err_code_t
ssh_receive_key_secret (gpg_stream_t stream, ssh_key_secret_t *key_secret)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;
  ssh_key_secret_t key = { 0 };
  unsigned char *key_type = NULL;
  gcry_mpi_t mpi_iqmp = NULL;
	
  err = gpg_stream_read_string (stream, &key_type, NULL);
  if (err)
    goto out;

  err = ssh_key_type_lookup (key_type, &key.type);
  if (err)
    goto out;

  switch (key.type)
    {
    case SSH_KEY_TYPE_RSA:
      {
	err = gpg_stream_read_mpint (stream, &key.material.rsa.n, 0);
	if (err)
	  break;
	err = gpg_stream_read_mpint (stream, &key.material.rsa.e, 0);
	if (err)
	  break;
	err = gpg_stream_read_mpint (stream, &key.material.rsa.d, 0);
	if (err)
	  break;
	err = gpg_stream_read_mpint (stream, &mpi_iqmp, 0);
	if (err)
	  break;
	err = gpg_stream_read_mpint (stream, &key.material.rsa.p, 0);
	if (err)
	  break;
	err = gpg_stream_read_mpint (stream, &key.material.rsa.q, 0);
	if (err)
	  break;

	if (gcry_mpi_cmp (key.material.rsa.p, key.material.rsa.q))
	  {
	    /* P shall be smaller then Q!  Swap primes.  iqmp becomes
	       u.  */
	    gcry_mpi_t mpi_tmp = NULL;

	    mpi_tmp = key.material.rsa.p;
	    key.material.rsa.p = key.material.rsa.q;
	    key.material.rsa.q = mpi_tmp;
	    key.material.rsa.u = mpi_iqmp;
	    mpi_iqmp = NULL;
	  }
	else
	  {
	    /* u has to be recomputed.  */

	    key.material.rsa.u = gcry_mpi_new (0);
	    gcry_mpi_invm (key.material.rsa.u,
			   key.material.rsa.p, key.material.rsa.q);
	  }
	
	break;
      }

    case SSH_KEY_TYPE_NONE:
    default:
      err = GPG_ERR_INTERNAL;	/* fixme: key type unsupported.  */
      break;
    }
  if (err)
    goto out;

 out:

  free (key_type);
  gcry_mpi_release (mpi_iqmp);

  if (! err)
    *key_secret = key;
  else
    {
      gcry_mpi_release (key.material.rsa.n);
      gcry_mpi_release (key.material.rsa.e);
      gcry_mpi_release (key.material.rsa.d);
      gcry_mpi_release (key.material.rsa.p);
      gcry_mpi_release (key.material.rsa.q);
      gcry_mpi_release (key.material.rsa.u);
    }

  return err;
}

static gpg_err_code_t
ssh_send_key_public (gpg_stream_t stream, ssh_key_public_t *key_public)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;

  switch (key_public->type)
    {
    case SSH_KEY_TYPE_RSA:
      {
	err = gpg_stream_write_cstring (stream, "ssh-rsa");
	if (err)
	  goto out;
	err = gpg_stream_write_mpint (stream, key_public->material.rsa.e, 0);
	if (err)
	  goto out;
	err = gpg_stream_write_mpint (stream, key_public->material.rsa.n, 0);
	if (err)
	  goto out;

	break;
      }

    case SSH_KEY_TYPE_NONE:
    default:
      err = GPG_ERR_INTERNAL;	/* FIXME */
    }

 out:

  return err;
}

static gpg_err_code_t
ssh_receive_key_public (gpg_stream_t stream, ssh_key_public_t *key_public)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;
  ssh_key_public_t key = { 0 };
  unsigned char *key_type = NULL;

  err = gpg_stream_read_string (stream, &key_type, NULL);
  if (err)
    goto out;

  err = ssh_key_type_lookup (key_type, &key.type);
  if (err)
    goto out;

  switch (key.type)
   {
    case SSH_KEY_TYPE_RSA:
      {
	err = gpg_stream_read_mpint (stream, &key.material.rsa.e, 0);
	if (err)
	  break;
	err = gpg_stream_read_mpint (stream, &key.material.rsa.n, 0);
	if (err)
	  break;
	break;
      }

    case SSH_KEY_TYPE_NONE:
      err = GPG_ERR_INTERNAL;	/* fixme: key type unsupported.  */
      break;
    }

  if (err)
    goto out;

 out:

  free (key_type);

  if (! err)
    *key_public = key;
  else
    {
      switch (key.type)
	{
	case SSH_KEY_TYPE_RSA:
	  gcry_mpi_release (key.material.rsa.e);
	  gcry_mpi_release (key.material.rsa.n);
	  break;

	case SSH_KEY_TYPE_NONE:
	  break;
	}
    }

  return err;
}

static gpg_err_code_t
ssh_extract_key_public_from_blob (unsigned char *blob, size_t blob_size,
				  ssh_key_public_t *key_public)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;
  gpg_stream_t blob_stream = NULL;

  err = gpg_stream_create (&blob_stream, NULL,
			   GPG_STREAM_FLAG_READ | GPG_STREAM_FLAG_WRITE,
			   gpg_stream_functions_mem);
  if (err)
    goto out;

  err = gpg_stream_write (blob_stream, blob, blob_size, NULL);
  if (err)
    goto out;

  err = gpg_stream_seek (blob_stream, 0, SEEK_SET);
  if (err)
    goto out;

  err = ssh_receive_key_public (blob_stream, key_public);
  if (err)
    goto out;

 out:

  gpg_stream_destroy (blob_stream);

  return err;
}

static gpg_err_code_t
ssh_convert_key_to_blob (unsigned char **blob, size_t *blob_size,
			 ssh_key_public_t *key_public)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;
  gpg_stream_t blob_stream = NULL;
  unsigned char *blob_new = NULL;
  size_t blob_new_size = 0;
  size_t bytes_read = 0;

  err = gpg_stream_create (&blob_stream, NULL,
			   GPG_STREAM_FLAG_READ | GPG_STREAM_FLAG_WRITE,
			   gpg_stream_functions_mem);
  if (err)
    goto out;

  err = ssh_send_key_public (blob_stream, key_public);
  if (err)
    goto out;

  err = gpg_stream_seek (blob_stream, 0, SEEK_SET);
  if (err)
    goto out;

  err = gpg_stream_stat (blob_stream, &blob_new_size);
  if (err)
    goto out;

  blob_new = malloc (blob_new_size);
  if (! blob_new)
    {
      err = gpg_err_code_from_errno (errno);
      goto out;
    }

  err = gpg_stream_read (blob_stream, blob_new, blob_new_size, &bytes_read);
  if ((! err) && (bytes_read != blob_new_size))
    err = GPG_ERR_INTERNAL;	/* FIXME? */
  if (err)
    goto out;

 out:

  gpg_stream_destroy (blob_stream);

  if (! err)
    {
      *blob = blob_new;
      *blob_size = blob_new_size;
    }
  else
    {
      if (blob_new)
	free (blob_new);
    }

  return err;
}



static gpg_err_code_t
ssh_key_grip (ssh_key_public_t *public, ssh_key_secret_t *secret,
	      unsigned char *buffer)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;
  unsigned char *ret = NULL;
  gcry_sexp_t sexp = NULL;
  
  switch (public ? public->type : secret->type)
    {
    case SSH_KEY_TYPE_RSA:
      err = gcry_sexp_build (&sexp, NULL,
			     "(public-key (rsa (n %m) (e %m)))",
			     public
			     ? public->material.rsa.n
			     : secret->material.rsa.n,
			     public
			     ? public->material.rsa.e
			     : secret->material.rsa.n);
      break;

    case SSH_KEY_TYPE_NONE:
      abort ();
      break;
    }
  if (err)
    goto out;

  ret = gcry_pk_get_keygrip (sexp, buffer);
  if (! ret)
    {
      err = GPG_ERR_INTERNAL;	/* FIXME?  */
      goto out;
    }

 out:

  gcry_sexp_release (sexp);

  return err;
}

static gpg_err_code_t
ssh_key_public_from_stored_key (unsigned char *buffer, size_t buffer_n,
				ssh_key_public_t *key)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;
  gcry_sexp_t key_stored = NULL;
  gcry_sexp_t key_data = NULL;
  gcry_sexp_t value = NULL;
  const char *identifier = NULL;
  size_t identifier_n = 0;
  
  err = gcry_sexp_new (&key_stored, buffer, buffer_n, 1);
  if (err)
    goto out;

  identifier = gcry_sexp_nth_data (key_stored, 0, &identifier_n);
  if (! identifier)
    {
      err = GPG_ERR_INTERNAL;
      goto out;
    }

  if ((identifier_n == 21)
      && (! strncmp (identifier, "protected-private-key", identifier_n)))
    {
      key_data = gcry_sexp_cadr (key_stored);
      if (! key_data)
	{
	  err = GPG_ERR_INTERNAL;
	  goto out;
	}
      identifier = gcry_sexp_nth_data (key_data, 0, &identifier_n);
      if (! identifier)
	{
	  err = GPG_ERR_INTERNAL;
	  goto out;
	}

      if ((identifier_n == 3)
	  && (! (strncmp (identifier, "rsa", identifier_n))))
	{
	  gcry_mpi_t mpi_n = NULL;
	  gcry_mpi_t mpi_e = NULL;

	  value = gcry_sexp_find_token (key_data, "n", 0);
	  if (! value)
	    err = GPG_ERR_INTERNAL;
	  else
	    mpi_n = gcry_sexp_nth_mpi (value, 1, GCRYMPI_FMT_STD);

	  if (! err)
	    {
	      value = gcry_sexp_find_token (key_data, "e", 0);
	      if (! value)
		err = GPG_ERR_INTERNAL;
	      else
		mpi_e = gcry_sexp_nth_mpi (value, 1, GCRYMPI_FMT_STD);
	    }

	  if (! err)
	    {
	      key->type = SSH_KEY_TYPE_RSA;
	      key->material.rsa.e = mpi_e;
	      key->material.rsa.n = mpi_n;
	    }
	  else
	    {
	      gcry_mpi_release (mpi_n);
	      gcry_mpi_release (mpi_e);
	    }
	}
    }

 out:

  gcry_sexp_release (key_stored);
  gcry_sexp_release (key_data);
  gcry_sexp_release (value);

  return err;
}



/* Request handler.  */

static void
ssh_handler_request_identities (ctrl_t ctrl,
				gpg_stream_t request, gpg_stream_t response)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;
  gpg_err_code_t ret = GPG_ERR_NO_ERROR;
  struct dirent *dir_entry = NULL;
  char *key_directory = NULL;
  size_t key_directory_n = 0;
  char *key_path = NULL;
  unsigned char *key_blob = NULL;
  size_t key_blob_n = 0;
  unsigned char *buffer = NULL;
  size_t buffer_n = 0;
  uint32_t key_counter = 0;
  gpg_stream_t key_blobs = NULL;
  ssh_key_public_t key = { SSH_KEY_TYPE_NONE };
  DIR *dir = NULL;

  /* Prepare buffer stream.  */

  err = gpg_stream_create (&key_blobs, NULL,
			   GPG_STREAM_FLAG_READ | GPG_STREAM_FLAG_WRITE,
			   gpg_stream_functions_mem);
  if (err)
    goto out;

  /* Open key directory.  */
  key_directory = make_filename (opt.homedir, GNUPG_PRIVATE_KEYS_DIR, NULL);
  if (! key_directory)
    {
      err = gpg_err_code_from_errno (errno);
      goto out;
    }
  key_directory_n = strlen (key_directory);
  
  key_path = malloc (key_directory_n + 46);
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

  while (1)
    {
      dir_entry = readdir (dir);
      if (dir_entry)
	{
	  if ((dir_entry->d_namlen == 44)
	      && (! strncmp (dir_entry->d_name + 40, ".key", 4)))
	    {
	      strncpy (key_path + key_directory_n + 1, dir_entry->d_name, 40);

	      /* Read file content.  */
	      err = gpg_stream_read_file (key_path, &buffer, &buffer_n);
	      if (err)
		goto out;

	      /* Convert it into a public key.   */
	      err = ssh_key_public_from_stored_key (buffer, buffer_n, &key);
	      free (buffer);
	      buffer = NULL;
	      if (err)
		goto out;

	      /* Convert public key to key blob.  */
	      err = ssh_convert_key_to_blob (&key_blob, &key_blob_n, &key);
	      if (err)
		goto out;

	      /* Add key blob to buffer stream.  */
	      err = gpg_stream_write_string (key_blobs, key_blob, key_blob_n);
	      free (key_blob);
	      key_blob = NULL;
	      if (err)
		goto out;
	      err = gpg_stream_write_cstring (key_blobs, "");
	      if (err)
		goto out;
					     
	      key_counter++;
	    }
	}
      else
	break;
    }

  err = gpg_stream_seek (key_blobs, 0, SEEK_SET);
  if (err)
    goto out;

 out:

  /* Send response.  */

  ret = gpg_stream_write_byte (response, SSH_RESPONSE_IDENTITIES_ANSWER);

  if (! ret)
    ret = gpg_stream_write_uint32 (response, err ? 0 : key_counter);

  if ((! ret) && (! err))
    gpg_stream_copy (response, key_blobs);

  gpg_stream_destroy (key_blobs);
  closedir (dir);
  free (key_directory);
  free (key_path);
  free (key_blob);
}

static gpg_err_code_t
data_hash (unsigned char *data, size_t data_n,
	   int md_algorithm, unsigned char *hash)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;

  gcry_md_hash_buffer (md_algorithm, hash, data, data_n);

  return err;
}

static gpg_err_code_t
data_sign (CTRL ctrl, unsigned char **sig, size_t *sig_n)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;
  gcry_sexp_t signature_sexp = NULL;
  gpg_stream_t stream = NULL;
  gcry_sexp_t sublist = NULL;
  unsigned char *signature = NULL;
  size_t signature_n = 0;
  gcry_mpi_t sig_value = NULL;
  unsigned char *sig_blob = NULL;
  size_t sig_blob_n = 0;
  size_t bytes_read = 0;
  char description[] =
    "Please provide the passphrase for key "
    "`0123456789012345678901234567890123456789':";
  char key_grip[41];
  unsigned int i = 0;

  for (i = 0; i < 20; i++)
    sprintf (&key_grip[i * 2], "%02X", ctrl->keygrip[i]);
  strncpy (strchr (description, '0'), key_grip, 40);
	   
  err = agent_pksign_do (ctrl, description, &signature_sexp, 0);
  if (err)
    goto out;

  err = gpg_stream_create (&stream, NULL,
			   GPG_STREAM_FLAG_READ | GPG_STREAM_FLAG_WRITE,
			   gpg_stream_functions_mem);
  if (err)
    goto out;

  /* FIXME */
  switch (1 /* rsa */)
    {
    case 1:
      sublist = gcry_sexp_find_token (signature_sexp, "s", 0);
      if (! sublist)
	{
	  err = GPG_ERR_INTERNAL;
	  break;
	}

      sig_value = gcry_sexp_nth_mpi (sublist, 1, GCRYMPI_FMT_USG);
      if (! sig_value)
	{
	  err = GPG_ERR_INTERNAL;
	  break;
	}

      err = gcry_mpi_aprint (GCRYMPI_FMT_USG,
			     &signature, &signature_n, sig_value);
      if (err)
	break;

      err = gpg_stream_write_cstring (stream, "ssh-rsa");
      if (err)
	break;

      err = gpg_stream_write_string (stream, signature, signature_n);
      if (err)
	break;
    }
  if (err)
    goto out;

  err = gpg_stream_seek (stream, 0, SEEK_SET);
  if (err)
    goto out;

  err = gpg_stream_stat (stream, &sig_blob_n);
  if (err)
    goto out;

  sig_blob = malloc (sig_blob_n);
  if (! sig_blob)
    {
      err = gpg_err_code_from_errno (errno);
      goto out;
    }

  err = gpg_stream_read (stream, sig_blob, sig_blob_n, &bytes_read);
  if ((! err) && (sig_blob_n != bytes_read))
    err = GPG_ERR_INTERNAL; 	/* violation */
  if (err)
    goto out;

 out:

  gpg_stream_destroy (stream);
  gcry_mpi_release (sig_value);
  free (signature);

  if (! err)
    {
      *sig = sig_blob;
      *sig_n = sig_blob_n;
    }
  else
    {
      gcry_sexp_release (signature_sexp);
      gcry_sexp_release (sublist);
      free (sig_blob);
    }

  return err;
}

static void
ssh_handler_sign_request (ctrl_t ctrl,
			  gpg_stream_t request, gpg_stream_t response)
{
  ssh_key_public_t key = { SSH_KEY_TYPE_NONE };
  unsigned char hash[MAX_DIGEST_LEN] = { 0 };
  unsigned int hash_n = 0;
  gpg_err_code_t err = GPG_ERR_NO_ERROR;
  unsigned char key_grip[20] = { 0 };
  unsigned char *key_blob = NULL;
  uint32_t key_blob_size = 0;
  unsigned char *sig = NULL;
  unsigned char *data = NULL;
  uint32_t data_size = 0;
  size_t sig_n = 0;
  uint32_t flags = 0;

  if (DBG_COMMAND)
    log_debug ("[ssh-agent] sign request\n");

  /* Receive key.  */
  
  err = gpg_stream_read_string (request, &key_blob, &key_blob_size);
  if (err)
    goto out;
  
  err = ssh_extract_key_public_from_blob (key_blob, key_blob_size, &key);
  if (err)
    goto out;

  /* Receive data to sign.  */
  
  err = gpg_stream_read_string (request, &data, &data_size);
  if (err)
    goto out;

  /* Read flags, FIXME?  */

  err = gpg_stream_read_uint32 (request, &flags);
  if (err)
    goto out;

  /* Hash data.  */
  
  hash_n = gcry_md_get_algo_dlen (GCRY_MD_SHA1);
  if (! hash_n)
    {
      err = GPG_ERR_INTERNAL;	/* FIXME? */
      goto out;
    }

  err = data_hash (data, data_size, GCRY_MD_SHA1, hash);
  if (err)
    goto out;

  /* Calculate key grip.  */
  
  err = ssh_key_grip (&key, NULL, key_grip);
  if (err)
    goto out;

  /* Fill control structure.  */

  ctrl->digest.algo = GCRY_MD_SHA1;
  memcpy (ctrl->digest.value, hash, hash_n);
  ctrl->digest.valuelen = hash_n;
  ctrl->have_keygrip = 1;
  memcpy (ctrl->keygrip, key_grip, 20);

  /* Sign data.  */

  err = data_sign (ctrl, &sig, &sig_n);
  if (err)
    goto out;

 out:

  /* Done.  */
  
  if (! err)
    {
      err = gpg_stream_write_byte (response, SSH_RESPONSE_SIGN_RESPONSE);
      if (! err)
	err = gpg_stream_write_string (response, sig, sig_n);
    }
  else
    gpg_stream_write_byte (response, SSH_RESPONSE_FAILURE);

  free (key_blob);
  free (data);
  free (sig);
}

static gpg_err_code_t
ssh_key_to_sexp_buffer (ssh_key_secret_t *key, const char *passphrase,
			unsigned char **buffer, size_t *buffer_n)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;
  unsigned char *buffer_new = NULL;
  unsigned int buffer_new_n = 0;
  gcry_sexp_t key_sexp = NULL;

  err = gcry_sexp_build (&key_sexp, NULL,
			 "(private-key"
			 " (rsa"
			 "  (n %m)"
			 "  (e %m)"
			 "  (d %m)"
			 "  (p %m)"
			 "  (q %m)"
			 "  (u %m)))",
			 key->material.rsa.n,
			 key->material.rsa.e,
			 key->material.rsa.d,
			 key->material.rsa.p,
			 key->material.rsa.q,
			 key->material.rsa.u);
  if (err)
    goto out;

  buffer_new_n = gcry_sexp_sprint (key_sexp, GCRYSEXP_FMT_CANON, NULL, 0);
  buffer_new = malloc (buffer_new_n);
  if (! buffer_new)
    {
      err = gpg_err_code_from_errno (errno);
      goto out;
    }
  
  gcry_sexp_sprint (key_sexp, GCRYSEXP_FMT_CANON, buffer_new, buffer_new_n);

  err = agent_protect (buffer_new, passphrase, buffer, buffer_n);
  if (err)
    goto out;

 out:

  if (key_sexp)
    gcry_sexp_release (key_sexp);
  if (buffer_new)
    free (buffer_new);

  return err;
}

static gpg_err_code_t
get_passphrase (char *description, size_t passphrase_n, char *passphrase)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;
  struct pin_entry_info_s *pi = NULL;

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

 out:

  return err;
}

static gpg_err_code_t
ssh_identity_register (ssh_key_secret_t *key, int ttl)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;
  unsigned char key_grip[21] = { 0 };
  unsigned char *buffer = NULL;
  unsigned int buffer_n = 0;
  char passphrase[100] = { 0 };
  int ret = 0;

  if (DBG_COMMAND)
    log_debug ("[ssh-agent] registering identity `%s'\n", key_grip);

  err = ssh_key_grip (NULL, key, key_grip);
  if (err)
    goto out;

  ret = agent_key_available (key_grip);
  if (! ret)
    goto out;

  err = get_passphrase ("foo", sizeof (passphrase), passphrase);
  if (err)
    goto out;

  err = ssh_key_to_sexp_buffer (key, passphrase, &buffer, &buffer_n);
  if (err)
    goto out;

  err = agent_write_private_key (key_grip, buffer, buffer_n, 0);
  if (err)
    goto out;

  err = agent_put_cache (key_grip, passphrase, ttl);
  if (err)
    goto out;

 out:

  free (buffer);

  return err;
}

static gpg_err_code_t
ssh_identity_drop (ssh_key_public_t *key)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;
  unsigned char key_grip[21] = { 0 };

  err = ssh_key_grip (key, NULL, key_grip);
  if (err)
    goto out;

  /* FIXME */

  if (DBG_COMMAND)
    log_debug ("[ssh-agent] dropping identity `%s'\n", key_grip);

 out:

  return err;
}

static void
ssh_handler_add_identity (ctrl_t ctrl,
			  gpg_stream_t request, gpg_stream_t response)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;
  ssh_key_secret_t key = { 0 };
  unsigned char *comment = NULL;
  byte_t b = 0;
  int confirm = 0;
  int death = 0;

  if (DBG_COMMAND)
    log_debug ("[ssh-agent] add identity\n");

  err = ssh_receive_key_secret (request, &key);
  if (err)
    goto out;

  err = gpg_stream_read_string (request, &comment, NULL);
  if (err)
    goto out;
  
  while (1)
    {
      err = gpg_stream_read_byte (request, &b);
      if (err)
	{
	  err = GPG_ERR_NO_ERROR;
	  break;
	}

      switch (b)
	{
	case SSH_OPT_CONSTRAIN_LIFETIME:
	  {
	    uint32_t n = 0;

	    err = gpg_stream_read_uint32 (request, &n);
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
	  break;
	}
    }
  if (err)
    goto out;

  if (lifetime_default && (! death))
    death = time (NULL) + lifetime_default;

  /* FIXME: are constraints used correctly?  */

  err = ssh_identity_register (&key, death);
  if (err)
    goto out;

 out:

  free (comment);
  
  //ssh_key_destroy (key); FIXME

  gpg_stream_write_byte (response,
			 err
			 ? SSH_RESPONSE_FAILURE
			 : SSH_RESPONSE_SUCCESS);
}

static void
ssh_handler_remove_identity (ctrl_t ctrl,
			     gpg_stream_t request, gpg_stream_t response)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;
  ssh_key_public_t key = { SSH_KEY_TYPE_NONE };
  unsigned char *key_blob = NULL;
  uint32_t key_blob_size = 0;

  /* Receive key.  */

  if (DBG_COMMAND)
    log_debug ("[ssh-agent] remove identity\n");
  
  err = gpg_stream_read_string (request, &key_blob, NULL);
  if (err)
    goto out;

  err = ssh_extract_key_public_from_blob (key_blob, key_blob_size, &key);
  if (err)
    goto out;
  
  err = ssh_identity_drop (&key);
  if (err)
    goto out;

 out:

  free (key_blob);
  
  err = gpg_stream_write_byte (response,
			       err
			       ? SSH_RESPONSE_FAILURE
			       : SSH_RESPONSE_SUCCESS);
}

static gpg_err_code_t
ssh_identities_remove_all (void)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;

  if (DBG_COMMAND)
    log_debug ("[ssh-agent] remove all identities\n");

  /* FIXME: shall we remove _all_ cache entries or only those
     registered through the ssh emulation?  */
  
  return err;
}

static void
ssh_handler_remove_all_identities (ctrl_t ctrl,
				   gpg_stream_t request, gpg_stream_t response)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;

  err = ssh_identities_remove_all ();

  gpg_stream_write_byte (response,
			 err
			 ? SSH_RESPONSE_FAILURE
			 : SSH_RESPONSE_SUCCESS);
}

static gpg_err_code_t
ssh_lock (void)
{
  gpg_err_code_t err = GPG_ERR_NOT_IMPLEMENTED;

  if (DBG_COMMAND)
    log_debug ("[ssh-agent] lock\n");

  return err;
}

static gpg_err_code_t
ssh_unlock (void)
{
  gpg_err_code_t err = GPG_ERR_NOT_IMPLEMENTED;

  if (DBG_COMMAND)
    log_debug ("[ssh-agent] unlock\n");

  return err;
}

static void
ssh_handler_lock (ctrl_t ctrl,
		  gpg_stream_t request, gpg_stream_t response)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;

  err = ssh_lock ();

  gpg_stream_write_byte (response,
			 err
			 ? SSH_RESPONSE_FAILURE
			 : SSH_RESPONSE_SUCCESS);
}

static void
ssh_handler_unlock (ctrl_t ctrl,
		    gpg_stream_t request, gpg_stream_t response)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;

  err = ssh_unlock ();

  gpg_stream_write_byte (response,
			 err
			 ? SSH_RESPONSE_FAILURE
			 : SSH_RESPONSE_SUCCESS);
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



static gpg_err_code_t
ssh_request_process (ctrl_t ctrl, gpg_stream_t request, gpg_stream_t response)
{
  ssh_request_type_t request_type = 0;
  gpg_err_code_t err = GPG_ERR_NO_ERROR;
  unsigned int i = 0;

  err = gpg_stream_read_byte (request, &request_type);
  if (err)
    goto out;

  if (DBG_COMMAND)
    log_debug ("[ssh-agent] request: %u\n", request_type);

  for (i = 0; i < DIM (request_specs); i++)
    if (request_specs[i].type == request_type)
      break;
  if (i == DIM (request_specs))
    {
      err = gpg_stream_write_byte (response, SSH_RESPONSE_FAILURE);
      goto out;
    }

  (*request_specs[i].handler) (ctrl, request, response);

 out:
  
  return err;
}

static gpg_err_code_t
gpg_stream_eof_p (gpg_stream_t stream, unsigned int *eof)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;
  size_t bytes_left = 0;

  err = gpg_stream_peek (stream, NULL, &bytes_left);
  if (! err)
    *eof = !bytes_left;

  return err;
}

void
start_command_handler_ssh (int sock_client)
{
  struct server_control_s ctrl =  { NULL };
  gpg_err_code_t err = GPG_ERR_NO_ERROR;
  gpg_stream_t stream_sock = NULL;
  gpg_stream_t stream_request = NULL;
  gpg_stream_t stream_response = NULL;
  unsigned char *request = NULL;
  uint32_t request_size = 0;
  unsigned int eof = 0;
  size_t size = 0;

  /* Setup control structure.  */

  if (DBG_COMMAND)
    log_debug ("[ssh-agent] Starting command handler\n");

  ctrl.connection_fd = sock_client;

  err = gpg_stream_create_fd (&stream_sock, sock_client,
			      GPG_STREAM_FLAG_READ | GPG_STREAM_FLAG_WRITE);
  if (err)
    goto out;
  
  while (1)
    {
      err = gpg_stream_eof_p (stream_sock, &eof);
      if (err || eof)
	break;

      /* Create memory streams for request/response data.  */
      stream_request = NULL;
      err = gpg_stream_create (&stream_request, NULL,
			       GPG_STREAM_FLAG_READ | GPG_STREAM_FLAG_WRITE,
			       gpg_stream_functions_mem);
      if (err)
	break;
      stream_response = NULL;
      err = gpg_stream_create (&stream_response, NULL,
			       GPG_STREAM_FLAG_READ | GPG_STREAM_FLAG_WRITE,
			       gpg_stream_functions_mem);
      if (err)
	break;

      /* Retrieve request length.  */
      free (request);
      request = NULL;
      err = gpg_stream_read_string (stream_sock, &request, &request_size);
      if (err)
	break;

      if (DBG_COMMAND)
	log_debug ("[ssh-agent] Received request of length: %u\n",
		   request_size);

      /* Write request data to request stream.  */
      err = gpg_stream_write (stream_request, request, request_size, NULL);
      if (err)
	break;

      err = gpg_stream_seek (stream_request, 0, SEEK_SET);
      if (err)
	break;

      /* Process request.  */
      err = ssh_request_process (&ctrl, stream_request, stream_response);
      if (err)
	break;
 
      /* Figure out size of response data.  */
      err = gpg_stream_seek (stream_response, 0, SEEK_SET);
      if (err)
	break;
      err = gpg_stream_stat (stream_response, &size);
      if (err)
	break;

      /* Write response data to socket stream.  */
      err = gpg_stream_write_uint32 (stream_sock, size);
      if (err)
	break;
      err = gpg_stream_copy (stream_sock, stream_response);
      if (err)
	break;
      
      err = gpg_stream_flush (stream_sock);
      if (err)
	break;
    };
  if (err)
    goto out;


 out:

  gpg_stream_destroy (stream_sock);
  gpg_stream_destroy (stream_request);
  gpg_stream_destroy (stream_response);
  free (request);

  if (DBG_COMMAND)
    log_debug ("[ssh-agent] Leaving ssh command handler: %s\n", gpg_strerror (err));

  /* fixme: make sure that stream_destroy closes client socket.  */
}
