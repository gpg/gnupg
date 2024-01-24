/* command-ssh.c - gpg-agent's implementation of the ssh-agent protocol.
 * Copyright (C) 2004-2006, 2009, 2012 Free Software Foundation, Inc.
 * Copyright (C) 2004-2006, 2009, 2012-2014 Werner Koch
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

/* Only v2 of the ssh-agent protocol is implemented.  Relevant RFCs
   are:

   RFC-4250 - Protocol Assigned Numbers
   RFC-4251 - Protocol Architecture
   RFC-4252 - Authentication Protocol
   RFC-4253 - Transport Layer Protocol
   RFC-5656 - ECC support

   The protocol for the agent is defined in:

   https://tools.ietf.org/html/draft-miller-ssh-agent

  */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#ifndef HAVE_W32_SYSTEM
#include <sys/socket.h>
#include <sys/un.h>
#endif /*!HAVE_W32_SYSTEM*/
#ifdef HAVE_SYS_UCRED_H
#include <sys/ucred.h>
#endif
#ifdef HAVE_UCRED_H
#include <ucred.h>
#endif

#include "agent.h"

#include "../common/i18n.h"
#include "../common/util.h"
#include "../common/ssh-utils.h"




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

/* Other constants.  */
#define SSH_DSA_SIGNATURE_PADDING 20
#define SSH_DSA_SIGNATURE_ELEMS    2
#define SSH_AGENT_RSA_SHA2_256            0x02
#define SSH_AGENT_RSA_SHA2_512            0x04
#define SPEC_FLAG_USE_PKCS1V2 (1 << 0)
#define SPEC_FLAG_IS_ECDSA    (1 << 1)
#define SPEC_FLAG_IS_EdDSA    (1 << 2)  /*(lowercase 'd' on purpose.)*/
#define SPEC_FLAG_WITH_CERT   (1 << 7)

/* The name of the control file.  */
#define SSH_CONTROL_FILE_NAME "sshcontrol"

/* The blurb we put into the header of a newly created control file.  */
static const char sshcontrolblurb[] =
"# List of allowed ssh keys.  Only keys present in this file are used\n"
"# in the SSH protocol.  The ssh-add tool may add new entries to this\n"
"# file to enable them; you may also add them manually.  Comment\n"
"# lines, like this one, as well as empty lines are ignored.  Lines do\n"
"# have a certain length limit but this is not serious limitation as\n"
"# the format of the entries is fixed and checked by gpg-agent. A\n"
"# non-comment line starts with optional white spaces, followed by the\n"
"# keygrip of the key given as 40 hex digits, optionally followed by a\n"
"# caching TTL in seconds, and another optional field for arbitrary\n"
"# flags.   Prepend the keygrip with an '!' mark to disable it.\n"
"\n";


/* Macros.  */

/* Return a new uint32 with b0 being the most significant byte and b3
   being the least significant byte.  */
#define uint32_construct(b0, b1, b2, b3) \
  ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3)




/*
 * Basic types.
 */

/* Type for a request handler.  */
typedef gpg_error_t (*ssh_request_handler_t) (ctrl_t ctrl,
					      estream_t request,
					      estream_t response);


struct ssh_key_type_spec;
typedef struct ssh_key_type_spec ssh_key_type_spec_t;

/* Type, which is used for associating request handlers with the
   appropriate request IDs.  */
typedef struct ssh_request_spec
{
  unsigned char type;
  ssh_request_handler_t handler;
  const char *identifier;
  unsigned int secret_input;
} ssh_request_spec_t;

/* Type for "key modifier functions", which are necessary since
   OpenSSH and GnuPG treat key material slightly different.  A key
   modifier is called right after a new key identity has been received
   in order to "sanitize" the material.  */
typedef gpg_error_t (*ssh_key_modifier_t) (const char *elems,
                                           gcry_mpi_t *mpis);

/* The encoding of a generated signature is dependent on the
   algorithm; therefore algorithm specific signature encoding
   functions are necessary.  */
typedef gpg_error_t (*ssh_signature_encoder_t) (ssh_key_type_spec_t *spec,
                                                estream_t signature_blob,
						gcry_sexp_t sig);

/* Type, which is used for boundling all the algorithm specific
   information together in a single object.  */
struct ssh_key_type_spec
{
  /* Algorithm identifier as used by OpenSSH.  */
  const char *ssh_identifier;

  /* Human readable name of the algorithm.  */
  const char *name;

  /* Algorithm identifier as used by GnuPG.  */
  int algo;

  /* List of MPI names for secret keys; order matches the one of the
     agent protocol.  */
  const char *elems_key_secret;

  /* List of MPI names for public keys; order matches the one of the
     agent protocol.  */
  const char *elems_key_public;

  /* List of MPI names for signature data.  */
  const char *elems_signature;

  /* List of MPI names for secret keys; order matches the one, which
     is required by gpg-agent's key access layer.  */
  const char *elems_sexp_order;

  /* Key modifier function.  Key modifier functions are necessary in
     order to fix any inconsistencies between the representation of
     keys on the SSH and on the GnuPG side.  */
  ssh_key_modifier_t key_modifier;

  /* Signature encoder function.  Signature encoder functions are
     necessary since the encoding of signatures depends on the used
     algorithm.  */
  ssh_signature_encoder_t signature_encoder;

  /* The name of the ECC curve or NULL for non-ECC algos.  This is the
   * canonical name for the curve as specified by RFC-5656.  */
  const char *curve_name;

  /* An alias for curve_name or NULL.  Actually this is Libcgrypt's
   * primary name of the curve.  */
  const char *alt_curve_name;

  /* The hash algorithm to be used with this key.  0 for using the
     default.  */
  int hash_algo;

  /* Misc flags.  */
  unsigned int flags;
};


/* Definition of an object to access the sshcontrol file.  */
struct ssh_control_file_s
{
  char *fname;  /* Name of the file.  */
  estream_t fp; /* This is never NULL. */
  int lnr;      /* The current line number.  */
  struct {
    int valid;           /* True if the data of this structure is valid.  */
    int disabled;        /* The item is disabled.  */
    int ttl;             /* The TTL of the item.   */
    int confirm;         /* The confirm flag is set.  */
    char hexgrip[40+1];  /* The hexgrip of the item (uppercase).  */
  } item;
};


/* Prototypes.  */
static gpg_error_t ssh_handler_request_identities (ctrl_t ctrl,
						   estream_t request,
						   estream_t response);
static gpg_error_t ssh_handler_sign_request (ctrl_t ctrl,
					     estream_t request,
					     estream_t response);
static gpg_error_t ssh_handler_add_identity (ctrl_t ctrl,
					     estream_t request,
					     estream_t response);
static gpg_error_t ssh_handler_remove_identity (ctrl_t ctrl,
						estream_t request,
						estream_t response);
static gpg_error_t ssh_handler_remove_all_identities (ctrl_t ctrl,
						      estream_t request,
						      estream_t response);
static gpg_error_t ssh_handler_lock (ctrl_t ctrl,
				     estream_t request,
				     estream_t response);
static gpg_error_t ssh_handler_unlock (ctrl_t ctrl,
				       estream_t request,
				       estream_t response);

static gpg_error_t ssh_key_modifier_rsa (const char *elems, gcry_mpi_t *mpis);
static gpg_error_t ssh_signature_encoder_rsa (ssh_key_type_spec_t *spec,
                                              estream_t signature_blob,
                                              gcry_sexp_t signature);
static gpg_error_t ssh_signature_encoder_dsa (ssh_key_type_spec_t *spec,
                                              estream_t signature_blob,
                                              gcry_sexp_t signature);
static gpg_error_t ssh_signature_encoder_ecdsa (ssh_key_type_spec_t *spec,
                                                estream_t signature_blob,
                                                gcry_sexp_t signature);
static gpg_error_t ssh_signature_encoder_eddsa (ssh_key_type_spec_t *spec,
                                                estream_t signature_blob,
                                                gcry_sexp_t signature);
static gpg_error_t ssh_key_extract_comment (gcry_sexp_t key, char **comment);



/* Global variables.  */


/* Associating request types with the corresponding request
   handlers.  */

static const ssh_request_spec_t request_specs[] =
  {
#define REQUEST_SPEC_DEFINE(id, name, secret_input) \
  { SSH_REQUEST_##id, ssh_handler_##name, #name, secret_input }

    REQUEST_SPEC_DEFINE (REQUEST_IDENTITIES,    request_identities,    1),
    REQUEST_SPEC_DEFINE (SIGN_REQUEST,          sign_request,          0),
    REQUEST_SPEC_DEFINE (ADD_IDENTITY,          add_identity,          1),
    REQUEST_SPEC_DEFINE (ADD_ID_CONSTRAINED,    add_identity,          1),
    REQUEST_SPEC_DEFINE (REMOVE_IDENTITY,       remove_identity,       0),
    REQUEST_SPEC_DEFINE (REMOVE_ALL_IDENTITIES, remove_all_identities, 0),
    REQUEST_SPEC_DEFINE (LOCK,                  lock,                  0),
    REQUEST_SPEC_DEFINE (UNLOCK,                unlock,                0)
#undef REQUEST_SPEC_DEFINE
  };


/* Table holding key type specifications.  */
static const ssh_key_type_spec_t ssh_key_types[] =
  {
    {
      "ssh-ed25519", "Ed25519", GCRY_PK_EDDSA, "qd",  "q", "rs", "qd",
      NULL,                 ssh_signature_encoder_eddsa,
      "Ed25519", NULL, 0,   SPEC_FLAG_IS_EdDSA
    },
    {
      "ssh-rsa", "RSA", GCRY_PK_RSA, "nedupq", "en",   "s",  "nedpqu",
      ssh_key_modifier_rsa, ssh_signature_encoder_rsa,
      NULL, NULL, 0,        SPEC_FLAG_USE_PKCS1V2
    },
    {
      "ssh-dss", "DSA", GCRY_PK_DSA, "pqgyx",  "pqgy", "rs", "pqgyx",
      NULL,                 ssh_signature_encoder_dsa,
      NULL, NULL, 0, 0
    },
    {
      "ecdsa-sha2-nistp256", "ECDSA", GCRY_PK_ECC, "qd",  "q", "rs", "qd",
      NULL,                 ssh_signature_encoder_ecdsa,
      "nistp256", "NIST P-256", GCRY_MD_SHA256, SPEC_FLAG_IS_ECDSA
    },
    {
      "ecdsa-sha2-nistp384", "ECDSA", GCRY_PK_ECC, "qd",  "q", "rs", "qd",
      NULL,                 ssh_signature_encoder_ecdsa,
      "nistp384", "NIST P-384", GCRY_MD_SHA384, SPEC_FLAG_IS_ECDSA
    },
    {
      "ecdsa-sha2-nistp521", "ECDSA", GCRY_PK_ECC, "qd",  "q", "rs", "qd",
      NULL,                 ssh_signature_encoder_ecdsa,
      "nistp521", "NIST P-521", GCRY_MD_SHA512, SPEC_FLAG_IS_ECDSA
    },
    {
      "ssh-ed25519-cert-v01@openssh.com", "Ed25519",
      GCRY_PK_EDDSA, "qd",  "q", "rs", "qd",
      NULL,                 ssh_signature_encoder_eddsa,
      "Ed25519", NULL, 0,   SPEC_FLAG_IS_EdDSA | SPEC_FLAG_WITH_CERT
    },
    {
      "ssh-rsa-cert-v01@openssh.com", "RSA",
      GCRY_PK_RSA, "nedupq", "en",   "s",  "nedpqu",
      ssh_key_modifier_rsa, ssh_signature_encoder_rsa,
      NULL, NULL, 0, SPEC_FLAG_USE_PKCS1V2 | SPEC_FLAG_WITH_CERT
    },
    {
      "ssh-dss-cert-v01@openssh.com", "DSA",
      GCRY_PK_DSA, "pqgyx",  "pqgy", "rs", "pqgyx",
      NULL,                 ssh_signature_encoder_dsa,
      NULL, NULL, 0, SPEC_FLAG_WITH_CERT | SPEC_FLAG_WITH_CERT
    },
    {
      "ecdsa-sha2-nistp256-cert-v01@openssh.com", "ECDSA",
      GCRY_PK_ECC, "qd",  "q", "rs", "qd",
      NULL,                 ssh_signature_encoder_ecdsa,
      "nistp256", "NIST P-256", GCRY_MD_SHA256,
                                SPEC_FLAG_IS_ECDSA | SPEC_FLAG_WITH_CERT
    },
    {
      "ecdsa-sha2-nistp384-cert-v01@openssh.com", "ECDSA",
      GCRY_PK_ECC, "qd",  "q", "rs", "qd",
      NULL,                 ssh_signature_encoder_ecdsa,
      "nistp384", "NIST P-384", GCRY_MD_SHA384,
                                SPEC_FLAG_IS_ECDSA | SPEC_FLAG_WITH_CERT
    },
    {
      "ecdsa-sha2-nistp521-cert-v01@openssh.com", "ECDSA",
      GCRY_PK_ECC, "qd",  "q", "rs", "qd",
      NULL,                 ssh_signature_encoder_ecdsa,
      "nistp521", "NIST P-521", GCRY_MD_SHA512,
                                SPEC_FLAG_IS_ECDSA | SPEC_FLAG_WITH_CERT
    }
  };





/*
   General utility functions.
 */

/* A secure realloc, i.e. it makes sure to allocate secure memory if A
   is NULL.  This is required because the standard gcry_realloc does
   not know whether to allocate secure or normal if NULL is passed as
   existing buffer.  */
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


/* Lookup the ssh-identifier for the ECC curve CURVE_NAME.  Returns
 * NULL if not found.  If found the ssh indetifier is returned and a
 * pointer to the canonical curve name as specified for ssh is stored
 * at R_CANON_NAME.  */
static const char *
ssh_identifier_from_curve_name (const char *curve_name,
                                const char **r_canon_name)
{
  int i;

  for (i = 0; i < DIM (ssh_key_types); i++)
    if (ssh_key_types[i].curve_name
        && (!strcmp (ssh_key_types[i].curve_name, curve_name)
            || (ssh_key_types[i].alt_curve_name
                && !strcmp (ssh_key_types[i].alt_curve_name, curve_name))))
      {
        *r_canon_name = ssh_key_types[i].curve_name;
        return ssh_key_types[i].ssh_identifier;
      }

  return NULL;
}


/*
   Primitive I/O functions.
 */


/* Read a byte from STREAM, store it in B.  */
static gpg_error_t
stream_read_byte (estream_t stream, unsigned char *b)
{
  gpg_error_t err;
  int ret;

  ret = es_fgetc (stream);
  if (ret == EOF)
    {
      if (es_ferror (stream))
	err = gpg_error_from_syserror ();
      else
	err = gpg_error (GPG_ERR_EOF);
      *b = 0;
    }
  else
    {
      *b = ret & 0xFF;
      err = 0;
    }

  return err;
}

/* Write the byte contained in B to STREAM.  */
static gpg_error_t
stream_write_byte (estream_t stream, unsigned char b)
{
  gpg_error_t err;
  int ret;

  ret = es_fputc (b, stream);
  if (ret == EOF)
    err = gpg_error_from_syserror ();
  else
    err = 0;

  return err;
}


/* Read a uint32 from STREAM, store it in UINT32.  */
static gpg_error_t
stream_read_uint32 (estream_t stream, u32 *uint32)
{
  unsigned char buffer[4];
  size_t bytes_read;
  gpg_error_t err;
  int ret;

  ret = es_read (stream, buffer, sizeof (buffer), &bytes_read);
  if (ret)
    err = gpg_error_from_syserror ();
  else
    {
      if (bytes_read != sizeof (buffer))
	err = gpg_error (GPG_ERR_EOF);
      else
	{
	  u32 n;

	  n = uint32_construct (buffer[0], buffer[1], buffer[2], buffer[3]);
	  *uint32 = n;
	  err = 0;
	}
    }

  return err;
}

/* Write the uint32 contained in UINT32 to STREAM.  */
static gpg_error_t
stream_write_uint32 (estream_t stream, u32 uint32)
{
  unsigned char buffer[4];
  gpg_error_t err;
  int ret;

  buffer[0] = uint32 >> 24;
  buffer[1] = uint32 >> 16;
  buffer[2] = uint32 >>  8;
  buffer[3] = uint32 >>  0;

  ret = es_write (stream, buffer, sizeof (buffer), NULL);
  if (ret)
    err = gpg_error_from_syserror ();
  else
    err = 0;

  return err;
}

/* Read SIZE bytes from STREAM into BUFFER.  */
static gpg_error_t
stream_read_data (estream_t stream, unsigned char *buffer, size_t size)
{
  gpg_error_t err;
  size_t bytes_read;
  int ret;

  ret = es_read (stream, buffer, size, &bytes_read);
  if (ret)
    err = gpg_error_from_syserror ();
  else
    {
      if (bytes_read != size)
	err = gpg_error (GPG_ERR_EOF);
      else
	err = 0;
    }

  return err;
}

/* Skip over SIZE bytes from STREAM.  */
static gpg_error_t
stream_read_skip (estream_t stream, size_t size)
{
  char buffer[128];
  size_t bytes_to_read, bytes_read;
  int ret;

  do
    {
      bytes_to_read = size;
      if (bytes_to_read > sizeof buffer)
        bytes_to_read = sizeof buffer;

      ret = es_read (stream, buffer, bytes_to_read, &bytes_read);
      if (ret)
        return gpg_error_from_syserror ();
      else if (bytes_read != bytes_to_read)
        return gpg_error (GPG_ERR_EOF);
      else
        size -= bytes_to_read;
    }
  while (size);

  return 0;
}


/* Write SIZE bytes from BUFFER to STREAM.  */
static gpg_error_t
stream_write_data (estream_t stream, const unsigned char *buffer, size_t size)
{
  gpg_error_t err;
  int ret;

  ret = es_write (stream, buffer, size, NULL);
  if (ret)
    err = gpg_error_from_syserror ();
  else
    err = 0;

  return err;
}

/* Read a binary string from STREAM into STRING, store size of string
   in STRING_SIZE.  Append a hidden nul so that the result may
   directly be used as a C string.  Depending on SECURE use secure
   memory for STRING.  If STRING is NULL do only a dummy read.  */
static gpg_error_t
stream_read_string (estream_t stream, unsigned int secure,
		    unsigned char **string, u32 *string_size)
{
  gpg_error_t err;
  unsigned char *buffer = NULL;
  u32 length = 0;

  if (string_size)
    *string_size = 0;

  /* Read string length.  */
  err = stream_read_uint32 (stream, &length);
  if (err)
    goto out;

  if (string)
    {
      /* Allocate space.  */
      if (secure)
        buffer = xtrymalloc_secure (length + 1);
      else
        buffer = xtrymalloc (length + 1);
      if (! buffer)
        {
          err = gpg_error_from_syserror ();
          goto out;
        }

      /* Read data.  */
      err = length? stream_read_data (stream, buffer, length) : 0;
      if (err)
        goto out;

      /* Finalize string object.  */
      buffer[length] = 0;
      *string = buffer;
    }
  else  /* Dummy read requested.  */
    {
      err = length? stream_read_skip (stream, length) : 0;
      if (err)
        goto out;
    }

  if (string_size)
    *string_size = length;

 out:

  if (err)
    xfree (buffer);

  return err;
}


/* Read a binary string from STREAM and store it as an opaque MPI at
   R_MPI, adding 0x40 (this is the prefix for EdDSA key in OpenPGP).
   Depending on SECURE use secure memory.  If the string is too large
   for key material return an error.  */
static gpg_error_t
stream_read_blob (estream_t stream, unsigned int secure, gcry_mpi_t *r_mpi)
{
  gpg_error_t err;
  unsigned char *buffer = NULL;
  u32 length = 0;

  *r_mpi = NULL;

  /* Read string length.  */
  err = stream_read_uint32 (stream, &length);
  if (err)
    goto leave;

  /* To avoid excessive use of secure memory we check that an MPI is
     not too large. */
  if (length > (4096/8) + 8)
    {
      log_error (_("ssh keys greater than %d bits are not supported\n"), 4096);
      err = GPG_ERR_TOO_LARGE;
      goto leave;
    }

  /* Allocate space.  */
  if (secure)
    buffer = xtrymalloc_secure (length+1);
  else
    buffer = xtrymalloc (length+1);
  if (!buffer)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  /* Read data.  */
  err = stream_read_data (stream, buffer + 1, length);
  if (err)
    goto leave;

  buffer[0] = 0x40;
  *r_mpi = gcry_mpi_set_opaque (NULL, buffer, 8*(length+1));
  buffer = NULL;

 leave:
  xfree (buffer);
  return err;
}


/* Read a C-string from STREAM, store copy in STRING.  */
static gpg_error_t
stream_read_cstring (estream_t stream, char **string)
{
  return stream_read_string (stream, 0, (unsigned char **)string, NULL);
}


/* Write a binary string from STRING of size STRING_N to STREAM.  */
static gpg_error_t
stream_write_string (estream_t stream,
		     const unsigned char *string, u32 string_n)
{
  gpg_error_t err;

  err = stream_write_uint32 (stream, string_n);
  if (err)
    goto out;

  err = stream_write_data (stream, string, string_n);

 out:

  return err;
}

/* Write a C-string from STRING to STREAM.  */
static gpg_error_t
stream_write_cstring (estream_t stream, const char *string)
{
  gpg_error_t err;

  err = stream_write_string (stream,
			     (const unsigned char *) string, strlen (string));

  return err;
}

/* Read an MPI from STREAM, store it in MPINT.  Depending on SECURE
   use secure memory.  */
static gpg_error_t
stream_read_mpi (estream_t stream, unsigned int secure, gcry_mpi_t *mpint)
{
  unsigned char *mpi_data;
  u32 mpi_data_size;
  gpg_error_t err;
  gcry_mpi_t mpi;

  mpi_data = NULL;

  err = stream_read_string (stream, secure, &mpi_data, &mpi_data_size);
  if (err)
    goto out;

  /* To avoid excessive use of secure memory we check that an MPI is
     not too large. */
  if (mpi_data_size > 520)
    {
      log_error (_("ssh keys greater than %d bits are not supported\n"), 4096);
      err = GPG_ERR_TOO_LARGE;
      goto out;
    }

  err = gcry_mpi_scan (&mpi, GCRYMPI_FMT_STD, mpi_data, mpi_data_size, NULL);
  if (err)
    goto out;

  *mpint = mpi;

 out:

  xfree (mpi_data);

  return err;
}

/* Write the MPI contained in MPINT to STREAM.  */
static gpg_error_t
stream_write_mpi (estream_t stream, gcry_mpi_t mpint)
{
  unsigned char *mpi_buffer;
  size_t mpi_buffer_n;
  gpg_error_t err;

  mpi_buffer = NULL;

  err = gcry_mpi_aprint (GCRYMPI_FMT_STD, &mpi_buffer, &mpi_buffer_n, mpint);
  if (err)
    goto out;

  err = stream_write_string (stream, mpi_buffer, mpi_buffer_n);

 out:

  xfree (mpi_buffer);

  return err;
}


/* Copy data from SRC to DST until EOF is reached.  */
static gpg_error_t
stream_copy (estream_t dst, estream_t src)
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
	    err = gpg_error_from_syserror ();
	  break;
	}
      ret = es_write (dst, buffer, bytes_read, NULL);
      if (ret)
	{
	  err = gpg_error_from_syserror ();
	  break;
	}
    }

  return err;
}

/* Open the ssh control file and create it if not available.  With
   APPEND passed as true the file will be opened in append mode,
   otherwise in read only mode.  On success 0 is returned and a new
   control file object stored at R_CF.  On error an error code is
   returned and NULL is stored at R_CF.  */
static gpg_error_t
open_control_file (ssh_control_file_t *r_cf, int append)
{
  gpg_error_t err;
  ssh_control_file_t cf;

  cf = xtrycalloc (1, sizeof *cf);
  if (!cf)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  /* Note: As soon as we start to use non blocking functions here
     (i.e. where Pth might switch threads) we need to employ a
     mutex.  */
  cf->fname = make_filename_try (gnupg_homedir (), SSH_CONTROL_FILE_NAME, NULL);
  if (!cf->fname)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  /* FIXME: With "a+" we are not able to check whether this will
     be created and thus the blurb needs to be written first.  */
  cf->fp = es_fopen (cf->fname, append? "a+":"r");
  if (!cf->fp && errno == ENOENT)
    {
      estream_t stream = es_fopen (cf->fname, "wx,mode=-rw-r");
      if (!stream)
        {
          err = gpg_error_from_syserror ();
          log_error (_("can't create '%s': %s\n"),
                     cf->fname, gpg_strerror (err));
          goto leave;
        }
      es_fputs (sshcontrolblurb, stream);
      es_fclose (stream);
      cf->fp = es_fopen (cf->fname, append? "a+":"r");
    }

  if (!cf->fp)
    {
      err = gpg_error_from_syserror ();
      log_error (_("can't open '%s': %s\n"),
                 cf->fname, gpg_strerror (err));
      goto leave;
    }

  err = 0;

 leave:
  if (err && cf)
    {
      if (cf->fp)
        es_fclose (cf->fp);
      xfree (cf->fname);
      xfree (cf);
    }
  else
    *r_cf = cf;

  return err;
}


static void
rewind_control_file (ssh_control_file_t cf)
{
  es_fseek (cf->fp, 0, SEEK_SET);
  cf->lnr = 0;
  es_clearerr (cf->fp);
}


static void
close_control_file (ssh_control_file_t cf)
{
  if (!cf)
    return;
  es_fclose (cf->fp);
  xfree (cf->fname);
  xfree (cf);
}



/* Read the next line from the control file and store the data in CF.
   Returns 0 on success, GPG_ERR_EOF on EOF, or other error codes. */
static gpg_error_t
read_control_file_item (ssh_control_file_t cf)
{
  int c, i, n;
  char *p, *pend, line[256];
  long ttl = 0;

  cf->item.valid = 0;
  es_clearerr (cf->fp);

  do
    {
      if (!es_fgets (line, DIM(line)-1, cf->fp) )
        {
          if (es_feof (cf->fp))
            return gpg_error (GPG_ERR_EOF);
          return gpg_error_from_syserror ();
        }
      cf->lnr++;

      if (!*line || line[strlen(line)-1] != '\n')
        {
          /* Eat until end of line */
          while ((c = es_getc (cf->fp)) != EOF && c != '\n')
            ;
          return gpg_error (*line? GPG_ERR_LINE_TOO_LONG
                                 : GPG_ERR_INCOMPLETE_LINE);
        }

      /* Allow for empty lines and spaces */
      for (p=line; spacep (p); p++)
        ;
    }
  while (!*p || *p == '\n' || *p == '#');

  cf->item.disabled = 0;
  if (*p == '!')
    {
      cf->item.disabled = 1;
      for (p++; spacep (p); p++)
        ;
    }

  for (i=0; hexdigitp (p) && i < 40; p++, i++)
    cf->item.hexgrip[i] = (*p >= 'a'? (*p & 0xdf): *p);
  cf->item.hexgrip[i] = 0;
  if (i != 40 || !(spacep (p) || *p == '\n'))
    {
      log_error ("%s:%d: invalid formatted line\n", cf->fname, cf->lnr);
      return gpg_error (GPG_ERR_BAD_DATA);
    }

  ttl = strtol (p, &pend, 10);
  p = pend;
  if (!(spacep (p) || *p == '\n') || (int)ttl < -1)
    {
      log_error ("%s:%d: invalid TTL value; assuming 0\n", cf->fname, cf->lnr);
      cf->item.ttl = 0;
    }
  cf->item.ttl = ttl;

  /* Now check for key-value pairs of the form NAME[=VALUE]. */
  cf->item.confirm = 0;
  while (*p)
    {
      for (; spacep (p) && *p != '\n'; p++)
        ;
      if (!*p || *p == '\n')
        break;
      n = strcspn (p, "= \t\n");
      if (p[n] == '=')
        {
          log_error ("%s:%d: assigning a value to a flag is not yet supported; "
                     "flag ignored\n", cf->fname, cf->lnr);
          p++;
        }
      else if (n == 7 && !memcmp (p, "confirm", 7))
        {
          cf->item.confirm = 1;
        }
      else
        log_error ("%s:%d: invalid flag '%.*s'; ignored\n",
                   cf->fname, cf->lnr, n, p);
      p += n;
    }

  /* log_debug ("%s:%d: grip=%s ttl=%d%s%s\n", */
  /*            cf->fname, cf->lnr, */
  /*            cf->item.hexgrip, cf->item.ttl, */
  /*            cf->item.disabled? " disabled":"", */
  /*            cf->item.confirm? " confirm":""); */

  cf->item.valid = 1;
  return 0; /* Okay: valid entry found.  */
}



/* Search the control file CF from the beginning until a matching
   HEXGRIP is found; return success in this case and store true at
   DISABLED if the found key has been disabled.  If R_TTL is not NULL
   a specified TTL for that key is stored there.  If R_CONFIRM is not
   NULL it is set to 1 if the key has the confirm flag set. */
static gpg_error_t
search_control_file (ssh_control_file_t cf, const char *hexgrip,
                     int *r_disabled, int *r_ttl, int *r_confirm)
{
  gpg_error_t err;

  assert (strlen (hexgrip) == 40 );

  if (r_disabled)
    *r_disabled = 0;
  if (r_ttl)
    *r_ttl = 0;
  if (r_confirm)
    *r_confirm = 0;

  rewind_control_file (cf);
  while (!(err=read_control_file_item (cf)))
    {
      if (!cf->item.valid)
        continue; /* Should not happen.  */
      if (!strcmp (hexgrip, cf->item.hexgrip))
        break;
    }
  if (!err)
    {
      if (r_disabled)
        *r_disabled = cf->item.disabled;
      if (r_ttl)
        *r_ttl = cf->item.ttl;
      if (r_confirm)
        *r_confirm = cf->item.confirm;
    }
  return err;
}



/* Add an entry to the control file to mark the key with the keygrip
   HEXGRIP as usable for SSH; i.e. it will be returned when ssh asks
   for it.  FMTFPR is the fingerprint string.  This function is in
   general used to add a key received through the ssh-add function.
   We can assume that the user wants to allow ssh using this key. */
static gpg_error_t
add_control_entry (ctrl_t ctrl, ssh_key_type_spec_t *spec,
                   const char *hexgrip, gcry_sexp_t key,
                   int ttl, int confirm)
{
  gpg_error_t err;
  ssh_control_file_t cf;
  int disabled;
  char *fpr_md5 = NULL;
  char *fpr_sha256 = NULL;

  (void)ctrl;

  err = open_control_file (&cf, 1);
  if (err)
    return err;

  err = search_control_file (cf, hexgrip, &disabled, NULL, NULL);
  if (err && gpg_err_code(err) == GPG_ERR_EOF)
    {
      struct tm *tp;
      time_t atime = time (NULL);

      err = ssh_get_fingerprint_string (key, GCRY_MD_MD5, &fpr_md5);
      if (err)
        goto out;

      err = ssh_get_fingerprint_string (key, GCRY_MD_SHA256, &fpr_sha256);
      if (err)
        goto out;

      /* Not yet in the file - add it. Because the file has been
         opened in append mode, we simply need to write to it.  */
      tp = localtime (&atime);
      es_fprintf (cf->fp,
               ("# %s key added on: %04d-%02d-%02d %02d:%02d:%02d\n"
                "# Fingerprints:  %s\n"
                "#                %s\n"
                "%s %d%s\n"),
               spec->name,
               1900+tp->tm_year, tp->tm_mon+1, tp->tm_mday,
               tp->tm_hour, tp->tm_min, tp->tm_sec,
               fpr_md5, fpr_sha256, hexgrip, ttl, confirm? " confirm":"");

    }
 out:
  xfree (fpr_md5);
  xfree (fpr_sha256);
  close_control_file (cf);
  return 0;
}


/* Scan the sshcontrol file and return the TTL.  */
static int
ttl_from_sshcontrol (const char *hexgrip)
{
  ssh_control_file_t cf;
  int disabled, ttl;

  if (!hexgrip || strlen (hexgrip) != 40)
    return 0;  /* Wrong input: Use global default.  */

  if (open_control_file (&cf, 0))
    return 0; /* Error: Use the global default TTL.  */

  if (search_control_file (cf, hexgrip, &disabled, &ttl, NULL)
      || disabled)
    ttl = 0;  /* Use the global default if not found or disabled.  */

  close_control_file (cf);

  return ttl;
}


/* Scan the sshcontrol file and return the confirm flag.  */
static int
confirm_flag_from_sshcontrol (const char *hexgrip)
{
  ssh_control_file_t cf;
  int disabled, confirm;

  if (!hexgrip || strlen (hexgrip) != 40)
    return 1;  /* Wrong input: Better ask for confirmation.  */

  if (open_control_file (&cf, 0))
    return 1; /* Error: Better ask for confirmation.  */

  if (search_control_file (cf, hexgrip, &disabled, NULL, &confirm)
      || disabled)
    confirm = 0;  /* If not found or disabled, there is no reason to
                     ask for confirmation.  */

  close_control_file (cf);

  return confirm;
}




/* Open the ssh control file for reading.  This is a public version of
   open_control_file.  The caller must use ssh_close_control_file to
   release the returned handle.  */
ssh_control_file_t
ssh_open_control_file (void)
{
  ssh_control_file_t cf;

  /* Then look at all the registered and non-disabled keys. */
  if (open_control_file (&cf, 0))
    return NULL;
  return cf;
}

/* Close an ssh control file handle.  This is the public version of
   close_control_file.  CF may be NULL.  */
void
ssh_close_control_file (ssh_control_file_t cf)
{
  close_control_file (cf);
}

/* Read the next item from the ssh control file.  The function returns
   0 if a item was read, GPG_ERR_EOF on eof or another error value.
   R_HEXGRIP shall either be null or a BUFFER of at least 41 byte.
   R_DISABLED, R_TTLm and R_CONFIRM return flags from the control
   file; they are only set on success. */
gpg_error_t
ssh_read_control_file (ssh_control_file_t cf,
                       char *r_hexgrip,
                       int *r_disabled, int *r_ttl, int *r_confirm)
{
  gpg_error_t err;

  do
    err = read_control_file_item (cf);
  while (!err && !cf->item.valid);
  if (!err)
    {
      if (r_hexgrip)
        strcpy (r_hexgrip, cf->item.hexgrip);
      if (r_disabled)
        *r_disabled = cf->item.disabled;
      if (r_ttl)
        *r_ttl = cf->item.ttl;
      if (r_confirm)
        *r_confirm = cf->item.confirm;
    }
  return err;
}


/* Search for a key with HEXGRIP in sshcontrol and return all
   info.  */
gpg_error_t
ssh_search_control_file (ssh_control_file_t cf,
                         const char *hexgrip,
                         int *r_disabled, int *r_ttl, int *r_confirm)
{
  gpg_error_t err;
  int i;
  const char *s;
  char uphexgrip[41];

  /* We need to make sure that HEXGRIP is all uppercase.  The easiest
     way to do this and also check its length is by copying to a
     second buffer. */
  for (i=0, s=hexgrip; i < 40 && *s; s++, i++)
    uphexgrip[i] = *s >= 'a'? (*s & 0xdf): *s;
  uphexgrip[i] = 0;
  if (i != 40)
    err = gpg_error (GPG_ERR_INV_LENGTH);
  else
    err = search_control_file (cf, uphexgrip, r_disabled, r_ttl, r_confirm);
  if (gpg_err_code (err) == GPG_ERR_EOF)
    err = gpg_error (GPG_ERR_NOT_FOUND);
  return err;
}




/*

  MPI lists.

 */

/* Free the list of MPIs MPI_LIST.  */
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

/* Receive key material MPIs from STREAM according to KEY_SPEC;
   depending on SECRET expect a public key or secret key.  CERT is the
   certificate blob used if KEY_SPEC indicates the certificate format;
   it needs to be positioned to the end of the nonce.  The newly
   allocated list of MPIs is stored in MPI_LIST.  Returns usual error
   code.  */
static gpg_error_t
ssh_receive_mpint_list (estream_t stream, int secret,
			ssh_key_type_spec_t *spec, estream_t cert,
                        gcry_mpi_t **mpi_list)
{
  const char *elems_public;
  unsigned int elems_n;
  const char *elems;
  int elem_is_secret;
  gcry_mpi_t *mpis = NULL;
  gpg_error_t err = 0;
  unsigned int i;

  if (secret)
    elems = spec->elems_key_secret;
  else
    elems = spec->elems_key_public;
  elems_n = strlen (elems);
  elems_public = spec->elems_key_public;

  /* Check that either both, CERT and the WITH_CERT flag, are given or
     none of them.  */
  if (!(!!(spec->flags & SPEC_FLAG_WITH_CERT) ^ !cert))
    {
      err = gpg_error (GPG_ERR_INV_CERT_OBJ);
      goto out;
    }

  mpis = xtrycalloc (elems_n + 1, sizeof *mpis );
  if (!mpis)
    {
      err = gpg_error_from_syserror ();
      goto out;
    }

  elem_is_secret = 0;
  for (i = 0; i < elems_n; i++)
    {
      if (secret)
	elem_is_secret = !strchr (elems_public, elems[i]);

      if (cert && !elem_is_secret)
        err = stream_read_mpi (cert, elem_is_secret, &mpis[i]);
      else
        err = stream_read_mpi (stream, elem_is_secret, &mpis[i]);
      if (err)
	goto out;
    }

  *mpi_list = mpis;
  mpis = NULL;

 out:
  if (err)
    mpint_list_free (mpis);

  return err;
}



/* Key modifier function for RSA.  */
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

/* Signature encoder function for RSA.  */
static gpg_error_t
ssh_signature_encoder_rsa (ssh_key_type_spec_t *spec,
                           estream_t signature_blob,
                           gcry_sexp_t s_signature)
{
  gpg_error_t err = 0;
  gcry_sexp_t valuelist = NULL;
  gcry_sexp_t sublist = NULL;
  gcry_mpi_t sig_value = NULL;
  gcry_mpi_t *mpis = NULL;
  const char *elems;
  size_t elems_n;
  int i;

  unsigned char *data;
  size_t data_n;
  gcry_mpi_t s;

  valuelist = gcry_sexp_nth (s_signature, 1);
  if (!valuelist)
    {
      err = gpg_error (GPG_ERR_INV_SEXP);
      goto out;
    }

  elems = spec->elems_signature;
  elems_n = strlen (elems);

  mpis = xtrycalloc (elems_n + 1, sizeof *mpis);
  if (!mpis)
    {
      err = gpg_error_from_syserror ();
      goto out;
    }

  for (i = 0; i < elems_n; i++)
    {
      sublist = gcry_sexp_find_token (valuelist, spec->elems_signature + i, 1);
      if (!sublist)
	{
	  err = gpg_error (GPG_ERR_INV_SEXP);
	  break;
	}

      sig_value = gcry_sexp_nth_mpi (sublist, 1, GCRYMPI_FMT_USG);
      if (!sig_value)
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

  /* RSA specific */
  s = mpis[0];

  err = gcry_mpi_aprint (GCRYMPI_FMT_USG, &data, &data_n, s);
  if (err)
    goto out;

  err = stream_write_string (signature_blob, data, data_n);
  xfree (data);

 out:
  gcry_sexp_release (valuelist);
  gcry_sexp_release (sublist);
  mpint_list_free (mpis);
  return err;
}


/* Signature encoder function for DSA.  */
static gpg_error_t
ssh_signature_encoder_dsa (ssh_key_type_spec_t *spec,
                           estream_t signature_blob,
                           gcry_sexp_t s_signature)
{
  gpg_error_t err = 0;
  gcry_sexp_t valuelist = NULL;
  gcry_sexp_t sublist = NULL;
  gcry_mpi_t sig_value = NULL;
  gcry_mpi_t *mpis = NULL;
  const char *elems;
  size_t elems_n;
  int i;

  unsigned char buffer[SSH_DSA_SIGNATURE_PADDING * SSH_DSA_SIGNATURE_ELEMS];
  unsigned char *data = NULL;
  size_t data_n;

  valuelist = gcry_sexp_nth (s_signature, 1);
  if (!valuelist)
    {
      err = gpg_error (GPG_ERR_INV_SEXP);
      goto out;
    }

  elems = spec->elems_signature;
  elems_n = strlen (elems);

  mpis = xtrycalloc (elems_n + 1, sizeof *mpis);
  if (!mpis)
    {
      err = gpg_error_from_syserror ();
      goto out;
    }

  for (i = 0; i < elems_n; i++)
    {
      sublist = gcry_sexp_find_token (valuelist, spec->elems_signature + i, 1);
      if (!sublist)
	{
	  err = gpg_error (GPG_ERR_INV_SEXP);
	  break;
	}

      sig_value = gcry_sexp_nth_mpi (sublist, 1, GCRYMPI_FMT_USG);
      if (!sig_value)
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

  /* DSA specific code.  */

  /* FIXME: Why this complicated code?  Why collecting boths mpis in a
     buffer instead of writing them out one after the other?  */
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

  err = stream_write_string (signature_blob, buffer, sizeof (buffer));

 out:
  xfree (data);
  gcry_sexp_release (valuelist);
  gcry_sexp_release (sublist);
  mpint_list_free (mpis);
  return err;
}


/* Signature encoder function for ECDSA.  */
static gpg_error_t
ssh_signature_encoder_ecdsa (ssh_key_type_spec_t *spec,
                             estream_t stream, gcry_sexp_t s_signature)
{
  gpg_error_t err = 0;
  gcry_sexp_t valuelist = NULL;
  gcry_sexp_t sublist = NULL;
  gcry_mpi_t sig_value = NULL;
  gcry_mpi_t *mpis = NULL;
  const char *elems;
  size_t elems_n;
  int i;

  unsigned char *data[2] = {NULL, NULL};
  size_t data_n[2];
  size_t innerlen;

  valuelist = gcry_sexp_nth (s_signature, 1);
  if (!valuelist)
    {
      err = gpg_error (GPG_ERR_INV_SEXP);
      goto out;
    }

  elems = spec->elems_signature;
  elems_n = strlen (elems);

  mpis = xtrycalloc (elems_n + 1, sizeof *mpis);
  if (!mpis)
    {
      err = gpg_error_from_syserror ();
      goto out;
    }

  for (i = 0; i < elems_n; i++)
    {
      sublist = gcry_sexp_find_token (valuelist, spec->elems_signature + i, 1);
      if (!sublist)
	{
	  err = gpg_error (GPG_ERR_INV_SEXP);
	  break;
	}

      sig_value = gcry_sexp_nth_mpi (sublist, 1, GCRYMPI_FMT_USG);
      if (!sig_value)
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

  /* ECDSA specific */

  innerlen = 0;
  for (i = 0; i < DIM(data); i++)
    {
      err = gcry_mpi_aprint (GCRYMPI_FMT_STD, &data[i], &data_n[i], mpis[i]);
      if (err)
	goto out;
      innerlen += 4 + data_n[i];
    }

  err = stream_write_uint32 (stream, innerlen);
  if (err)
    goto out;

  for (i = 0; i < DIM(data); i++)
    {
      err = stream_write_string (stream, data[i], data_n[i]);
      if (err)
        goto out;
    }

 out:
  for (i = 0; i < DIM(data); i++)
    xfree (data[i]);
  gcry_sexp_release (valuelist);
  gcry_sexp_release (sublist);
  mpint_list_free (mpis);
  return err;
}


/* Signature encoder function for EdDSA.  */
static gpg_error_t
ssh_signature_encoder_eddsa (ssh_key_type_spec_t *spec,
                             estream_t stream, gcry_sexp_t s_signature)
{
  gpg_error_t err = 0;
  gcry_sexp_t valuelist = NULL;
  gcry_sexp_t sublist = NULL;
  const char *elems;
  size_t elems_n;
  int i;

  unsigned char *data[2] = {NULL, NULL};
  size_t data_n[2];
  size_t totallen = 0;

  valuelist = gcry_sexp_nth (s_signature, 1);
  if (!valuelist)
    {
      err = gpg_error (GPG_ERR_INV_SEXP);
      goto out;
    }

  elems = spec->elems_signature;
  elems_n = strlen (elems);

  if (elems_n != DIM(data))
    {
      err = gpg_error (GPG_ERR_INV_SEXP);
      goto out;
    }

  for (i = 0; i < DIM(data); i++)
    {
      sublist = gcry_sexp_find_token (valuelist, spec->elems_signature + i, 1);
      if (!sublist)
	{
	  err = gpg_error (GPG_ERR_INV_SEXP);
	  break;
	}

      data[i] = gcry_sexp_nth_buffer (sublist, 1, &data_n[i]);
      if (!data[i])
	{
	  err = gpg_error (GPG_ERR_INTERNAL); /* FIXME?  */
	  break;
	}
      totallen += data_n[i];
      gcry_sexp_release (sublist);
      sublist = NULL;
    }
  if (err)
    goto out;

  err = stream_write_uint32 (stream, totallen);
  if (err)
    goto out;

  for (i = 0; i < DIM(data); i++)
    {
      err = stream_write_data (stream, data[i], data_n[i]);
      if (err)
        goto out;
    }

 out:
  for (i = 0; i < DIM(data); i++)
    xfree (data[i]);
  gcry_sexp_release (valuelist);
  gcry_sexp_release (sublist);
  return err;
}


/*
   S-Expressions.
 */


/* This function constructs a new S-Expression for the key identified
   by the KEY_SPEC, SECRET, CURVE_NAME, MPIS, and COMMENT, which is to
   be stored at R_SEXP.  Returns an error code.  */
static gpg_error_t
sexp_key_construct (gcry_sexp_t *r_sexp,
		    ssh_key_type_spec_t key_spec, int secret,
		    const char *curve_name, gcry_mpi_t *mpis,
                    const char *comment)
{
  gpg_error_t err;
  gcry_sexp_t sexp_new = NULL;
  void *formatbuf = NULL;
  void **arg_list = NULL;
  estream_t format = NULL;
  char *algo_name = NULL;

  /* We can't encode an empty string in an S-expression, thus to keep
   * the code simple we use "(none)" instead.  */
  if (!comment || !*comment)
    comment = "(none)";

  if ((key_spec.flags & SPEC_FLAG_IS_EdDSA))
    {
      /* It is much easier and more readable to use a separate code
         path for EdDSA.  */
      if (!curve_name)
        err = gpg_error (GPG_ERR_INV_CURVE);
      else if (!mpis[0] || !gcry_mpi_get_flag (mpis[0], GCRYMPI_FLAG_OPAQUE))
        err = gpg_error (GPG_ERR_BAD_PUBKEY);
      else if (secret
               && (!mpis[1]
                   || !gcry_mpi_get_flag (mpis[1], GCRYMPI_FLAG_OPAQUE)))
        err = gpg_error (GPG_ERR_BAD_SECKEY);
      else if (secret)
        err = gcry_sexp_build (&sexp_new, NULL,
                               "(private-key(ecc(curve %s)"
                               "(flags eddsa)(q %m)(d %m))"
                               "(comment%s))",
                               curve_name,
                               mpis[0], mpis[1],
                               comment);
      else
        err = gcry_sexp_build (&sexp_new, NULL,
                               "(public-key(ecc(curve %s)"
                               "(flags eddsa)(q %m))"
                               "(comment%s))",
                               curve_name,
                               mpis[0],
                               comment);

    }
  else
    {
      const char *key_identifier[] = { "public-key", "private-key" };
      int arg_idx;
      const char *elems;
      size_t elems_n;
      unsigned int i, j;

      if (secret)
        elems = key_spec.elems_sexp_order;
      else
        elems = key_spec.elems_key_public;
      elems_n = strlen (elems);

      format = es_fopenmem (0, "a+b");
      if (!format)
        {
          err = gpg_error_from_syserror ();
          goto out;
        }

      /* Key identifier, algorithm identifier, mpis, comment, and a NULL
         as a safeguard. */
      arg_list = xtrymalloc (sizeof (*arg_list) * (2 + 1 + elems_n + 1 + 1));
      if (!arg_list)
        {
          err = gpg_error_from_syserror ();
          goto out;
        }
      arg_idx = 0;

      es_fputs ("(%s(%s", format);
      arg_list[arg_idx++] = &key_identifier[secret];
      algo_name = xtrystrdup (gcry_pk_algo_name (key_spec.algo));
      if (!algo_name)
        {
          err = gpg_error_from_syserror ();
          goto out;
        }
      strlwr (algo_name);
      arg_list[arg_idx++] = &algo_name;
      if (curve_name)
        {
          es_fputs ("(curve%s)", format);
          arg_list[arg_idx++] = &curve_name;
        }

      for (i = 0; i < elems_n; i++)
        {
          es_fprintf (format, "(%c%%m)", elems[i]);
          if (secret)
            {
              for (j = 0; j < elems_n; j++)
                if (key_spec.elems_key_secret[j] == elems[i])
                  break;
            }
          else
            j = i;
          arg_list[arg_idx++] = &mpis[j];
        }
      es_fputs (")(comment%s))", format);
      arg_list[arg_idx++] = &comment;
      arg_list[arg_idx] = NULL;

      es_putc (0, format);
      if (es_ferror (format))
        {
          err = gpg_error_from_syserror ();
          goto out;
        }
      if (es_fclose_snatch (format, &formatbuf, NULL))
        {
          err = gpg_error_from_syserror ();
          goto out;
        }
      format = NULL;

      err = gcry_sexp_build_array (&sexp_new, NULL, formatbuf, arg_list);
    }

  if (!err)
    *r_sexp = sexp_new;

 out:
  es_fclose (format);
  xfree (arg_list);
  xfree (formatbuf);
  xfree (algo_name);

  return err;
}


/* This function extracts the key from the s-expression SEXP according
   to KEY_SPEC and stores it in ssh format at (R_BLOB, R_BLOBLEN).  If
   WITH_SECRET is true, the secret key parts are also extracted if
   possible.  Returns 0 on success or an error code.  Note that data
   stored at R_BLOB must be freed using es_free!  */
static gpg_error_t
ssh_key_to_blob (gcry_sexp_t sexp, int with_secret,
                 ssh_key_type_spec_t key_spec,
                 void **r_blob, size_t *r_blob_size)
{
  gpg_error_t err = 0;
  gcry_sexp_t value_list = NULL;
  gcry_sexp_t value_pair = NULL;
  estream_t stream = NULL;
  void *blob = NULL;
  size_t blob_size;
  const char *elems, *p_elems;
  const char *data;
  size_t datalen;

  *r_blob = NULL;
  *r_blob_size = 0;

  stream = es_fopenmem (0, "r+b");
  if (!stream)
    {
      err = gpg_error_from_syserror ();
      goto out;
    }

  /* Get the type of the key expression.  */
  data = gcry_sexp_nth_data (sexp, 0, &datalen);
  if (!data)
    {
      err = gpg_error (GPG_ERR_INV_SEXP);
      goto out;
    }

  if ((datalen == 10 && !strncmp (data, "public-key", 10))
      || (datalen == 21 && !strncmp (data, "protected-private-key", 21))
      || (datalen == 20 && !strncmp (data, "shadowed-private-key", 20)))
    elems = key_spec.elems_key_public;
  else if (datalen == 11 && !strncmp (data, "private-key", 11))
    elems = with_secret? key_spec.elems_key_secret : key_spec.elems_key_public;
  else
    {
      err = gpg_error (GPG_ERR_INV_SEXP);
      goto out;
    }

  /* Get key value list.  */
  value_list = gcry_sexp_cadr (sexp);
  if (!value_list)
    {
      err = gpg_error (GPG_ERR_INV_SEXP);
      goto out;
    }

  /* Write the ssh algorithm identifier.  */
  if ((key_spec.flags & SPEC_FLAG_IS_ECDSA))
    {
      /* Map the curve name to the ssh name.  */
      const char *name, *sshname, *canon_name;

      name = gcry_pk_get_curve (sexp, 0, NULL);
      if (!name)
        {
          err = gpg_error (GPG_ERR_INV_CURVE);
          goto out;
        }

      sshname = ssh_identifier_from_curve_name (name, &canon_name);
      if (!sshname)
        {
          err = gpg_error (GPG_ERR_UNKNOWN_CURVE);
          goto out;
        }
      err = stream_write_cstring (stream, sshname);
      if (err)
        goto out;
      err = stream_write_cstring (stream, canon_name);
      if (err)
        goto out;
    }
  else
    {
      /* Note: This is also used for EdDSA.  */
      err = stream_write_cstring (stream, key_spec.ssh_identifier);
      if (err)
        goto out;
    }

  /* Write the parameters.  */
  for (p_elems = elems; *p_elems; p_elems++)
    {
      gcry_sexp_release (value_pair);
      value_pair = gcry_sexp_find_token (value_list, p_elems, 1);
      if (!value_pair)
	{
	  err = gpg_error (GPG_ERR_INV_SEXP);
	  goto out;
	}
      if ((key_spec.flags & SPEC_FLAG_IS_EdDSA))
        {

          data = gcry_sexp_nth_data (value_pair, 1, &datalen);
          if (!data)
            {
              err = gpg_error (GPG_ERR_INV_SEXP);
              goto out;
            }
          if (*p_elems == 'q' && datalen)
            { /* Remove the prefix 0x40.  */
              data++;
              datalen--;
            }
          err = stream_write_string (stream, data, datalen);
          if (err)
            goto out;
        }
      else
        {
          gcry_mpi_t mpi;

          /* Note that we need to use STD format; i.e. prepend a 0x00
             to indicate a positive number if the high bit is set. */
          mpi = gcry_sexp_nth_mpi (value_pair, 1, GCRYMPI_FMT_STD);
          if (!mpi)
            {
              err = gpg_error (GPG_ERR_INV_SEXP);
              goto out;
            }
          err = stream_write_mpi (stream, mpi);
          gcry_mpi_release (mpi);
          if (err)
            goto out;
        }
    }

  if (es_fclose_snatch (stream, &blob, &blob_size))
    {
      err = gpg_error_from_syserror ();
      goto out;
    }
  stream = NULL;

  *r_blob = blob;
  blob = NULL;
  *r_blob_size = blob_size;

 out:
  gcry_sexp_release (value_list);
  gcry_sexp_release (value_pair);
  es_fclose (stream);
  es_free (blob);

  return err;
}


/*

  Key I/O.

*/

/* Search for a key specification entry.  If SSH_NAME is not NULL,
   search for an entry whose "ssh_name" is equal to SSH_NAME;
   otherwise, search for an entry whose algorithm is equal to ALGO.
   Store found entry in SPEC on success, return error otherwise.  */
static gpg_error_t
ssh_key_type_lookup (const char *ssh_name, int algo,
		     ssh_key_type_spec_t *spec)
{
  gpg_error_t err;
  unsigned int i;

  for (i = 0; i < DIM (ssh_key_types); i++)
    if ((ssh_name && (! strcmp (ssh_name, ssh_key_types[i].ssh_identifier)))
	|| algo == ssh_key_types[i].algo)
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


/* Receive a key from STREAM, according to the key specification given
   as KEY_SPEC.  Depending on SECRET, receive a secret or a public
   key.  If READ_COMMENT is true, receive a comment string as well.
   Constructs a new S-Expression from received data and stores it in
   KEY_NEW.  Returns zero on success or an error code.  */
static gpg_error_t
ssh_receive_key (estream_t stream, gcry_sexp_t *key_new, int secret,
                 int read_comment, ssh_key_type_spec_t *key_spec)
{
  gpg_error_t err;
  char *key_type = NULL;
  char *comment = NULL;
  estream_t cert = NULL;
  gcry_sexp_t key = NULL;
  ssh_key_type_spec_t spec;
  gcry_mpi_t *mpi_list = NULL;
  const char *elems;
  const char *curve_name = NULL;


  err = stream_read_cstring (stream, &key_type);
  if (err)
    goto out;

  err = ssh_key_type_lookup (key_type, 0, &spec);
  if (err)
    goto out;

  if ((spec.flags & SPEC_FLAG_WITH_CERT))
    {
      /* This is an OpenSSH certificate+private key.  The certificate
         is an SSH string and which we store in an estream object. */
      unsigned char *buffer;
      u32 buflen;
      char *cert_key_type;

      err = stream_read_string (stream, 0, &buffer, &buflen);
      if (err)
        goto out;
      cert = es_fopenmem_init (0, "rb", buffer, buflen);
      xfree (buffer);
      if (!cert)
        {
          err = gpg_error_from_syserror ();
          goto out;
        }

      /* Check that the key type matches.  */
      err = stream_read_cstring (cert, &cert_key_type);
      if (err)
        goto out;
      if (strcmp (cert_key_type, key_type) )
        {
          xfree (cert_key_type);
          log_error ("key types in received ssh certificate do not match\n");
          err = gpg_error (GPG_ERR_INV_CERT_OBJ);
          goto out;
        }
      xfree (cert_key_type);

      /* Skip the nonce.  */
      err = stream_read_string (cert, 0, NULL, NULL);
      if (err)
        goto out;
    }

  if ((spec.flags & SPEC_FLAG_IS_EdDSA))
    {
      /* The format of an EdDSA key is:
       *   string	key_type ("ssh-ed25519")
       *   string	public_key
       *   string	private_key
       *
       * Note that the private key is the concatenation of the private
       * key with the public key.  Thus there's are 64 bytes; however
       * we only want the real 32 byte private key - Libgcrypt expects
       * this.
       */
      mpi_list = xtrycalloc (3, sizeof *mpi_list);
      if (!mpi_list)
        {
          err = gpg_error_from_syserror ();
          goto out;
        }

      err = stream_read_blob (cert? cert : stream, 0, &mpi_list[0]);
      if (err)
        goto out;
      if (secret)
        {
          u32 len = 0;
          unsigned char *buffer;

          /* Read string length.  */
          err = stream_read_uint32 (stream, &len);
          if (err)
            goto out;
          if (len != 32 && len != 64)
            {
              err = gpg_error (GPG_ERR_BAD_SECKEY);
              goto out;
            }
          buffer = xtrymalloc_secure (32);
          if (!buffer)
            {
              err = gpg_error_from_syserror ();
              goto out;
            }
          err = stream_read_data (stream, buffer, 32);
          if (err)
            {
              xfree (buffer);
              goto out;
            }
          mpi_list[1] = gcry_mpi_set_opaque (NULL, buffer, 8*32);
          buffer = NULL;
          if (len == 64)
            {
              err = stream_read_skip (stream, 32);
              if (err)
                goto out;
            }
        }
    }
  else if ((spec.flags & SPEC_FLAG_IS_ECDSA))
    {
      /* The format of an ECDSA key is:
       *   string	key_type ("ecdsa-sha2-nistp256" |
       *                          "ecdsa-sha2-nistp384" |
       *		          "ecdsa-sha2-nistp521" )
       *   string	ecdsa_curve_name
       *   string	ecdsa_public_key
       *   mpint	ecdsa_private
       *
       * Note that we use the mpint reader instead of the string
       * reader for ecsa_public_key.  For the certificate variante
       * ecdsa_curve_name+ecdsa_public_key are replaced by the
       * certificate.
       */
      unsigned char *buffer;

      err = stream_read_string (cert? cert : stream, 0, &buffer, NULL);
      if (err)
        goto out;
      /* Get the canonical name.  Should be the same as the read
       * string but we use this mapping to validate that name.  */
      if (!ssh_identifier_from_curve_name (buffer, &curve_name))
        {
          err = gpg_error (GPG_ERR_UNKNOWN_CURVE);
          xfree (buffer);
          goto out;
        }
      xfree (buffer);

      err = ssh_receive_mpint_list (stream, secret, &spec, cert, &mpi_list);
      if (err)
        goto out;
    }
  else
    {
      err = ssh_receive_mpint_list (stream, secret, &spec, cert, &mpi_list);
      if (err)
        goto out;
    }

  if (read_comment)
    {
      err = stream_read_cstring (stream, &comment);
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

  if ((spec.flags & SPEC_FLAG_IS_EdDSA))
    {
      if (secret)
        {
          err = gcry_sexp_build (&key, NULL,
                                 "(private-key(ecc(curve \"Ed25519\")"
                                 "(flags eddsa)(q %m)(d %m))"
                                 "(comment%s))",
                                 mpi_list[0], mpi_list[1],
                                 comment? comment:"");
        }
      else
        {
          err = gcry_sexp_build (&key, NULL,
                                 "(public-key(ecc(curve \"Ed25519\")"
                                 "(flags eddsa)(q %m))"
                                 "(comment%s))",
                                 mpi_list[0],
                                 comment? comment:"");
        }
    }
  else
    {
      err = sexp_key_construct (&key, spec, secret, curve_name, mpi_list,
                                comment? comment:"");
      if (err)
        goto out;
    }

  if (key_spec)
    *key_spec = spec;
  *key_new = key;

 out:
  es_fclose (cert);
  mpint_list_free (mpi_list);
  xfree (key_type);
  xfree (comment);

  return err;
}


/* Write the public key from KEY to STREAM in SSH key format.  If
   OVERRIDE_COMMENT is not NULL, it will be used instead of the
   comment stored in the key.  */
static gpg_error_t
ssh_send_key_public (estream_t stream, gcry_sexp_t key,
                     const char *override_comment)
{
  ssh_key_type_spec_t spec;
  int algo;
  char *comment = NULL;
  void *blob = NULL;
  size_t bloblen;
  gpg_error_t err = 0;

  algo = get_pk_algo_from_key (key);
  if (algo == 0)
    goto out;

  err = ssh_key_type_lookup (NULL, algo, &spec);
  if (err)
    goto out;

  err = ssh_key_to_blob (key, 0, spec, &blob, &bloblen);
  if (err)
    goto out;

  err = stream_write_string (stream, blob, bloblen);
  if (err)
    goto out;

  if (override_comment)
    err = stream_write_cstring (stream, override_comment);
  else
    {
      err = ssh_key_extract_comment (key, &comment);
      if (err)
        err = stream_write_cstring (stream, "(none)");
      else
        err = stream_write_cstring (stream, comment);
    }
  if (err)
    goto out;

 out:
  xfree (comment);
  es_free (blob);

  return err;
}


/* Read a public key out of BLOB/BLOB_SIZE according to the key
   specification given as KEY_SPEC, storing the new key in KEY_PUBLIC.
   Returns zero on success or an error code.  */
static gpg_error_t
ssh_read_key_public_from_blob (unsigned char *blob, size_t blob_size,
			       gcry_sexp_t *key_public,
			       ssh_key_type_spec_t *key_spec)
{
  gpg_error_t err;
  estream_t blob_stream;

  blob_stream = es_fopenmem (0, "r+b");
  if (!blob_stream)
    {
      err = gpg_error_from_syserror ();
      goto out;
    }

  err = stream_write_data (blob_stream, blob, blob_size);
  if (err)
    goto out;

  err = es_fseek (blob_stream, 0, SEEK_SET);
  if (err)
    goto out;

  err = ssh_receive_key (blob_stream, key_public, 0, 0, key_spec);

 out:
  es_fclose (blob_stream);
  return err;
}



/* This function calculates the key grip for the key contained in the
   S-Expression KEY and writes it to BUFFER, which must be large
   enough to hold it.  Returns usual error code.  */
static gpg_error_t
ssh_key_grip (gcry_sexp_t key, unsigned char *buffer)
{
  if (!gcry_pk_get_keygrip (key, buffer))
    {
      gpg_error_t err = gcry_pk_testkey (key);
      return err? err : gpg_error (GPG_ERR_INTERNAL);
    }

  return 0;
}


static gpg_error_t
card_key_list (ctrl_t ctrl, char **r_serialno, strlist_t *result)
{
  gpg_error_t err;

  *r_serialno = NULL;
  *result = NULL;

  err = agent_card_serialno (ctrl, r_serialno, NULL);
  if (err)
    {
      if (gpg_err_code (err) != GPG_ERR_ENODEV && opt.verbose)
        log_info (_("error getting serial number of card: %s\n"),
                  gpg_strerror (err));

      /* Nothing available.  */
      return 0;
    }

  err = agent_card_cardlist (ctrl, result);
  if (err)
    {
      xfree (*r_serialno);
      *r_serialno = NULL;
    }
  return err;
}

/* Check whether a smartcard is available and whether it has a usable
   key.  Store a copy of that key at R_PK and return 0.  If no key is
   available store NULL at R_PK and return an error code.  If CARDSN
   is not NULL, a string with the serial number of the card will be
   a malloced and stored there. */
static gpg_error_t
card_key_available (ctrl_t ctrl, gcry_sexp_t *r_pk, char **cardsn)
{
  gpg_error_t err;
  char *authkeyid;
  char *serialno = NULL;
  unsigned char *pkbuf;
  size_t pkbuflen;
  gcry_sexp_t s_pk;
  unsigned char grip[20];

  *r_pk = NULL;
  if (cardsn)
    *cardsn = NULL;

  /* First see whether a card is available and whether the application
     is supported.  */
  err = agent_card_getattr (ctrl, "$AUTHKEYID", &authkeyid);
  if ( gpg_err_code (err) == GPG_ERR_CARD_REMOVED )
    {
      /* Ask for the serial number to reset the card.  */
      err = agent_card_serialno (ctrl, &serialno, NULL);
      if (err)
        {
          if (opt.verbose)
            log_info (_("error getting serial number of card: %s\n"),
                      gpg_strerror (err));
          return err;
        }
      log_info (_("detected card with S/N: %s\n"), serialno);
      err = agent_card_getattr (ctrl, "$AUTHKEYID", &authkeyid);
    }
  if (err)
    {
      log_error (_("no authentication key for ssh on card: %s\n"),
                 gpg_strerror (err));
      xfree (serialno);
      return err;
    }

  /* Get the S/N if we don't have it yet.  Use the fast getattr method.  */
  if (!serialno && (err = agent_card_getattr (ctrl, "SERIALNO", &serialno)) )
    {
      log_error (_("error getting serial number of card: %s\n"),
                 gpg_strerror (err));
      xfree (authkeyid);
      return err;
    }

  /* Read the public key.  */
  err = agent_card_readkey (ctrl, authkeyid, &pkbuf);
  if (err)
    {
      if (opt.verbose)
        log_info (_("no suitable card key found: %s\n"), gpg_strerror (err));
      xfree (serialno);
      xfree (authkeyid);
      return err;
    }

  pkbuflen = gcry_sexp_canon_len (pkbuf, 0, NULL, NULL);
  err = gcry_sexp_sscan (&s_pk, NULL, (char*)pkbuf, pkbuflen);
  if (err)
    {
      log_error ("failed to build S-Exp from received card key: %s\n",
                 gpg_strerror (err));
      xfree (pkbuf);
      xfree (serialno);
      xfree (authkeyid);
      return err;
    }

  err = ssh_key_grip (s_pk, grip);
  if (err)
    {
      log_debug ("error computing keygrip from received card key: %s\n",
		 gcry_strerror (err));
      xfree (pkbuf);
      gcry_sexp_release (s_pk);
      xfree (serialno);
      xfree (authkeyid);
      return err;
    }

  if ( agent_key_available (grip) )
    {
      char *dispserialno;

      /* (Shadow)-key is not available in our key storage.  */
      agent_card_getattr (ctrl, "$DISPSERIALNO", &dispserialno);
      err = agent_write_shadow_key (grip, serialno, authkeyid, pkbuf, 0, 0,
                                    dispserialno);
      xfree (dispserialno);
      if (err)
        {
          xfree (pkbuf);
          gcry_sexp_release (s_pk);
          xfree (serialno);
          xfree (authkeyid);
          return err;
        }
    }

  if (cardsn)
    {
      char *dispsn;

      /* If the card handler is able to return a short serialnumber,
         use that one, else use the complete serialno. */
      if (!agent_card_getattr (ctrl, "$DISPSERIALNO", &dispsn))
        {
          *cardsn = xtryasprintf ("cardno:%s", dispsn);
          xfree (dispsn);
        }
      else
        *cardsn = xtryasprintf ("cardno:%s", serialno);
      if (!*cardsn)
        {
          err = gpg_error_from_syserror ();
          xfree (pkbuf);
          gcry_sexp_release (s_pk);
          xfree (serialno);
          xfree (authkeyid);
          return err;
        }
    }

  xfree (pkbuf);
  xfree (serialno);
  xfree (authkeyid);
  *r_pk = s_pk;
  return 0;
}




/*

  Request handler.  Each handler is provided with a CTRL context, a
  REQUEST object and a RESPONSE object.  The actual request is to be
  read from REQUEST, the response needs to be written to RESPONSE.

*/


/* Handler for the "request_identities" command.  */
static gpg_error_t
ssh_handler_request_identities (ctrl_t ctrl,
                                estream_t request, estream_t response)
{
  u32 key_counter;
  estream_t key_blobs;
  gcry_sexp_t key_public;
  gpg_error_t err;
  int ret;
  ssh_control_file_t cf = NULL;
  gpg_error_t ret_err;

  (void)request;

  /* Prepare buffer stream.  */

  key_public = NULL;
  key_counter = 0;

  key_blobs = es_fopenmem (0, "r+b");
  if (! key_blobs)
    {
      err = gpg_error_from_syserror ();
      goto out;
    }

  /* First check whether a key is currently available in the card
     reader - this should be allowed even without being listed in
     sshcontrol. */

  if (!opt.disable_scdaemon)
    {
      char *serialno;
      strlist_t card_list, sl;

      err = card_key_list (ctrl, &serialno, &card_list);
      if (err)
        {
          if (opt.verbose)
            log_info (_("error getting list of cards: %s\n"),
                      gpg_strerror (err));
          goto scd_out;
        }

      for (sl = card_list; sl; sl = sl->next)
        {
          char *serialno0;
          char *cardsn;

          err = agent_card_serialno (ctrl, &serialno0, sl->d);
          if (err)
            {
              if (opt.verbose)
                log_info (_("error getting serial number of card: %s\n"),
                          gpg_strerror (err));
              continue;
            }

          xfree (serialno0);
          if (card_key_available (ctrl, &key_public, &cardsn))
            continue;

          err = ssh_send_key_public (key_blobs, key_public, cardsn);
          gcry_sexp_release (key_public);
          key_public = NULL;
          xfree (cardsn);
          if (err)
            {
              if (opt.verbose)
                gcry_log_debugsxp ("pubkey", key_public);
              if (gpg_err_code (err) == GPG_ERR_UNKNOWN_CURVE
                  || gpg_err_code (err) == GPG_ERR_INV_CURVE)
                {
                  /* For example a Brainpool curve or a curve we don't
                   * support at all but a smartcard lists that curve.
                   * We ignore them.  */
                }
              else
                {
                  xfree (serialno);
                  free_strlist (card_list);
                  goto out;
                }
            }
          else
            key_counter++;
        }

      xfree (serialno);
      free_strlist (card_list);
    }

 scd_out:
  /* Then look at all the registered and non-disabled keys. */
  err = open_control_file (&cf, 0);
  if (err)
    goto out;

  while (!read_control_file_item (cf))
    {
      unsigned char grip[20];

      if (!cf->item.valid)
        continue; /* Should not happen.  */
      if (cf->item.disabled)
        continue;
      assert (strlen (cf->item.hexgrip) == 40);
      hex2bin (cf->item.hexgrip, grip, sizeof (grip));

      err = agent_public_key_from_file (ctrl, grip, &key_public);
      if (err)
        {
          log_error ("%s:%d: key '%s' skipped: %s\n",
                     cf->fname, cf->lnr, cf->item.hexgrip,
                     gpg_strerror (err));
          continue;
        }

      err = ssh_send_key_public (key_blobs, key_public, NULL);
      if (err)
        goto out;
      gcry_sexp_release (key_public);
      key_public = NULL;

      key_counter++;
    }
  err = 0;

  ret = es_fseek (key_blobs, 0, SEEK_SET);
  if (ret)
    {
      err = gpg_error_from_syserror ();
      goto out;
    }

 out:
  /* Send response.  */

  gcry_sexp_release (key_public);

  if (!err)
    {
      ret_err = stream_write_byte (response, SSH_RESPONSE_IDENTITIES_ANSWER);
      if (!ret_err)
        ret_err = stream_write_uint32 (response, key_counter);
      if (!ret_err)
        ret_err = stream_copy (response, key_blobs);
    }
  else
    {
      log_error ("ssh request identities failed: %s <%s>\n",
                 gpg_strerror (err), gpg_strsource (err));
      ret_err = stream_write_byte (response, SSH_RESPONSE_FAILURE);
    }

  es_fclose (key_blobs);
  close_control_file (cf);

  return ret_err;
}


/* This function hashes the data contained in DATA of size DATA_N
   according to the message digest algorithm specified by MD_ALGORITHM
   and writes the message digest to HASH, which needs to large enough
   for the digest.  */
static gpg_error_t
data_hash (unsigned char *data, size_t data_n,
	   int md_algorithm, unsigned char *hash)
{
  gcry_md_hash_buffer (md_algorithm, hash, data, data_n);

  return 0;
}


/* This function signs the data described by CTRL. If HASH is not
   NULL, (HASH,HASHLEN) overrides the hash stored in CTRL.  This is to
   allow the use of signature algorithms that implement the hashing
   internally (e.g. Ed25519).  On success the created signature is
   stored in ssh format at R_SIG and it's size at R_SIGLEN; the caller
   must use es_free to releaase this memory.  */
static gpg_error_t
data_sign (ctrl_t ctrl, ssh_key_type_spec_t *spec,
           const void *hash, size_t hashlen,
	   unsigned char **r_sig, size_t *r_siglen)
{
  gpg_error_t err;
  gcry_sexp_t signature_sexp = NULL;
  estream_t stream = NULL;
  void *blob = NULL;
  size_t bloblen;
  char hexgrip[40+1];

  *r_sig = NULL;
  *r_siglen = 0;

  /* Quick check to see whether we have a valid keygrip and convert it
     to hex.  */
  if (!ctrl->have_keygrip)
    {
      err = gpg_error (GPG_ERR_NO_SECKEY);
      goto out;
    }
  bin2hex (ctrl->keygrip, 20, hexgrip);

  /* Ask for confirmation if needed.  */
  if (confirm_flag_from_sshcontrol (hexgrip))
    {
      gcry_sexp_t key;
      char *fpr, *prompt;
      char *comment = NULL;

      err = agent_raw_key_from_file (ctrl, ctrl->keygrip, &key);
      if (err)
        goto out;
      err = ssh_get_fingerprint_string (key, opt.ssh_fingerprint_digest, &fpr);
      if (!err)
        {
          gcry_sexp_t tmpsxp = gcry_sexp_find_token (key, "comment", 0);
          if (tmpsxp)
            comment = gcry_sexp_nth_string (tmpsxp, 1);
          gcry_sexp_release (tmpsxp);
        }
      gcry_sexp_release (key);
      if (err)
        goto out;
      prompt = xtryasprintf (L_("An ssh process requested the use of key%%0A"
                                "  %s%%0A"
                                "  (%s)%%0A"
                                "Do you want to allow this?"),
                             fpr, comment? comment:"");
      xfree (fpr);
      gcry_free (comment);
      err = agent_get_confirmation (ctrl, prompt, L_("Allow"), L_("Deny"), 0);
      xfree (prompt);
      if (err)
        goto out;
    }

  /* Create signature.  */
  ctrl->use_auth_call = 1;
  err = agent_pksign_do (ctrl, NULL,
                         L_("Please enter the passphrase "
                            "for the ssh key%%0A  %F%%0A  (%c)"),
                         &signature_sexp,
                         CACHE_MODE_SSH, ttl_from_sshcontrol,
                         hash, hashlen);
  ctrl->use_auth_call = 0;
  if (err)
    goto out;

  stream = es_fopenmem (0, "r+b");
  if (!stream)
    {
      err = gpg_error_from_syserror ();
      goto out;
    }

  err = stream_write_cstring (stream, spec->ssh_identifier);
  if (err)
    goto out;

  err = spec->signature_encoder (spec, stream, signature_sexp);
  if (err)
    goto out;

  err = es_fclose_snatch (stream, &blob, &bloblen);
  if (err)
    goto out;
  stream = NULL;

  *r_sig = blob; blob = NULL;
  *r_siglen = bloblen;

 out:
  xfree (blob);
  es_fclose (stream);
  gcry_sexp_release (signature_sexp);

  return err;
}


/* Handler for the "sign_request" command.  */
static gpg_error_t
ssh_handler_sign_request (ctrl_t ctrl, estream_t request, estream_t response)
{
  gcry_sexp_t key = NULL;
  ssh_key_type_spec_t spec;
  unsigned char hash[MAX_DIGEST_LEN];
  unsigned int hash_n;
  unsigned char key_grip[20];
  unsigned char *key_blob = NULL;
  u32 key_blob_size;
  unsigned char *data = NULL;
  unsigned char *sig = NULL;
  size_t sig_n;
  u32 data_size;
  gpg_error_t err;
  gpg_error_t ret_err;
  int hash_algo;

  /* Receive key.  */

  err = stream_read_string (request, 0, &key_blob, &key_blob_size);
  if (err)
    goto out;

  err = ssh_read_key_public_from_blob (key_blob, key_blob_size, &key, &spec);
  if (err)
    goto out;

  /* Receive data to sign.  */
  err = stream_read_string (request, 0, &data, &data_size);
  if (err)
    goto out;

  /* Flag processing.  */
  {
    u32 flags;

    err = stream_read_uint32 (request, &flags);
    if (err)
      goto out;

    if (spec.algo == GCRY_PK_RSA)
      {
        if ((flags & SSH_AGENT_RSA_SHA2_512))
          {
            flags &= ~SSH_AGENT_RSA_SHA2_512;
            spec.ssh_identifier = "rsa-sha2-512";
            spec.hash_algo = GCRY_MD_SHA512;
          }
        if ((flags & SSH_AGENT_RSA_SHA2_256))
          {
            /* Note: We prefer SHA256 over SHA512.  */
            flags &= ~SSH_AGENT_RSA_SHA2_256;
            spec.ssh_identifier = "rsa-sha2-256";
            spec.hash_algo = GCRY_MD_SHA256;
          }
      }

    /* Some flag is present that we do not know about.  Note that
     * processed or known flags have been cleared at this point.  */
    if (flags)
      {
        err = gpg_error (GPG_ERR_UNKNOWN_OPTION);
        goto out;
      }
  }

  hash_algo = spec.hash_algo;
  if (!hash_algo)
    hash_algo = GCRY_MD_SHA1;  /* Use the default.  */
  ctrl->digest.algo = hash_algo;
  if ((spec.flags & SPEC_FLAG_USE_PKCS1V2))
    ctrl->digest.raw_value = 0;
  else
    ctrl->digest.raw_value = 1;

  /* Calculate key grip.  */
  err = ssh_key_grip (key, key_grip);
  if (err)
    goto out;
  ctrl->have_keygrip = 1;
  memcpy (ctrl->keygrip, key_grip, 20);

  /* Hash data unless we use EdDSA.  */
  if ((spec.flags & SPEC_FLAG_IS_EdDSA))
    {
      ctrl->digest.valuelen = 0;
    }
  else
    {
      hash_n = gcry_md_get_algo_dlen (hash_algo);
      if (!hash_n)
        {
          err = gpg_error (GPG_ERR_INTERNAL);
          goto out;
        }
      err = data_hash (data, data_size, hash_algo, hash);
      if (err)
        goto out;
      memcpy (ctrl->digest.value, hash, hash_n);
      ctrl->digest.valuelen = hash_n;
    }

  /* Sign data.  */
  if ((spec.flags & SPEC_FLAG_IS_EdDSA))
    err = data_sign (ctrl, &spec, data, data_size, &sig, &sig_n);
  else
    err = data_sign (ctrl, &spec, NULL, 0, &sig, &sig_n);

 out:
  /* Done.  */
  if (!err)
    {
      ret_err = stream_write_byte (response, SSH_RESPONSE_SIGN_RESPONSE);
      if (ret_err)
	goto leave;
      ret_err = stream_write_string (response, sig, sig_n);
      if (ret_err)
	goto leave;
    }
  else
    {
      log_error ("ssh sign request failed: %s <%s>\n",
                 gpg_strerror (err), gpg_strsource (err));
      ret_err = stream_write_byte (response, SSH_RESPONSE_FAILURE);
      if (ret_err)
	goto leave;
    }

 leave:

  gcry_sexp_release (key);
  xfree (key_blob);
  xfree (data);
  es_free (sig);

  return ret_err;
}


/* This function extracts the comment contained in the key
   s-expression KEY and stores a copy in COMMENT.  Returns usual error
   code.  */
static gpg_error_t
ssh_key_extract_comment (gcry_sexp_t key, char **r_comment)
{
  gcry_sexp_t comment_list;

  *r_comment = NULL;

  comment_list = gcry_sexp_find_token (key, "comment", 0);
  if (!comment_list)
    return gpg_error (GPG_ERR_INV_SEXP);

  *r_comment = gcry_sexp_nth_string (comment_list, 1);
  gcry_sexp_release (comment_list);
  if (!*r_comment)
    return gpg_error (GPG_ERR_INV_SEXP);

  return 0;
}


/* This function converts the key contained in the S-Expression KEY
   into a buffer, which is protected by the passphrase PASSPHRASE.
   If PASSPHRASE is the empty passphrase, the key is not protected.
   Returns usual error code.  */
static gpg_error_t
ssh_key_to_protected_buffer (gcry_sexp_t key, const char *passphrase,
			     unsigned char **buffer, size_t *buffer_n)
{
  unsigned char *buffer_new;
  unsigned int buffer_new_n;
  gpg_error_t err;

  buffer_new_n = gcry_sexp_sprint (key, GCRYSEXP_FMT_CANON, NULL, 0);
  buffer_new = xtrymalloc_secure (buffer_new_n);
  if (! buffer_new)
    {
      err = gpg_error_from_syserror ();
      goto out;
    }

  buffer_new_n = gcry_sexp_sprint (key, GCRYSEXP_FMT_CANON,
                                   buffer_new, buffer_new_n);

  if (*passphrase)
    err = agent_protect (buffer_new, passphrase, buffer, buffer_n, 0);
  else
    {
      /* The key derivation function does not support zero length
       * strings.  Store key unprotected if the user wishes so.  */
      *buffer = buffer_new;
      *buffer_n = buffer_new_n;
      buffer_new = NULL;
      err = 0;
    }

 out:

  xfree (buffer_new);

  return err;
}



/* Callback function to compare the first entered PIN with the one
   currently being entered. */
static gpg_error_t
reenter_compare_cb (struct pin_entry_info_s *pi)
{
  const char *pin1 = pi->check_cb_arg;

  if (!strcmp (pin1, pi->pin))
    return 0; /* okay */
  return gpg_error (GPG_ERR_BAD_PASSPHRASE);
}


/* Store the ssh KEY into our local key storage and protect it after
   asking for a passphrase.  Cache that passphrase.  TTL is the
   maximum caching time for that key.  If the key already exists in
   our key storage, don't do anything.  When entering a key also add
   an entry to the sshcontrol file.  */
static gpg_error_t
ssh_identity_register (ctrl_t ctrl, ssh_key_type_spec_t *spec,
                       gcry_sexp_t key, int ttl, int confirm)
{
  gpg_error_t err;
  unsigned char key_grip_raw[20];
  char key_grip[41];
  unsigned char *buffer = NULL;
  size_t buffer_n;
  char *description = NULL;
  const char *description2 = L_("Please re-enter this passphrase");
  char *comment = NULL;
  char *key_fpr = NULL;
  const char *initial_errtext = NULL;
  struct pin_entry_info_s *pi = NULL;
  struct pin_entry_info_s *pi2 = NULL;

  err = ssh_key_grip (key, key_grip_raw);
  if (err)
    goto out;

  bin2hex (key_grip_raw, 20, key_grip);

  err = ssh_get_fingerprint_string (key, opt.ssh_fingerprint_digest, &key_fpr);
  if (err)
    goto out;

  /* Check whether the key is already in our key storage.  Don't do
     anything then besides (re-)adding it to sshcontrol.  */
  if ( !agent_key_available (key_grip_raw) )
    goto key_exists; /* Yes, key is available.  */

  err = ssh_key_extract_comment (key, &comment);
  if (err)
    goto out;

  if ( asprintf (&description,
                 L_("Please enter a passphrase to protect"
                    " the received secret key%%0A"
                    "   %s%%0A"
                    "   %s%%0A"
                    "within gpg-agent's key storage"),
                 key_fpr, comment ? comment : "") < 0)
    {
      err = gpg_error_from_syserror ();
      goto out;
    }

  pi = gcry_calloc_secure (1, sizeof (*pi) + MAX_PASSPHRASE_LEN + 1);
  if (!pi)
    {
      err = gpg_error_from_syserror ();
      goto out;
    }
  pi2 = gcry_calloc_secure (1, sizeof (*pi2) + MAX_PASSPHRASE_LEN + 1);
  if (!pi2)
    {
      err = gpg_error_from_syserror ();
      goto out;
    }
  pi->max_length = MAX_PASSPHRASE_LEN + 1;
  pi->max_tries = 1;
  pi->with_repeat = 1;
  pi2->max_length = MAX_PASSPHRASE_LEN + 1;
  pi2->max_tries = 1;
  pi2->check_cb = reenter_compare_cb;
  pi2->check_cb_arg = pi->pin;

 next_try:
  err = agent_askpin (ctrl, description, NULL, initial_errtext, pi, NULL, 0);
  initial_errtext = NULL;
  if (err)
    goto out;

  /* Unless the passphrase is empty or the pinentry told us that
     it already did the repetition check, ask to confirm it.  */
  if (*pi->pin && !pi->repeat_okay)
    {
      err = agent_askpin (ctrl, description2, NULL, NULL, pi2, NULL, 0);
      if (gpg_err_code (err) == GPG_ERR_BAD_PASSPHRASE)
	{ /* The re-entered one did not match and the user did not
	     hit cancel. */
	  initial_errtext = L_("does not match - try again");
	  goto next_try;
	}
    }

  err = ssh_key_to_protected_buffer (key, pi->pin, &buffer, &buffer_n);
  if (err)
    goto out;

  /* Store this key to our key storage.  We do not store a creation
   * timestamp because we simply do not know.  */
  err = agent_write_private_key (key_grip_raw, buffer, buffer_n, 0, 0,
                                 NULL, NULL, NULL, 0);
  if (err)
    goto out;

  /* Cache this passphrase. */
  err = agent_put_cache (ctrl, key_grip, CACHE_MODE_SSH, pi->pin, ttl);
  if (err)
    goto out;

 key_exists:
  /* And add an entry to the sshcontrol file.  */
  err = add_control_entry (ctrl, spec, key_grip, key, ttl, confirm);


 out:
  if (pi2 && pi2->max_length)
    wipememory (pi2->pin, pi2->max_length);
  xfree (pi2);
  if (pi && pi->max_length)
    wipememory (pi->pin, pi->max_length);
  xfree (pi);
  xfree (buffer);
  xfree (comment);
  xfree (key_fpr);
  xfree (description);

  return err;
}


/* This function removes the key contained in the S-Expression KEY
   from the local key storage, in case it exists there.  Returns usual
   error code.  FIXME: this function is a stub.  */
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

 out:

  return err;
}

/* Handler for the "add_identity" command.  */
static gpg_error_t
ssh_handler_add_identity (ctrl_t ctrl, estream_t request, estream_t response)
{
  gpg_error_t ret_err;
  ssh_key_type_spec_t spec;
  gpg_error_t err;
  gcry_sexp_t key;
  unsigned char b;
  int confirm;
  int ttl;

  confirm = 0;
  key = NULL;
  ttl = 0;

  /* FIXME?  */
  err = ssh_receive_key (request, &key, 1, 1, &spec);
  if (err)
    goto out;

  while (1)
    {
      err = stream_read_byte (request, &b);
      if (err)
        {
          if (gpg_err_code (err) == GPG_ERR_EOF)
            err = 0;
	  break;
	}

      switch (b)
	{
	case SSH_OPT_CONSTRAIN_LIFETIME:
	  {
	    u32 n = 0;

	    err = stream_read_uint32 (request, &n);
	    if (! err)
	      ttl = n;
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

  err = ssh_identity_register (ctrl, &spec, key, ttl, confirm);

 out:

  gcry_sexp_release (key);

  if (! err)
    ret_err = stream_write_byte (response, SSH_RESPONSE_SUCCESS);
  else
    ret_err = stream_write_byte (response, SSH_RESPONSE_FAILURE);

  return ret_err;
}

/* Handler for the "remove_identity" command.  */
static gpg_error_t
ssh_handler_remove_identity (ctrl_t ctrl,
			     estream_t request, estream_t response)
{
  unsigned char *key_blob;
  u32 key_blob_size;
  gcry_sexp_t key;
  gpg_error_t ret_err;
  gpg_error_t err;

  (void)ctrl;

  /* Receive key.  */

  key_blob = NULL;
  key = NULL;

  err = stream_read_string (request, 0, &key_blob, &key_blob_size);
  if (err)
    goto out;

  err = ssh_read_key_public_from_blob (key_blob, key_blob_size, &key, NULL);
  if (err)
    goto out;

  err = ssh_identity_drop (key);

 out:

  xfree (key_blob);
  gcry_sexp_release (key);

  if (! err)
    ret_err = stream_write_byte (response, SSH_RESPONSE_SUCCESS);
  else
    ret_err = stream_write_byte (response, SSH_RESPONSE_FAILURE);

  return ret_err;
}

/* FIXME: stub function.  Actually useful?  */
static gpg_error_t
ssh_identities_remove_all (void)
{
  gpg_error_t err;

  err = 0;

  /* FIXME: shall we remove _all_ cache entries or only those
     registered through the ssh-agent protocol?  */

  return err;
}

/* Handler for the "remove_all_identities" command.  */
static gpg_error_t
ssh_handler_remove_all_identities (ctrl_t ctrl,
				   estream_t request, estream_t response)
{
  gpg_error_t ret_err;
  gpg_error_t err;

  (void)ctrl;
  (void)request;

  err = ssh_identities_remove_all ();

  if (! err)
    ret_err = stream_write_byte (response, SSH_RESPONSE_SUCCESS);
  else
    ret_err = stream_write_byte (response, SSH_RESPONSE_FAILURE);

  return ret_err;
}

/* Lock agent?  FIXME: stub function.  */
static gpg_error_t
ssh_lock (void)
{
  gpg_error_t err;

  /* FIXME */
  log_error ("ssh-agent's lock command is not implemented\n");
  err = 0;

  return err;
}

/* Unock agent?  FIXME: stub function.  */
static gpg_error_t
ssh_unlock (void)
{
  gpg_error_t err;

  log_error ("ssh-agent's unlock command is not implemented\n");
  err = 0;

  return err;
}

/* Handler for the "lock" command.  */
static gpg_error_t
ssh_handler_lock (ctrl_t ctrl, estream_t request, estream_t response)
{
  gpg_error_t ret_err;
  gpg_error_t err;

  (void)ctrl;
  (void)request;

  err = ssh_lock ();

  if (! err)
    ret_err = stream_write_byte (response, SSH_RESPONSE_SUCCESS);
  else
    ret_err = stream_write_byte (response, SSH_RESPONSE_FAILURE);

  return ret_err;
}

/* Handler for the "unlock" command.  */
static gpg_error_t
ssh_handler_unlock (ctrl_t ctrl, estream_t request, estream_t response)
{
  gpg_error_t ret_err;
  gpg_error_t err;

  (void)ctrl;
  (void)request;

  err = ssh_unlock ();

  if (! err)
    ret_err = stream_write_byte (response, SSH_RESPONSE_SUCCESS);
  else
    ret_err = stream_write_byte (response, SSH_RESPONSE_FAILURE);

  return ret_err;
}



/* Return the request specification for the request identified by TYPE
   or NULL in case the requested request specification could not be
   found.  */
static const ssh_request_spec_t *
request_spec_lookup (int type)
{
  const ssh_request_spec_t *spec;
  unsigned int i;

  for (i = 0; i < DIM (request_specs); i++)
    if (request_specs[i].type == type)
      break;
  if (i == DIM (request_specs))
    {
      if (opt.verbose)
        log_info ("ssh request %u is not supported\n", type);
      spec = NULL;
    }
  else
    spec = request_specs + i;

  return spec;
}

/* Process a single request.  The request is read from and the
   response is written to STREAM_SOCK.  Uses CTRL as context.  Returns
   zero in case of success, non zero in case of failure.  */
static int
ssh_request_process (ctrl_t ctrl, estream_t stream_sock)
{
  const ssh_request_spec_t *spec;
  estream_t response = NULL;
  estream_t request = NULL;
  unsigned char request_type;
  gpg_error_t err;
  int send_err = 0;
  int ret;
  unsigned char *request_data = NULL;
  u32 request_data_size;
  u32 response_size;

  /* Create memory streams for request/response data.  The entire
     request will be stored in secure memory, since it might contain
     secret key material.  The response does not have to be stored in
     secure memory, since we never give out secret keys.

     Note: we only have little secure memory, but there is NO
     possibility of DoS here; only trusted clients are allowed to
     connect to the agent.  What could happen is that the agent
     returns out-of-secure-memory errors on requests in case the
     agent's owner floods his own agent with many large messages.
     -moritz */

  /* Retrieve request.  */
  err = stream_read_string (stream_sock, 1, &request_data, &request_data_size);
  if (err)
    goto out;

  if (opt.verbose > 1)
    log_info ("received ssh request of length %u\n",
              (unsigned int)request_data_size);

  if (! request_data_size)
    {
      send_err = 1;
      goto out;
      /* Broken request; FIXME.  */
    }

  request_type = request_data[0];
  spec = request_spec_lookup (request_type);
  if (! spec)
    {
      send_err = 1;
      goto out;
      /* Unknown request; FIXME.  */
    }

  if (spec->secret_input)
    request = es_mopen (NULL, 0, 0, 1, realloc_secure, gcry_free, "r+b");
  else
    request = es_mopen (NULL, 0, 0, 1, gcry_realloc, gcry_free, "r+b");
  if (! request)
    {
      err = gpg_error_from_syserror ();
      goto out;
    }
  ret = es_setvbuf (request, NULL, _IONBF, 0);
  if (ret)
    {
      err = gpg_error_from_syserror ();
      goto out;
    }
  err = stream_write_data (request, request_data + 1, request_data_size - 1);
  if (err)
    goto out;
  es_rewind (request);

  response = es_fopenmem (0, "r+b");
  if (! response)
    {
      err = gpg_error_from_syserror ();
      goto out;
    }

  if (opt.verbose)
    log_info ("ssh request handler for %s (%u) started\n",
	       spec->identifier, spec->type);

  err = (*spec->handler) (ctrl, request, response);

  if (opt.verbose)
    {
      if (err)
        log_info ("ssh request handler for %s (%u) failed: %s\n",
                  spec->identifier, spec->type, gpg_strerror (err));
      else
        log_info ("ssh request handler for %s (%u) ready\n",
                  spec->identifier, spec->type);
    }

  if (err)
    {
      send_err = 1;
      goto out;
    }

  response_size = es_ftell (response);
  if (opt.verbose > 1)
    log_info ("sending ssh response of length %u\n",
              (unsigned int)response_size);

  err = es_fseek (response, 0, SEEK_SET);
  if (err)
    {
      send_err = 1;
      goto out;
    }

  err = stream_write_uint32 (stream_sock, response_size);
  if (err)
    {
      send_err = 1;
      goto out;
    }

  err = stream_copy (stream_sock, response);
  if (err)
    goto out;

  err = es_fflush (stream_sock);
  if (err)
    goto out;

 out:

  if (err && es_feof (stream_sock))
    log_error ("error occurred while processing request: %s\n",
	       gpg_strerror (err));

  if (send_err)
    {
      if (opt.verbose > 1)
        log_info ("sending ssh error response\n");
      err = stream_write_uint32 (stream_sock, 1);
      if (err)
	goto leave;
      err = stream_write_byte (stream_sock, SSH_RESPONSE_FAILURE);
      if (err)
	goto leave;
    }

 leave:

  es_fclose (request);
  es_fclose (response);
  xfree (request_data);

  return !!err;
}


/* Return the peer's pid.  */
static unsigned long
get_client_pid (int fd)
{
  pid_t client_pid = (pid_t)0;

#ifdef SO_PEERCRED
  {
#ifdef HAVE_STRUCT_SOCKPEERCRED_PID
    struct sockpeercred cr;
#else
    struct ucred cr;
#endif
    socklen_t cl = sizeof cr;

    if (!getsockopt (fd, SOL_SOCKET, SO_PEERCRED, &cr, &cl))
      {
#if defined (HAVE_STRUCT_SOCKPEERCRED_PID) || defined (HAVE_STRUCT_UCRED_PID)
        client_pid = cr.pid;
#elif defined (HAVE_STRUCT_UCRED_CR_PID)
        client_pid = cr.cr_pid;
#else
#error "Unknown SO_PEERCRED struct"
#endif
      }
  }
#elif defined (LOCAL_PEERPID)
  {
    socklen_t len = sizeof (pid_t);

    getsockopt (fd, SOL_LOCAL, LOCAL_PEERPID, &client_pid, &len);
  }
#elif defined (LOCAL_PEEREID)
  {
    struct unpcbid unp;
    socklen_t unpl = sizeof unp;

    if (getsockopt (fd, 0, LOCAL_PEEREID, &unp, &unpl) != -1)
      client_pid = unp.unp_pid;
  }
#elif defined (HAVE_GETPEERUCRED)
  {
    ucred_t *ucred = NULL;

    if (getpeerucred (fd, &ucred) != -1)
      {
        client_pid= ucred_getpid (ucred);
        ucred_free (ucred);
      }
  }
#else
  (void)fd;
#endif

  return (unsigned long)client_pid;
}


/* Start serving client on SOCK_CLIENT.  */
void
start_command_handler_ssh (ctrl_t ctrl, gnupg_fd_t sock_client)
{
  estream_t stream_sock = NULL;
  gpg_error_t err;
  int ret;

  err = agent_copy_startup_env (ctrl);
  if (err)
    goto out;

  ctrl->client_pid = get_client_pid (FD2INT(sock_client));

  /* Create stream from socket.  */
  stream_sock = es_fdopen (FD2INT(sock_client), "r+");
  if (!stream_sock)
    {
      err = gpg_error_from_syserror ();
      log_error (_("failed to create stream from socket: %s\n"),
		 gpg_strerror (err));
      goto out;
    }
  /* We have to disable the estream buffering, because the estream
     core doesn't know about secure memory.  */
  ret = es_setvbuf (stream_sock, NULL, _IONBF, 0);
  if (ret)
    {
      err = gpg_error_from_syserror ();
      log_error ("failed to disable buffering "
                 "on socket stream: %s\n", gpg_strerror (err));
      goto out;
    }

  /* Main processing loop. */
  while ( !ssh_request_process (ctrl, stream_sock) )
    {
      /* Check whether we have reached EOF before trying to read
	 another request.  */
      int c;

      c = es_fgetc (stream_sock);
      if (c == EOF)
        break;
      es_ungetc (c, stream_sock);
    }

  /* Reset the SCD in case it has been used. */
  agent_reset_scd (ctrl);


 out:
  if (stream_sock)
    es_fclose (stream_sock);
}


#ifdef HAVE_W32_SYSTEM
/* Serve one ssh-agent request.  This is used for the Putty support.
   REQUEST is the mmapped memory which may be accessed up to a
   length of MAXREQLEN.  Returns 0 on success which also indicates
   that a valid SSH response message is now in REQUEST.  */
int
serve_mmapped_ssh_request (ctrl_t ctrl,
                           unsigned char *request, size_t maxreqlen)
{
  gpg_error_t err;
  int send_err = 0;
  int valid_response = 0;
  const ssh_request_spec_t *spec;
  u32 msglen;
  estream_t request_stream, response_stream;

  if (agent_copy_startup_env (ctrl))
    goto leave; /* Error setting up the environment.  */

  if (maxreqlen < 5)
    goto leave; /* Caller error.  */

  msglen = uint32_construct (request[0], request[1], request[2], request[3]);
  if (msglen < 1 || msglen > maxreqlen - 4)
    {
      log_error ("ssh message len (%u) out of range", (unsigned int)msglen);
      goto leave;
    }

  spec = request_spec_lookup (request[4]);
  if (!spec)
    {
      send_err = 1;  /* Unknown request type.  */
      goto leave;
    }

  /* Create a stream object with the data part of the request.  */
  if (spec->secret_input)
    request_stream = es_mopen (NULL, 0, 0, 1, realloc_secure, gcry_free, "r+");
  else
    request_stream = es_mopen (NULL, 0, 0, 1, gcry_realloc, gcry_free, "r+");
  if (!request_stream)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  /* We have to disable the estream buffering, because the estream
     core doesn't know about secure memory.  */
  if (es_setvbuf (request_stream, NULL, _IONBF, 0))
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  /* Copy the request to the stream but omit the request type.  */
  err = stream_write_data (request_stream, request + 5, msglen - 1);
  if (err)
    goto leave;
  es_rewind (request_stream);

  response_stream = es_fopenmem (0, "r+b");
  if (!response_stream)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  if (opt.verbose)
    log_info ("ssh request handler for %s (%u) started\n",
	       spec->identifier, spec->type);

  err = (*spec->handler) (ctrl, request_stream, response_stream);

  if (opt.verbose)
    {
      if (err)
        log_info ("ssh request handler for %s (%u) failed: %s\n",
                  spec->identifier, spec->type, gpg_strerror (err));
      else
        log_info ("ssh request handler for %s (%u) ready\n",
                  spec->identifier, spec->type);
    }

  es_fclose (request_stream);
  request_stream = NULL;

  if (err)
    {
      send_err = 1;
      goto leave;
    }

  /* Put the response back into the mmapped buffer.  */
  {
    void *response_data;
    size_t response_size;

    /* NB: In contrast to the request-stream, the response stream
       includes the message type byte.  */
    if (es_fclose_snatch (response_stream, &response_data, &response_size))
      {
        log_error ("snatching ssh response failed: %s",
                   gpg_strerror (gpg_error_from_syserror ()));
        send_err = 1; /* Ooops.  */
        goto leave;
      }

    if (opt.verbose > 1)
      log_info ("sending ssh response of length %u\n",
                (unsigned int)response_size);
    if (response_size > maxreqlen - 4)
      {
        log_error ("invalid length of the ssh response: %s",
                   gpg_strerror (GPG_ERR_INTERNAL));
        es_free (response_data);
        send_err = 1;
        goto leave;
      }

    request[0] = response_size >> 24;
    request[1] = response_size >> 16;
    request[2] = response_size >>  8;
    request[3] = response_size >>  0;
    memcpy (request+4, response_data, response_size);
    es_free (response_data);
    valid_response = 1;
  }

 leave:
  if (send_err)
    {
      request[0] = 0;
      request[1] = 0;
      request[2] = 0;
      request[3] = 1;
      request[4] = SSH_RESPONSE_FAILURE;
      valid_response = 1;
    }

  /* Reset the SCD in case it has been used. */
  agent_reset_scd (ctrl);

  return valid_response? 0 : -1;
}
#endif /*HAVE_W32_SYSTEM*/
