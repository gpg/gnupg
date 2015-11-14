/* gpg.h - top level include file for gpg etc.
 * Copyright (C) 2003, 2006, 2010 Free Software Foundation, Inc.
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
#ifndef GNUPG_G10_GPG_H
#define GNUPG_G10_GPG_H

/* Note, that this file should be the first one after the system
   header files.  This is required to set the error source to the
   correct value and may be of advantage if we ever have to do
   special things. */

#ifdef GPG_ERR_SOURCE_DEFAULT
#error GPG_ERR_SOURCE_DEFAULT already defined
#endif
#define GPG_ERR_SOURCE_DEFAULT  GPG_ERR_SOURCE_GPG
#define map_assuan_err(a) \
        map_assuan_err_with_source (GPG_ERR_SOURCE_DEFAULT, (a))
#include <gpg-error.h>
#include <gcrypt.h>


/* Number of bits we accept when reading or writing MPIs. */
#define MAX_EXTERN_MPI_BITS 16384

/* The maximum length of a binary fingerprints.  This is used to
   provide a static buffer and will be increased if we need to support
   longer fingerprints.
   Warning: At some places we still use 20 instead of this macro. */
#define MAX_FINGERPRINT_LEN 20

/* The maximum length of a formatted fingerprint as returned by
   format_hexfingerprint().  */
#define MAX_FORMATTED_FINGERPRINT_LEN 50


/*
   Forward declarations.
 */

/* Object used to keep state locally to server.c . */
struct server_local_s;

/* Object used to keep state locally to call-dirmngr.c .  */
struct dirmngr_local_s;
typedef struct dirmngr_local_s *dirmngr_local_t;

/* Object used to describe a keyblok node.  */
typedef struct kbnode_struct *KBNODE;
typedef struct kbnode_struct *kbnode_t;


/* Session control object.  This object is passed to most functions to
   convey the status of a session.  Note that the defaults are set by
   gpg_init_default_ctrl(). */
struct server_control_s
{
  /* Local data for server.c  */
  struct server_local_s *server_local;

  /* Local data for call-dirmngr.c  */
  dirmngr_local_t dirmngr_local;
};



#endif /*GNUPG_G10_GPG_H*/
