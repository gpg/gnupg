/* gpgtar.h - Global definitions for gpgtar
 * Copyright (C) 2010 Free Software Foundation, Inc.
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

#ifndef GPGTAR_H
#define GPGTAR_H

#include "../common/util.h"
#include "../common/strlist.h"


/* We keep all global options in the structure OPT.  */
EXTERN_UNLESS_MAIN_MODULE
struct
{
  int verbose;
  unsigned int debug_level;
  int quiet;
  int dry_run;
  int utf8strings;
  const char *gpg_program;
  strlist_t gpg_arguments;
  const char *outfile;
  strlist_t recipients;
  const char *user;
  int symmetric;
  const char *filename;
  const char *directory;
  int batch;
  int answer_yes;
  int answer_no;
  int status_fd;
  int require_compliance;
  int with_log;
} opt;


/* An info structure to avoid global variables.  */
struct tarinfo_s
{
  unsigned long long nblocks;     /* Count of processed blocks.  */
  unsigned long long headerblock; /* Number of current header block. */
};
typedef struct tarinfo_s *tarinfo_t;


/* The size of a tar record.  All IO is done in chunks of this size.
   Note that we don't care about blocking because this version of tar
   is not expected to be used directly on a tape drive in fact it is
   used in a pipeline with GPG and thus any blocking would be
   useless.  */
#define RECORDSIZE 512


/* Description of the USTAR header format.  */
struct ustar_raw_header
{
  char name[100];
  char mode[8];
  char uid[8];
  char gid[8];
  char size[12];
  char mtime[12];
  char checksum[8];
  char typeflag[1];
  char linkname[100];
  char magic[6];
  char version[2];
  char uname[32];
  char gname[32];
  char devmajor[8];
  char devminor[8];
  char prefix[155];
  char pad[12];
};


/* Filetypes as defined by USTAR.  */
typedef enum
  {
    TF_REGULAR,
    TF_HARDLINK,
    TF_SYMLINK,
    TF_CHARDEV,
    TF_BLOCKDEV,
    TF_DIRECTORY,
    TF_FIFO,
    TF_RESERVED,
    TF_GEXTHDR,    /* Global extended header.  */
    TF_EXTHDR,     /* Extended header.  */
    TF_UNKNOWN,    /* Needs to be treated as regular file.  */
    TF_NOTSUP      /* Not supported (used with --create).  */
  } typeflag_t;


/* The internal represenation of a TAR header.  */
struct tar_header_s;
typedef struct tar_header_s *tar_header_t;
struct tar_header_s
{
  tar_header_t next;        /* Used to build a linked list of entries.  */

  unsigned long mode;       /* The file mode.  */
  unsigned long nlink;      /* Number of hard links.  */
  unsigned long uid;        /* The user id of the file.  */
  unsigned long gid;        /* The group id of the file.  */
  unsigned long long size;  /* The size of the file.  */
  unsigned long long mtime; /* Modification time since Epoch.  Note
                               that we don't use time_t here but a
                               type which is more likely to be larger
                               that 32 bit and thus allows tracking
                               times beyond 2106.  */
  typeflag_t typeflag;      /* The type of the file.  */


  unsigned long long nrecords; /* Number of data records.  */

  char name[1];             /* Filename (UTF-8, dynamically extended).  */
};


/*-- gpgtar.c --*/
gpg_error_t read_record (estream_t stream, void *record);
gpg_error_t write_record (estream_t stream, const void *record);

/*-- gpgtar-create.c --*/
gpg_error_t gpgtar_create (char **inpattern, const char *files_from,
                           int null_names, int encrypt, int sign);

/*-- gpgtar-extract.c --*/
gpg_error_t gpgtar_extract (const char *filename, int decrypt);

/*-- gpgtar-list.c --*/
gpg_error_t gpgtar_list (const char *filename, int decrypt);
gpg_error_t gpgtar_read_header (estream_t stream, tarinfo_t info,
                                tar_header_t *r_header, strlist_t *r_extheader);
void gpgtar_print_header (tar_header_t header, strlist_t extheader,
                          estream_t out);


#endif /*GPGTAR_H*/
