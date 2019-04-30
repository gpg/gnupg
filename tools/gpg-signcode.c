/* gpg-signcode.c - An interactive tool to work with cards.
 * Copyright (C) 2019 g10 Code GmbH
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://gnu.org/licenses/>.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "../common/util.h"
#include "../common/i18n.h"
#include "../common/status.h"
#include "../common/init.h"
#include "../common/session-env.h"
#include "../common/sysutils.h"
#include "../common/ccparray.h"
#include "../common/exectool.h"

/* Constants to identify the commands and options. */
enum opt_values
  {
    aNull = 0,

    oQuiet      = 'q',
    oVerbose	= 'v',

    oDebug      = 500,

    oGpgProgram,
    oGpgsmProgram,
    oStatusFD,
    oWithColons,
    oNoAutostart,
    oAgentProgram,

    oDisplay,
    oTTYname,
    oTTYtype,
    oXauthority,
    oLCctype,
    oLCmessages,

    oDummy
  };


/* The list of commands and options. */
static ARGPARSE_OPTS opts[] = {
  ARGPARSE_group (301, ("@\nOptions:\n ")),

  ARGPARSE_s_n (oVerbose, "verbose", ("verbose")),
  ARGPARSE_s_n (oQuiet,	"quiet",  ("be somewhat more quiet")),
  ARGPARSE_s_s (oDebug, "debug", "@"),
  ARGPARSE_s_s (oGpgProgram, "gpg", "@"),
  ARGPARSE_s_s (oGpgsmProgram, "gpgsm", "@"),
  ARGPARSE_s_i (oStatusFD, "status-fd", ("|FD|write status info to this FD")),
  ARGPARSE_s_n (oWithColons, "with-colons", "@"),
  ARGPARSE_s_n (oNoAutostart, "no-autostart", "@"),
  ARGPARSE_s_s (oAgentProgram, "agent-program", "@"),
  ARGPARSE_s_s (oDisplay,    "display",    "@"),
  ARGPARSE_s_s (oTTYname,    "ttyname",    "@"),
  ARGPARSE_s_s (oTTYtype,    "ttytype",    "@"),
  ARGPARSE_s_s (oXauthority, "xauthority", "@"),
  ARGPARSE_s_s (oLCctype,    "lc-ctype",   "@"),
  ARGPARSE_s_s (oLCmessages, "lc-messages","@"),

  ARGPARSE_end ()
};


/* We keep all global options in the structure OPT.  */
struct
{
  int interactive;
  int verbose;
  unsigned int debug;
  int quiet;
  int with_colons;
  const char *gpg_program;
  const char *gpgsm_program;
  const char *agent_program;
  int autostart;

  /* Options passed to the gpg-agent: */
  session_env_t session_env;
  char *lc_ctype;
  char *lc_messages;

} opt;

/* Debug values and macros.  */
#define DBG_EXTPROG_VALUE 16384 /* Debug external program calls */

#define DBG_IPC       (opt.debug & DBG_IPC_VALUE)
#define DBG_EXTPROG   (opt.debug & DBG_EXTPROG_VALUE)


/* The list of supported debug flags.  */
static struct debug_flags_s debug_flags [] =
  {
    /* { DBG_IPC_VALUE    , "ipc"     }, */
    /* { DBG_EXTPROG_VALUE, "extprog" }, */
    { 0, NULL }
  };



/* Local prototypes.  */
static gpg_error_t read_file (const char *fname,
                              char **r_buf, size_t *r_length);
static gpg_error_t signcode (const char *fname, char *file, size_t filelen);
static gpg_error_t pe_signcode (const char *fname, char *file, size_t filelen);


/* Small helpers.  */
static inline unsigned int
le16_to_uint (const void *buffer)
{
  const unsigned char *p = buffer;

  return (((unsigned int)p[1] << 8) | p[0]);
}

static inline unsigned int
le32_to_uint (const void *buffer)
{
  const unsigned char *p = buffer;

  return (((unsigned int)p[3] << 24) | (p[2] << 16) | (p[1] << 8) | p[0]);
}





/* Print usage information and provide strings for help. */
static const char *
my_strusage( int level )
{
  const char *p;

  switch (level)
    {
    case 11: p = "gpg-signcode"; break;
    case 12: p = "@GNUPG@"; break;
    case 13: p = VERSION; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = ("Please report bugs to <@EMAIL@>.\n"); break;

    case 1:
    case 40:
      p = ("Usage: gpg-signcode [options] [INFILE]");
      break;
    case 41:
      p = ("Syntax: gpg-signcode [options] [INFILE]\n\n"
           "Tool to sign PE binaries.");
      break;

    default: p = NULL; break;
    }
  return p;
}


static void
set_opt_session_env (const char *name, const char *value)
{
  gpg_error_t err;

  err = session_env_setenv (opt.session_env, name, value);
  if (err)
    log_fatal ("error setting session environment: %s\n",
               gpg_strerror (err));
}



/* Command line parsing.  */
static void
parse_arguments (ARGPARSE_ARGS *pargs, ARGPARSE_OPTS *popts)
{
  while (optfile_parse (NULL, NULL, NULL, pargs, popts))
    {
      switch (pargs->r_opt)
        {
	case oQuiet:     opt.quiet = 1; break;
        case oVerbose:   opt.verbose++; break;
        case oDebug:
          if (parse_debug_flag (pargs->r.ret_str, &opt.debug, debug_flags))
            {
              pargs->r_opt = ARGPARSE_INVALID_ARG;
              pargs->err = ARGPARSE_PRINT_ERROR;
            }
          break;

        case oGpgProgram:   opt.gpg_program = pargs->r.ret_str; break;
        case oGpgsmProgram: opt.gpgsm_program = pargs->r.ret_str; break;
        case oAgentProgram: opt.agent_program = pargs->r.ret_str; break;

        case oStatusFD:
          gnupg_set_status_fd (translate_sys2libc_fd_int (pargs->r.ret_int, 1));
          break;

        case oWithColons:  opt.with_colons = 1; break;
        case oNoAutostart: opt.autostart = 0; break;

        case oDisplay: set_opt_session_env ("DISPLAY", pargs->r.ret_str); break;
        case oTTYname: set_opt_session_env ("GPG_TTY", pargs->r.ret_str); break;
        case oTTYtype: set_opt_session_env ("TERM", pargs->r.ret_str); break;
        case oXauthority: set_opt_session_env ("XAUTHORITY",
                                               pargs->r.ret_str); break;
        case oLCctype:     opt.lc_ctype = pargs->r.ret_str; break;
        case oLCmessages:  opt.lc_messages = pargs->r.ret_str; break;

        default: pargs->err = 2; break;
	}
    }
}



/* gpg-card main. */
int
main (int argc, char **argv)
{
  gpg_error_t err;
  ARGPARSE_ARGS pargs;
  char *file;
  size_t filelen;

  gnupg_reopen_std ("gpg-signcode");
  set_strusage (my_strusage);
  log_set_prefix ("gpg-signcode", GPGRT_LOG_WITH_PREFIX);

  /* Make sure that our subsystems are ready.  */
  i18n_init();
  init_common_subsystems (&argc, &argv);

  /* Setup default options.  */
  opt.autostart = 1;
  opt.session_env = session_env_new ();
  if (!opt.session_env)
    log_fatal ("error allocating session environment block: %s\n",
               gpg_strerror (gpg_error_from_syserror ()));


  /* Parse the command line. */
  pargs.argc  = &argc;
  pargs.argv  = &argv;
  pargs.flags = ARGPARSE_FLAG_KEEP;
  parse_arguments (&pargs, opts);

  if (log_get_errorcount (0))
    exit (2);
  if (argc > 2)
    usage (1);

  /* Set defaults for non given options.  */
  if (!opt.gpg_program)
    opt.gpg_program = gnupg_module_name (GNUPG_MODULE_NAME_GPG);
  if (!opt.gpgsm_program)
    opt.gpgsm_program = gnupg_module_name (GNUPG_MODULE_NAME_GPGSM);

  err = read_file (argc? *argv : NULL, &file, &filelen);
  if (!err)
    err = signcode (argc? *argv : "-", file, filelen);

  xfree (file);

  if (err)
    gnupg_status_printf (STATUS_FAILURE, "- %u", err);
  else if (log_get_errorcount (0))
    gnupg_status_printf (STATUS_FAILURE, "- %u", GPG_ERR_GENERAL);
  else
    gnupg_status_printf (STATUS_SUCCESS, NULL);
  return log_get_errorcount (0)? 1:0;
}


/* Read the file FNAME or stdin if FNAME is NULL and store a malloced
 * buffer with the content at R_BUF.  R_LENGTH receives the length of
 * the file.  On error a diagnostic is printed and an error code is
 * returned. */
static gpg_error_t
read_file (const char *fname, char **r_buf, size_t *r_length)
{
  gpg_error_t err;
  FILE *fp;
  char *buf;
  size_t buflen;

  *r_buf = NULL;

  if (!strcmp (fname, "-"))
    {
      size_t nread, bufsize = 0;

      fp = stdin;
      buf = NULL;
      buflen = 0;
#define NCHUNK (1024*1024)
      do
        {
          bufsize += NCHUNK;
          buf = xtryrealloc (buf, bufsize);
          if (!buf)
            {
              err = gpg_error_from_syserror ();
              log_fatal ("can't allocate buffer: %s\n", gpg_strerror (err));
            }

          nread = fread (buf+buflen, 1, NCHUNK, fp);
          if (nread < NCHUNK && ferror (fp))
            {
              err = gpg_error_from_syserror ();
              log_error ("error reading '[stdin]': %s\n", gpg_strerror (err));
              xfree (buf);
              return err;
            }
          buflen += nread;
        }
      while (nread == NCHUNK);
#undef NCHUNK
    }
  else
    {
      struct stat st;

      fp = fopen (fname, "rb");
      if (!fp)
        {
          err = gpg_error_from_syserror ();
          log_error ("can't open '%s': %s\n", fname, gpg_strerror (err));
          return err;
        }

      if (fstat (fileno(fp), &st))
        {
          err = gpg_error_from_syserror ();
          log_error ("can't stat '%s': %s\n", fname, gpg_strerror (err));
          fclose (fp);
          return err;
        }

      buflen = st.st_size;
      buf = xtrymalloc (buflen+1);
      if (!buf)
        {
          err = gpg_error_from_syserror ();
          log_fatal ("can't allocate buffer: %s\n", gpg_strerror (err));
        }
      if (fread (buf, buflen, 1, fp) != 1)
        {
          err = gpg_error_from_syserror ();
          log_error ("error reading '%s': %s\n", fname, gpg_strerror (err));
          fclose (fp);
          xfree (buf);
          return err;
        }
      fclose (fp);
    }

  *r_buf = buf;
  *r_length = buflen;
  return 0;
}


/* Dispatch on file types.  */
static gpg_error_t
signcode (const char *fname, char *file, size_t filelen)
{
  if (filelen > 4 && !memcmp (file, "MSCF", 4))
    {
      log_error ("CAB files are not yet supported\n");
      return gpg_error (GPG_ERR_NOT_SUPPORTED);
    }
  else if (filelen > 2 && !memcmp (file, "MZ", 2))
    return pe_signcode (fname, file, filelen);
  else if (filelen > 8 &&!memcmp (file, "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 8))
    {
      log_error ("MSI files are not yet supported\n");
      return gpg_error (GPG_ERR_NOT_SUPPORTED);
    }
  else
    {
      log_error ("unknown file type\n");
      return gpg_error (GPG_ERR_NOT_SUPPORTED);
    }
}



/*******************************************
 *
 *          PE specific code
 *
 *******************************************/

static gpg_error_t
pe_get_indirect_data_blob (byte **blob, int *len, gcry_md_hd_t md,
                           char *file, unsigned int peheader, int pe32plus,
                           unsigned int sigpos)
{
  /* byte *p; */
  /* int hashlen, l; */
  /* void *hash; */
  /* SpcIndirectDataContent *idc; */
  /* SpcPeImageData *pid; */

  /* ASN1_OBJECT *dtype; */


  /* idc = SpcIndirectDataContent_new(); */
  /* idc->data->value = ASN1_TYPE_new(); */
  /* idc->data->value->type = V_ASN1_SEQUENCE; */
  /* idc->data->value->value.sequence = ASN1_STRING_new(); */

  /* pid = SpcPeImageData_new(); */
  /* ASN1_BIT_STRING_set(pid->flags, (unsigned char*)"0", 0); */
  /* pid->file = get_obsolete_link(); */
  /* l = i2d_SpcPeImageData(pid, NULL); */
  /* p = OPENSSL_malloc(l); */
  /* i2d_SpcPeImageData(pid, &p); */
  /* p -= l; */
  /* dtype = OBJ_txt2obj(SPC_PE_IMAGE_DATA_OBJID, 1); */
  /* SpcPeImageData_free(pid); */

  /* idc->data->type = dtype; */
  /* idc->data->value->value.sequence->data = p; */
  /* idc->data->value->value.sequence->length = l; */
  /* idc->messageDigest->digestAlgorithm->algorithm = OBJ_nid2obj(EVP_MD_nid(md)); */
  /* idc->messageDigest->digestAlgorithm->parameters = ASN1_TYPE_new(); */
  /* idc->messageDigest->digestAlgorithm->parameters->type = V_ASN1_NULL; */

  /* hashlen = EVP_MD_size(md); */
  /* hash = OPENSSL_malloc(hashlen); */
  /* memset(hash, 0, hashlen); */
  /* ASN1_OCTET_STRING_set(idc->messageDigest->digest, hash, hashlen); */
  /* OPENSSL_free(hash); */

  /* *len  = i2d_SpcIndirectDataContent(idc, NULL); */
  /* *blob = OPENSSL_malloc(*len); */
  /* p = *blob; */
  /* i2d_SpcIndirectDataContent(idc, &p); */
  /* SpcIndirectDataContent_free(idc); */
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
}


/* Main for PE files.  */
static gpg_error_t
pe_signcode (const char *fname, char *file, size_t filesize)
{
  gpg_error_t err;
  unsigned int peheaderoff;
  unsigned int magic;
  int pe32plus;         /* Flag */
  unsigned int filelen; /* Used length of the file.  */
  unsigned int nrvas;   /* Number of certificate resources.  */
  unsigned int sigoff, siglen;
  unsigned int n;
  char *buffer = NULL;
  unsigned int bufsize;
  gcry_md_hd_t hash = NULL;
  estream_t outfile = NULL;

  if (filesize < 64)
    {
      log_error ("DOS part of PE file is too short\n");
      return gpg_error (GPG_ERR_TOO_SHORT);
    }

  peheaderoff = le32_to_uint (file+60);
  if (filesize < peheaderoff + 160)
    {
      log_error ("corrupt PE file: %s\n", "offset to PE header to high");
      return gpg_error (GPG_ERR_GENERAL);
    }
  if (memcmp (file + peheaderoff, "PE\0", 4))
    {
      log_error ("corrupt PE file: %s\n", "no PE marker");
      return gpg_error (GPG_ERR_GENERAL);
    }

  magic = le16_to_uint (file + peheaderoff + 24);
  switch (magic)
    {
    case 0x020b: pe32plus = 1; break;
    case 0x010b: pe32plus = 0; break;
    default:
      log_error ("corrupt PE file: unknown magix 0x%04x\n", magic);
      return gpg_error (GPG_ERR_GENERAL);
    }

  nrvas = le32_to_uint (file + peheaderoff + 116 + pe32plus*16);
  if (nrvas < 5)
    {
      log_error ("not enough certificate resources in PE file (got %u)\n",
                 nrvas);
      return gpg_error (GPG_ERR_GENERAL);
    }
  if (filesize < peheaderoff + 152 + pe32plus*16 + 4 + 4)
    {
      log_error ("corrupt PE file: %s\n",
                 "header too short to carry offset to the signature");
      return gpg_error (GPG_ERR_GENERAL);
    }
  sigoff = le32_to_uint (file + peheaderoff + 152 + pe32plus*16);
  siglen = le32_to_uint (file + peheaderoff + 152 + pe32plus*16 + 4);
  if (sigoff && sigoff + siglen != filesize)
    {
      /* Since the fix for MS Bulletin MS12-024 we can assume that an
       * existisng signature is the last part of the file.  */
      log_error ("corrupt PE file: current signature not at end of file\n");
      return gpg_error (GPG_ERR_GENERAL);
    }

  /* Strip an existing signature.  */
  filelen = sigoff? sigoff : filesize;

  /* Create a helper buffer.  */
  bufsize = 64 * 1024;
  buffer = xtrymalloc (bufsize);
  if (!buffer)
    {
      err = gpg_error_from_syserror ();
      log_error ("error allocating help buffer: %s\n", gpg_strerror (err));
      goto leave;
    }

  err = gcry_md_open (&hash, GCRY_MD_SHA256, 0);
  if (err)
    {
      log_error ("error creating digest context: %s\n", gpg_strerror (err));
      goto leave;
    }

  n = peheaderoff + 88;
  gcry_md_write (hash, file, n);
  es_write (outfile, file, n, NULL);

  /* Zero out the checksum. */
  memset (buffer, 0, 4);
  es_write (outfile, buffer, 4, NULL);
  n += 4;

  gcry_md_write (hash, file + n, 60 + pe32plus*16);
  es_write (outfile, file + n, 60 + pe32plus*16, NULL);
  n += 60 + pe32plus*16;

  /* Zero out the sigtable offset + len.  */
  memset (buffer, 0, 8);
  es_write(outfile, buffer, 8, NULL);
  n += 8;

  log_assert (n < filelen);
  gcry_md_write (hash, file + n, filelen - n);
  es_write (outfile, file + n, filelen - n, NULL);

  /* Zero pad the PE file to a 8 byte boundary.  */
  n = 8 - filelen % 8;
  if (n > 0 && n != 8)
    {
      memset (buffer, 0, n);
      gcry_md_write (hash, buffer, n);
      es_write (outfile, buffer, n, NULL);
      filelen += n;
      /* Note that FILELEN might be larger than FILESIZE.  */
    }

  /* Create the indirect data blob DER object.  */



 leave:
  gcry_md_close (hash);
  xfree (buffer);
  return err;
}
