/* verify.c - Verify signed data
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2004, 2005, 2006,
 *               2007 Free Software Foundation, Inc.
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "gpg.h"
#include "options.h"
#include "packet.h"
#include "status.h"
#include "iobuf.h"
#include "keydb.h"
#include "util.h"
#include "main.h"
#include "status.h"
#include "filter.h"
#include "ttyio.h"
#include "i18n.h"



/****************
 * Assume that the input is a signature and verify it without
 * generating any output.  With no arguments, the signature packet
 * is read from stdin (it may be a detached signature when not
 * used in batch mode). If only a sigfile is given, it may be a complete
 * signature or a detached signature in which case the signed stuff
 * is expected from stdin. With more than 1 argument, the first should
 * be a detached signature and the remaining files are the signed stuff.
 */

int
verify_signatures( int nfiles, char **files )
{
    IOBUF fp;
    armor_filter_context_t *afx = NULL;
    progress_filter_context_t *pfx = new_progress_context ();
    const char *sigfile;
    int i, rc;
    strlist_t sl;

    /* Decide whether we should handle a detached or a normal signature,
     * which is needed so that the code later can hash the correct data and
     * not have a normal signature act as detached signature and ignoring the
     * indended signed material from the 2nd file or stdin.
     * 1. gpg <file        - normal
     * 2. gpg file         - normal (or detached)
     * 3. gpg file <file2  - detached
     * 4. gpg file file2   - detached
     * The question is how decide between case 2 and 3?  The only way
     * we can do it is by reading one byte from stdin and then unget
     * it; the problem here is that we may be reading from the
     * terminal (which could be detected using isatty() but won't work
     * when under contol of a pty using program (e.g. expect)) and
     * might get us in trouble when stdin is used for another purpose
     * (--passphrase-fd 0).  So we have to break with the behaviour
     * prior to gpg 1.0.4 by assuming that case 3 is a normal
     * signature (where file2 is ignored and require for a detached
     * signature to indicate signed material comes from stdin by using
     * case 4 with a file2 of "-".
     *
     * Actually we don't have to change anything here but can handle
     * that all quite easily in mainproc.c 
     */
     
    sigfile = nfiles? *files : NULL;

    /* open the signature file */
    fp = iobuf_open(sigfile);
    if (fp && is_secured_file (iobuf_get_fd (fp)))
      {
        iobuf_close (fp);
        fp = NULL;
        errno = EPERM;
      }
    if( !fp ) {
        rc = gpg_error_from_syserror ();
	log_error(_("can't open `%s': %s\n"),
                  print_fname_stdin(sigfile), strerror (errno));
        goto leave;
    }
    handle_progress (pfx, fp, sigfile);

    if ( !opt.no_armor && use_armor_filter( fp ) )
      {
        afx = new_armor_context ();
	push_armor_filter (afx, fp);
      }

    sl = NULL;
    for(i=nfiles-1 ; i > 0 ; i-- )
	add_to_strlist( &sl, files[i] );
    rc = proc_signature_packets( NULL, fp, sl, sigfile );
    free_strlist(sl);
    iobuf_close(fp);
    if( (afx && afx->no_openpgp_data && rc == -1) || rc == G10ERR_NO_DATA ) {
	log_error(_("the signature could not be verified.\n"
		   "Please remember that the signature file (.sig or .asc)\n"
		   "should be the first file given on the command line.\n") );
	rc = 0;
    }

 leave:
    release_armor_context (afx);
    release_progress_context (pfx);
    return rc;
}



void
print_file_status( int status, const char *name, int what )
{
    char *p = xmalloc(strlen(name)+10);
    sprintf(p, "%d %s", what, name );
    write_status_text( status, p );
    xfree(p);
}


static int
verify_one_file( const char *name )
{
    IOBUF fp;
    armor_filter_context_t *afx = NULL;
    progress_filter_context_t *pfx = new_progress_context ();
    int rc;

    print_file_status( STATUS_FILE_START, name, 1 );
    fp = iobuf_open(name);
    if (fp)
      iobuf_ioctl (fp,3,1,NULL); /* disable fd caching */
    if (fp && is_secured_file (iobuf_get_fd (fp)))
      {
        iobuf_close (fp);
        fp = NULL;
        errno = EPERM;
      }
    if( !fp ) {
        rc = gpg_error_from_syserror ();
	log_error(_("can't open `%s': %s\n"),
                  print_fname_stdin(name), strerror (errno));
	print_file_status( STATUS_FILE_ERROR, name, 1 );
        goto leave;
    }
    handle_progress (pfx, fp, name);

    if( !opt.no_armor ) {
	if( use_armor_filter( fp ) ) {
            afx = new_armor_context ();
	    push_armor_filter (afx, fp);
	}
    }

    rc = proc_signature_packets( NULL, fp, NULL, name );
    iobuf_close(fp);
    write_status( STATUS_FILE_DONE );

    reset_literals_seen();

 leave:
    release_armor_context (afx);
    release_progress_context (pfx);
    return rc;
}

/****************
 * Verify each file given in the files array or read the names of the
 * files from stdin.
 * Note:  This function can not handle detached signatures.
 */
int
verify_files( int nfiles, char **files )
{
    int i;

    if( !nfiles ) { /* read the filenames from stdin */
	char line[2048];
	unsigned int lno = 0;

	while( fgets(line, DIM(line), stdin) ) {
	    lno++;
	    if( !*line || line[strlen(line)-1] != '\n' ) {
		log_error(_("input line %u too long or missing LF\n"), lno );
		return G10ERR_GENERAL;
	    }
	    /* This code does not work on MSDOS but how cares there are
	     * also no script languages available.  We don't strip any
	     * spaces, so that we can process nearly all filenames */
	    line[strlen(line)-1] = 0;
	    verify_one_file( line );
	}

    }
    else {  /* take filenames from the array */
	for(i=0; i < nfiles; i++ )
	    verify_one_file( files[i] );
    }
    return 0;
}




/* Perform a verify operation.  To verify detached signatures, DATA_FD
   shall be the descriptor of the signed data; for regular signatures
   it needs to be -1.  If OUT_FP is not NULL and DATA_FD is not -1 the
   the signed material gets written that stream. 

   FIXME: OUTFP is not yet implemented.
*/
int
gpg_verify (ctrl_t ctrl, int sig_fd, int data_fd, FILE *out_fp)
{
  int rc;
  iobuf_t fp;
  armor_filter_context_t *afx = NULL;
  progress_filter_context_t *pfx = new_progress_context ();

  (void)ctrl;
  (void)out_fp;

  fp = iobuf_fdopen (sig_fd, "rb");
  if (fp && is_secured_file (sig_fd))
    {
      fp = NULL;
      errno = EPERM;
    }
  if ( !fp )
    {
      rc = gpg_error_from_syserror ();
      log_error (_("can't open fd %d: %s\n"), sig_fd, strerror (errno));
      goto leave;
    }

  handle_progress (pfx, fp, NULL);

  if ( !opt.no_armor && use_armor_filter (fp) )
    {
      afx = new_armor_context ();
      push_armor_filter (afx, fp);
    }

  rc = proc_signature_packets_by_fd ( NULL, fp, data_fd );

  if ( afx && afx->no_openpgp_data
       && (rc == -1 || gpg_err_code (rc) == GPG_ERR_EOF) )
    rc = gpg_error (GPG_ERR_NO_DATA);

 leave:  
  if (fp)
    iobuf_close (fp);
  release_progress_context (pfx);
  release_armor_context (afx);
  return rc;
}

