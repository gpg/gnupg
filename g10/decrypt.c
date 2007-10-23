/* decrypt.c - verify signed data
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
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

#include "options.h"
#include "packet.h"
#include "errors.h"
#include "iobuf.h"
#include "keydb.h"
#include "memory.h"
#include "util.h"
#include "main.h"
#include "status.h"
#include "i18n.h"



/****************
 * Assume that the input is an encrypted message and decrypt
 * (and if signed, verify the signature on) it.
 * This command differs from the default operation, as it never
 * writes to the filename which is included in the file and it
 * rejects files which don't begin with an encrypted message.
 */

int
decrypt_message( const char *filename )
{
    IOBUF fp;
    armor_filter_context_t afx;
    progress_filter_context_t pfx;
    int rc;
    int no_out=0;

    /* open the message file */
    fp = iobuf_open(filename);
    if (fp && is_secured_file (iobuf_get_fd (fp)))
      {
        iobuf_close (fp);
        fp = NULL;
        errno = EPERM;
      }
    if( !fp ) {
	log_error(_("can't open `%s'\n"), print_fname_stdin(filename));
	return G10ERR_OPEN_FILE;
    }

    handle_progress (&pfx, fp, filename);

    if( !opt.no_armor ) {
	if( use_armor_filter( fp ) ) {
	    memset( &afx, 0, sizeof afx);
	    iobuf_push_filter( fp, armor_filter, &afx );
	}
    }

    if( !opt.outfile ) {
	no_out = 1;
	opt.outfile = "-";
    }
    rc = proc_encryption_packets( NULL, fp );
    if( no_out )
       opt.outfile = NULL;
    iobuf_close(fp);
    return rc;
}

void
decrypt_messages(int nfiles, char *files[])
{
  IOBUF fp;
  armor_filter_context_t afx;  
  progress_filter_context_t pfx;
  char *p, *output = NULL;
  int rc=0,use_stdin=0;
  unsigned int lno=0;
  
  if (opt.outfile)
    {
      log_error(_("--output doesn't work for this command\n"));
      return;
        
    }

  if(!nfiles)
    use_stdin=1;

  for(;;)
    {
      char line[2048];
      char *filename=NULL;

      if(use_stdin)
	{
	  if(fgets(line, DIM(line), stdin))
	    {
	      lno++;
	      if (!*line || line[strlen(line)-1] != '\n')
		log_error("input line %u too long or missing LF\n", lno);
	      else
		{
		  line[strlen(line)-1] = '\0';
		  filename=line;
		}
	    }
	}
      else
	{
	  if(nfiles)
	    {
	      filename=*files;
	      nfiles--;
	      files++;
	    }
	}

      if(filename==NULL)
	break;

      print_file_status(STATUS_FILE_START, filename, 3);      
      output = make_outfile_name(filename);
      if (!output)
        goto next_file;
      fp = iobuf_open(filename);
      if (fp)
        iobuf_ioctl (fp,3,1,NULL); /* disable fd caching */
      if (fp && is_secured_file (iobuf_get_fd (fp)))
        {
          iobuf_close (fp);
          fp = NULL;
          errno = EPERM;
        }
      if (!fp)
        {
          log_error(_("can't open `%s'\n"), print_fname_stdin(filename));
          goto next_file;
        }

      handle_progress (&pfx, fp, filename);

      if (!opt.no_armor)
        {
          if (use_armor_filter(fp))
            {
              memset(&afx, 0, sizeof afx);
              iobuf_push_filter(fp, armor_filter, &afx);
            }
        }
      rc = proc_packets(NULL, fp);
      iobuf_close(fp);
      if (rc)
        log_error("%s: decryption failed: %s\n", print_fname_stdin(filename),
                  g10_errstr(rc));
      p = get_last_passphrase();
      set_next_passphrase(p);
      xfree (p);

    next_file:
      /* Note that we emit file_done even after an error. */
      write_status( STATUS_FILE_DONE );
      iobuf_ioctl( NULL, 2, 0, NULL); /* Invalidate entire cache. */
      xfree(output);
      reset_literals_seen();
    }

  set_next_passphrase(NULL);  
}
