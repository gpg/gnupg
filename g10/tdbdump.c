/* tdbdump.c
 * Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "gpg.h"
#include "../common/status.h"
#include "../common/iobuf.h"
#include "keydb.h"
#include "../common/util.h"
#include "trustdb.h"
#include "options.h"
#include "packet.h"
#include "main.h"
#include "../common/i18n.h"
#include "tdbio.h"


#define HEXTOBIN(x) ( (x) >= '0' && (x) <= '9' ? ((x)-'0') : \
		      (x) >= 'A' && (x) <= 'F' ? ((x)-'A'+10) : ((x)-'a'+10))


/*
 * Write a record; die on error.
 */
static void
write_record (ctrl_t ctrl, TRUSTREC *rec)
{
    int rc = tdbio_write_record (ctrl, rec);
    if( !rc )
	return;
    log_error(_("trust record %lu, type %d: write failed: %s\n"),
			    rec->recnum, rec->rectype, gpg_strerror (rc) );
    tdbio_invalid();
}


/*
 * Dump the entire trustdb to FP or only the entries of one key.
 */
void
list_trustdb (ctrl_t ctrl, estream_t fp, const char *username)
{
  TRUSTREC rec;

  (void)username;

  init_trustdb (ctrl, 0);
  /* For now we ignore the user ID. */
  if (1)
    {
      ulong recnum;
      int i;

      es_fprintf (fp, "TrustDB: %s\n", tdbio_get_dbname ());
      for (i = 9 + strlen (tdbio_get_dbname()); i > 0; i-- )
        es_fputc ('-', fp);
      es_putc ('\n', fp);
      for (recnum=0; !tdbio_read_record (recnum, &rec, 0); recnum++)
        tdbio_dump_record (&rec, fp);
    }
}





/****************
 * Print a list of all defined owner trust value.
 */
void
export_ownertrust (ctrl_t ctrl)
{
  TRUSTREC rec;
  ulong recnum;
  int i;
  byte *p;

  init_trustdb (ctrl, 0);
  es_printf (_("# List of assigned trustvalues, created %s\n"
               "# (Use \"gpg --import-ownertrust\" to restore them)\n"),
             asctimestamp( make_timestamp() ) );
  for (recnum=0; !tdbio_read_record (recnum, &rec, 0); recnum++ )
    {
      if (rec.rectype == RECTYPE_TRUST)
        {
          if (!rec.r.trust.ownertrust)
            continue;
          p = rec.r.trust.fingerprint;
          for (i=0; i < 20; i++, p++ )
            es_printf("%02X", *p );
          es_printf (":%u:\n", (unsigned int)rec.r.trust.ownertrust );
	}
    }
}


void
import_ownertrust (ctrl_t ctrl, const char *fname )
{
    estream_t fp;
    int is_stdin=0;
    char line[256];
    char *p;
    size_t n, fprlen;
    unsigned int otrust;
    byte fpr[20];
    int any = 0;
    int rc;

    init_trustdb (ctrl, 0);
    if( iobuf_is_pipe_filename (fname) ) {
	fp = es_stdin;
	fname = "[stdin]";
	is_stdin = 1;
    }
    else if( !(fp = es_fopen( fname, "r" )) ) {
	log_error ( _("can't open '%s': %s\n"), fname, strerror(errno) );
	return;
    }

    if (is_secured_file (es_fileno (fp)))
      {
        es_fclose (fp);
        gpg_err_set_errno (EPERM);
	log_error (_("can't open '%s': %s\n"), fname, strerror(errno) );
	return;
      }

    while (es_fgets (line, DIM(line)-1, fp)) {
	TRUSTREC rec;

	if( !*line || *line == '#' )
	    continue;
	n = strlen(line);
	if( line[n-1] != '\n' ) {
	    log_error (_("error in '%s': %s\n"), fname, _("line too long") );
	    /* ... or last line does not have a LF */
	    break; /* can't continue */
	}
	for(p = line; *p && *p != ':' ; p++ )
	    if( !hexdigitp(p) )
		break;
	if( *p != ':' ) {
	    log_error (_("error in '%s': %s\n"), fname, _("colon missing") );
	    continue;
	}
	fprlen = p - line;
	if( fprlen != 32 && fprlen != 40 ) {
	    log_error (_("error in '%s': %s\n"),
                       fname, _("invalid fingerprint") );
	    continue;
	}
	if( sscanf(p, ":%u:", &otrust ) != 1 ) {
	    log_error (_("error in '%s': %s\n"),
                       fname, _("ownertrust value missing"));
	    continue;
	}
	if( !otrust )
	    continue; /* no otrust defined - no need to update or insert */
	/* convert the ascii fingerprint to binary */
	for(p=line, fprlen=0; fprlen < 20 && *p != ':'; p += 2 )
	    fpr[fprlen++] = HEXTOBIN(p[0]) * 16 + HEXTOBIN(p[1]);
	while (fprlen < 20)
	    fpr[fprlen++] = 0;

	rc = tdbio_search_trust_byfpr (ctrl, fpr, &rec);
	if( !rc ) { /* found: update */
	    if (rec.r.trust.ownertrust != otrust)
              {
                if (!opt.quiet)
                  {
                    if( rec.r.trust.ownertrust )
                      log_info("changing ownertrust from %u to %u\n",
                               rec.r.trust.ownertrust, otrust );
                    else
                      log_info("setting ownertrust to %u\n", otrust );
                  }
                rec.r.trust.ownertrust = otrust;
                write_record (ctrl, &rec);
                any = 1;
              }
	}
	else if (gpg_err_code (rc) == GPG_ERR_NOT_FOUND) { /* insert */
            if (!opt.quiet)
              log_info("inserting ownertrust of %u\n", otrust );
            memset (&rec, 0, sizeof rec);
            rec.recnum = tdbio_new_recnum (ctrl);
            rec.rectype = RECTYPE_TRUST;
            memcpy (rec.r.trust.fingerprint, fpr, 20);
            rec.r.trust.ownertrust = otrust;
            write_record (ctrl, &rec);
            any = 1;
	}
	else /* error */
	    log_error (_("error finding trust record in '%s': %s\n"),
                       fname, gpg_strerror (rc));
    }
    if (es_ferror (fp))
	log_error ( _("read error in '%s': %s\n"), fname, strerror(errno) );
    if (!is_stdin)
	es_fclose (fp);

    if (any)
      {
        revalidation_mark (ctrl);
        rc = tdbio_sync ();
        if (rc)
          log_error (_("trustdb: sync failed: %s\n"), gpg_strerror (rc) );
      }

}
