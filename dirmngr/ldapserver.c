/* dirmngr.c - LDAP access
   Copyright (C) 2008 g10 Code GmbH

   This file is part of DirMngr.

   DirMngr is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   DirMngr is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
   02110-1301, USA.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "dirmngr.h"
#include "ldapserver.h"


/* Release the list of SERVERS.  As usual it is okay to call this
   function with SERVERS passed as NULL.  */
void
ldapserver_list_free (ldap_server_t servers)
{
  while (servers)
    {
      ldap_server_t tmp = servers->next;
      xfree (servers->host);
      xfree (servers->user);
      if (servers->pass)
        memset (servers->pass, 0, strlen (servers->pass));
      xfree (servers->pass);
      xfree (servers->base);
      xfree (servers);
      servers = tmp;
    }
}


/* Parse a single LDAP server configuration line.  Returns the server
   or NULL in case of errors.  The configuration line is assumed to be
   colon seprated with these fields:

   1. field: Hostname
   2. field: Portnumber
   3. field: Username
   4. field: Password
   5. field: Base DN

   FILENAME and LINENO are used for diagnostic purposes only.
*/
ldap_server_t
ldapserver_parse_one (char *line,
		      const char *filename, unsigned int lineno)
{
  char *p;
  char *endp;
  ldap_server_t server;
  int fieldno;
  int fail = 0;

  /* Parse the colon separated fields.  */
  server = xcalloc (1, sizeof *server);
  for (fieldno = 1, p = line; p; p = endp, fieldno++ )
    {
      endp = strchr (p, ':');
      if (endp)
	*endp++ = '\0';
      trim_spaces (p);
      switch (fieldno)
	{
	case 1:
	  if (*p)
	    server->host = xstrdup (p);
	  else
	    {
	      log_error (_("%s:%u: no hostname given\n"),
			 filename, lineno);
	      fail = 1;
	    }
	  break;

	case 2:
	  if (*p)
	    server->port = atoi (p);
	  break;

	case 3:
	  if (*p)
	    server->user = xstrdup (p);
	  break;

	case 4:
	  if (*p && !server->user)
	    {
	      log_error (_("%s:%u: password given without user\n"),
			 filename, lineno);
	      fail = 1;
	    }
	  else if (*p)
	    server->pass = xstrdup (p);
	  break;

	case 5:
	  if (*p)
	    server->base = xstrdup (p);
	  break;

	default:
	  /* (We silently ignore extra fields.) */
	  break;
	}
    }

  if (fail)
    {
      log_info (_("%s:%u: skipping this line\n"), filename, lineno);
      ldapserver_list_free (server);
      server = NULL;
    }

  return server;
}
