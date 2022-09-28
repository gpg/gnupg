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
 * or NULL in case of errors.  The configuration line is assumed to be
 * colon separated with these fields:
 *
 * 1. field: Hostname
 * 2. field: Portnumber
 * 3. field: Username
 * 4. field: Password
 * 5. field: Base DN
 * 6. field: Flags
 *
 * Flags are:
 *
 *   starttls  := Use STARTTLS with a default port of 389
 *   ldaptls   := Tunnel LDAP trough a TLS tunnel with default port 636
 *   plain     := Switch to plain unsecured LDAP.
 *   (The last of these 3 flags is the effective one)
 *   ntds      := Use Active Directory authentication
 *   areconly  := Use option LDAP_OPT_AREC_EXCLUSIVE
 *
 * FILENAME and LINENO are used for diagnostic purposes only.
 */
ldap_server_t
ldapserver_parse_one (const char *line,
		      const char *filename, unsigned int lineno)
{
  char *p;
  const char *s;
  ldap_server_t server;
  int fieldno;
  int fail = 0;
  int i;
  char **fields = NULL;

  server = xtrycalloc (1, sizeof *server);
  if (!server)
    {
      fail = 1;
      goto leave;
    }

  fields = strtokenize (line, ":");
  if (!fields)
    {
      fail = 1;
      goto leave;
    }

  for (fieldno=0; (p = fields[fieldno]); fieldno++)
    {
      switch (fieldno)
	{
	case 0:
          server->host = xtrystrdup (p);
          if (!server->host)
            fail = 1;
	  break;

	case 1:
	  if (*p)
	    server->port = atoi (p);
	  break;

	case 2:
          server->user = xtrystrdup (p);
          if (!server->user)
            fail = 1;
	  break;

	case 3:
	  if (*p && !server->user)
	    {
              if (filename)
                log_error (_("%s:%u: password given without user\n"),
                           filename, lineno);
              else
                log_error ("ldap: password given without user ('%s')\n", line);
	      fail = 1;
	    }
	  else if (*p)
            {
              server->pass = xtrystrdup (p);
              if (!server->pass)
                fail = 1;
            }
	  break;

	case 4:
	  if (*p)
            {
              server->base = xtrystrdup (p);
              if (!server->base)
                fail = 1;;
            }
	  break;

        case 5:
          {
            char **flags = NULL;

            flags = strtokenize (p, ",");
            if (!flags)
              {
                log_error ("strtokenize failed: %s\n",
                           gpg_strerror (gpg_error_from_syserror ()));
                fail = 1;
                break;
              }

            for (i=0; (s = flags[i]); i++)
              {
                if (!*s)
                  ;
                else if (!ascii_strcasecmp (s, "starttls"))
                  {
                    server->starttls = 1;
                    server->ldap_over_tls = 0;
                  }
                else if (!ascii_strcasecmp (s, "ldaptls"))
                  {
                    server->starttls = 0;
                    server->ldap_over_tls = 1;
                  }
                else if (!ascii_strcasecmp (s, "plain"))
                  {
                    server->starttls = 0;
                    server->ldap_over_tls = 0;
                  }
                else if (!ascii_strcasecmp (s, "ntds"))
                  {
                    server->ntds = 1;
                  }
                else if (!ascii_strcasecmp (s, "areconly"))
                  {
                    server->areconly = 1;
                  }
                else
                  {
                    if (filename)
                      log_info (_("%s:%u: ignoring unknown flag '%s'\n"),
                                filename, lineno, s);
                    else
                      log_info ("ldap: unknown flag '%s' ignored in (%s)\n",
                                s, line);
                  }
              }

            xfree (flags);
          }
          break;

	default:
	  /* (We silently ignore extra fields.) */
	  break;
	}
    }

 leave:
  if (fail)
    {
      if (filename)
        log_info (_("%s:%u: skipping this line\n"), filename, lineno);
      else
        log_info ("ldap: error in server spec ('%s')\n", line);
      ldapserver_list_free (server);
      server = NULL;
    }
  xfree (fields);

  return server;
}
