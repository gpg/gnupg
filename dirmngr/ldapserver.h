/* ldapserver.h
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
   along with this program; if not, see <https://www.gnu.org/licenses/>.  */

#ifndef LDAPSERVER_H
#define LDAPSERVER_H

#include "dirmngr.h"

/* Release the list of SERVERS.  As usual it is okay to call this
   function with SERVERS passed as NULL.  */
void ldapserver_list_free (ldap_server_t servers);


ldap_server_t ldapserver_parse_one (const char *line,
				    const char *filename, unsigned int lineno);


/* Iterate over all servers.  */

struct ldapserver_iter
{
  ctrl_t ctrl;
  enum { LDAPSERVER_SESSION, LDAPSERVER_GLOBAL } group;
  ldap_server_t server;
};


static inline void
ldapserver_iter_next (struct ldapserver_iter *iter)
{
  if (iter->server)
    iter->server = iter->server->next;

  if (! iter->server)
    {
      if (iter->group == LDAPSERVER_SESSION)
	{
	  iter->group = LDAPSERVER_GLOBAL;
	  iter->server = opt.ldapservers;
	}
    }
}


static inline int
ldapserver_iter_end_p (struct ldapserver_iter *iter)
{
  return (iter->group == LDAPSERVER_GLOBAL && iter->server == NULL);
}


static inline void
ldapserver_iter_begin (struct ldapserver_iter *iter, ctrl_t ctrl)
{
  iter->ctrl = ctrl;
  iter->group = LDAPSERVER_SESSION;
  iter->server = get_ldapservers_from_ctrl (ctrl);

  while (iter->server == NULL && ! ldapserver_iter_end_p (iter))
    ldapserver_iter_next (iter);
}

#endif	/* LDAPSERVER_H */
