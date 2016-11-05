/* w32-ldap-help.h - Map utf8 based API into a wchar_t API.
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

#ifndef W32_LDAP_HELP_H
#define W32_LDAP_HELP_H

#ifndef HAVE_W32CE_SYSTEM
# error This is only required for W32CE.
#endif


static inline LDAP *
_dirmngr_ldap_init (const char *host, unsigned short port)
{
  LDAP *ld;
  wchar_t *whost = NULL;

  if (host)
    {
      whost = utf8_to_wchar (host);
      if (!whost)
        return NULL;
    }
  ld = ldap_init (whost, port);
  xfree (whost);
  return ld;
}


static inline ULONG
_dirmngr_ldap_simple_bind_s (LDAP *ld, const char *user, const char *pass)
{
  ULONG ret;
  wchar_t *wuser, *wpass;

  wuser = user? utf8_to_wchar (user) : NULL;
  wpass = pass? utf8_to_wchar (pass) : NULL;
  /* We can't easily map errnos to ldap_errno, thus we pass a NULL to
     the function in the hope that the server will throw an error.  */
  ret = ldap_simple_bind_s (ld, wuser, wpass);
  xfree (wpass);
  xfree (wuser);
  return ret;
}


static inline ULONG
_dirmngr_ldap_search_st (LDAP *ld, const char *base, ULONG scope,
                         const char *filter, char **attrs,
                         ULONG attrsonly, struct timeval *timeout,
                         LDAPMessage **res)
{
  ULONG ret = LDAP_NO_MEMORY;
  wchar_t *wbase = NULL;
  wchar_t *wfilter = NULL;
  wchar_t **wattrs = NULL;
  int i;

  if (base)
    {
      wbase = utf8_to_wchar (base);
      if (!wbase)
        goto leave;
    }
  if (filter)
    {
      wfilter = utf8_to_wchar (filter);
      if (!wfilter)
        goto leave;
    }
  if (attrs)
    {
      for (i=0; attrs[i]; i++)
        ;
      wattrs = xtrycalloc (i+1, sizeof *wattrs);
      if (!wattrs)
        goto leave;
      for (i=0; attrs[i]; i++)
        {
          wattrs[i] = utf8_to_wchar (attrs[i]);
          if (!wattrs[i])
            goto leave;
        }
    }

  ret = ldap_search_st (ld, wbase, scope, wfilter, wattrs, attrsonly,
                        (struct l_timeval *)timeout, res);

 leave:
  if (wattrs)
    {
      for (i=0; wattrs[i]; i++)
        xfree (wattrs[i]);
      xfree (wattrs);
    }
  xfree (wfilter);
  xfree (wbase);
  return ret;
}


static inline char *
_dirmngr_ldap_first_attribute (LDAP *ld, LDAPMessage *msg, BerElement **elem)
{
  wchar_t *wattr;
  char *attr;

  wattr = ldap_first_attribute (ld, msg, elem);
  if (!wattr)
    return NULL;
  attr = wchar_to_utf8 (wattr);
  ldap_memfree (wattr);
  return attr;
}


static inline char *
_dirmngr_ldap_next_attribute (LDAP *ld, LDAPMessage *msg, BerElement *elem)
{
  wchar_t *wattr;
  char *attr;

  wattr = ldap_next_attribute (ld, msg, elem);
  if (!wattr)
    return NULL;
  attr = wchar_to_utf8 (wattr);
  ldap_memfree (wattr);
  return attr;
}

static inline BerValue **
_dirmngr_ldap_get_values_len (LDAP *ld, LDAPMessage *msg, const char *attr)
{
  BerValue **ret;
  wchar_t *wattr;

  if (attr)
    {
      wattr = utf8_to_wchar (attr);
      if (!wattr)
        return NULL;
    }
  else
    wattr = NULL;

  ret = ldap_get_values_len (ld, msg, wattr);
  xfree (wattr);

  return ret;
}


#endif /*W32_LDAP_HELP_H*/
