/* Copyright 2007 g10 Code GmbH

 This file is free software; as a special exception the author gives
 unlimited permission to copy and/or distribute it, with or without
 modifications, as long as this notice is preserved.

 This file is distributed in the hope that it will be useful, but
 WITHOUT ANY WARRANTY, to the extent permitted by law; without even
 the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 PURPOSE.  */

#ifndef LDAP_URL_H
#define LDAP_URL_H 1

#define LDAP_CONST const

typedef struct ldap_url_desc
{
  struct ldap_url_desc *lud_next;
  char *lud_scheme;
  char *lud_host;
  int lud_port;
  char *lud_dn;
  char **lud_attrs;
  int lud_scope;
  char *lud_filter;
  char **lud_exts;
  int lud_crit_exts;
} LDAPURLDesc;

#define LDAP_URL_SUCCESS	0x00
#define LDAP_URL_ERR_MEM	0x01
#define LDAP_URL_ERR_PARAM	0x02

#define LDAP_URL_ERR_BADSCHEME	0x03
#define LDAP_URL_ERR_BADENCLOSURE 0x04
#define LDAP_URL_ERR_BADURL	0x05
#define LDAP_URL_ERR_BADHOST	0x06
#define LDAP_URL_ERR_BADATTRS	0x07
#define LDAP_URL_ERR_BADSCOPE	0x08
#define LDAP_URL_ERR_BADFILTER	0x09
#define LDAP_URL_ERR_BADEXTS	0x0a

#define LDAPS_PORT 636

int ldap_is_ldap_url (LDAP_CONST char *url);
int ldap_url_parse (LDAP_CONST char *url_in, LDAPURLDesc **ludpp);
void ldap_free_urldesc (LDAPURLDesc *ludp);

#endif /* !LDAP_URL_H */
