/* crlcache.h - LDAP access
 *      Copyright (C) 2002 Klarälvdalens Datakonsult AB
 *
 * This file is part of DirMngr.
 *
 * DirMngr is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * DirMngr is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifndef CRLCACHE_H
#define CRLCACHE_H


typedef enum
  {
    CRL_CACHE_VALID = 0,
    CRL_CACHE_INVALID,
    CRL_CACHE_DONTKNOW,
    CRL_CACHE_NOTTRUSTED,
    CRL_CACHE_CANTUSE
  }
crl_cache_result_t;

typedef enum foo
  {
    CRL_SIG_OK = 0,
    CRL_SIG_NOT_OK,
    CRL_TOO_OLD,
    CRL_SIG_ERROR,
    CRL_GENERAL_ERROR
  }
crl_sig_result_t;

struct crl_cache_entry_s;
typedef struct crl_cache_entry_s *crl_cache_entry_t;

/*-- crlcache.c --*/

void crl_cache_init (void);
void crl_cache_deinit (void);
int crl_cache_flush(void);

crl_cache_result_t crl_cache_isvalid (ctrl_t ctrl,
                                      const char *issuer_hash,
                                      const char *cert_id,
                                      int force_refresh);

gpg_error_t crl_cache_cert_isvalid (ctrl_t ctrl, ksba_cert_t cert,
                                    int force_refresh);

gpg_error_t crl_cache_insert (ctrl_t ctrl, const char *url,
                              ksba_reader_t reader);

gpg_error_t crl_cache_list (estream_t fp);

gpg_error_t crl_cache_load (ctrl_t ctrl, const char *filename);

gpg_error_t crl_cache_reload_crl (ctrl_t ctrl, ksba_cert_t cert);


/*-- fakecrl.c --*/
gpg_error_t fakecrl_isvalid (ctrl_t ctrl,
                             const char *issuer_hash,
                             const char *cert_id);



#endif /* CRLCACHE_H */
