#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <unistd.h>

#include "agent.h"
#include <assuan.h>
#include "../common/strlist.h"
#include "../common/sexp-parse.h"
#include "../common/i18n.h"

static int
start_tpm2d (ctrl_t ctrl)
{
  return daemon_start (DAEMON_TPM2D, ctrl);
}

static int
unlock_tpm2d (ctrl_t ctrl, gpg_error_t err)
{
  return daemon_unlock (DAEMON_TPM2D, ctrl, err);
}

static assuan_context_t
daemon_ctx (ctrl_t ctrl)
{
  return daemon_type_ctx (DAEMON_TPM2D, ctrl);
}

struct inq_parm_s {
  assuan_context_t ctx;
  gpg_error_t (*getpin_cb)(ctrl_t, const char *, char **);
  ctrl_t ctrl;
  /* The next fields are used by inq_keydata.  */
  const unsigned char *keydata;
  size_t keydatalen;
  /* following only used by inq_extra */
  const unsigned char *extra;
  size_t extralen;
  char *pin;
};

static gpg_error_t
inq_needpin (void *opaque, const char *line)
{
  struct inq_parm_s *parm = opaque;
  char *pin = NULL;
  gpg_error_t rc;
  const char *s;

  if ((s = has_leading_keyword (line, "NEEDPIN")))
    {
      rc = parm->getpin_cb (parm->ctrl, s, &pin);
      if (!rc)
        rc = assuan_send_data (parm->ctx, pin, strlen(pin));
      parm->pin = pin;
    }
  else
    {
      log_error ("unsupported inquiry '%s'\n", line);
      rc = gpg_error (GPG_ERR_ASS_UNKNOWN_INQUIRE);
    }

  return rc;
}

static gpg_error_t
inq_keydata (void *opaque, const char *line)
{
  struct inq_parm_s *parm = opaque;

  if (has_leading_keyword (line, "KEYDATA"))
    return assuan_send_data (parm->ctx, parm->keydata, parm->keydatalen);
  else
    return inq_needpin (opaque, line);
}

static gpg_error_t
inq_extra (void *opaque, const char *line)
{
  struct inq_parm_s *parm = opaque;

  if (has_leading_keyword (line, "EXTRA"))
    return assuan_send_data (parm->ctx, parm->extra, parm->extralen);
  else
    return inq_keydata (opaque, line);
}

int
agent_tpm2d_writekey (ctrl_t ctrl, unsigned char **shadow_info,
		      gcry_sexp_t s_skey)
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  size_t n;
  unsigned char *kbuf;
  membuf_t data;
  struct inq_parm_s inqparm;
  size_t len;

  rc = start_tpm2d (ctrl);
  if (rc)
    return rc;

  /* note: returned data is TPM protected so no need for a sensitive context */
  init_membuf(&data, 4096);

  inqparm.ctx = daemon_ctx (ctrl);
  inqparm.getpin_cb = agent_ask_new_passphrase;
  inqparm.ctrl = ctrl;
  inqparm.pin = NULL;

  n = gcry_sexp_sprint (s_skey, GCRYSEXP_FMT_CANON, NULL, 0);
  kbuf = xtrymalloc (n);
  gcry_sexp_sprint (s_skey, GCRYSEXP_FMT_CANON, kbuf, n);
  inqparm.keydata = kbuf;
  inqparm.keydatalen = n;
  snprintf(line, sizeof(line), "IMPORT");

  rc = assuan_transact (daemon_ctx (ctrl), line,
			put_membuf_cb, &data,
			inq_keydata, &inqparm,
			NULL, NULL);
  xfree (kbuf);
  xfree (inqparm.pin);
  if (rc)
    {
      xfree (get_membuf (&data, &len));
      return unlock_tpm2d (ctrl, rc);
    }

  *shadow_info = get_membuf (&data, &len);

  return unlock_tpm2d (ctrl, 0);
}

static gpg_error_t
pin_cb (ctrl_t ctrl, const char *prompt, char **passphrase)
{
  char hexgrip[2*KEYGRIP_LEN + 1];

  bin2hex (ctrl->keygrip, KEYGRIP_LEN, hexgrip);
  *passphrase = agent_get_cache (ctrl, hexgrip, CACHE_MODE_USER);
  if (*passphrase)
    return 0;
  return agent_get_passphrase(ctrl, passphrase,
			      _("Please enter your passphrase, so that the "
				"secret key can be unlocked for this session"),
			      prompt, NULL, 0,
			      hexgrip, CACHE_MODE_USER, NULL);
}

int
agent_tpm2d_pksign (ctrl_t ctrl, const unsigned char *digest,
		    size_t digestlen, const unsigned char *shadow_info,
		    unsigned char **r_sig, size_t *r_siglen)
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  membuf_t data;
  struct inq_parm_s inqparm;
  char hexgrip[2*KEYGRIP_LEN + 1];

  rc = start_tpm2d (ctrl);
  if (rc)
    return rc;

  init_membuf (&data, 1024);

  inqparm.ctx = daemon_ctx (ctrl);
  inqparm.getpin_cb = pin_cb;
  inqparm.ctrl = ctrl;
  inqparm.keydata = shadow_info;
  inqparm.keydatalen = gcry_sexp_canon_len (shadow_info, 0, NULL, NULL);
  inqparm.extra = digest;
  inqparm.extralen = digestlen;
  inqparm.pin = NULL;

  snprintf(line, sizeof(line), "PKSIGN");

  rc = assuan_transact (daemon_ctx (ctrl), line,
			put_membuf_cb, &data,
			inq_extra, &inqparm,
			NULL, NULL);
  if (!rc)
    {
      bin2hex (ctrl->keygrip, KEYGRIP_LEN, hexgrip);
      agent_put_cache (ctrl, hexgrip, CACHE_MODE_USER, inqparm.pin, 0);
    }

  xfree (inqparm.pin);

  if (rc)
    {
      size_t len;
      xfree (get_membuf (&data, &len));
      return unlock_tpm2d (ctrl, rc);
    }

  *r_sig = get_membuf (&data, r_siglen);

  return unlock_tpm2d (ctrl, 0);
}

int
agent_tpm2d_pkdecrypt (ctrl_t ctrl, const unsigned char *cipher,
		       size_t cipherlen, const unsigned char *shadow_info,
		       char **r_buf, size_t *r_len)
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  membuf_t data;
  struct inq_parm_s inqparm;
  char hexgrip[2*KEYGRIP_LEN + 1];

  rc = start_tpm2d (ctrl);
  if (rc)
    return rc;

  init_membuf (&data, 1024);

  inqparm.ctx = daemon_ctx (ctrl);
  inqparm.getpin_cb = pin_cb;
  inqparm.ctrl = ctrl;
  inqparm.keydata = shadow_info;
  inqparm.keydatalen = gcry_sexp_canon_len (shadow_info, 0, NULL, NULL);
  inqparm.extra = cipher;
  inqparm.extralen = cipherlen;
  inqparm.pin = NULL;

  snprintf(line, sizeof(line), "PKDECRYPT");

  rc = assuan_transact (daemon_ctx (ctrl), line,
			put_membuf_cb, &data,
			inq_extra, &inqparm,
			NULL, NULL);
  if (!rc)
    {
      bin2hex (ctrl->keygrip, KEYGRIP_LEN, hexgrip);
      agent_put_cache (ctrl, hexgrip, CACHE_MODE_USER, inqparm.pin, 0);
    }

  xfree (inqparm.pin);

  if (rc)
    {
      size_t len;
      xfree (get_membuf (&data, &len));
      return unlock_tpm2d (ctrl, rc);
    }

  *r_buf = get_membuf (&data, r_len);

  return unlock_tpm2d (ctrl, 0);
}
