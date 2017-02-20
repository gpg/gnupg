/* simple-pwquery.c - A simple password query client for gpg-agent
 *	Copyright (C) 2002, 2004, 2007 Free Software Foundation, Inc.
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

/* This module is intended as a simple client implementation to
   gpg-agent's GET_PASSPHRASE command.  It can only cope with an
   already running gpg-agent.  Some stuff is configurable in the
   header file. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <assuan.h>
#ifdef HAVE_W32_SYSTEM
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <sys/un.h>
#endif
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif

#define GNUPG_COMMON_NEED_AFLOCAL
#include "../common/mischelp.h"
#include "sysutils.h"
#include "membuf.h"


#define SIMPLE_PWQUERY_IMPLEMENTATION 1
#include "simple-pwquery.h"

#define SPWQ_OUT_OF_CORE	gpg_error_from_errno (ENOMEM)
#define SPWQ_IO_ERROR		gpg_error_from_errno (EIO)
#define SPWQ_PROTOCOL_ERROR	gpg_error (GPG_ERR_PROTOCOL_VIOLATION)
#define SPWQ_ERR_RESPONSE	gpg_error (GPG_ERR_INV_RESPONSE)
#define SPWQ_NO_AGENT		gpg_error (GPG_ERR_NO_AGENT)
#define SPWQ_SYS_ERROR		gpg_error_from_syserror ()
#define SPWQ_GENERAL_ERROR	gpg_error (GPG_ERR_GENERAL)
#define SPWQ_NO_PIN_ENTRY	gpg_error (GPG_ERR_NO_PIN_ENTRY)

#ifndef _
#define _(a) (a)
#endif

#if !defined (hexdigitp) && !defined (xtoi_2)
#define digitp(p)   (*(p) >= '0' && *(p) <= '9')
#define hexdigitp(a) (digitp (a)                     \
                      || (*(a) >= 'A' && *(a) <= 'F')  \
                      || (*(a) >= 'a' && *(a) <= 'f'))
#define xtoi_1(p)   (*(p) <= '9'? (*(p)- '0'): \
                     *(p) <= 'F'? (*(p)-'A'+10):(*(p)-'a'+10))
#define xtoi_2(p)   ((xtoi_1(p) * 16) + xtoi_1((p)+1))
#endif


/* Name of the socket to be used.  This is a kludge to keep on using
   the existsing code despite that we only support a standard socket.  */
static char *default_gpg_agent_info;





#ifndef HAVE_STPCPY
static char *
my_stpcpy(char *a,const char *b)
{
    while( *b )
	*a++ = *b++;
    *a = 0;

    return (char*)a;
}
#define stpcpy(a,b)  my_stpcpy((a), (b))
#endif


/* Send an option to the agent */
static int
agent_send_option (assuan_context_t ctx, const char *name, const char *value)
{
  int err;
  char *line;

  line = spwq_malloc (7 + strlen (name) + 1 + strlen (value) + 2);
  if (!line)
    return SPWQ_OUT_OF_CORE;
  strcpy (stpcpy (stpcpy (stpcpy (
                     stpcpy (line, "OPTION "), name), "="), value), "\n");

  err = assuan_transact (ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);

  spwq_free (line);
  return err;
}


/* Send all available options to the agent. */
static int
agent_send_all_options (assuan_context_t ctx)
{
  char *dft_display = NULL;
  char *dft_ttyname = NULL;
  char *dft_ttytype = NULL;
  char *dft_xauthority = NULL;
  char *dft_pinentry_user_data = NULL;
  int rc = 0;

  dft_display = getenv ("DISPLAY");
  if (dft_display)
    {
      if ((rc = agent_send_option (ctx, "display", dft_display)))
        return rc;
    }

  dft_ttyname = getenv ("GPG_TTY");
#if !defined(HAVE_W32_SYSTEM) && !defined(HAVE_BROKEN_TTYNAME)
  if ((!dft_ttyname || !*dft_ttyname) && ttyname (0))
    dft_ttyname = ttyname (0);
#endif
  if (dft_ttyname && *dft_ttyname)
    {
      if ((rc=agent_send_option (ctx, "ttyname", dft_ttyname)))
        return rc;
    }

  dft_ttytype = getenv ("TERM");
  if (dft_ttyname && dft_ttytype)
    {
      if ((rc = agent_send_option (ctx, "ttytype", dft_ttytype)))
        return rc;
    }

#if defined(HAVE_SETLOCALE)
  {
    char *old_lc = NULL;
    char *dft_lc = NULL;

#if defined(LC_CTYPE)
    old_lc = setlocale (LC_CTYPE, NULL);
    if (old_lc)
      {
        char *p = spwq_malloc (strlen (old_lc)+1);
        if (!p)
          return SPWQ_OUT_OF_CORE;
        strcpy (p, old_lc);
        old_lc = p;
      }
    dft_lc = setlocale (LC_CTYPE, "");
    if (dft_ttyname && dft_lc)
      rc = agent_send_option (ctx, "lc-ctype", dft_lc);
    if (old_lc)
      {
        setlocale (LC_CTYPE, old_lc);
        spwq_free (old_lc);
      }
    if (rc)
      return rc;
#endif

#if defined(LC_MESSAGES)
    old_lc = setlocale (LC_MESSAGES, NULL);
    if (old_lc)
      {
        char *p = spwq_malloc (strlen (old_lc)+1);
        if (!p)
          return SPWQ_OUT_OF_CORE;
        strcpy (p, old_lc);
        old_lc = p;
      }
    dft_lc = setlocale (LC_MESSAGES, "");
    if (dft_ttyname && dft_lc)
      rc = agent_send_option (ctx, "lc-messages", dft_lc);
    if (old_lc)
      {
        setlocale (LC_MESSAGES, old_lc);
        spwq_free (old_lc);
      }
    if (rc)
      return rc;
#endif
  }
#endif /*HAVE_SETLOCALE*/

  /* Send the XAUTHORITY variable.  */
  dft_xauthority = getenv ("XAUTHORITY");
  if (dft_xauthority)
    {
      /* We ignore errors here because older gpg-agents don't support
         this option.  */
      agent_send_option (ctx, "xauthority", dft_xauthority);
    }

  /* Send the PINENTRY_USER_DATA variable.  */
  dft_pinentry_user_data = getenv ("PINENTRY_USER_DATA");
  if (dft_pinentry_user_data)
    {
      /* We ignore errors here because older gpg-agents don't support
         this option.  */
      agent_send_option (ctx, "pinentry-user-data", dft_pinentry_user_data);
    }

  /* Tell the agent that we support Pinentry notifications.  No
     error checking so that it will work with older agents.  */
  assuan_transact (ctx, "OPTION allow-pinentry-notify",
                   NULL, NULL, NULL, NULL, NULL, NULL);

  return 0;
}



/* Try to open a connection to the agent, send all options and return
   the file descriptor for the connection.  Return -1 in case of
   error. */
static int
agent_open (assuan_context_t *ctx)
{
  int rc;
  char *infostr;

  infostr = default_gpg_agent_info;
  if ( !infostr || !*infostr )
    {
#ifdef SPWQ_USE_LOGGING
      log_error (_("no gpg-agent running in this session\n"));
#endif
      return SPWQ_NO_AGENT;
    }

  rc = assuan_new (ctx);
  if (rc)
    return rc;

  rc = assuan_socket_connect (*ctx, infostr, 0, 0);
  if (rc)
    {
#ifdef SPWQ_USE_LOGGING
      log_error (_("can't connect to '%s': %s\n"),
                 infostr, gpg_strerror (rc));
#endif
      goto errout;
    }

  rc = agent_send_all_options (*ctx);
  if (rc)
    {
#ifdef SPWQ_USE_LOGGING
      log_error (_("problem setting the gpg-agent options\n"));
#endif
      goto errout;
    }

  return 0;

 errout:
  assuan_release (*ctx);
  *ctx = NULL;
  return rc;
}


/* Copy text to BUFFER and escape as required.  Return a pointer to
   the end of the new buffer.  Note that BUFFER must be large enough
   to keep the entire text; allocataing it 3 times the size of TEXT
   is sufficient. */
static char *
copy_and_escape (char *buffer, const char *text)
{
  int i;
  const unsigned char *s = (unsigned char *)text;
  char *p = buffer;


  for (i=0; s[i]; i++)
    {
      if (s[i] < ' ' || s[i] == '+')
        {
          sprintf (p, "%%%02X", s[i]);
          p += 3;
        }
      else if (s[i] == ' ')
        *p++ = '+';
      else
        *p++ = s[i];
    }
  return p;
}


/* Set the name of the default socket to NAME.  */
int
simple_pw_set_socket (const char *name)
{
  spwq_free (default_gpg_agent_info);
  default_gpg_agent_info = NULL;
  if (name)
    {
      default_gpg_agent_info = spwq_malloc (strlen (name) + 1);
      if (!default_gpg_agent_info)
        return SPWQ_OUT_OF_CORE;
      strcpy (default_gpg_agent_info, name);
    }

  return 0;
}


/* This is the default inquiry callback.  It merely handles the
   Pinentry notification.  */
static gpg_error_t
default_inq_cb (void *opaque, const char *line)
{
  (void)opaque;

  if (!strncmp (line, "PINENTRY_LAUNCHED", 17) && (line[17]==' '||!line[17]))
    {
      gnupg_allow_set_foregound_window ((pid_t)strtoul (line+17, NULL, 10));
      /* We do not return errors to avoid breaking other code.  */
    }
  else
    {
#ifdef SPWQ_USE_LOGGING
      log_debug ("ignoring gpg-agent inquiry '%s'\n", line);
#endif
    }

  return 0;
}


/* Ask the gpg-agent for a passphrase and present the user with a
   DESCRIPTION, a PROMPT and optionally with a TRYAGAIN extra text.
   If a CACHEID is not NULL it is used to locate the passphrase in
   the cache and store it under this ID.  If OPT_CHECK is true
   gpg-agent is asked to apply some checks on the passphrase security.
   If ERRORCODE is not NULL it should point a variable receiving an
   errorcode; this error code might be 0 if the user canceled the
   operation.  The function returns NULL to indicate an error.  */
char *
simple_pwquery (const char *cacheid,
                const char *tryagain,
                const char *prompt,
                const char *description,
                int opt_check,
                int *errorcode)
{
  int rc;
  assuan_context_t ctx;
  membuf_t data;
  char *result = NULL;
  char *pw = NULL;
  char *p;
  size_t n;


  rc = agent_open (&ctx);
  if (rc)
    goto leave;

  if (!cacheid)
    cacheid = "X";
  if (!tryagain)
    tryagain = "X";
  if (!prompt)
    prompt = "X";
  if (!description)
    description = "X";

  {
    char *line;
    /* We allocate 3 times the needed space so that there is enough
       space for escaping. */
    line = spwq_malloc (15 + 10
                        + 3*strlen (cacheid) + 1
                        + 3*strlen (tryagain) + 1
                        + 3*strlen (prompt) + 1
                        + 3*strlen (description) + 1
                        + 2);
    if (!line)
      {
        rc = SPWQ_OUT_OF_CORE;
        goto leave;
      }
    strcpy (line, "GET_PASSPHRASE ");
    p = line+15;
    if (opt_check)
      p = stpcpy (p, "--check ");
    p = copy_and_escape (p, cacheid);
    *p++ = ' ';
    p = copy_and_escape (p, tryagain);
    *p++ = ' ';
    p = copy_and_escape (p, prompt);
    *p++ = ' ';
    p = copy_and_escape (p, description);
    *p++ = '\n';

    init_membuf_secure (&data, 64);

    rc = assuan_transact (ctx, line, put_membuf_cb, &data,
                          default_inq_cb, NULL, NULL, NULL);
    spwq_free (line);

    /* Older Pinentries return the old assuan error code for canceled
       which gets translated by libassuan to GPG_ERR_ASS_CANCELED and
       not to the code for a user cancel.  Fix this here. */
    if (rc && gpg_err_source (rc)
        && gpg_err_code (rc) == GPG_ERR_ASS_CANCELED)
      rc = gpg_err_make (gpg_err_source (rc), GPG_ERR_CANCELED);

    if (rc)
      {
        p = get_membuf (&data, &n);
        if (p)
          wipememory (p, n);
        spwq_free (p);
      }
    else
      {
        put_membuf (&data, "", 1);
        result = get_membuf (&data, NULL);
        if (pw == NULL)
          rc = gpg_error_from_syserror ();
      }
  }

 leave:
  if (errorcode)
    *errorcode = rc;
  assuan_release (ctx);
  return result;
}


/* Ask the gpg-agent to clear the passphrase for the cache ID CACHEID.  */
int
simple_pwclear (const char *cacheid)
{
  char line[500];
  char *p;

  /* We need not more than 50 characters for the command and the
     terminating nul.  */
  if (strlen (cacheid) * 3 > sizeof (line) - 50)
    return SPWQ_PROTOCOL_ERROR;

  strcpy (line, "CLEAR_PASSPHRASE ");
  p = line + 17;
  p = copy_and_escape (p, cacheid);
  *p++ = '\n';
  *p++ = '\0';

  return simple_query (line);
}


/* Perform the simple query QUERY (which must be new-line and 0
   terminated) and return the error code.  */
int
simple_query (const char *query)
{
  assuan_context_t ctx;
  int rc;

  rc = agent_open (&ctx);
  if (rc)
    return rc;

  rc = assuan_transact (ctx, query, NULL, NULL, NULL, NULL, NULL, NULL);

  assuan_release (ctx);
  return rc;
}
