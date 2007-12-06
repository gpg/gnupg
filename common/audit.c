/* audit.c - GnuPG's audit subsystem
 *	Copyright (C) 2007 Free Software Foundation, Inc.
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
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>

#include "util.h"
#include "i18n.h"
#include "audit.h"
#include "audit-events.h"

/* One log entry.  */
struct log_item_s
{
  audit_event_t event; /* The event.  */
  gpg_error_t err;     /* The logged error code.  */
  int intvalue;        /* A logged interger value.  */
  char *string;        /* A malloced string or NULL.  */
  ksba_cert_t cert;    /* A certifciate or NULL. */
  int have_err:1;
  int have_intvalue:1;
};
typedef struct log_item_s *log_item_t;



/* The main audit object.  */
struct audit_ctx_s
{
  const char *failure;  /* If set a description of the internal failure.  */
  audit_type_t type;
  
  log_item_t log;       /* The table with the log entries.  */
  size_t logsize;       /* The allocated size for LOG.  */
  size_t logused;       /* The used size of LOG.  */

  estream_t outstream;  /* The current output stream.  */
  int use_html;         /* The output shall be HTML formatted.  */
  int indentlevel;      /* Current level of indentation.  */
};




static void writeout_li (audit_ctx_t ctx, const char *oktext,
                         const char *format, ...) JNLIB_GCC_A_PRINTF(3,4);
static void writeout_rem (audit_ctx_t ctx, 
                          const char *format, ...) JNLIB_GCC_A_PRINTF(2,3);



static const char *
event2str (audit_event_t event)
{
  int idx = eventstr_msgidxof (event);
  if (idx == -1)
    return "Unknown event";
  else
    return eventstr_msgstr + eventstr_msgidx[idx];
}



/* Create a new audit context.  In case of an error NULL is returned
   and errno set appropriately. */ 
audit_ctx_t
audit_new (void)
{
  audit_ctx_t ctx;

  ctx = xtrycalloc (1, sizeof *ctx);

  return ctx;
}


/* Release an audit context.  Passing NULL for CTX is allowed and does
   nothing.  */
void
audit_release (audit_ctx_t ctx)
{
  int idx;
  if (!ctx)
    return;
  if (ctx->log)
    {
      for (idx=0; idx < ctx->logused; idx++)
        {
          if (ctx->log[idx].string)
            xfree (ctx->log[idx].string);
          if (ctx->log[idx].cert)
            ksba_cert_release (ctx->log[idx].cert);
        }
      xfree (ctx->log);
    }
  xfree (ctx);
}


/* Set the type for the audit operation.  If CTX is NULL, this is a
   dummy fucntion.  */
void
audit_set_type (audit_ctx_t ctx, audit_type_t type)
{
  if (!ctx || ctx->failure)
    return;  /* Audit not enabled or an internal error has occurred. */

  if (ctx->type && ctx->type != type)
    {
      ctx->failure = "conflict in type initialization";
      return;
    }
  ctx->type = type;
}


/* Create a new log item and put it into the table.  Return that log
   item on success; return NULL on memory failure and mark that in
   CTX. */
static log_item_t
create_log_item (audit_ctx_t ctx)
{
  log_item_t item, table;
  size_t size;

  if (!ctx->log)
    {
      size = 10;
      table = xtrymalloc (size * sizeof *table);
      if (!table)
        {
          ctx->failure = "Out of memory in create_log_item";
          return NULL;
        }
      ctx->log = table;
      ctx->logsize = size;
      item = ctx->log + 0;
      ctx->logused = 1;
    }
  else if (ctx->logused >= ctx->logsize)
    {
      size = ctx->logsize + 10;
      table = xtryrealloc (ctx->log, size * sizeof *table);
      if (!table)
        {
          ctx->failure = "Out of memory while reallocating in create_log_item";
          return NULL;
        }
      ctx->log = table;
      ctx->logsize = size;
      item = ctx->log + ctx->logused++;
    }
  else
    item = ctx->log + ctx->logused++;

  item->event = AUDIT_NULL_EVENT;
  item->err = 0;
  item->have_err = 0;
  item->intvalue = 0;
  item->have_intvalue = 0;
  item->string = NULL;
  item->cert = NULL;

  return item;
 
}

/* Add a new event to the audit log.  If CTX is NULL, this function
   does nothing.  */
void
audit_log (audit_ctx_t ctx, audit_event_t event)
{
  log_item_t item;

  if (!ctx || ctx->failure)
    return;  /* Audit not enabled or an internal error has occurred. */
  if (!event)
    {
      ctx->failure = "Invalid event passed to audit_log";
      return;
    }
  if (!(item = create_log_item (ctx)))
    return;
  item->event = event;
}

/* Add a new event to the audit log.  If CTX is NULL, this function
   does nothing.  This version also adds the result of the oepration
   to the log.. */
void
audit_log_ok (audit_ctx_t ctx, audit_event_t event, gpg_error_t err)
{
  log_item_t item;

  if (!ctx || ctx->failure)
    return;  /* Audit not enabled or an internal error has occurred. */
  if (!event)
    {
      ctx->failure = "Invalid event passed to audit_log_ok";
      return;
    }
  if (!(item = create_log_item (ctx)))
    return;
  item->event = event;
  item->err = err;
  item->have_err = 1;
}


/* Add a new event to the audit log.  If CTX is NULL, this function
   does nothing.  This version also add the integer VALUE to the log.  */
void
audit_log_i (audit_ctx_t ctx, audit_event_t event, int value)
{
  log_item_t item;

  if (!ctx || ctx->failure)
    return;  /* Audit not enabled or an internal error has occurred. */
  if (!event)
    {
      ctx->failure = "Invalid event passed to audit_log_i";
      return;
    }
  if (!(item = create_log_item (ctx)))
    return;
  item->event = event;
  item->intvalue = value;
  item->have_intvalue = 1;
}


/* Add a new event to the audit log.  If CTX is NULL, this function
   does nothing.  This version also add the integer VALUE to the log.  */
void
audit_log_s (audit_ctx_t ctx, audit_event_t event, const char *value)
{
  log_item_t item;
  char *tmp;

  if (!ctx || ctx->failure)
    return;  /* Audit not enabled or an internal error has occurred. */
  if (!event)
    {
      ctx->failure = "Invalid event passed to audit_log_s";
      return;
    }
  tmp = xtrystrdup (value? value : "");
  if (!tmp)
    {
      ctx->failure = "Out of memory in audit_event";
      return;
    }
  if (!(item = create_log_item (ctx)))
    {
      xfree (tmp);
      return;
    }
  item->event = event;
  item->string = tmp;
}

/* Add a new event to the audit log.  If CTX is NULL, this function
   does nothing.  This version also adds the certificate CERT and the
   result of an operation to the log.  */
void
audit_log_cert (audit_ctx_t ctx, audit_event_t event, 
                ksba_cert_t cert, gpg_error_t err)
{
  log_item_t item;

  if (!ctx || ctx->failure)
    return;  /* Audit not enabled or an internal error has occurred. */
  if (!event)
    {
      ctx->failure = "Invalid event passed to audit_log_cert";
      return;
    }
  if (!(item = create_log_item (ctx)))
    return;
  item->event = event;
  item->err = err;
  item->have_err = 1;
  if (cert)
    {
      ksba_cert_ref (cert); 
      item->cert = cert;
    }
}


/* Write TEXT to the outstream.  */
static void 
writeout (audit_ctx_t ctx, const char *text)
{
  if (ctx->use_html)
    {
      for (; *text; text++)
        {
          if (*text == '<')
            es_fputs ("&lt;", ctx->outstream);
          else if (*text == '&')
            es_fputs ("&amp;", ctx->outstream);
          else
            es_putc (*text, ctx->outstream);
        }
    }
  else
    es_fputs (text, ctx->outstream);
}


/* Write TEXT to the outstream using a variable argument list.  */
static void 
writeout_v (audit_ctx_t ctx, const char *format, va_list arg_ptr)
{
  char *buf;

  estream_vasprintf (&buf, format, arg_ptr);
  if (buf)
    {
      writeout (ctx, buf);
      xfree (buf);
    }
  else
    writeout (ctx, "[!!Out of core!!]");
}


/* Write TEXT as a paragraph.  */
static void
writeout_para (audit_ctx_t ctx, const char *text)
{
  if (ctx->use_html)
    es_fputs ("<p>", ctx->outstream);
  writeout (ctx, text);
  if (ctx->use_html)
    es_fputs ("</p>\n", ctx->outstream);
  else
    es_fputc ('\n', ctx->outstream);
}


static void
enter_li (audit_ctx_t ctx)
{
  if (ctx->use_html)
    {
      if (!ctx->indentlevel)
        {
          es_fputs ("<table border=\"0\">\n"
                    "  <colgroup>\n"
                    "    <col width=\"80%\" />\n"
                    "    <col width=\"20%\" />\n"
                    "   </colgroup>\n",
                    ctx->outstream);
        }
    }
  ctx->indentlevel++;
}


static void
leave_li (audit_ctx_t ctx)
{
  ctx->indentlevel--;
  if (ctx->use_html)
    {
      if (!ctx->indentlevel)
        es_fputs ("</table>\n", ctx->outstream);
    }
}

  
/* Write TEXT as a list element.  If OKTEXT is not NULL, append it to
   the last line. */
static void
writeout_li (audit_ctx_t ctx, const char *oktext, const char *format, ...)
{
  va_list arg_ptr;
  const char *color = NULL;

  if (ctx->use_html && format && oktext)
    {
      if (!strcmp (oktext, "OK") || !strcmp (oktext, "Yes"))
        color = "green";
      else if (!strcmp (oktext, "FAIL") || !strcmp (oktext, "No"))
        color = "red";
    }

  if (ctx->use_html)
    {
      int i;

      es_fputs ("  <tr><td><table><tr><td>", ctx->outstream);
      if (color)
        es_fprintf (ctx->outstream, "<font color=\"%s\">*</font>", color);
      else
        es_fputs ("*", ctx->outstream);
      for (i=1; i < ctx->indentlevel; i++)
        es_fputs ("&nbsp;&nbsp;", ctx->outstream);
      es_fputs ("</td><td>", ctx->outstream);
    }
  else
    es_fprintf (ctx->outstream, "* %*s", (ctx->indentlevel-1)*2, "");
  if (format)
    {
      va_start (arg_ptr, format) ;
      writeout_v (ctx, format, arg_ptr);
      va_end (arg_ptr);
    }
  if (ctx->use_html)
    es_fputs ("</td></tr></table>", ctx->outstream);
  if (format && oktext)
    {
      if (ctx->use_html)
        {
          es_fputs ("</td><td>", ctx->outstream);
          if (color)
            es_fprintf (ctx->outstream, "<font color=\"%s\">", color);
        }
      else  
        writeout (ctx, ":         ");
      writeout (ctx, oktext);
      if (color)
        es_fputs ("</font>", ctx->outstream);
    }
  
  if (ctx->use_html)
    es_fputs ("</td></tr>\n", ctx->outstream);
  else
    es_fputc ('\n', ctx->outstream);
}


/* Write a remark line.  */
static void
writeout_rem (audit_ctx_t ctx, const char *format, ...)
{
  va_list arg_ptr;

  if (ctx->use_html)
    {
      int i;

      es_fputs ("  <tr><td><table><tr><td>*", ctx->outstream);
      for (i=1; i < ctx->indentlevel; i++)
        es_fputs ("&nbsp;&nbsp;", ctx->outstream);
      es_fputs ("&nbsp;&nbsp;&nbsp;</td><td> (", ctx->outstream);

    }
  else
    es_fprintf (ctx->outstream, "* %*s  (", (ctx->indentlevel-1)*2, "");
  if (format)
    {
      va_start (arg_ptr, format) ;
      writeout_v (ctx, format, arg_ptr);
      va_end (arg_ptr);
    }
  if (ctx->use_html)
    es_fputs (")</td></tr></table></td></tr>\n", ctx->outstream);
  else
    es_fputs (")\n", ctx->outstream);
}


/* Return the first log item for EVENT.  If STOPEVENT is not 0 never
   look behind that event in the log. If STARTITEM is not NULL start
   search _after_that item.  */
static log_item_t
find_next_log_item (audit_ctx_t ctx, log_item_t startitem, 
                    audit_event_t event, audit_event_t stopevent)
{
  int idx;

  for (idx=0; idx < ctx->logused; idx++)
    {
      if (startitem)
        {
          if (ctx->log + idx == startitem)
            startitem = NULL;
        }
      else if (stopevent && ctx->log[idx].event == stopevent)
        break;
      else if (ctx->log[idx].event == event)
        return ctx->log + idx;
    }
  return NULL;
}


static log_item_t
find_log_item (audit_ctx_t ctx, audit_event_t event, audit_event_t stopevent)
{
  return find_next_log_item (ctx, NULL, event, stopevent);
}


/* Helper to a format a serial number.  */
static char *
format_serial (ksba_const_sexp_t sn)
{
  const char *p = (const char *)sn;
  unsigned long n;
  char *endp;

  if (!p)
    return NULL;
  if (*p != '(')
    BUG (); /* Not a valid S-expression. */
  n = strtoul (p+1, &endp, 10);
  p = endp;
  if (*p != ':')
    BUG (); /* Not a valid S-expression. */
  return bin2hex (p+1, n, NULL);
}


/* Return a malloced string with the serial number and the issuer DN
   of the certificate.  */
static char *
get_cert_name (ksba_cert_t cert)
{
  char *result;
  ksba_sexp_t sn;
  char *issuer, *p;

  if (!cert)
    return xtrystrdup ("[no certificate]");

  issuer = ksba_cert_get_issuer (cert, 0);
  sn = ksba_cert_get_serial (cert);
  if (issuer && sn)
    {
      p = format_serial (sn);
      if (!p)
        result = xtrystrdup ("[invalid S/N]");
      else
        {
          result = xtrymalloc (strlen (p) + strlen (issuer) + 2 + 1);
          if (result)
            {
              *result = '#';
              strcpy (stpcpy (stpcpy (result+1, p),"/"), issuer);
            }
          xfree (p);
        }
    }
  else
    result = xtrystrdup ("[missing S/N or issuer]");
  ksba_free (sn);
  xfree (issuer);
  return result;
}

/* Return a malloced string with the serial number and the issuer DN
   of the certificate.  */
static char *
get_cert_subject (ksba_cert_t cert, int idx)
{
  char *result;
  char *subject;

  if (!cert)
    return xtrystrdup ("[no certificate]");

  subject = ksba_cert_get_subject (cert, idx);
  if (subject)
    {
      result = xtrymalloc (strlen (subject) + 1 + 1);
      if (result)
        {
          *result = '/';
          strcpy (result+1, subject);
        }
    }
  else
    result = NULL;
  xfree (subject);
  return result;
}


/* List the chain of certificates from STARTITEM up to STOPEVENT.  The
   certifcates are written out as comments.  */
static void
list_certchain (audit_ctx_t ctx, log_item_t startitem, audit_event_t stopevent)
{
  log_item_t item;
  char *name;
  int idx;

  startitem = find_next_log_item (ctx, startitem, AUDIT_CHAIN_BEGIN,stopevent);
  if (!startitem)
    {
      writeout_li (ctx, gpg_strerror (GPG_ERR_MISSING_CERT)
                   , _("Certificate chain"));
      return; 
    }
  writeout_li (ctx, "OK", _("Certificate chain"));
  item = find_next_log_item (ctx, startitem, 
                             AUDIT_CHAIN_ROOTCERT, AUDIT_CHAIN_END);
  if (!item)
    writeout_rem (ctx, "%s", _("root certificate missing"));
  else
    {
      name = get_cert_name (item->cert);
      writeout_rem (ctx, "%s", name);
      xfree (name);
    }
  item = startitem;
  while ( ((item = find_next_log_item (ctx, item, 
                                       AUDIT_CHAIN_CERT, AUDIT_CHAIN_END))))
    {
      name = get_cert_name (item->cert);
      writeout_rem (ctx, "%s", name);
      xfree (name);
      enter_li (ctx);
      for (idx=0; (name = get_cert_subject (item->cert, idx)); idx++)
        {
          writeout_rem (ctx, "%s", name);
          xfree (name);
        }
      leave_li (ctx);
    }
}



/* Process a verification operation.  */
static void
proc_type_verify (audit_ctx_t ctx)
{
  log_item_t loopitem, item;
  int signo, count, idx;
  char numbuf[35];

  enter_li (ctx);
  
  writeout_li (ctx, "fixme", "%s", _("Signature verification"));
  enter_li (ctx);

  writeout_li (ctx, "fixme", "%s", _("Gpg-Agent ready"));
  writeout_li (ctx, "fixme", "%s", _("Dirmngr ready"));

  item = find_log_item (ctx, AUDIT_GOT_DATA, AUDIT_NEW_SIG);
  writeout_li (ctx, item? "Yes":"No", "%s", _("Data available"));
  if (!item)
    goto leave;

  item = find_log_item (ctx, AUDIT_NEW_SIG, 0);
  writeout_li (ctx, item? "Yes":"No", "%s", _("Signature available"));
  if (!item)
    goto leave;

  item = find_log_item (ctx, AUDIT_DATA_HASH_ALGO, AUDIT_NEW_SIG);
  if (item)
    writeout_li (ctx, "OK", "%s", _("Parsing signature"));
  else 
    {
      item = find_log_item (ctx, AUDIT_BAD_DATA_HASH_ALGO, AUDIT_NEW_SIG);
      if (item)
        {
          writeout_li (ctx,"FAIL", "%s",  _("Parsing signature"));
          writeout_rem (ctx, _("Bad hash algorithm: %s"), 
                        item->string? item->string:"?");
        }
      else
        writeout_li (ctx, "FAIL", "%s", _("Parsing signature") );
      goto leave;
    }

  /* Loop over all signatures.  */
  loopitem = find_log_item (ctx, AUDIT_NEW_SIG, 0);
  assert (loopitem);
  do
    {
      signo = loopitem->have_intvalue? loopitem->intvalue : -1;

      item = find_next_log_item (ctx, loopitem,
                                 AUDIT_SIG_STATUS, AUDIT_NEW_SIG);
      writeout_li (ctx, item? item->string:"?", _("Signature %d"), signo);
      item = find_next_log_item (ctx, loopitem,
                                 AUDIT_SIG_NAME, AUDIT_NEW_SIG);
      if (item)
        writeout_rem (ctx, "%s", item->string);
      enter_li (ctx);
      
      /* List the certificate chain.  */
      list_certchain (ctx, loopitem, AUDIT_NEW_SIG);

      /* Show the result of the chain validation.  */
      item = find_next_log_item (ctx, loopitem,
                                 AUDIT_CHAIN_STATUS, AUDIT_NEW_SIG);
      if (item && item->have_err)
        {
          writeout_li (ctx, item->err? "FAIL":"OK", 
                       _("Validation of certificate chain"));
          if (item->err)
            writeout_rem (ctx, "%s", gpg_strerror (item->err));
        }
      
      /* Show whether the root certificate is fine.  */
      writeout_li (ctx, "No", "%s", _("Root certificate trustworthy"));

      /* Show result of the CRL/OCSP check.  */
      writeout_li (ctx, "-", "%s", _("CRL/OCSP check of certificates"));


      leave_li (ctx);
    }
  while ((loopitem = find_next_log_item (ctx, loopitem, AUDIT_NEW_SIG, 0)));


 leave:
  /* Always list the certificates stored in the signature.  */
  item = NULL;
  count = 0;
  while ( ((item = find_next_log_item (ctx, item, 
                                       AUDIT_SAVE_CERT, AUDIT_NEW_SIG))))
    count++;
  snprintf (numbuf, sizeof numbuf, "%d", count);
  writeout_li (ctx, numbuf, _("Included certificates"));
  item = NULL;
  while ( ((item = find_next_log_item (ctx, item, 
                                       AUDIT_SAVE_CERT, AUDIT_NEW_SIG))))
    {
      char *name = get_cert_name (item->cert);
      writeout_rem (ctx, "%s", name);
      xfree (name);
      enter_li (ctx);
      for (idx=0; (name = get_cert_subject (item->cert, idx)); idx++)
        {
          writeout_rem (ctx, "%s", name);
          xfree (name);
        }
      leave_li (ctx);
    }

  leave_li (ctx);
  leave_li (ctx);
}




/* Print the formatted audit result.    THIS IS WORK IN PROGRESS.  */
void
audit_print_result (audit_ctx_t ctx, estream_t out, int use_html)
{
  int idx;
  int maxlen;
  size_t n;

  if (getenv ("use_html"))
    use_html = 1;

  if (!ctx)
    return;

  assert (!ctx->outstream);
  ctx->outstream = out;
  ctx->use_html = use_html;
  ctx->indentlevel = 0;

  if (use_html)
    es_fputs ("<div class=\"GnuPGAuditLog\">\n", ctx->outstream);

  if (!ctx->log || !ctx->logused)
    {
      writeout_para (ctx, _("No audit log entries."));
      goto leave;
    }

  for (idx=0,maxlen=0; idx < DIM (eventstr_msgidx); idx++)
    {
      n = strlen (eventstr_msgstr + eventstr_msgidx[idx]);    
      if (n > maxlen)
        maxlen = n;
    }

  if (use_html)
    es_fputs ("<pre>\n", out);
  for (idx=0; idx < ctx->logused; idx++)
    {
      es_fprintf (out, "log: %-*s", 
                  maxlen, event2str (ctx->log[idx].event));
      if (ctx->log[idx].have_intvalue)
        es_fprintf (out, " i=%d", ctx->log[idx].intvalue); 
      if (ctx->log[idx].string)
        {
          es_fputs (" s=`", out); 
          writeout (ctx, ctx->log[idx].string); 
          es_fputs ("'", out); 
        }
      if (ctx->log[idx].cert)
        es_fprintf (out, " has_cert"); 
      if (ctx->log[idx].have_err)
        {
          es_fputs (" err=`", out);
          writeout (ctx, gpg_strerror (ctx->log[idx].err)); 
          es_fputs ("'", out);
        }
      es_fputs ("\n", out);
    }
  if (use_html)
    es_fputs ("</pre>\n", out);
  else
    es_fputs ("\n", out);

  switch (ctx->type)
    {
    case AUDIT_TYPE_NONE:
      writeout_para (ctx, _("Audit of this operation is not supported."));
      break;
    case AUDIT_TYPE_VERIFY:
      proc_type_verify (ctx);
      break;
    }

 leave:
  if (use_html)
    es_fputs ("</div>\n", ctx->outstream);
  ctx->outstream = NULL;
  ctx->use_html = 0;
}

