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


#include "util.h"
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

};




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



/* Print the formatted audit result.    THIS IS WORK IN PROGRESS.  */
void
audit_print_result (audit_ctx_t ctx, estream_t out)
{
  int idx;
  int maxlen;
  size_t n;

  es_fputs ("<div class=\"GnuPGAuditLog\">\n", out);

  if (!ctx)
    goto leave;
  if (!ctx->log || !ctx->logused)
    {
      es_fprintf (out, "<p>AUDIT-LOG: No entries</p>\n");
      goto leave;
    }

  for (idx=0,maxlen=0; idx < DIM (eventstr_msgidx); idx++)
    {
      n = strlen (eventstr_msgstr + eventstr_msgidx[idx]);    
      if (n > maxlen)
        maxlen = n;
    }

  es_fputs ("<ul>\n", out);
  for (idx=0; idx < ctx->logused; idx++)
    {
      es_fprintf (out, " <li>%-*s", 
                  maxlen, event2str (ctx->log[idx].event));
      if (ctx->log[idx].have_intvalue)
        es_fprintf (out, " i=%d", ctx->log[idx].intvalue); 
      if (ctx->log[idx].string)
        es_fprintf (out, " s=`%s'", ctx->log[idx].string); 
      if (ctx->log[idx].cert)
        es_fprintf (out, " has_cert"); 
      if (ctx->log[idx].have_err)
        es_fprintf (out, " err=\"%s\"", gpg_strerror (ctx->log[idx].err)); 
      es_fputs ("</li>\n", out);
    }
  es_fputs ("</ul>\n", out);

 leave:
  es_fputs ("</div>\n", out);
}

