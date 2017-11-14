/* workqueue.c - Maintain a queue of background tasks
 * Copyright (C) 2017 Werner Koch
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
 *
 * SPDX-License-Identifier: GPL-3.0+
 */

#include <config.h>
#include <stdlib.h>
#include <string.h>

#include "dirmngr.h"


/* An object for one item in the workqueue.  */
struct wqitem_s
{
  struct wqitem_s *next;

  /* This flag is set if the task requires network access.  */
  unsigned int need_network:1;

  /* The id of the session which created this task.  If this is 0 the
   * task is not associated with a specific session.  */
  unsigned int session_id;

  /* The function to perform the backgrount task.  */
  wqtask_t func;

  /* A string with the string argument for that task.  */
  char args[1];
};
typedef struct wqitem_s *wqitem_t;


/* The workque is a simple linked list.  */
static wqitem_t workqueue;


/* Dump the queue using Assuan status comments.  */
void
workqueue_dump_queue (ctrl_t ctrl)
{
  wqitem_t saved_workqueue;
  wqitem_t item;
  unsigned int count;

  /* Temporay detach the entiere workqueue so that other threads don't
   * get into our way.  */
  saved_workqueue = workqueue;
  workqueue = NULL;

  for (count=0, item = saved_workqueue; item; item = item->next)
    count++;

  dirmngr_status_helpf (ctrl, "wq: number of entries: %u", count);
  for (item = saved_workqueue; item; item = item->next)
    dirmngr_status_helpf (ctrl, "wq: sess=%u net=%d %s(\"%.100s%s\")",
                          item->session_id, item->need_network,
                          item->func? item->func (NULL, NULL): "nop",
                          item->args, strlen (item->args) > 100? "[...]":"");

  /* Restore then workqueue.  Actually we append the saved queue do a
   * possibly updated workqueue.  */
  if (!(item=workqueue))
    workqueue = saved_workqueue;
  else
    {
      while (item->next)
        item = item->next;
      item->next = saved_workqueue;
    }
}


/* Append the task (FUNC,ARGS) to the work queue.  FUNC shall return
 * its name when called with (NULL, NULL).  */
gpg_error_t
workqueue_add_task (wqtask_t func, const char *args, unsigned int session_id,
                    int need_network)
{
  wqitem_t item, wi;

  item = xtrycalloc (1, sizeof *item + strlen (args));
  if (!item)
    return gpg_error_from_syserror ();
  strcpy (item->args, args);
  item->func = func;
  item->session_id = session_id;
  item->need_network = !!need_network;

  if (!(wi=workqueue))
    workqueue = item;
  else
    {
      while (wi->next)
        wi = wi->next;
      wi->next = item;
    }
  return 0;
}


/* Run the task described by ITEM.  ITEM must have been detached from
 * the workqueue; its ownership is transferred to this fucntion.  */
static void
run_a_task (ctrl_t ctrl, wqitem_t item)
{
  log_assert (!item->next);

  if (opt.verbose)
    log_info ("session %u: running %s(\"%s%s\")\n",
              item->session_id,
              item->func? item->func (NULL, NULL): "nop",
              item->args, strlen (item->args) > 100? "[...]":"");
  if (item->func)
    item->func (ctrl, item->args);

  xfree (item);
}


/* Run tasks not associated with a session.  This is called from the
 * ticker every few minutes.  If WITH_NETWORK is not set tasks which
 * require the network are not run.  */
void
workqueue_run_global_tasks (ctrl_t ctrl, int with_network)
{
  wqitem_t item, prev;

  with_network = !!with_network;

  if (opt.verbose)
    log_info ("running scheduled tasks%s\n", with_network?" (with network)":"");

  for (;;)
    {
      prev = NULL;
      for (item = workqueue; item; prev = item, item = item->next)
        if (!item->session_id
            && (!item->need_network || (item->need_network && with_network)))
          break;
      if (!item)
        break;  /* No more tasks to run.  */

      /* Detach that item from the workqueue.  */
      if (!prev)
        workqueue = item->next;
      else
        prev->next = item->next;
      item->next = NULL;

      /* Run the task.  */
      run_a_task (ctrl, item);
    }
}


/* Run tasks scheduled for running after a session.  Those tasks are
 * identified by the SESSION_ID.  */
void
workqueue_run_post_session_tasks (unsigned int session_id)
{
  struct server_control_s ctrlbuf;
  ctrl_t ctrl = NULL;
  wqitem_t item, prev;

  if (!session_id)
    return;

  for (;;)
    {
      prev = NULL;
      for (item = workqueue; item; prev = item, item = item->next)
        if (item->session_id == session_id)
          break;
      if (!item)
        break;  /* No more tasks for this session.  */

      /* Detach that item from the workqueue.  */
      if (!prev)
        workqueue = item->next;
      else
        prev->next = item->next;
      item->next = NULL;

      /* Create a CTRL object the first time we need it.  */
      if (!ctrl)
        {
          memset (&ctrlbuf, 0, sizeof ctrlbuf);
          ctrl = &ctrlbuf;
          dirmngr_init_default_ctrl (ctrl);
        }

      /* Run the task.  */
      run_a_task (ctrl, item);
    }

  dirmngr_deinit_default_ctrl (ctrl);
}
