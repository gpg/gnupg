/* ksutil.c - general keyserver utility functions
 * Copyright (C) 2004 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
#include <signal.h>
#include <unistd.h>
#include "keyserver.h"
#include "ksutil.h"

static void
catch_alarm(int foo)
{
  _exit(KEYSERVER_TIMEOUT);
}

unsigned int
set_timeout(unsigned int seconds)
{
#ifdef HAVE_DOSISH_SYSTEM
  return 0;
#else
  return alarm(seconds);
#endif
}

int
register_timeout(void)
{
#ifdef HAVE_DOSISH_SYSTEM
  return 0;
#else
#if defined(HAVE_SIGACTION) && defined(HAVE_STRUCT_SIGACTION)
  struct sigaction act;

  act.sa_handler=catch_alarm;
  sigemptyset(&act.sa_mask);
  act.sa_flags=0;
  return sigaction(SIGALRM,&act,NULL);
#else 
  if(signal(SIGALRM,catch_alarm)==SIG_ERR)
    return -1;
  else
    return 0;
#endif
#endif
}
