/* exec.c - generic call-a-program code
 * Copyright (C) 2001, 2002, 2003, 2004, 2005 Free Software Foundation, Inc.
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

#include <config.h>
#include <stdlib.h>
#include <string.h>

#include "gpg.h"
#include "options.h"
#include "../common/i18n.h"
#include "exec.h"

#ifdef NO_EXEC
int set_exec_path(const char *path) { return GPG_ERR_GENERAL; }
#else
/* Replaces current $PATH */
int
set_exec_path(const char *path)
{
  char *p;

  p=xmalloc(5+strlen(path)+1);
  strcpy(p,"PATH=");
  strcat(p,path);

  if(DBG_EXTPROG)
    log_debug("set_exec_path: %s\n",p);

  /* Notice that path is never freed.  That is intentional due to the
     way putenv() works.  This leaks a few bytes if we call
     set_exec_path multiple times. */

  if(putenv(p)!=0)
    return GPG_ERR_GENERAL;
  else
    return 0;
}
#endif /* ! NO_EXEC */
