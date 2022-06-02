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
#ifdef HAVE_DOSISH_SYSTEM
# ifdef HAVE_WINSOCK2_H
#  include <winsock2.h>
# endif
# include <windows.h>
#endif
#include <string.h>

#include "gpg.h"
#include "options.h"
#include "../common/i18n.h"
#include "exec.h"

#ifdef NO_EXEC
int set_exec_path(const char *path) { return GPG_ERR_GENERAL; }
#else
#if defined (_WIN32)
/* This is a nicer system() for windows that waits for programs to
   return before returning control to the caller.  I hate helpful
   computers. */
int
w32_system(const char *command)
{
  if (!strncmp (command, "!ShellExecute ", 14))
    {
      SHELLEXECUTEINFOW see;
      wchar_t *wname;
      int waitms;

      command = command + 14;
      while (spacep (command))
        command++;
      waitms = atoi (command);
      if (waitms < 0)
        waitms = 0;
      else if (waitms > 60*1000)
        waitms = 60000;
      while (*command && !spacep (command))
        command++;
      while (spacep (command))
        command++;

      wname = utf8_to_wchar (command);
      if (!wname)
        return -1;

      memset (&see, 0, sizeof see);
      see.cbSize = sizeof see;
      see.fMask = (SEE_MASK_NOCLOSEPROCESS
                   | SEE_MASK_NOASYNC
                   | SEE_MASK_FLAG_NO_UI
                   | SEE_MASK_NO_CONSOLE);
      see.lpVerb = L"open";
      see.lpFile = (LPCWSTR)wname;
      see.nShow = SW_SHOW;

      if (DBG_EXTPROG)
        log_debug ("running ShellExecuteEx(open,'%s')\n", command);
      if (!ShellExecuteExW (&see))
        {
          if (DBG_EXTPROG)
            log_debug ("ShellExecuteEx failed: rc=%d\n", (int)GetLastError ());
          xfree (wname);
          return -1;
        }
      if (DBG_EXTPROG)
        log_debug ("ShellExecuteEx succeeded (hProcess=%p,hInstApp=%d)\n",
                   see.hProcess, (int)see.hInstApp);

      if (!see.hProcess)
        {
          gnupg_usleep (waitms*1000);
          if (DBG_EXTPROG)
            log_debug ("ShellExecuteEx ready (wait=%dms)\n", waitms);
        }
      else
        {
          WaitForSingleObject (see.hProcess, INFINITE);
          if (DBG_EXTPROG)
            log_debug ("ShellExecuteEx ready\n");
        }
      CloseHandle (see.hProcess);

      xfree (wname);
    }
  else
    {
      char *string;
      wchar_t *wstring;
      PROCESS_INFORMATION pi;
      STARTUPINFOW si;

      /* We must use a copy of the command as CreateProcess modifies
       * this argument. */
      string = xstrdup (command);
      wstring = utf8_to_wchar (string);
      xfree (string);
      if (!wstring)
        return -1;

      memset (&pi, 0, sizeof(pi));
      memset (&si, 0, sizeof(si));
      si.cb = sizeof (si);

      if (!CreateProcessW (NULL, wstring, NULL, NULL, FALSE,
                           DETACHED_PROCESS,
                           NULL, NULL, &si, &pi))
        {
          xfree (wstring);
          return -1;
        }

      /* Wait for the child to exit */
      WaitForSingleObject (pi.hProcess, INFINITE);

      CloseHandle (pi.hProcess);
      CloseHandle (pi.hThread);
      xfree (wstring);
    }

  return 0;
}
#endif /*_W32*/


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
