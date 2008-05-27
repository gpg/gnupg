/* w32main.c - W32 main entry pint and taskbar support for the GnuPG Agent
 * Copyright (C) 2007 Free Software Foundation, Inc.
 * Copyright 1996, 1998 Alexandre Julliard
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
#ifndef HAVE_W32_SYSTEM
#error This module is only useful for the W32 version of gpg-agent
#endif

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <windows.h>

#include "util.h"
#include "w32main.h"

/* The instance handle has received by WinMain.  */
static HINSTANCE glob_hinst;
static HWND glob_hwnd;


/* Build an argv array from the command in CMDLINE.  RESERVED is the
   number of args to reserve before the first one.  This code is based
   on Alexandre Julliard's LGPLed wine-0.9.34/dlls/kernel32/process.c
   and modified to fit into our framework.  The function returns NULL
   on error; on success an arry with the argiments is returned.  This
   array has been allocaqted using a plain malloc (and not the usual
   xtrymalloc). */
static char **
build_argv (char *cmdline_arg, int reserved)
{
  int argc;
  char **argv;
  char *cmdline, *s, *arg, *d;
  int in_quotes, bs_count;

  cmdline = malloc (strlen (cmdline_arg) + 1);
  if (!cmdline)
    return NULL;
  strcpy (cmdline, cmdline_arg);

  /* First determine the required size of the array.  */
  argc = reserved + 1;
  bs_count = 0;
  in_quotes = 0;
  s = cmdline;
  for (;;)
    {
      if ( !*s || ((*s==' ' || *s=='\t') && !in_quotes)) /* A space.  */
        {
          argc++;
          /* Skip the remaining spaces.  */
          while (*s==' ' || *s=='\t') 
            s++;
          if (!*s)
            break;
          bs_count = 0;
        } 
      else if (*s=='\\')
        {
          bs_count++;
          s++;
        }
      else if ( (*s == '\"') && !(bs_count & 1))
        {
          /* Unescaped '\"' */
          in_quotes = !in_quotes;
          bs_count=0;
          s++;
        } 
      else /* A regular character. */
        {
          bs_count = 0;
          s++;
        }
    }

  argv = xtrymalloc (argc * sizeof *argv);
  if (!argv)
    {
      xfree (cmdline);
      return NULL;
    }

  /* Now actually parse the command line.  */
  argc = reserved;
  bs_count = 0;
  in_quotes=0;
  arg = d = s = cmdline;
  while (*s)
    {
      if ((*s==' ' || *s=='\t') && !in_quotes)
        {
          /* Close the argument and copy it. */
          *d = 0;
          argv[argc++] = arg;

          /* Skip the remaining spaces. */
          do 
            s++;
          while (*s==' ' || *s=='\t');

          /* Start with a new argument */
          arg = d = s;
          bs_count = 0;
        } 
      else if (*s=='\\') 
        {
          *d++ = *s++;
          bs_count++;
        } 
      else if (*s=='\"') 
        {
          if ( !(bs_count & 1) )
            {
              /* Preceded by an even number of backslashes, this is
                 half that number of backslashes, plus a '\"' which we
                 discard.  */
              d -= bs_count/2;
              s++;
              in_quotes = !in_quotes;
            }
          else 
            {
              /* Preceded by an odd number of backslashes, this is
                 half that number of backslashes followed by a '\"'.  */
              d = d - bs_count/2 - 1;
              *d++ ='\"';
              s++;
            }
          bs_count=0;
        } 
      else /* A regular character. */
        {
          *d++ = *s++;
          bs_count = 0;
        }
    }

  if (*arg)
    {
      *d = 0;
      argv[argc++] = arg;
    }
  argv[argc] = NULL;

  return argv;
}



/* Our window message processing function.  */
static LRESULT CALLBACK 
wndw_proc (HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{		

  switch (msg)
    {
    case WM_USER:
      fprintf (stderr,"%s: received WM_%s\n", __func__, "USER" );
      break;

    }

  return DefWindowProc (hwnd, msg, wparam, lparam);
}


/* This function is called to do some fast event polling and
   processing.  */
void
w32_poll_events (void)
{
/*   MSG msg; */

/*   fprintf (stderr,"%s: enter\n", __func__); */
/*   while (PeekMessage (&msg, glob_hwnd,  0, 0, PM_REMOVE))  */
/*     {  */
/*       DispatchMessage (&msg); */
/*     } */
/*   fprintf (stderr,"%s: leave\n", __func__); */
}



static void *
handle_taskbar (void *ctx)
{
  WNDCLASS wndwclass = {0, wndw_proc, 0, 0, glob_hinst,
                        0, 0, 0, 0, "gpg-agent"};
  NOTIFYICONDATA nid;
  HWND hwnd;
  MSG msg;
  int rc;

  if (!RegisterClass (&wndwclass))
    {
      log_error ("error registering window class\n");
      ExitThread (0);
    }
  hwnd = CreateWindow ("gpg-agent", "gpg-agent",
                       0, 0, 0, 0, 0,
                       NULL, NULL, glob_hinst, NULL);
  if (!hwnd)
    {
      log_error ("error creating main window\n");
      ExitThread (0);
    }
  glob_hwnd = hwnd;
  UpdateWindow (hwnd);

  memset (&nid, 0, sizeof nid);
  nid.cbSize = sizeof (nid);
  nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
  nid.uCallbackMessage = WM_USER;
  nid.hWnd = glob_hwnd;
  nid.uID = 1;
  nid.hIcon = LoadIcon (glob_hinst, MAKEINTRESOURCE (1));
  mem2str (nid.szTip, "GnuPG Agent version "PACKAGE_VERSION,
           sizeof nid.szTip);
  Shell_NotifyIcon (NIM_ADD, &nid);
  DestroyIcon (nid.hIcon);

  fprintf (stderr, "%s: enter\n", __func__);
  while ( (rc=GetMessage (&msg, hwnd,  0, 0)) ) 
    { 
      if (rc == -1)
        {
          log_error ("getMessage failed: %s\n", w32_strerror (-1));
          break;
        }
      TranslateMessage (&msg);
      DispatchMessage (&msg);
    }
  fprintf (stderr,"%s: leave\n", __func__);
  ExitThread (0);
  return NULL;
}



/* This function initializes the Window system and sets up the taskbar
   icon.  We only have very limited GUI support just to give the
   taskbar icon a little bit of life.  This fucntion is called once to
   fire up the icon.  */
int
w32_setup_taskbar (void)
{
  SECURITY_ATTRIBUTES sa;
  DWORD tid;
  HANDLE th;

  memset (&sa, 0, sizeof sa);
  sa.nLength = sizeof sa;
  sa.bInheritHandle = FALSE;

  fprintf (stderr,"creating thread for the taskbar_event_loop...\n");
  th = CreateThread (&sa, 128*1024,
                     (LPTHREAD_START_ROUTINE)handle_taskbar,
                     NULL, 0, &tid);
  fprintf (stderr,"created thread %p tid=%d\n", th, (int)tid);

  CloseHandle (th);

  return 0;
}


/* The main entry point for the Windows version.  We save away all GUI
   related stuff, parse the command line and finally call the real
   main.  */
int WINAPI
WinMain (HINSTANCE hinst, HINSTANCE hprev, LPSTR cmdline, int showcmd)
{
  char **argv;
  int argc;

  /* We use the GetCommandLine function because that also includes the
     program name in contrast to the CMDLINE arg. */
  argv = build_argv (GetCommandLineA (), 0);
  if (!argv)
    return 2; /* Can't do much about a malloc failure.  */
  for (argc=0; argv[argc]; argc++)
    ;

  glob_hinst = hinst;

  return w32_main (argc, argv);
}
