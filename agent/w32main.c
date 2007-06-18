/* w32main.c - W32 main entry pint and taskbar support for the GnuPG Agent
 * Copyright (C) 2007 Free Software Foundation, Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
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
   related stuff, parse the commandline and finally call the real
   main.  */
int WINAPI
WinMain (HINSTANCE hinst, HINSTANCE hprev, LPSTR cmdline, int showcmd)
{
  /* Fixme: We need a parser for the command line.  Should be
     available in some CRT code - need to see whether we can find a
     GNU version.  For nopw we call gpg-agent with a couple of fixed arguments 
   */
  char *argv[] = { "gpg-agent.exe", "--daemon", "-v", "--debug-all", NULL };


  glob_hinst = hinst;

  return w32_main (DIM(argv)-1, argv);
}





