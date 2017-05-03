/* g4wihelp.c - NSIS Helper DLL used with gpg4win. -*- coding: latin-1; -*-
 * Copyright (C) 2005 g10 Code GmbH
 * Copyright (C) 2001 Justin Frankel
 *
 * This software is provided 'as-is', without any express or implied
 * warranty. In no event will the authors be held liable for any
 * damages arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any
 * purpose, including commercial applications, and to alter it and
 * redistribute it freely, subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you must
 *    not claim that you wrote the original software. If you use this
 *    software in a product, an acknowledgment in the product
 *    documentation would be appreciated but is not required.
 *
 * 2. Altered source versions must be plainly marked as such, and must
 *    not be misrepresented as being the original software.
 *
 * 3. This notice may not be removed or altered from any source
 *    distribution.
 ************************************************************
 * The code for the splash screen has been taken from the Splash
 * plugin of the NSIS 2.04 distribution.  That code comes without
 * explicit copyright notices in the source files or author names, it
 * seems that it has been written by Justin Frankel; not sure about
 * the year, though. [wk 2005-11-28]
 *
 * Fixed some compiler warnings. [wk 2014-02-24].
 */

#include <stdio.h>
#include <windows.h>
#include "exdll.h"

static HINSTANCE g_hInstance; /* Our Instance. */
static HWND g_hwndParent;     /* Handle of parent window or NULL. */
static HBITMAP g_hbm;         /* Handle of the splash image. */
static int sleepint;          /* Milliseconds to show the spals image. */


/* Standard entry point for DLLs. */
int WINAPI
DllMain (HANDLE hinst, DWORD reason, LPVOID reserved)
{
   if (reason == DLL_PROCESS_ATTACH)
     g_hInstance = hinst;
   return TRUE;
}



/* Dummy function for testing. */
void __declspec(dllexport)
dummy (HWND hwndParent, int string_size, char *variables,
       stack_t **stacktop, extra_parameters_t *extra)
{
  g_hwndParent = hwndParent;

  EXDLL_INIT();

  // note if you want parameters from the stack, pop them off in order.
  // i.e. if you are called via exdll::myFunction file.dat poop.dat
  // calling popstring() the first time would give you file.dat,
  // and the second time would give you poop.dat.
  // you should empty the stack of your parameters, and ONLY your
  // parameters.

  // do your stuff here
  {
    char buf[1024];
    snprintf (buf, sizeof buf, "$R0=%s\r\n$R1=%s\r\n",
              getuservariable(INST_R0),
              getuservariable(INST_R1));
    MessageBox (g_hwndParent,buf,0,MB_OK);

    snprintf (buf, sizeof buf,
             "autoclose    =%d\r\n"
             "all_user_var =%d\r\n"
             "exec_error   =%d\r\n"
             "abort        =%d\r\n"
             "exec_reboot  =%d\r\n"
             "reboot_called=%d\r\n"
             "silent       =%d\r\n"
             "instdir_error=%d\r\n"
             "rtl          =%d\r\n"
             "errlvl       =%d\r\n",
             extra->exec_flags->autoclose,
             extra->exec_flags->all_user_var,
             extra->exec_flags->exec_error,
             extra->exec_flags->abort,
             extra->exec_flags->exec_reboot,
             extra->exec_flags->reboot_called,
             extra->exec_flags->silent,
             extra->exec_flags->instdir_error,
             extra->exec_flags->rtl,
             extra->exec_flags->errlvl);
    MessageBox(g_hwndParent,buf,0,MB_OK);
  }
}


void __declspec(dllexport)
runonce (HWND hwndParent, int string_size, char *variables,
         stack_t **stacktop, extra_parameters_t *extra)
{
  const char *result;

  g_hwndParent = hwndParent;
  EXDLL_INIT();

  CreateMutexA (NULL, 0, getuservariable(INST_R0));
  result = GetLastError ()? "1":"0";
  setuservariable (INST_R0, result);
}


void __declspec(dllexport)
playsound (HWND hwndParent, int string_size, char *variables,
           stack_t **stacktop, extra_parameters_t *extra)
{
  char fname[MAX_PATH];

  g_hwndParent = hwndParent;
  EXDLL_INIT();

  if (popstring(fname, sizeof fname))
    return;
  PlaySound (fname, NULL, SND_ASYNC|SND_FILENAME|SND_NODEFAULT);
}


void __declspec(dllexport)
stopsound (HWND hwndParent, int string_size, char *variables,
           stack_t **stacktop, extra_parameters_t *extra)
{
  g_hwndParent = hwndParent;
  EXDLL_INIT();
  PlaySound (NULL, NULL, 0);
}


/* Windows procedure to control the splashimage.  This one pauses the
   execution until the sleep time is over or the user closes this
   windows. */
static LRESULT CALLBACK
splash_wndproc (HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
  LRESULT result = 0;

  switch (uMsg)
    {
    case WM_CREATE:
      {
        BITMAP bm;
        RECT vp;

        GetObject(g_hbm, sizeof(bm), (LPSTR)&bm);
        SystemParametersInfo(SPI_GETWORKAREA, 0, &vp, 0);
        SetWindowLong(hwnd,GWL_STYLE,0);
        SetWindowPos(hwnd,NULL,
                     vp.left+(vp.right-vp.left-bm.bmWidth)/2,
                     vp.top+(vp.bottom-vp.top-bm.bmHeight)/2,
                     bm.bmWidth,bm.bmHeight,
                     SWP_NOZORDER);
        ShowWindow(hwnd,SW_SHOW);
        SetTimer(hwnd,1,sleepint,NULL);
      }
      break;

    case WM_PAINT:
      {
        PAINTSTRUCT ps;
        RECT r;
        HDC curdc=BeginPaint(hwnd,&ps);
        HDC hdc=CreateCompatibleDC(curdc);
        HBITMAP oldbm;
        GetClientRect(hwnd,&r);
        oldbm=(HBITMAP)SelectObject(hdc,g_hbm);
        BitBlt(curdc,r.left,r.top,r.right-r.left,r.bottom-r.top,
               hdc,0,0,SRCCOPY);
        SelectObject(hdc,oldbm);
        DeleteDC(hdc);
        EndPaint(hwnd,&ps);
      }
      break;

    case WM_CLOSE:
      break;

    case WM_TIMER:
    case WM_LBUTTONDOWN:
      DestroyWindow(hwnd);
      /*(fall through)*/
    default:
      result =  DefWindowProc (hwnd, uMsg, wParam, lParam);
    }

  return result;
}


/* Display a splash screen.  Call as

     g4wihelp::showsplash SLEEP FNAME

   With SLEEP being the time in milliseconds to show the splashscreen
   and FNAME the complete filename of the image.  As of now only BMP
   is supported.
*/
void __declspec(dllexport)
showsplash (HWND hwndParent, int string_size, char *variables,
           stack_t **stacktop, extra_parameters_t *extra)
{
  static WNDCLASS wc;
  char sleepstr[30];
  char fname[MAX_PATH];
  int err = 0;
  char *p;
  char classname[] = "_sp";

  g_hwndParent = hwndParent;
  EXDLL_INIT();
  if (popstring(sleepstr, sizeof sleepstr))
    err = 1;
  if (popstring(fname, sizeof fname))
    err = 1;
  if (err)
    return;

  if (!*fname)
    return; /* Nothing to do. */

  for (sleepint=0, p=sleepstr; *p >= '0' && *p <= '9'; p++)
    {
      sleepint *= 10;
      sleepint += *p - '0';
    }
  if (sleepint <= 0)
    return; /* Nothing to do. */

  wc.lpfnWndProc = splash_wndproc;
  wc.hInstance = g_hInstance;
  wc.hCursor = LoadCursor(NULL,IDC_ARROW);
  wc.lpszClassName = classname;
  if (!RegisterClass(&wc))
    return; /* Error. */

  g_hbm = LoadImage (NULL, fname, IMAGE_BITMAP,
                     0, 0 , LR_CREATEDIBSECTION|LR_LOADFROMFILE);
  if (g_hbm)
    {
      MSG msg;
      HWND hwnd;

      hwnd = CreateWindowEx (WS_EX_TOOLWINDOW, classname, classname,
                             0, 0, 0, 0, 0, (HWND)hwndParent, NULL,
                             g_hInstance, NULL);

      while (IsWindow(hwnd) && GetMessage ( &msg, hwnd, 0, 0))
        {
          DispatchMessage (&msg);
        }

      DeleteObject (g_hbm);
      g_hbm = NULL;
    }
  UnregisterClass (classname, g_hInstance);
}


/* Service Management.  */

/* Use this to report unexpected errors.  FIXME: This is really not
   very descriptive.  */
void
service_error (const char *str)
{
  char buf[1024];
  snprintf (buf, sizeof (buf), "error: %s: ec=%d\r\n", str,
	    GetLastError ());
  MessageBox(g_hwndParent, buf, 0, MB_OK);

  setuservariable (INST_R0, "1");
}


void __declspec(dllexport)
service_create (HWND hwndParent, int string_size, char *variables,
		 stack_t **stacktop, extra_parameters_t *extra)
{
  SC_HANDLE sc;
  SC_HANDLE service;
  const char *result = NULL;
  char service_name[256];
  char display_name[256];
  char program[256];
  int err = 0;

  g_hwndParent = hwndParent;
  EXDLL_INIT();

  /* The expected stack layout: service_name, display_name, program.  */
  if (popstring (service_name, sizeof (service_name)))
    err = 1;
  if (!err && popstring (display_name, sizeof (display_name)))
    err = 1;
  if (!err && popstring (program, sizeof (program)))
    err = 1;
  if (err)
    {
      setuservariable (INST_R0, "1");
      return;
    }

  sc = OpenSCManager (NULL, NULL, SC_MANAGER_ALL_ACCESS);
  if (sc == NULL)
    {
      service_error ("OpenSCManager");
      return;
    }

  service = CreateService (sc, service_name, display_name,
			   SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
			   /* Use SERVICE_DEMAND_START for testing.
			      FIXME: Currently not configurable by caller.  */
			   SERVICE_AUTO_START,
			   SERVICE_ERROR_NORMAL, program,
			   NULL, NULL, NULL,
			   /* FIXME: Currently not configurable by caller.  */
			   /* FIXME: LocalService or NetworkService
			      don't work for dirmngr right now.  NOTE!
			      If you change it here, you also should
			      adjust make-msi.pl for the msi
			      installer.  In the future, this should
			      be an argument to the function and then
			      the make-msi.pl script can extract it
			      from the invocation.  */
			   NULL /* "NT AUTHORITY\\LocalService" */,
			   NULL);
  if (service == NULL)
    {
      service_error ("CreateService");
      CloseServiceHandle (sc);
      return;
    }
  CloseServiceHandle (service);

  result = GetLastError () ? "1":"0";
  setuservariable (INST_R0, result);
  return;
}


/* Requires g_hwndParent to be set!  */
SC_HANDLE
service_lookup (char *service_name)
{
  SC_HANDLE sc;
  SC_HANDLE service;

  sc = OpenSCManager (NULL, NULL, SC_MANAGER_ALL_ACCESS);
  if (sc == NULL)
    {
      service_error ("OpenSCManager");
      return NULL;
    }
  service = OpenService (sc, service_name, SC_MANAGER_ALL_ACCESS);
  if (service == NULL)
    {
      /* Fail silently here.  */
      CloseServiceHandle (sc);
      return NULL;
    }
  CloseServiceHandle (sc);
  return service;
}


/* Returns status.  */
void __declspec(dllexport)
service_query (HWND hwndParent, int string_size, char *variables,
	       stack_t **stacktop, extra_parameters_t *extra)
{
  SC_HANDLE service;
  const char *result = NULL;
  char service_name[256];
  int err = 0;
  SERVICE_STATUS status;

  g_hwndParent = hwndParent;
  EXDLL_INIT();

  /* The expected stack layout: service_name argc [argv].  */
  if (popstring (service_name, sizeof (service_name)))
    err = 1;
  if (err)
    {
      setuservariable (INST_R0, "ERROR");
      return;
    }

  service = service_lookup (service_name);
  if (service == NULL)
  if (err == 0)
    {
      setuservariable (INST_R0, "MISSING");
      return;
    }

  err = QueryServiceStatus (service, &status);
  if (err == 0)
    {
      setuservariable (INST_R0, "ERROR");
      CloseServiceHandle (service);
      return;
    }
  CloseServiceHandle (service);

  switch (status.dwCurrentState)
    {
    case SERVICE_START_PENDING:
      result = "START_PENDING";
      break;
    case SERVICE_RUNNING:
      result = "RUNNING";
      break;
    case SERVICE_PAUSE_PENDING:
      result = "PAUSE_PENDING";
      break;
    case SERVICE_PAUSED:
      result = "PAUSED";
      break;
    case SERVICE_CONTINUE_PENDING:
      result = "CONTINUE_PENDING";
      break;
    case SERVICE_STOP_PENDING:
      result = "STOP_PENDING";
      break;
    case SERVICE_STOPPED:
      result = "STOPPED";
      break;
    default:
      result = "UNKNOWN";
    }
  setuservariable (INST_R0, result);
  return;
}


void __declspec(dllexport)
service_start (HWND hwndParent, int string_size, char *variables,
	       stack_t **stacktop, extra_parameters_t *extra)
{
  SC_HANDLE service;
  const char *result = NULL;
  char service_name[256];
  char argc_str[256];
#define NR_ARGS 10
#define ARG_MAX 256
  char argv_str[NR_ARGS][ARG_MAX];
  const char *argv[NR_ARGS + 1];
  int argc;
  int i;
  int err = 0;

  g_hwndParent = hwndParent;
  EXDLL_INIT();

  /* The expected stack layout: service_name argc [argv].  */
  if (popstring (service_name, sizeof (service_name)))
    err = 1;
  if (!err && popstring (argc_str, sizeof (argc_str)))
    err = 1;
  if (!err)
    {
      argc = atoi (argc_str);
      for (i = 0; i < argc; i++)
	{
	  if (popstring (argv_str[i], ARG_MAX))
	    {
	      err = 1;
	      break;
	    }
	  argv[i] = argv_str[i];
	}
      argv[i] = NULL;
    }
  if (err)
    {
      setuservariable (INST_R0, "1");
      return;
    }

  service = service_lookup (service_name);
  if (service == NULL)
    return;

  err = StartService (service, argc, argc == 0 ? NULL : argv);
  if (err == 0)
    {
      service_error ("StartService");
      CloseServiceHandle (service);
      return;
    }
  CloseServiceHandle (service);

  setuservariable (INST_R0, "0");
  return;
}


void __declspec(dllexport)
service_stop (HWND hwndParent, int string_size, char *variables,
	      stack_t **stacktop, extra_parameters_t *extra)
{
  SC_HANDLE service;
  const char *result = NULL;
  char service_name[256];
  int err = 0;
  SERVICE_STATUS status;
  DWORD timeout = 10000;	/* 10 seconds.  */
  DWORD start_time;

  g_hwndParent = hwndParent;
  EXDLL_INIT();

  /* The expected stack layout: service_name argc [argv].  */
  if (popstring (service_name, sizeof (service_name)))
    err = 1;
  if (err)
    {
      setuservariable (INST_R0, "1");
      return;
    }

  service = service_lookup (service_name);
  if (service == NULL)
    return;

  err = QueryServiceStatus (service, &status);
  if (err == 0)
    {
      service_error ("QueryService");
      CloseServiceHandle (service);
      return;
    }

  if (status.dwCurrentState != SERVICE_STOPPED
      && status.dwCurrentState != SERVICE_STOP_PENDING)
    {
      err = ControlService (service, SERVICE_CONTROL_STOP, &status);
      if (err == 0)
	{
	  service_error ("ControlService");
	  CloseServiceHandle (service);
	  return;
	}
    }

  start_time = GetTickCount ();
  while (status.dwCurrentState != SERVICE_STOPPED)
    {
      Sleep (1000);	/* One second.  */
      if (!QueryServiceStatus (service, &status))
	{
	  service_error ("QueryService");
	  CloseServiceHandle (service);
	  return;
	}
      if (status.dwCurrentState == SERVICE_STOPPED)
	break;

      if (GetTickCount () - start_time > timeout)
	{
	  char buf[1024];
	  snprintf (buf, sizeof (buf),
		    "time out waiting for service %s to stop\r\n",
		    service_name);
	  MessageBox (g_hwndParent, buf, 0, MB_OK);
	  setuservariable (INST_R0, "1");
	  return;
	}
    }
  CloseServiceHandle (service);
  setuservariable (INST_R0, "0");
  return;
}


void __declspec(dllexport)
service_delete (HWND hwndParent, int string_size, char *variables,
		stack_t **stacktop, extra_parameters_t *extra)
{
  SC_HANDLE service;
  const char *result = NULL;
  char service_name[256];
  int err = 0;

  g_hwndParent = hwndParent;
  EXDLL_INIT();

  /* The expected stack layout: service_name argc [argv].  */
  if (popstring (service_name, sizeof (service_name)))
    err = 1;
  if (err)
    {
      setuservariable (INST_R0, "1");
      return;
    }

  service = service_lookup (service_name);
  if (service == NULL)
    return;

  err = DeleteService (service);
  if (err == 0)
    {
      service_error ("DeleteService");
      CloseServiceHandle (service);
      return;
    }
  CloseServiceHandle (service);

  setuservariable (INST_R0, "0");
  return;
}


#include <stdio.h>

/* Extract config file parameters.  FIXME: Not particularly robust.
   We expect some reasonable formatting.  The parser below is very
   limited.  It expects a command line option /c=FILE or /C=FILE,
   where FILE must be enclosed in double-quotes if it contains spaces.
   That file should contain a single section [gpg4win] and KEY=VALUE
   pairs for each additional configuration file to install.  Comments
   are supported only on lines by themselves.  VALUE can be quoted in
   double-quotes, but does not need to be, unless it has whitespace at
   the beginning or end.  KEY can, for example, be "gpg.conf" (without
   the quotes).  */
void
config_init (char **keys, char **values, int max)
{
  /* First, parse the command line.  */
  char *cmdline;
  char *begin = NULL;
  char *end = NULL;
  char mark;
  char *fname;
  char *ptr;
  FILE *conf;

  *keys = NULL;
  *values = NULL;

  cmdline = getuservariable (INST_CMDLINE);

  mark = (*cmdline == '"') ? (cmdline++, '"') : ' ';
  while (*cmdline && *cmdline != mark)
    cmdline++;
  if (mark == '"' && *cmdline)
    cmdline++;
  while (*cmdline && *cmdline == ' ')
    cmdline++;

  while (*cmdline)
    {
      /* We are at the beginning of a new argument.  */
      if (cmdline[0] == '/' && (cmdline[1] == 'C' || cmdline[1] == 'c')
	  && cmdline[2] == '=')
	{
	  cmdline += 3;
	  begin = cmdline;
	}

      while (*cmdline && *cmdline != ' ')
	{
	  /* Skip over quoted parts.  */
	  if (*cmdline == '"')
	    {
	      cmdline++;
	      while (*cmdline && *cmdline != '"')
		cmdline++;
	      if (*cmdline)
		cmdline++;
	    }
	  else
	    cmdline++;
	}
      if (begin && !end)
	{
	  end = cmdline - 1;
	  break;
	}
      while (*cmdline && *cmdline == ' ')
	cmdline++;
    }

  if (!begin || begin > end)
    return;

  /* Strip quotes.  */
  if (*begin == '"' && *end == '"')
    {
      begin++;
      end--;
    }
  if (begin > end)
    return;

  fname = malloc (end - begin + 2);
  if (!fname)
    return;

  ptr = fname;
  while (begin <= end)
    *(ptr++) = *(begin++);
  *ptr = '\0';

  conf = fopen (fname, "r");
  free (fname);
  if (!conf)
    return;

  while (max - 1 > 0)
    {
      char line[256];
      char *ptr2;

      if (fgets (line, sizeof (line), conf) == NULL)
	break;
      ptr = &line[strlen (line)];
      while (ptr > line && (ptr[-1] == '\n' || ptr[-1] == '\r'
			    || ptr[-1] == ' ' || ptr[-1] == '\t'))
	ptr--;
      *ptr = '\0';

      ptr = line;
      while (*ptr && (*ptr == ' ' || *ptr == '\t'))
	ptr++;
      /* Ignore comment lines.  */
      /* FIXME: Ignore section markers.  */
      if (*ptr == '\0' || *ptr == ';' || *ptr == '[')
	continue;
      begin = ptr;
      while (*ptr && *ptr != '=' && *ptr != ' ' && *ptr != '\t')
	ptr++;
      end = ptr - 1;
      while (*ptr && (*ptr == ' ' || *ptr == '\t'))
	ptr++;
      if (*ptr != '=')
	continue;
      ptr++;

      if (begin > end)
	continue;

      /* We found a key.  */
      *keys = malloc (end - begin + 2);
      if (!keys)
	return;
      ptr2 = *keys;
      while (begin <= end)
	*(ptr2++) = *(begin++);
      *ptr2 = '\0';

      *values = NULL;

      while (*ptr && (*ptr == ' ' || *ptr == '\t'))
	ptr++;
      begin = ptr;
      /* In this case, end points to the byte after the value, which
	 is OK because that is '\0'.  */
      end = &line[strlen (line)];
      if (begin > end)
	begin = end;

      /* Strip quotes.  */
      if (*begin == '"' && end[-1] == '"')
	{
	  begin++;
	  end--;
	  *end = '\0';
	}
      if (begin > end)
	return;

      *values = malloc (end - begin + 1);
      ptr2 = *values;
      while (begin <= end)
	*(ptr2++) = *(begin++);

      keys++;
      values++;
      max--;
    }

  fclose (conf);
  *keys = NULL;
  *values = NULL;
}


char *
config_lookup (char *key)
{
#define MAX_KEYS 128
  static int initialised = 0;
  static char *keys[MAX_KEYS];
  static char *values[MAX_KEYS];
  int i;

  if (initialised == 0)
    {
      initialised = 1;
      config_init (keys, values, MAX_KEYS);

#if 0
      MessageBox(g_hwndParent, "Configuration File:", 0, MB_OK);
      i = 0;
      while (keys[i])
	{
	  char buf[256];
	  sprintf (buf, "%s=%s\r\n", keys[i], values[i]);
	  MessageBox (g_hwndParent, buf, 0, MB_OK);
	  i++;
	}
#endif
    }

  i = 0;
  while (keys[i])
    {
      if (!strcmp (keys[i], key))
	return values[i];
      i++;
    }

  return NULL;
}


void __declspec(dllexport)
config_fetch (HWND hwndParent, int string_size, char *variables,
	      stack_t **stacktop, extra_parameters_t *extra)
{
  char key[256];
  int err = 0;
  char *value;

  g_hwndParent = hwndParent;
  EXDLL_INIT();

  /* The expected stack layout: key.  */
  if (popstring (key, sizeof (key)))
    err = 1;
  if (err)
    {
      setuservariable (INST_R0, "");
      return;
    }

  value = config_lookup (key);

  setuservariable (INST_R0, value == NULL ? "" : value);
  return;
}


void __declspec(dllexport)
config_fetch_bool (HWND hwndParent, int string_size, char *variables,
		   stack_t **stacktop, extra_parameters_t *extra)
{
  char key[256];
  int err = 0;
  char *value;
  int result;

  g_hwndParent = hwndParent;
  EXDLL_INIT();

  /* The expected stack layout: key.  */
  if (popstring (key, sizeof (key)))
    err = 1;
  if (err)
    {
      setuservariable (INST_R0, "");
      return;
    }

  value = config_lookup (key);
  if (value == NULL || *value == '\0')
    {
      setuservariable (INST_R0, "");
      return;
    }

  result = 0;
  if (!strcasecmp (value, "true")
      || !strcasecmp (value, "yes")
      || atoi (value) != 0)
    result = 1;

  setuservariable (INST_R0, result == 0 ? "0" : "1");
  return;
}


/* Return a string from the Win32 Registry or NULL in case of error.
   Caller must release the return value.  A NULL for root is an alias
   for HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE in turn.  */
char *
read_w32_registry_string (HKEY root, const char *dir, const char *name)
{
  HKEY root_key;
  HKEY key_handle;
  DWORD n1, nbytes, type;
  char *result = NULL;

  root_key = root;
  if (! root_key)
    root_key = HKEY_CURRENT_USER;

  if( RegOpenKeyEx( root_key, dir, 0, KEY_READ, &key_handle ) )
    {
      if (root)
	return NULL; /* no need for a RegClose, so return direct */
      /* It seems to be common practise to fall back to HKLM. */
      if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, dir, 0, KEY_READ, &key_handle) )
	return NULL; /* still no need for a RegClose, so return direct */
    }

  nbytes = 1;
  if( RegQueryValueEx( key_handle, name, 0, NULL, NULL, &nbytes ) ) {
    if (root)
      goto leave;
    /* Try to fallback to HKLM also vor a missing value.  */
    RegCloseKey (key_handle);
    if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, dir, 0, KEY_READ, &key_handle) )
      return NULL; /* Nope.  */
    if (RegQueryValueEx( key_handle, name, 0, NULL, NULL, &nbytes))
      goto leave;
  }

  result = malloc( (n1=nbytes+1) );

  if( !result )
    goto leave;
  if( RegQueryValueEx( key_handle, name, 0, &type, result, &n1 ) ) {
    free(result); result = NULL;
    goto leave;
  }
  result[nbytes] = 0; /* make sure it is really a string  */

 leave:
  RegCloseKey( key_handle );
  return result;
}


#define ENV_HK HKEY_LOCAL_MACHINE
#define ENV_REG "SYSTEM\\CurrentControlSet\\Control\\" \
    "Session Manager\\Environment"
  /* The following setting can be used for a per-user setting.  */
#define ENV_HK_USER HKEY_CURRENT_USER
#define ENV_REG_USER "Environment"
/* Due to a bug in Windows7 (kb 2685893) we better put a lower limit
   than 8191 on the maximum length of the PATH variable.  Note, that
   depending on the used toolchain we used to had a 259 byte limit in
   the past.  */
#define PATH_LENGTH_LIMIT 2047

void __declspec(dllexport)
path_add (HWND hwndParent, int string_size, char *variables,
	  stack_t **stacktop, extra_parameters_t *extra)
{
  char dir[PATH_LENGTH_LIMIT];
  char is_user_install[2];
  char *path;
  char *path_new;
  int path_new_size;
  char *comp;
  const char delims[] = ";";
  int is_user;
  HKEY key_handle = 0;
  HKEY root_key;
  const char *env_reg;

  g_hwndParent = hwndParent;
  EXDLL_INIT();

  setuservariable (INST_R0, "0");

/*   MessageBox (g_hwndParent, "XXX 1", 0, MB_OK); */

  /* The expected stack layout: path component.  */
  if (popstring (dir, sizeof (dir)))
    return;

  /* The expected stack layout: HKEY component.  */
  if (popstring (is_user_install, sizeof (is_user_install)))
    return;

  if (!strcmp(is_user_install, "1"))
    {
      root_key = ENV_HK_USER;
      env_reg = ENV_REG_USER;
    }
  else
    {
      root_key = ENV_HK;
      env_reg = ENV_REG;
    }

  path = read_w32_registry_string (root_key, env_reg, "Path");

  if (! path)
    {
      path = strdup ("");
    }

/*   MessageBox (g_hwndParent, "XXX 3", 0, MB_OK); */

  /* Old path plus semicolon plus dir plus terminating nul.  */
  path_new_size = strlen (path) + 1 + strlen (dir) + 1;
  if (path_new_size > PATH_LENGTH_LIMIT)
    {
      MessageBox (g_hwndParent, "PATH env variable too big", 0, MB_OK);
      free (path);
      return;
    }

/*   MessageBox (g_hwndParent, "XXX 4", 0, MB_OK); */

  path_new = malloc (path_new_size);
  if (!path_new)
    {
      free (path);
      return;
    }

/*   MessageBox (g_hwndParent, "XXX 5", 0, MB_OK); */

  strcpy (path_new, path);
  strcat (path_new, ";");
  strcat (path_new, dir);

/*   MessageBox (g_hwndParent, "XXX 6", 0, MB_OK); */
/*   MessageBox (g_hwndParent, dir, 0, MB_OK); */
/*   MessageBox (g_hwndParent, "XXX 7", 0, MB_OK); */

  /* Check if the directory already exists in the path.  */
  comp = strtok (path, delims);
  do
    {
/*       MessageBox (g_hwndParent, comp, 0, MB_OK); */
      if (!comp)
        break;

      if (!strcmp (comp, dir))
	{
	  free (path);
	  free (path_new);
	  return;
	}
      comp = strtok (NULL, delims);
    }
  while (comp);
  free (path);

  /* Update the path key.  */
  RegCreateKey (root_key, env_reg, &key_handle);
  RegSetValueEx (key_handle, "Path", 0, REG_EXPAND_SZ,
		 path_new, path_new_size);
  RegCloseKey (key_handle);
  SetEnvironmentVariable("PATH", path_new);
  free (path_new);

/*   MessageBox (g_hwndParent, "XXX 9", 0, MB_OK); */

  setuservariable (INST_R0, "1");
}


void __declspec(dllexport)
path_remove (HWND hwndParent, int string_size, char *variables,
	     stack_t **stacktop, extra_parameters_t *extra)
{
  char dir[PATH_LENGTH_LIMIT];
  char is_user_install[2];
  char *path;
  char *path_new;
  int path_new_size;
  char *comp;
  const char delims[] = ";";
  HKEY key_handle = 0;
  int changed = 0;
  int count = 0;
  HKEY root_key;
  const char *env_reg;

  g_hwndParent = hwndParent;
  EXDLL_INIT();

  setuservariable (INST_R0, "0");

  /* The expected stack layout: path component.  */
  if (popstring (dir, sizeof (dir)))
    return;

  /* The expected stack layout: HKEY component.  */
  if (popstring (is_user_install, sizeof (is_user_install)))
    return;

  if (!strcmp(is_user_install, "1"))
    {
      root_key = ENV_HK_USER;
      env_reg = ENV_REG_USER;
    }
  else
    {
      root_key = ENV_HK;
      env_reg = ENV_REG;
    }

  path = read_w32_registry_string (root_key, env_reg, "Path");

  if (!path)
    return;
  /* Old path plus semicolon plus dir plus terminating nul.  */
  path_new_size = strlen (path) + 1;
  path_new = malloc (path_new_size);
  if (!path_new)
    {
      free (path);
      return;
    }
  path_new[0] = '\0';

  /* Compose the new path.  */
  comp = strtok (path, delims);
  do
    {
      if (strcmp (comp, dir))
	{
	  if (count != 0)
	    strcat (path_new, ";");
	  strcat (path_new, comp);
	  count++;
	}
      else
	changed = 1;

      comp = strtok (NULL, delims);
    }
  while (comp);
  free (path);

  if (! changed)
    return;

  /* Set a key for our CLSID.  */
  RegCreateKey (root_key, env_reg, &key_handle);
  RegSetValueEx (key_handle, "Path", 0, REG_EXPAND_SZ,
		 path_new, path_new_size);
  RegCloseKey (key_handle);
  free (path_new);

  setuservariable (INST_R0, "1");
}
