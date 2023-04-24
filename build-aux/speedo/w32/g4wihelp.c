/* g4wihelp.c - NSIS Helper DLL used with gpg4win.
 * Copyright (C) 2005, 2023 g10 Code GmbH
 * Copyright (C) 2001 Justin Frankel
 * Copyright (C) 2016, 2017 Intevation GmbH
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
 * explicit copyright notices in tyhe source files or author names, it
 * seems that it has been written by Justin Frankel; not sure about
 * the year, though. [wk 2005-11-28]
 *
 * Fixed some compiler warnings. [wk 2014-02-24].
 * Merged code from GnuPG version.  [wk 2023-04-24].
 *
 * Compile time macros:
 *  ENABLE_SLIDE_SHOW :: Define for Gpg4win.
 */

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>
#include "exdll.h"

/* We keep some code here for documentation reasons.  That code has not
 * yet been converted to the Unicode NSIS plugin API. */
/* #define ENABLE_SOUND_GADGET 1   */
/* #define ENABLE_SPLASH_GADGET 1   */
/* #define ENABLE_SERVICE_MANAGEMENT 1   */


static HINSTANCE g_hInstance; /* Our Instance. */
static HWND g_hwndParent;     /* Handle of parent window or NULL. */
static HBITMAP g_hbm;         /* Handle of the splash image. */
static int sleepint;          /* Milliseconds to show the spals image. */

#ifdef ENABLE_SLIDE_SHOW
void
slide_stop(HWND hwndParent, int string_size, TCHAR *variables, stack_t **stacktop);
#endif

/* Standard entry point for DLLs. */
int WINAPI
DllMain (HANDLE hinst, DWORD reason, LPVOID reserved)
{
   if (reason == DLL_PROCESS_ATTACH)
     g_hInstance = hinst;
   else if (reason == DLL_PROCESS_DETACH)
     {
#ifdef ENABLE_SLIDE_SHOW
       slide_stop (NULL, 0, NULL, NULL);
#endif
     }
   return TRUE;
}



/* Dummy function for testing. */
void __declspec(dllexport)
dummy (HWND hwndParent, int string_size, LPTSTR variables,
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

  /* Let's dump the variables.  */
  {
    char line[512];
    char *p;
    const unsigned char *s = (void*)g_variables;
    int i,j;

    for (i=0; i < string_size* __INST_LAST; i+=32, s += 32)
      {
        for (j=0; j < 32; j++)
          if (s[j])
            break;
        if (j != 32)
          {
            p = line;
            *p = 0;
            snprintf (p, 10, "%05x: ", i);
            p += strlen (p);
            for (j=0; j < 32; j++)
              {
                snprintf (p, 10, "%02x", s[j]);
                p += strlen (p);
              }
            strcat (p, " |");
            p += strlen (p);
            for (j=0; j < 32; j++)
              {
                if (s[j] >= 32 && s[j] < 127)
                  *p = s[j];
                else
                  *p = '.';
                p++;
              }
            strcat (p, "|");
            OutputDebugStringA (line);
          }
      }
  }


  {
    wchar_t buf[1024];

    swprintf(buf, 1024,
             L"stringsize=%d\r\n$0=%s\r\n$1=%s\r\n$R0=%s\r\n$R1=%s\r\n",
            string_size,
            getuservariable(INST_0),
            getuservariable(INST_1),
            getuservariable(INST_R0),
            getuservariable(INST_R1));
    MessageBoxW(g_hwndParent,buf,0,MB_OK);

    swprintf (buf, 1024,
             L"autoclose    =%d\r\n"
             "all_user_var =%d\r\n"
             "exec_error   =%d\r\n"
             "abort        =%d\r\n"
             "exec_reboot  =%d\r\n"
             "reboot_called=%d\r\n"
	     "api_version  =%d\r\n"
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
             extra->exec_flags->plugin_api_version,
             extra->exec_flags->silent,
             extra->exec_flags->instdir_error,
             extra->exec_flags->rtl,
             extra->exec_flags->errlvl);
    MessageBoxW(g_hwndParent,buf,0,MB_OK);
  }
}



void __declspec(dllexport)
runonce (HWND hwndParent, int string_size, LPTSTR variables,
         stack_t **stacktop, extra_parameters_t *extra)
{
  LPCWSTR result;

  g_hwndParent = hwndParent;
  EXDLL_INIT();

  CreateMutexW (NULL, 0, getuservariable(INST_R0));
  result = GetLastError ()? L"1" : L"0";
  setuservariable (INST_R0, result);
}



#ifdef ENABLE_SOUND_GADGET
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
#endif /*ENABLE_SOUND_GADGET*/


#ifdef ENABLE_SPLASH_GADGET
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
#endif /*ENABLE_SPLASH_GADGET*/


#ifdef ENABLE_SERVICE_MANAGEMENT
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
#endif /*ENABLE_SERVICE_MANAGEMENT*/


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
  LPCWSTR wcmdline;
  char *cmdline;
  char *begin = NULL;
  char *end = NULL;
  char mark;
  char *fname;
  char *ptr;
  FILE *conf;

  *keys = NULL;
  *values = NULL;

  cmdline = malloc (4096);
  if (!cmdline)
    return;

  wcmdline = getuservariable (INST_CMDLINE);
  *cmdline = 0;
  WideCharToMultiByte(CP_ACP, 0, wcmdline, -1, cmdline, 4095, NULL, NULL);
  if (!*cmdline)
    return;

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
  free (cmdline);
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
config_fetch (HWND hwndParent, int string_size, LPTSTR variables,
	      stack_t **stacktop, extra_parameters_t *extra)
{
  char key[256];
  int err = 0;
  char *value;

  g_hwndParent = hwndParent;
  EXDLL_INIT();

  /* The expected stack layout: key.  */
  if (PopStringNA (key, sizeof (key)))
    err = 1;
  if (err)
    {
      setuservariable (INST_R0, L"");
      return;
    }

  value = config_lookup (key);

  SetUserVariableA (INST_R0, value == NULL ? "" : value);
  return;
}


void __declspec(dllexport)
config_fetch_bool (HWND hwndParent, int string_size, LPTSTR variables,
		   stack_t **stacktop, extra_parameters_t *extra)
{
  char key[256];
  int err = 0;
  char *value;
  int result;

  g_hwndParent = hwndParent;
  EXDLL_INIT();

  /* The expected stack layout: key.  */
  if (PopStringNA (key, sizeof (key)))
    err = 1;
  if (err)
    {
      setuservariable (INST_R0, L"");
      return;
    }

  value = config_lookup (key);
  if (value == NULL || *value == '\0')
    {
      setuservariable (INST_R0, L"");
      return;
    }

  result = 0;
  if (!strcasecmp (value, "true")
      || !strcasecmp (value, "yes")
      || atoi (value) != 0)
    result = 1;

  SetUserVariableA (INST_R0, result == 0 ? "0" : "1");
  return;
}


/* Return a string from the Win32 Registry or NULL in case of error.
   Caller must release the return value.  A NULL for root is an alias
   for HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE in turn.  */
static wchar_t *
read_w32_registry_string (HKEY root, const wchar_t *dir, const wchar_t *name)
{
  HKEY root_key;
  HKEY key_handle;
  DWORD n1, nbytes, type;
  wchar_t *result = NULL;

  root_key = root;
  if (!root_key)
    root_key = HKEY_CURRENT_USER;

  if (RegOpenKeyExW (root_key, dir, 0, KEY_READ, &key_handle))
    {
      if (root)
	return NULL; /* no need for a RegClose, so return direct */
      /* It seems to be common practise to fall back to HKLM. */
      if (RegOpenKeyExW (HKEY_LOCAL_MACHINE, dir, 0, KEY_READ, &key_handle))
	return NULL; /* still no need for a RegClose, so return direct */
    }

  nbytes = 1;
  if (RegQueryValueExW (key_handle, name, 0, NULL, NULL, &nbytes))
    {
      if (root)
        goto leave;
      /* Try to fallback to HKLM also for a missing value.  */
      RegCloseKey (key_handle);
      if (RegOpenKeyExW (HKEY_LOCAL_MACHINE, dir, 0, KEY_READ, &key_handle))
        return NULL; /* Nope.  */
      if (RegQueryValueExW (key_handle, name, 0, NULL, NULL, &nbytes))
        goto leave;
  }

  result = calloc ((n1=nbytes+1), sizeof *result);
  if (!result)
    goto leave;

  if (RegQueryValueExW (key_handle, name, 0, &type,
                        (unsigned char *)result, &n1))
    {
      free (result);
      result = NULL;
      goto leave;
    }
  result[nbytes] = 0; /* Make sure it is really a string  */

 leave:
  RegCloseKey (key_handle);
  return result;
}


/* Registry keys for PATH for HKLM and HKCU.  */
#define ENV_HK HKEY_LOCAL_MACHINE
#define ENV_REG     L"SYSTEM\\CurrentControlSet\\Control\\" \
                           "Session Manager\\Environment"
#define ENV_HK_USER HKEY_CURRENT_USER
#define ENV_REG_USER L"Environment"

/* Due to a bug in Windows7 (kb 2685893) we better put a lower limit
 * than 8191 on the maximum length of the PATH variable.  Note, that
 * depending on the used toolchain we used to had a 259 byte limit in
 * the past.
 * [wk 2023-04-24]: Can this be lifted now that we use the wchar_t API?
 */
#define PATH_LENGTH_LIMIT 2047

void __declspec(dllexport)
path_add (HWND hwndParent, int string_size, LPTSTR variables,
	  stack_t **stacktop, extra_parameters_t *extra)
{
  wchar_t dir[PATH_LENGTH_LIMIT];
  wchar_t is_user_install[2];
  wchar_t *path;
  wchar_t *path_new;
  size_t path_new_size;
  wchar_t *comp;
  const wchar_t delims[] = L";";
  int is_user;
  HKEY key_handle = 0;
  HKEY root_key;
  const wchar_t *env_reg;
  /* wchar_t *tokctx;     Context var for wcstok - not yet needed.  */

  g_hwndParent = hwndParent;
  EXDLL_INIT();

  setuservariable (INST_R0, L"0");  /* Default return value.  */

  /* The expected stack layout: path component.  */
  if (popstringn (dir, COUNTOF (dir)))
    return;
  dir[COUNTOF(dir)-1] = 0;

  /* The expected stack layout: HKEY component.  */
  if (popstringn (is_user_install, COUNTOF (is_user_install)))
    return;
  is_user_install[COUNTOF(is_user_install)-1] = 0;

  if (!wcscmp (is_user_install, L"1"))
    {
      root_key = ENV_HK_USER;
      env_reg = ENV_REG_USER;
    }
  else
    {
      root_key = ENV_HK;
      env_reg = ENV_REG;
    }

  path = read_w32_registry_string (root_key, env_reg, L"Path");
  if (!path)
    {
      path = wcsdup (L"");
    }

  /* Old path plus semicolon plus dir plus terminating nul.  */
  path_new_size = wcslen (path) + 1 + wcslen (dir) + 1;
  if (path_new_size > PATH_LENGTH_LIMIT)
    {
      MessageBox (g_hwndParent, L"PATH env variable too big", 0, MB_OK);
      free (path);
      return;
    }

  path_new = calloc (path_new_size, sizeof *path_new);
  if (!path_new)
    {
      free (path);
      return;
    }

  wcscpy (path_new, path);
  wcscat (path_new, L";");
  wcscat (path_new, dir);

  /* Check if the directory already exists in the path.  */
  comp = wcstok (path, delims/*, &tokctx*/);
  do
    {
      /*       MessageBox (g_hwndParent, comp, 0, MB_OK); */
      if (!comp)
        break;

      if (!wcscmp (comp, dir))
	{
	  free (path);
	  free (path_new);
	  return;
	}
      comp = wcstok (NULL, delims/*, &tokctx*/);
    }
  while (comp);
  free (path);

  /* Update the path key.  */
  RegCreateKeyW (root_key, env_reg, &key_handle);
  RegSetValueEx (key_handle, L"Path", 0, REG_EXPAND_SZ,
		 (unsigned char*)path_new,
                 wcslen (path_new) * sizeof *path_new);
  RegCloseKey (key_handle);
  SetEnvironmentVariableW(L"PATH", path_new);
  free (path_new);

/*   MessageBox (g_hwndParent, "XXX 9", 0, MB_OK); */

  setuservariable (INST_R0, L"1");  /* success.  */
}


void __declspec(dllexport)
path_remove (HWND hwndParent, int string_size, LPTSTR variables,
	     stack_t **stacktop, extra_parameters_t *extra)
{
  wchar_t dir[PATH_LENGTH_LIMIT];
  wchar_t is_user_install[2];
  wchar_t *path;
  wchar_t *path_new;
  size_t path_new_size;
  wchar_t *comp;
  const wchar_t delims[] = L";";
  HKEY key_handle = 0;
  int changed = 0;
  int count = 0;
  HKEY root_key;
  const wchar_t *env_reg;
  /* wchar_t *tokctx;     Context var for wcstok - not yet needed.  */

  g_hwndParent = hwndParent;
  EXDLL_INIT();

  setuservariable (INST_R0, L"0");

  /* The expected stack layout: path component.  */
  if (popstringn (dir, COUNTOF (dir)))
    return;
  dir[COUNTOF(dir)-1] = 0;

  /* The expected stack layout: HKEY component.  */
  if (popstringn (is_user_install, COUNTOF (is_user_install)))
    return;
  is_user_install[COUNTOF(is_user_install)-1] = 0;

  if (!wcscmp (is_user_install, L"1"))
    {
      root_key = ENV_HK_USER;
      env_reg = ENV_REG_USER;
    }
  else
    {
      root_key = ENV_HK;
      env_reg = ENV_REG;
    }

  path = read_w32_registry_string (root_key, env_reg, L"Path");
  if (!path)
    return;

  /* Old path plus semicolon plus dir plus terminating nul.  */
  path_new_size = wcslen (path) + 1;
  path_new = calloc (path_new_size, sizeof *path_new);
  if (!path_new)
    {
      free (path);
      return;
    }

  /* Compose the new path.  */
  comp = wcstok (path, delims/*, &tokctx*/);
  do
    {
      if (wcscmp (comp, dir))
	{
	  if (count)
	    wcscat (path_new, L";");
	  wcscat (path_new, comp);
	  count++;
	}
      else
	changed = 1;
    }
  while ((comp = wcstok (NULL, delims/*, &tokctx*/)));
  free (path);

  if (!changed)
    {
      free (path_new);
      return;
    }

  /* Set a key for our CLSID.  */
  RegCreateKeyW (root_key, env_reg, &key_handle);
  RegSetValueEx (key_handle, L"Path", 0, REG_EXPAND_SZ,
		 (unsigned char*)path_new,
                 wcslen (path_new) * sizeof *path_new);
  RegCloseKey (key_handle);
  free (path_new);

  setuservariable (INST_R0, L"1");  /* success */
}


/** @brief Kill processes with the name name.
 *
 * This function tries to kill a process using ExitProcess.
 *
 * If it does not work it does not work. No return values.
 * The intention is to make an effort to kill something during
 * installation / uninstallation.
 *
 * The function signature is explained by NSIS.
 */
void __declspec(dllexport) __cdecl KillProc(HWND hwndParent,
                                            int string_size,
                                            char *variables,
                                            stack_t **stacktop)
{
  HANDLE h;
  PROCESSENTRY32 pe32;

  if (!stacktop || !*stacktop || !(*stacktop)->text)
    {
      ERRORPRINTF ("Invalid call to KillProc.");
      return;
    }


  h = CreateToolhelp32Snapshot (TH32CS_SNAPPROCESS, 0);
  if (h == INVALID_HANDLE_VALUE)
    {
      ERRORPRINTF ("Failed to create Toolhelp snapshot");
      return;
    }
  pe32.dwSize = sizeof (PROCESSENTRY32);

  if (!Process32First (h, &pe32))
    {
      ERRORPRINTF ("Failed to get first process");
      CloseHandle (h);
      return;
    }

  do
    {
      if (!wcscmp ((*stacktop)->text, pe32.szExeFile))
        {
          HANDLE hProc = OpenProcess (PROCESS_ALL_ACCESS, FALSE,
                                      pe32.th32ProcessID);
          if (!hProc)
            {
              ERRORPRINTF ("Failed to open process handle.");
              continue;
            }
          if (!TerminateProcess (hProc, 1))
            {
              ERRORPRINTF ("Failed to terminate process.");
            }
          CloseHandle (hProc);
        }
    }
  while (Process32Next (h, &pe32));
  CloseHandle (h);
}
