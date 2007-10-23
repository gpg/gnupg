/* rndw32.c  -	W32 entropy gatherer
 *	Copyright (C) 1999, 2000, 2001, 2002 Free Software Foundation, Inc.
 *	Copyright Peter Gutmann, Matt Thomlinson and Blake Coverett 1996-1999
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
 *
 *************************************************************************
 * The code here is based on code from Cryptlib 3.0 beta by Peter Gutmann.
 * Source file misc/rndwin32.c "Win32 Randomness-Gathering Code" with this
 * copyright notice:
 *
 * This module is part of the cryptlib continuously seeded pseudorandom
 * number generator.  For usage conditions, see lib_rand.c
 *
 * [Here is the notice from lib_rand.c, which is now called dev_sys.c]
 *
 * This module and the misc/rnd*.c modules represent the cryptlib
 * continuously seeded pseudorandom number generator (CSPRNG) as described in
 * my 1998 Usenix Security Symposium paper "The generation of random numbers
 * for cryptographic purposes".
 *
 * The CSPRNG code is copyright Peter Gutmann (and various others) 1996,
 * 1997, 1998, 1999, all rights reserved.  Redistribution of the CSPRNG
 * modules and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice
 *    and this permission notice in its entirety.
 *
 * 2. Redistributions in binary form must reproduce the copyright notice in
 *    the documentation and/or other materials provided with the distribution.
 *
 * 3. A copy of any bugfixes or enhancements made must be provided to the
 *    author, <pgut001@cs.auckland.ac.nz> to allow them to be added to the
 *    baseline version of the code.
 *
 * ALTERNATIVELY, the code may be distributed under the terms of the GNU
 * General Public License, version 2 or any later version published by the
 * Free Software Foundation, in which case the provisions of the GNU GPL are
 * required INSTEAD OF the above restrictions.
 *
 * Although not required under the terms of the GPL, it would still be nice if
 * you could make any changes available to the author to allow a consistent
 * code base to be maintained
 *************************************************************************
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <string.h>

#include <windows.h>


#include "types.h"
#include "util.h"
#include "algorithms.h"

#include "i18n.h"


static int debug_me;

/*
 * Definitions which are missing from the current GNU Windows32Api
 */

#ifndef TH32CS_SNAPHEAPLIST
#define TH32CS_SNAPHEAPLIST 1
#define TH32CS_SNAPPROCESS  2
#define TH32CS_SNAPTHREAD   4
#define TH32CS_SNAPMODULE   8
#define TH32CS_SNAPALL	    (1|2|4|8)
#define TH32CS_INHERIT	    0x80000000
#endif /*TH32CS_SNAPHEAPLIST*/

#ifndef IOCTL_DISK_PERFORMANCE
#define IOCTL_DISK_PERFORMANCE	0x00070020
#endif
#ifndef VER_PLATFORM_WIN32_WINDOWS
#define VER_PLATFORM_WIN32_WINDOWS 1
#endif

/* This used to be (6*8+5*4+8*2), but Peter Gutmann figured a larger
   value in a newer release. So we use a far larger value. */
#define SIZEOF_DISK_PERFORMANCE_STRUCT 256


typedef struct {
    DWORD dwSize;
    DWORD th32ProcessID;
    DWORD th32HeapID;
    DWORD dwFlags;
} HEAPLIST32;

typedef struct {
    DWORD dwSize;
    HANDLE hHandle;
    DWORD dwAddress;
    DWORD dwBlockSize;
    DWORD dwFlags;
    DWORD dwLockCount;
    DWORD dwResvd;
    DWORD th32ProcessID;
    DWORD th32HeapID;
} HEAPENTRY32;

typedef struct {
    DWORD dwSize;
    DWORD cntUsage;
    DWORD th32ProcessID;
    DWORD th32DefaultHeapID;
    DWORD th32ModuleID;
    DWORD cntThreads;
    DWORD th32ParentProcessID;
    LONG  pcPriClassBase;
    DWORD dwFlags;
    char  szExeFile[260];
} PROCESSENTRY32;

typedef struct {
    DWORD dwSize;
    DWORD cntUsage;
    DWORD th32ThreadID;
    DWORD th32OwnerProcessID;
    LONG  tpBasePri;
    LONG  tpDeltaPri;
    DWORD dwFlags;
} THREADENTRY32;

typedef struct {
    DWORD dwSize;
    DWORD th32ModuleID;
    DWORD th32ProcessID;
    DWORD GlblcntUsage;
    DWORD ProccntUsage;
    BYTE  *modBaseAddr;
    DWORD modBaseSize;
    HMODULE hModule;
    char  szModule[256];
    char  szExePath[260];
} MODULEENTRY32;



/* Type definitions for function pointers to call Toolhelp32 functions
 * used with the windows95 gatherer */
typedef BOOL (WINAPI * MODULEWALK) (HANDLE hSnapshot, MODULEENTRY32 *lpme);
typedef BOOL (WINAPI * THREADWALK) (HANDLE hSnapshot, THREADENTRY32 *lpte);
typedef BOOL (WINAPI * PROCESSWALK) (HANDLE hSnapshot, PROCESSENTRY32 *lppe);
typedef BOOL (WINAPI * HEAPLISTWALK) (HANDLE hSnapshot, HEAPLIST32 *lphl);
typedef BOOL (WINAPI * HEAPFIRST) (HEAPENTRY32 *lphe, DWORD th32ProcessID,
				   DWORD th32HeapID);
typedef BOOL (WINAPI * HEAPNEXT) (HEAPENTRY32 *lphe);
typedef HANDLE (WINAPI * CREATESNAPSHOT) (DWORD dwFlags, DWORD th32ProcessID);

/* Type definitions for function pointers to call NetAPI32 functions */
typedef DWORD (WINAPI * NETSTATISTICSGET) (LPWSTR szServer, LPWSTR szService,
					   DWORD dwLevel, DWORD dwOptions,
					   LPBYTE * lpBuffer);
typedef DWORD (WINAPI * NETAPIBUFFERSIZE) (LPVOID lpBuffer, LPDWORD cbBuffer);
typedef DWORD (WINAPI * NETAPIBUFFERFREE) (LPVOID lpBuffer);


/* When we query the performance counters, we allocate an initial buffer and
 * then reallocate it as required until RegQueryValueEx() stops returning
 * ERROR_MORE_DATA.  The following values define the initial buffer size and
 * step size by which the buffer is increased
 */
#define PERFORMANCE_BUFFER_SIZE 	65536	/* Start at 64K */
#define PERFORMANCE_BUFFER_STEP 	16384	/* Step by 16K */


static void
slow_gatherer_windows95( void (*add)(const void*, size_t, int), int requester )
{
    static CREATESNAPSHOT pCreateToolhelp32Snapshot = NULL;
    static MODULEWALK pModule32First = NULL;
    static MODULEWALK pModule32Next = NULL;
    static PROCESSWALK pProcess32First = NULL;
    static PROCESSWALK pProcess32Next = NULL;
    static THREADWALK pThread32First = NULL;
    static THREADWALK pThread32Next = NULL;
    static HEAPLISTWALK pHeap32ListFirst = NULL;
    static HEAPLISTWALK pHeap32ListNext = NULL;
    static HEAPFIRST pHeap32First = NULL;
    static HEAPNEXT pHeap32Next = NULL;
    HANDLE hSnapshot;


    /* initialize the Toolhelp32 function pointers */
    if ( !pCreateToolhelp32Snapshot ) {
	HANDLE hKernel;

	if ( debug_me )
	    log_debug ("rndw32#slow_gatherer_95: init toolkit\n" );

	/* Obtain the module handle of the kernel to retrieve the addresses
	 * of the Toolhelp32 functions */
	if ( ( !(hKernel = GetModuleHandle ("KERNEL32.DLL"))) ) {
	    g10_log_fatal ( "rndw32: can't get module handle\n" );
	}

	/* Now get pointers to the functions */
	pCreateToolhelp32Snapshot = (CREATESNAPSHOT) GetProcAddress (hKernel,
						  "CreateToolhelp32Snapshot");
	pModule32First = (MODULEWALK) GetProcAddress (hKernel, "Module32First");
	pModule32Next = (MODULEWALK) GetProcAddress (hKernel, "Module32Next");
	pProcess32First = (PROCESSWALK) GetProcAddress (hKernel,
							"Process32First");
	pProcess32Next = (PROCESSWALK) GetProcAddress (hKernel,
						       "Process32Next");
	pThread32First = (THREADWALK) GetProcAddress (hKernel, "Thread32First");
	pThread32Next = (THREADWALK) GetProcAddress (hKernel, "Thread32Next");
	pHeap32ListFirst = (HEAPLISTWALK) GetProcAddress (hKernel,
							  "Heap32ListFirst");
	pHeap32ListNext = (HEAPLISTWALK) GetProcAddress (hKernel,
							 "Heap32ListNext");
	pHeap32First = (HEAPFIRST) GetProcAddress (hKernel, "Heap32First");
	pHeap32Next = (HEAPNEXT) GetProcAddress (hKernel, "Heap32Next");

	if (	!pCreateToolhelp32Snapshot
	     || !pModule32First || !pModule32Next
	     || !pProcess32First || !pProcess32Next
	     || !pThread32First  || !pThread32Next
	     || !pHeap32ListFirst || !pHeap32ListNext
	     || !pHeap32First	  || !pHeap32Next  ) {
	    g10_log_fatal ( "rndw32: failed to get a toolhep function\n" );
	}
    }

    /* Take a snapshot of everything we can get to which is currently
     *	in the system */
    if ( !(hSnapshot = pCreateToolhelp32Snapshot (TH32CS_SNAPALL, 0)) ) {
	g10_log_fatal ( "rndw32: failed to take a toolhelp snapshot\n" );
    }

    /* Walk through the local heap */
    {	HEAPLIST32 hl32;
	hl32.dwSize = sizeof (HEAPLIST32);
	if (pHeap32ListFirst (hSnapshot, &hl32)) {
	    if ( debug_me )
		log_debug ("rndw32#slow_gatherer_95: walk heap\n" );
	    do {
		HEAPENTRY32 he32;

		/* First add the information from the basic Heaplist32 struct */
		(*add) ( &hl32, sizeof (hl32), requester );

		/* Now walk through the heap blocks getting information
		 * on each of them */
		he32.dwSize = sizeof (HEAPENTRY32);
		if (pHeap32First (&he32, hl32.th32ProcessID, hl32.th32HeapID)){
		    do {
			(*add) ( &he32, sizeof (he32), requester );
		    } while (pHeap32Next (&he32));
		}
	    } while (pHeap32ListNext (hSnapshot, &hl32));
	}
    }


    /* Walk through all processes */
    {	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof (PROCESSENTRY32);
	if (pProcess32First (hSnapshot, &pe32)) {
	    if ( debug_me )
		log_debug ("rndw32#slow_gatherer_95: walk processes\n" );
	    do {
		(*add) ( &pe32, sizeof (pe32), requester );
	    } while (pProcess32Next (hSnapshot, &pe32));
	}
    }

    /* Walk through all threads */
    {	THREADENTRY32 te32;
	te32.dwSize = sizeof (THREADENTRY32);
	if (pThread32First (hSnapshot, &te32)) {
	    if ( debug_me )
		log_debug ("rndw32#slow_gatherer_95: walk threads\n" );
	    do {
		(*add) ( &te32, sizeof (te32), requester );
	    } while (pThread32Next (hSnapshot, &te32));
	}
    }

    /* Walk through all modules associated with the process */
    {	MODULEENTRY32 me32;
	me32.dwSize = sizeof (MODULEENTRY32);
	if (pModule32First (hSnapshot, &me32)) {
	    if ( debug_me )
		log_debug ("rndw32#slow_gatherer_95: walk modules\n" );
	    do {
		(*add) ( &me32, sizeof (me32), requester );
	    } while (pModule32Next (hSnapshot, &me32));
	}
    }

    CloseHandle (hSnapshot);
}



static void
slow_gatherer_windowsNT( void (*add)(const void*, size_t, int), int requester )
{
    static int is_initialized = 0;
    static NETSTATISTICSGET pNetStatisticsGet = NULL;
    static NETAPIBUFFERSIZE pNetApiBufferSize = NULL;
    static NETAPIBUFFERFREE pNetApiBufferFree = NULL;
    static int is_workstation = 1;

    static int cbPerfData = PERFORMANCE_BUFFER_SIZE;
    PERF_DATA_BLOCK *pPerfData;
    HANDLE hDevice, hNetAPI32 = NULL;
    DWORD dwSize, status;
    int nDrive;

    if ( !is_initialized ) {
	HKEY hKey;

	if ( debug_me )
	    log_debug ("rndw32#slow_gatherer_nt: init toolkit\n" );
	/* Find out whether this is an NT server or workstation if necessary */
	if (RegOpenKeyEx (HKEY_LOCAL_MACHINE,
			  "SYSTEM\\CurrentControlSet\\Control\\ProductOptions",
			  0, KEY_READ, &hKey) == ERROR_SUCCESS) {
	    BYTE szValue[32];
	    dwSize = sizeof (szValue);

	    if ( debug_me )
		log_debug ("rndw32#slow_gatherer_nt: check product options\n" );
	    status = RegQueryValueEx (hKey, "ProductType", 0, NULL,
				      szValue, &dwSize);
	    if (status == ERROR_SUCCESS
                && ascii_strcasecmp (szValue, "WinNT")) {
		/* Note: There are (at least) three cases for ProductType:
		 * WinNT = NT Workstation, ServerNT = NT Server, LanmanNT =
		 * NT Server acting as a Domain Controller */
		is_workstation = 0;
		if ( debug_me )
		    log_debug ("rndw32: this is a NT server\n");
	    }
	    RegCloseKey (hKey);
	}

	/* Initialize the NetAPI32 function pointers if necessary */
	if ( (hNetAPI32 = LoadLibrary ("NETAPI32.DLL")) ) {
	    if ( debug_me )
		log_debug ("rndw32#slow_gatherer_nt: netapi32 loaded\n" );
	    pNetStatisticsGet = (NETSTATISTICSGET) GetProcAddress (hNetAPI32,
						       "NetStatisticsGet");
	    pNetApiBufferSize = (NETAPIBUFFERSIZE) GetProcAddress (hNetAPI32,
						       "NetApiBufferSize");
	    pNetApiBufferFree = (NETAPIBUFFERFREE) GetProcAddress (hNetAPI32,
						       "NetApiBufferFree");

	    if ( !pNetStatisticsGet
		 || !pNetApiBufferSize || !pNetApiBufferFree ) {
		FreeLibrary (hNetAPI32);
		hNetAPI32 = NULL;
		g10_log_debug ("rndw32: No NETAPI found\n" );
	    }
	}

	is_initialized = 1;
    }

    /* Get network statistics.	Note: Both NT Workstation and NT Server by
     * default will be running both the workstation and server services.  The
     * heuristic below is probably useful though on the assumption that the
     * majority of the network traffic will be via the appropriate service.
     * In any case the network statistics return almost no randomness */
    {	LPBYTE lpBuffer;
	if (hNetAPI32 && !pNetStatisticsGet (NULL,
			   is_workstation ? L"LanmanWorkstation" :
			   L"LanmanServer", 0, 0, &lpBuffer) ) {
	    if ( debug_me )
		log_debug ("rndw32#slow_gatherer_nt: get netstats\n" );
	    pNetApiBufferSize (lpBuffer, &dwSize);
	    (*add) ( lpBuffer, dwSize,requester );
	    pNetApiBufferFree (lpBuffer);
	}
    }

    /* Get disk I/O statistics for all the hard drives */
    for (nDrive = 0;; nDrive++) {
        char diskPerformance[SIZEOF_DISK_PERFORMANCE_STRUCT];
	char szDevice[50];

	/* Check whether we can access this device */
	sprintf (szDevice, "\\\\.\\PhysicalDrive%d", nDrive);
	hDevice = CreateFile (szDevice, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
			      NULL, OPEN_EXISTING, 0, NULL);
	if (hDevice == INVALID_HANDLE_VALUE)
	    break;

	/* Note: This only works if you have turned on the disk performance
	 * counters with 'diskperf -y'.  These counters are off by default */
	if (DeviceIoControl (hDevice, IOCTL_DISK_PERFORMANCE, NULL, 0,
			     diskPerformance, SIZEOF_DISK_PERFORMANCE_STRUCT,
			     &dwSize, NULL))
	{
	    if ( debug_me )
		log_debug ("rndw32#slow_gatherer_nt: iostats drive %d\n",
								  nDrive );
	    (*add) (diskPerformance, dwSize, requester );
	}
	else {
	    log_info ("NOTE: you should run 'diskperf -y' "
		      "to enable the disk statistics\n");
	}
	CloseHandle (hDevice);
    }

#if 0 /* we don't need this in GnuPG  */
    /* Wait for any async keyset driver binding to complete.  You may be
     * wondering what this call is doing here... the reason it's necessary is
     * because RegQueryValueEx() will hang indefinitely if the async driver
     * bind is in progress.  The problem occurs in the dynamic loading and
     * linking of driver DLL's, which work as follows:
     *
     * hDriver = LoadLibrary( DRIVERNAME );
     * pFunction1 = ( TYPE_FUNC1 ) GetProcAddress( hDriver, NAME_FUNC1 );
     * pFunction2 = ( TYPE_FUNC1 ) GetProcAddress( hDriver, NAME_FUNC2 );
     *
     * If RegQueryValueEx() is called while the GetProcAddress()'s are in
     * progress, it will hang indefinitely.  This is probably due to some
     * synchronisation problem in the NT kernel where the GetProcAddress()
     * calls affect something like a module reference count or function
     * reference count while RegQueryValueEx() is trying to take a snapshot
     * of the statistics, which include the reference counts.  Because of
     * this, we have to wait until any async driver bind has completed
     * before we can call RegQueryValueEx() */
    waitSemaphore (SEMAPHORE_DRIVERBIND);
#endif

    /* Get information from the system performance counters.  This can take
     * a few seconds to do.  In some environments the call to
     * RegQueryValueEx() can produce an access violation at some random time
     * in the future, adding a short delay after the following code block
     * makes the problem go away.  This problem is extremely difficult to
     * reproduce, I haven't been able to get it to occur despite running it
     * on a number of machines.  The best explanation for the problem is that
     * on the machine where it did occur, it was caused by an external driver
     * or other program which adds its own values under the
     * HKEY_PERFORMANCE_DATA key.  The NT kernel calls the required external
     * modules to map in the data, if there's a synchronisation problem the
     * external module would write its data at an inappropriate moment,
     * causing the access violation.  A low-level memory checker indicated
     * that ExpandEnvironmentStrings() in KERNEL32.DLL, called an
     * interminable number of calls down inside RegQueryValueEx(), was
     * overwriting memory (it wrote twice the allocated size of a buffer to a
     * buffer allocated by the NT kernel).  This may be what's causing the
     * problem, but since it's in the kernel there isn't much which can be
     * done.
     *
     * In addition to these problems the code in RegQueryValueEx() which
     * estimates the amount of memory required to return the performance
     * counter information isn't very accurate, since it always returns a
     * worst-case estimate which is usually nowhere near the actual amount
     * required.  For example it may report that 128K of memory is required,
     * but only return 64K of data */
    {	pPerfData =  xmalloc (cbPerfData);
	for (;;) {
	    dwSize = cbPerfData;
	    if ( debug_me )
		log_debug ("rndw32#slow_gatherer_nt: get perf data\n" );
	    status = RegQueryValueEx (HKEY_PERFORMANCE_DATA, "Global", NULL,
				      NULL, (LPBYTE) pPerfData, &dwSize);
	    if (status == ERROR_SUCCESS) {
		if (!memcmp (pPerfData->Signature, L"PERF", 8)) {
		    (*add) ( pPerfData, dwSize, requester );
		}
		else
		    g10_log_debug ( "rndw32: no PERF signature\n");
		break;
	    }
	    else if (status == ERROR_MORE_DATA) {
		cbPerfData += PERFORMANCE_BUFFER_STEP;
		pPerfData = xrealloc (pPerfData, cbPerfData);
	    }
	    else {
		g10_log_debug ( "rndw32: get performance data problem\n");
		break;
	    }
	}
	xfree (pPerfData);
    }
    /* Although this isn't documented in the Win32 API docs, it's necessary
       to explicitly close the HKEY_PERFORMANCE_DATA key after use (it's
       implicitly opened on the first call to RegQueryValueEx()).  If this
       isn't done then any system components which provide performance data
       can't be removed or changed while the handle remains active */
    RegCloseKey (HKEY_PERFORMANCE_DATA);
}


int
rndw32_gather_random (void (*add)(const void*, size_t, int), int requester,
                      size_t length, int level )
{
    static int is_initialized;
    static int is_windowsNT, has_toolhelp;


    if( !level )
	return 0;
    /* We don't differentiate between level 1 and 2 here because
     * there is no nternal entropy pool as a scary resource.  It may
     * all work slower, but because our entropy source will never
     * block but deliver some not easy to measure entropy, we assume level 2
     */


    if ( !is_initialized ) {
	OSVERSIONINFO osvi = { sizeof( osvi ) };
	DWORD platform;

	GetVersionEx( &osvi );
	platform = osvi.dwPlatformId;
        is_windowsNT = platform == VER_PLATFORM_WIN32_NT;
        has_toolhelp = (platform == VER_PLATFORM_WIN32_WINDOWS
                        || (is_windowsNT && osvi.dwMajorVersion >= 5));

	if ( platform == VER_PLATFORM_WIN32s ) {
	    g10_log_fatal("can't run on a W32s platform\n" );
	}
	is_initialized = 1;
	if ( debug_me )
	    log_debug ("rndw32#gather_random: platform=%d\n", (int)platform );
    }


    if ( debug_me )
	log_debug ("rndw32#gather_random: req=%d len=%u lvl=%d\n",
			   requester, (unsigned int)length, level );

    if ( has_toolhelp ) {
        slow_gatherer_windows95 ( add, requester );
    }
    if ( is_windowsNT ) {
        slow_gatherer_windowsNT ( add, requester );
    }

    return 0;
}



int
rndw32_gather_random_fast( void (*add)(const void*, size_t, int), int requester )
{
    static int addedFixedItems = 0;

    if ( debug_me )
	log_debug ("rndw32#gather_random_fast: req=%d\n", requester );

    /* Get various basic pieces of system information: Handle of active
     * window, handle of window with mouse capture, handle of clipboard owner
     * handle of start of clpboard viewer list, pseudohandle of current
     * process, current process ID, pseudohandle of current thread, current
     * thread ID, handle of desktop window, handle  of window with keyboard
     * focus, whether system queue has any events, cursor position for last
     * message, 1 ms time for last message, handle of window with clipboard
     * open, handle of process heap, handle of procs window station, types of
     * events in input queue, and milliseconds since Windows was started */
    {	byte buffer[20*sizeof(ulong)], *bufptr;
	bufptr = buffer;
#define ADD(f)  do { ulong along = (ulong)(f);		      \
			   memcpy (bufptr, &along, sizeof (along) );  \
			   bufptr += sizeof (along); } while (0)
	ADD ( GetActiveWindow ());
	ADD ( GetCapture ());
	ADD ( GetClipboardOwner ());
	ADD ( GetClipboardViewer ());
	ADD ( GetCurrentProcess ());
	ADD ( GetCurrentProcessId ());
	ADD ( GetCurrentThread ());
	ADD ( GetCurrentThreadId ());
	ADD ( GetDesktopWindow ());
	ADD ( GetFocus ());
	ADD ( GetInputState ());
	ADD ( GetMessagePos ());
	ADD ( GetMessageTime ());
	ADD ( GetOpenClipboardWindow ());
	ADD ( GetProcessHeap ());
	ADD ( GetProcessWindowStation ());
	ADD ( GetQueueStatus (QS_ALLEVENTS));
	ADD ( GetTickCount ());

	assert ( bufptr-buffer < sizeof (buffer) );
	(*add) ( buffer, bufptr-buffer, requester );
#undef ADD
    }

    /* Get multiword system information: Current caret position, current
     * mouse cursor position */
    {	POINT point;
	GetCaretPos (&point);
	(*add) ( &point, sizeof (point), requester );
	GetCursorPos (&point);
	(*add) ( &point, sizeof (point), requester );
    }

    /* Get percent of memory in use, bytes of physical memory, bytes of free
     * physical memory, bytes in paging file, free bytes in paging file, user
     * bytes of address space, and free user bytes */
    {	MEMORYSTATUS memoryStatus;
	memoryStatus.dwLength = sizeof (MEMORYSTATUS);
	GlobalMemoryStatus (&memoryStatus);
	(*add) ( &memoryStatus, sizeof (memoryStatus), requester );
    }

    /* Get thread and process creation time, exit time, time in kernel mode,
       and time in user mode in 100ns intervals */
    {	HANDLE handle;
	FILETIME creationTime, exitTime, kernelTime, userTime;
	DWORD minimumWorkingSetSize, maximumWorkingSetSize;

	handle = GetCurrentThread ();
	GetThreadTimes (handle, &creationTime, &exitTime,
					       &kernelTime, &userTime);
	(*add) ( &creationTime, sizeof (creationTime), requester );
	(*add) ( &exitTime, sizeof (exitTime), requester );
	(*add) ( &kernelTime, sizeof (kernelTime), requester );
	(*add) ( &userTime, sizeof (userTime), requester );

	handle = GetCurrentProcess ();
	GetProcessTimes (handle, &creationTime, &exitTime,
						&kernelTime, &userTime);
	(*add) ( &creationTime, sizeof (creationTime), requester );
	(*add) ( &exitTime, sizeof (exitTime), requester );
	(*add) ( &kernelTime, sizeof (kernelTime), requester );
	(*add) ( &userTime, sizeof (userTime), requester );

	/* Get the minimum and maximum working set size for the
           current process */
	GetProcessWorkingSetSize (handle, &minimumWorkingSetSize,
					  &maximumWorkingSetSize);
	(*add) ( &minimumWorkingSetSize,
				   sizeof (minimumWorkingSetSize), requester );
	(*add) ( &maximumWorkingSetSize,
				   sizeof (maximumWorkingSetSize), requester );
    }


    /* The following are fixed for the lifetime of the process so we only
     * add them once */
    if (!addedFixedItems) {
	STARTUPINFO startupInfo;

	/* Get name of desktop, console window title, new window position and
	 * size, window flags, and handles for stdin, stdout, and stderr */
	startupInfo.cb = sizeof (STARTUPINFO);
	GetStartupInfo (&startupInfo);
	(*add) ( &startupInfo, sizeof (STARTUPINFO), requester );
	addedFixedItems = 1;
    }

    /* The performance of QPC varies depending on the architecture it's
     * running on and on the OS.  Under NT it reads the CPU's 64-bit timestamp
     * counter (at least on a Pentium and newer '486's, it hasn't been tested
     * on anything without a TSC), under Win95 it reads the 1.193180 MHz PIC
     * timer.  There are vague mumblings in the docs that it may fail if the
     * appropriate hardware isn't available (possibly '386's or MIPS machines
     * running NT), but who's going to run NT on a '386? */
    {	LARGE_INTEGER performanceCount;
	if (QueryPerformanceCounter (&performanceCount)) {
	    if ( debug_me )
		log_debug ("rndw32#gather_random_fast: perf data\n");
	    (*add) (&performanceCount, sizeof (performanceCount), requester);
	}
	else { /* Millisecond accuracy at best... */
	    DWORD aword = GetTickCount ();
	    (*add) (&aword, sizeof (aword), requester );
	}
    }

    return 0;
}
