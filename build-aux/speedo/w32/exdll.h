#include <windows.h>
#ifndef ___NSIS_PLUGIN__H___
#define ___NSIS_PLUGIN__H___

#ifdef __cplusplus
extern "C" {
#endif

#ifndef NSISCALL
#  define NSISCALL __stdcall
#endif
#if !defined(_WIN32) && !defined(LPTSTR)
#  define LPTSTR TCHAR*
#endif



#ifndef NSISCALL
#  define NSISCALL WINAPI
#endif

#define EXDLL_INIT()           {  \
        g_stringsize=string_size; \
        g_stacktop=stacktop;      \
        g_variables=variables; }


enum NSPIM
{
  NSPIM_UNLOAD,
  NSPIM_GUIUNLOAD
};

typedef UINT_PTR (*NSISPLUGINCALLBACK)(enum NSPIM);

typedef struct _stack_t {
  struct _stack_t *next;
#ifdef UNICODE
  WCHAR text[1]; // this should be the length of g_stringsize when allocating
#else
  char text[1];
#endif
} stack_t;

typedef struct {
  int autoclose;
  int all_user_var;
  int exec_error;
  int abort;
  int exec_reboot;
  int reboot_called;
  int XXX_cur_insttype; /* deprecated */
  int plugin_api_version;   /* Used to be insttype_changed */
  int silent;
  int instdir_error;
  int rtl;
  int errlvl;
  int alter_reg_view;
  int status_update;
} exec_flags_t;

typedef struct {
  exec_flags_t *exec_flags;
  int (__stdcall *ExecuteCodeSegment)(int, HWND);
  void (__stdcall *validate_filename)(LPTSTR);
  int (__stdcall  *RegisterPluginCallback)(HMODULE, NSISPLUGINCALLBACK);
} extra_parameters_t;


enum
{
INST_0,         // $0
INST_1,         // $1
INST_2,         // $2
INST_3,         // $3
INST_4,         // $4
INST_5,         // $5
INST_6,         // $6
INST_7,         // $7
INST_8,         // $8
INST_9,         // $9
INST_R0,        // $R0
INST_R1,        // $R1
INST_R2,        // $R2
INST_R3,        // $R3
INST_R4,        // $R4
INST_R5,        // $R5
INST_R6,        // $R6
INST_R7,        // $R7
INST_R8,        // $R8
INST_R9,        // $R9
INST_CMDLINE,   // $CMDLINE
INST_INSTDIR,   // $INSTDIR
INST_OUTDIR,    // $OUTDIR
INST_EXEDIR,    // $EXEDIR
INST_LANG,      // $LANGUAGE
__INST_LAST
};

extern unsigned int g_stringsize;
extern stack_t **g_stacktop;
extern LPTSTR g_variables;

void NSISCALL pushstring(LPCTSTR str);
void NSISCALL pushintptr(INT_PTR value);
#define pushint(v) pushintptr((INT_PTR)(v))
int NSISCALL popstring(LPTSTR str); // 0 on success, 1 on empty stack
int NSISCALL popstringn(LPTSTR str, int maxlen); // with length limit, pass 0 for g_stringsize
INT_PTR NSISCALL popintptr();
#define popint() ( (int) popintptr() )
int NSISCALL popint_or(); // with support for or'ing (2|4|8)
INT_PTR NSISCALL nsishelper_str_to_ptr(LPCTSTR s);
#define myatoi(s) ( (int) nsishelper_str_to_ptr(s) ) // converts a string to an integer
unsigned int NSISCALL myatou(LPCTSTR s); // converts a string to an unsigned integer, decimal only
int NSISCALL myatoi_or(LPCTSTR s); // with support for or'ing (2|4|8)
LPTSTR NSISCALL getuservariable(const int varnum);
void NSISCALL setuservariable(const int varnum, LPCTSTR var);

#ifdef UNICODE
#define PopStringW(x) popstring(x)
#define PushStringW(x) pushstring(x)
#define SetUserVariableW(x,y) setuservariable(x,y)

int  NSISCALL PopStringA(LPSTR ansiStr);
int  NSISCALL PopStringNA(LPSTR ansiStr, int maxlen);
void NSISCALL PushStringA(LPCSTR ansiStr);
void NSISCALL GetUserVariableW(const int varnum, LPWSTR wideStr);
void NSISCALL GetUserVariableA(const int varnum, LPSTR ansiStr);
void NSISCALL SetUserVariableA(const int varnum, LPCSTR ansiStr);

#else
// ANSI defs

#define PopStringA(x) popstring(x)
#define PushStringA(x) pushstring(x)
#define SetUserVariableA(x,y) setuservariable(x,y)

int  NSISCALL PopStringW(LPWSTR wideStr);
void NSISCALL PushStringW(LPWSTR wideStr);
void NSISCALL GetUserVariableW(const int varnum, LPWSTR wideStr);
void NSISCALL GetUserVariableA(const int varnum, LPSTR ansiStr);
void NSISCALL SetUserVariableW(const int varnum, LPCWSTR wideStr);

#endif

#ifdef __cplusplus
}
#endif

#endif//!___NSIS_PLUGIN__H___

#ifndef COUNTOF
#define COUNTOF(a) (sizeof(a)/sizeof(a[0]))
#endif

// minimal tchar.h emulation
#ifndef _T
#  define _T TEXT
#endif
#if !defined(TCHAR) && !defined(_TCHAR_DEFINED)
#  ifdef UNICODE
#    define TCHAR WCHAR
#  else
#    define TCHAR char
#  endif
#endif

#define isvalidnsisvarindex(varnum) ( ((unsigned int)(varnum)) < (__INST_LAST) )

#define ERRORPRINTF(fmt, ...) \
  { \
    char buf[512]; \
    snprintf(buf, 511, "ERROR: " fmt, ##__VA_ARGS__); \
    buf[511] = '\0'; \
    OutputDebugStringA(buf); \
  }
