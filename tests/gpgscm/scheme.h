/* SCHEME.H */

#ifndef _SCHEME_H
#define _SCHEME_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Default values for #define'd symbols
 */
#ifndef STANDALONE       /* If used as standalone interpreter */
# define STANDALONE 1
#endif

#ifndef _MSC_VER
# define USE_STRCASECMP 1
# ifndef USE_STRLWR
#   define USE_STRLWR 1
# endif
# define SCHEME_EXPORT
#else
# define USE_STRCASECMP 0
# define USE_STRLWR 0
# ifdef _SCHEME_SOURCE
#  define SCHEME_EXPORT __declspec(dllexport)
# else
#  define SCHEME_EXPORT __declspec(dllimport)
# endif
#endif

#if USE_NO_FEATURES
# define USE_MATH 0
# define USE_CHAR_CLASSIFIERS 0
# define USE_ASCII_NAMES 0
# define USE_STRING_PORTS 0
# define USE_ERROR_HOOK 0
# define USE_TRACING 0
# define USE_COLON_HOOK 0
# define USE_COMPILE_HOOK 0
# define USE_DL 0
# define USE_PLIST 0
# define USE_SMALL_INTEGERS 0
# define USE_HISTORY 0
#endif


#if USE_DL
# define USE_INTERFACE 1
#endif


#ifndef USE_MATH         /* If math support is needed */
# define USE_MATH 1
#endif

#ifndef USE_CHAR_CLASSIFIERS  /* If char classifiers are needed */
# define USE_CHAR_CLASSIFIERS 1
#endif

#ifndef USE_ASCII_NAMES  /* If extended escaped characters are needed */
# define USE_ASCII_NAMES 1
#endif

#ifndef USE_STRING_PORTS      /* Enable string ports */
# define USE_STRING_PORTS 1
#endif

#ifndef USE_TRACING
# define USE_TRACING 1
#endif

#ifndef USE_PLIST
# define USE_PLIST 0
#endif

/* Keep a history of function calls.  This enables a feature similar
 * to stack traces.  */
#ifndef USE_HISTORY
# define USE_HISTORY 1
#endif

/* To force system errors through user-defined error handling (see *error-hook*) */
#ifndef USE_ERROR_HOOK
# define USE_ERROR_HOOK 1
#endif

#ifndef USE_COLON_HOOK   /* Enable qualified qualifier */
# define USE_COLON_HOOK 1
#endif

/* Compile functions using *compile-hook*.  The default hook expands
 * macros.  */
#ifndef USE_COMPILE_HOOK
# define USE_COMPILE_HOOK 1
#endif

/* Enable faster opcode dispatch.  */
#ifndef USE_THREADED_CODE
# define USE_THREADED_CODE 1
#endif

/* Use a static set of cells to represent small numbers.  This set
 * notably includes all opcodes, and hence saves a cell reservation
 * during 's_save'.  */
#ifndef USE_SMALL_INTEGERS
# define USE_SMALL_INTEGERS 1
#endif

#ifndef USE_STRCASECMP   /* stricmp for Unix */
# define USE_STRCASECMP 0
#endif

#ifndef USE_STRLWR
# define USE_STRLWR 1
#endif

#ifndef STDIO_ADDS_CR    /* Define if DOS/Windows */
# define STDIO_ADDS_CR 0
#endif

#ifndef INLINE
# define INLINE
#endif

#ifndef USE_INTERFACE
# define USE_INTERFACE 0
#endif

#ifndef SHOW_ERROR_LINE   /* Show error line in file */
# define SHOW_ERROR_LINE 1
#endif

typedef struct scheme scheme;
typedef struct cell *pointer;

typedef void * (*func_alloc)(size_t);
typedef void (*func_dealloc)(void *);

/* table of functions required for foreign objects */
typedef struct foreign_object_vtable {
     void (*finalize)(scheme *sc, void *data);
     void (*to_string)(scheme *sc, char *out, size_t size, void *data);
} foreign_object_vtable;

/* num, for generic arithmetic */
typedef struct num {
     char is_fixnum;
     union {
          long ivalue;
          double rvalue;
     } value;
} num;

SCHEME_EXPORT scheme *scheme_init_new(void);
SCHEME_EXPORT scheme *scheme_init_new_custom_alloc(func_alloc malloc, func_dealloc free);
SCHEME_EXPORT int scheme_init(scheme *sc);
SCHEME_EXPORT int scheme_init_custom_alloc(scheme *sc, func_alloc, func_dealloc);
SCHEME_EXPORT void scheme_deinit(scheme *sc);
void scheme_set_input_port_file(scheme *sc, FILE *fin);
void scheme_set_input_port_string(scheme *sc, char *start, char *past_the_end);
SCHEME_EXPORT void scheme_set_output_port_file(scheme *sc, FILE *fin);
void scheme_set_output_port_string(scheme *sc, char *start, char *past_the_end);
SCHEME_EXPORT void scheme_load_file(scheme *sc, FILE *fin);
SCHEME_EXPORT void scheme_load_named_file(scheme *sc, FILE *fin, const char *filename);
SCHEME_EXPORT void scheme_load_string(scheme *sc, const char *cmd);
SCHEME_EXPORT void scheme_load_memory(scheme *sc, const char *buf, size_t len,
                                      const char *filename);
SCHEME_EXPORT pointer scheme_apply0(scheme *sc, const char *procname);
SCHEME_EXPORT pointer scheme_call(scheme *sc, pointer func, pointer args);
SCHEME_EXPORT pointer scheme_eval(scheme *sc, pointer obj);
void scheme_set_external_data(scheme *sc, void *p);
SCHEME_EXPORT void scheme_define(scheme *sc, pointer env, pointer symbol, pointer value);

typedef pointer (*foreign_func)(scheme *, pointer);

pointer _cons(scheme *sc, pointer a, pointer b, int immutable);
pointer mk_integer(scheme *sc, long num);
pointer mk_real(scheme *sc, double num);
pointer mk_symbol(scheme *sc, const char *name);
pointer gensym(scheme *sc);
pointer mk_string(scheme *sc, const char *str);
pointer mk_counted_string(scheme *sc, const char *str, int len);
pointer mk_empty_string(scheme *sc, int len, char fill);
pointer mk_character(scheme *sc, int c);
pointer mk_foreign_func(scheme *sc, foreign_func f);
pointer mk_foreign_object(scheme *sc, const foreign_object_vtable *vtable, void *data);
void putstr(scheme *sc, const char *s);
int list_length(scheme *sc, pointer a);
int eqv(pointer a, pointer b);


#if USE_INTERFACE
struct scheme_interface {
  void (*scheme_define)(scheme *sc, pointer env, pointer symbol, pointer value);
  pointer (*cons)(scheme *sc, pointer a, pointer b);
  pointer (*immutable_cons)(scheme *sc, pointer a, pointer b);
  pointer (*reserve_cells)(scheme *sc, int n);
  pointer (*mk_integer)(scheme *sc, long num);
  pointer (*mk_real)(scheme *sc, double num);
  pointer (*mk_symbol)(scheme *sc, const char *name);
  pointer (*gensym)(scheme *sc);
  pointer (*mk_string)(scheme *sc, const char *str);
  pointer (*mk_counted_string)(scheme *sc, const char *str, int len);
  pointer (*mk_character)(scheme *sc, int c);
  pointer (*mk_vector)(scheme *sc, int len);
  pointer (*mk_foreign_func)(scheme *sc, foreign_func f);
  pointer (*mk_foreign_object)(scheme *sc, const foreign_object_vtable *vtable, void *data);
  const foreign_object_vtable *(*get_foreign_object_vtable)(pointer p);
  void *(*get_foreign_object_data)(pointer p);
  void (*putstr)(scheme *sc, const char *s);
  void (*putcharacter)(scheme *sc, int c);

  int (*is_string)(pointer p);
  char *(*string_value)(pointer p);
  int (*is_number)(pointer p);
  num (*nvalue)(pointer p);
  long (*ivalue)(pointer p);
  double (*rvalue)(pointer p);
  int (*is_integer)(pointer p);
  int (*is_real)(pointer p);
  int (*is_character)(pointer p);
  long (*charvalue)(pointer p);
  int (*is_list)(scheme *sc, pointer p);
  int (*is_vector)(pointer p);
  int (*list_length)(scheme *sc, pointer vec);
  long (*vector_length)(pointer vec);
  void (*fill_vector)(pointer vec, pointer elem);
  pointer (*vector_elem)(pointer vec, int ielem);
  pointer (*set_vector_elem)(pointer vec, int ielem, pointer newel);
  int (*is_port)(pointer p);

  int (*is_pair)(pointer p);
  pointer (*pair_car)(pointer p);
  pointer (*pair_cdr)(pointer p);
  pointer (*set_car)(pointer p, pointer q);
  pointer (*set_cdr)(pointer p, pointer q);

  int (*is_symbol)(pointer p);
  char *(*symname)(pointer p);

  int (*is_syntax)(pointer p);
  int (*is_proc)(pointer p);
  int (*is_foreign)(pointer p);
  char *(*syntaxname)(pointer p);
  int (*is_closure)(pointer p);
  int (*is_macro)(pointer p);
  pointer (*closure_code)(pointer p);
  pointer (*closure_env)(pointer p);

  int (*is_continuation)(pointer p);
  int (*is_promise)(pointer p);
  int (*is_environment)(pointer p);
  int (*is_immutable)(pointer p);
  void (*setimmutable)(pointer p);
  void (*load_file)(scheme *sc, FILE *fin);
  void (*load_string)(scheme *sc, const char *input);
  pointer (*mk_port_from_file)(scheme *sc, FILE *f, int kind);
};
#endif

#if !STANDALONE
typedef struct scheme_registerable
{
  foreign_func  f;
  const char *  name;
}
scheme_registerable;

void scheme_register_foreign_func_list(scheme * sc,
                                       scheme_registerable * list,
                                       int n);

#endif /* !STANDALONE */

#ifdef __cplusplus
}
#endif

#endif


/*
Local variables:
c-file-style: "k&r"
End:
*/
