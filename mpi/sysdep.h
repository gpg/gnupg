#ifdef C_UNDERSCORE

#if __STDC__
#define C_SYMBOL_NAME(name) _##name
#else
#define C_SYMBOL_NAME(name) _/**/name
#endif

#else /* C_UNDERSCORE */

#define C_SYMBOL_NAME(name) name

#endif /* C_UNDERSCORE */
