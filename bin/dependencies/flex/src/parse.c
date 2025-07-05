/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2021 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output, and Bison version.  */
#define YYBISON 30802

/* Bison version string.  */
#define YYBISON_VERSION "3.8.2"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1




/* First part of user prologue.  */
#line 35 "parse.y"

/*  Copyright (c) 1990 The Regents of the University of California. */
/*  All rights reserved. */

/*  This code is derived from software contributed to Berkeley by */
/*  Vern Paxson. */

/*  The United States Government has rights in this work pursuant */
/*  to contract no. DE-AC03-76SF00098 between the United States */
/*  Department of Energy and the University of California. */

/*  This file is part of flex. */

/*  Redistribution and use in source and binary forms, with or without */
/*  modification, are permitted provided that the following conditions */
/*  are met: */

/*  1. Redistributions of source code must retain the above copyright */
/*     notice, this list of conditions and the following disclaimer. */
/*  2. Redistributions in binary form must reproduce the above copyright */
/*     notice, this list of conditions and the following disclaimer in the */
/*     documentation and/or other materials provided with the distribution. */

/*  Neither the name of the University nor the names of its contributors */
/*  may be used to endorse or promote products derived from this software */
/*  without specific prior written permission. */

/*  THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR */
/*  IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED */
/*  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR */
/*  PURPOSE. */

#include "flexdef.h"
#include "tables.h"

int pat, scnum, eps, headcnt, trailcnt, lastchar, i, rulelen;
static int currccl;
bool trlcontxt;
static bool sc_is_exclusive, cclsorted, varlength, variable_trail_rule;

int *scon_stk;
int scon_stk_ptr;

static int madeany = false;  /* whether we've made the '.' character class */
static int ccldot, cclany;
int previous_continued_action;	/* whether the previous rule's action was '|' */

#define format_warn3(fmt, a1, a2) \
	do{ \
        char fw3_msg[MAXLINE];\
        snprintf( fw3_msg, MAXLINE,(fmt), (a1), (a2) );\
        lwarn( fw3_msg );\
	}while(0)

/* Expand a POSIX character class expression. */
#define CCL_EXPR(func) \
	do{ \
	int c; \
	for ( c = 0; c < ctrl.csize; ++c ) \
		if ( isascii(c) && func(c) ) \
			ccladd( currccl, c ); \
	}while(0)

/* negated class */
#define CCL_NEG_EXPR(func) \
	do{ \
	int c; \
	for ( c = 0; c < ctrl.csize; ++c ) \
		if ( !func(c) ) \
			ccladd( currccl, c ); \
	}while(0)

/* While POSIX defines isblank(), it's not ANSI C. */
#define IS_BLANK(c) ((c) == ' ' || (c) == '\t')

/* On some over-ambitious machines, such as DEC Alpha's, the default
 * token type is "long" instead of "int"; this leads to problems with
 * declaring yylval in flexdef.h.  But so far, all the yacc's I've seen
 * wrap their definitions of YYSTYPE with "#ifndef YYSTYPE"'s, so the
 * following should ensure that the default token type is "int".
 */
#define YYSTYPE int


#line 156 "parse.c"

# ifndef YY_CAST
#  ifdef __cplusplus
#   define YY_CAST(Type, Val) static_cast<Type> (Val)
#   define YY_REINTERPRET_CAST(Type, Val) reinterpret_cast<Type> (Val)
#  else
#   define YY_CAST(Type, Val) ((Type) (Val))
#   define YY_REINTERPRET_CAST(Type, Val) ((Type) (Val))
#  endif
# endif
# ifndef YY_NULLPTR
#  if defined __cplusplus
#   if 201103L <= __cplusplus
#    define YY_NULLPTR nullptr
#   else
#    define YY_NULLPTR 0
#   endif
#  else
#   define YY_NULLPTR ((void*)0)
#  endif
# endif

/* Use api.header.include to #include this header
   instead of duplicating it here.  */
#ifndef YY_YY_PARSE_H_INCLUDED
# define YY_YY_PARSE_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yydebug;
#endif

/* Token kinds.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    YYEMPTY = -2,
    YYEOF = 0,                     /* "end of file"  */
    YYerror = 256,                 /* error  */
    YYUNDEF = 257,                 /* "invalid token"  */
    CHAR = 258,                    /* CHAR  */
    NUMBER = 259,                  /* NUMBER  */
    SECTEND = 260,                 /* SECTEND  */
    SCDECL = 261,                  /* SCDECL  */
    XSCDECL = 262,                 /* XSCDECL  */
    NAME = 263,                    /* NAME  */
    PREVCCL = 264,                 /* PREVCCL  */
    EOF_OP = 265,                  /* EOF_OP  */
    TOK_OPTION = 266,              /* TOK_OPTION  */
    TOK_OUTFILE = 267,             /* TOK_OUTFILE  */
    TOK_PREFIX = 268,              /* TOK_PREFIX  */
    TOK_YYCLASS = 269,             /* TOK_YYCLASS  */
    TOK_HEADER_FILE = 270,         /* TOK_HEADER_FILE  */
    TOK_EXTRA_TYPE = 271,          /* TOK_EXTRA_TYPE  */
    TOK_TABLES_FILE = 272,         /* TOK_TABLES_FILE  */
    TOK_YYLMAX = 273,              /* TOK_YYLMAX  */
    TOK_NUMERIC = 274,             /* TOK_NUMERIC  */
    TOK_YYDECL = 275,              /* TOK_YYDECL  */
    TOK_PREACTION = 276,           /* TOK_PREACTION  */
    TOK_POSTACTION = 277,          /* TOK_POSTACTION  */
    TOK_USERINIT = 278,            /* TOK_USERINIT  */
    TOK_EMIT = 279,                /* TOK_EMIT  */
    TOK_BUFSIZE = 280,             /* TOK_BUFSIZE  */
    TOK_YYTERMINATE = 281,         /* TOK_YYTERMINATE  */
    CCE_ALNUM = 282,               /* CCE_ALNUM  */
    CCE_ALPHA = 283,               /* CCE_ALPHA  */
    CCE_BLANK = 284,               /* CCE_BLANK  */
    CCE_CNTRL = 285,               /* CCE_CNTRL  */
    CCE_DIGIT = 286,               /* CCE_DIGIT  */
    CCE_GRAPH = 287,               /* CCE_GRAPH  */
    CCE_LOWER = 288,               /* CCE_LOWER  */
    CCE_PRINT = 289,               /* CCE_PRINT  */
    CCE_PUNCT = 290,               /* CCE_PUNCT  */
    CCE_SPACE = 291,               /* CCE_SPACE  */
    CCE_UPPER = 292,               /* CCE_UPPER  */
    CCE_XDIGIT = 293,              /* CCE_XDIGIT  */
    CCE_NEG_ALNUM = 294,           /* CCE_NEG_ALNUM  */
    CCE_NEG_ALPHA = 295,           /* CCE_NEG_ALPHA  */
    CCE_NEG_BLANK = 296,           /* CCE_NEG_BLANK  */
    CCE_NEG_CNTRL = 297,           /* CCE_NEG_CNTRL  */
    CCE_NEG_DIGIT = 298,           /* CCE_NEG_DIGIT  */
    CCE_NEG_GRAPH = 299,           /* CCE_NEG_GRAPH  */
    CCE_NEG_LOWER = 300,           /* CCE_NEG_LOWER  */
    CCE_NEG_PRINT = 301,           /* CCE_NEG_PRINT  */
    CCE_NEG_PUNCT = 302,           /* CCE_NEG_PUNCT  */
    CCE_NEG_SPACE = 303,           /* CCE_NEG_SPACE  */
    CCE_NEG_UPPER = 304,           /* CCE_NEG_UPPER  */
    CCE_NEG_XDIGIT = 305,          /* CCE_NEG_XDIGIT  */
    CCL_OP_DIFF = 306,             /* CCL_OP_DIFF  */
    CCL_OP_UNION = 307,            /* CCL_OP_UNION  */
    BEGIN_REPEAT_POSIX = 308,      /* BEGIN_REPEAT_POSIX  */
    END_REPEAT_POSIX = 309,        /* END_REPEAT_POSIX  */
    BEGIN_REPEAT_FLEX = 310,       /* BEGIN_REPEAT_FLEX  */
    END_REPEAT_FLEX = 311          /* END_REPEAT_FLEX  */
  };
  typedef enum yytokentype yytoken_kind_t;
#endif
/* Token kinds.  */
#define YYEMPTY -2
#define YYEOF 0
#define YYerror 256
#define YYUNDEF 257
#define CHAR 258
#define NUMBER 259
#define SECTEND 260
#define SCDECL 261
#define XSCDECL 262
#define NAME 263
#define PREVCCL 264
#define EOF_OP 265
#define TOK_OPTION 266
#define TOK_OUTFILE 267
#define TOK_PREFIX 268
#define TOK_YYCLASS 269
#define TOK_HEADER_FILE 270
#define TOK_EXTRA_TYPE 271
#define TOK_TABLES_FILE 272
#define TOK_YYLMAX 273
#define TOK_NUMERIC 274
#define TOK_YYDECL 275
#define TOK_PREACTION 276
#define TOK_POSTACTION 277
#define TOK_USERINIT 278
#define TOK_EMIT 279
#define TOK_BUFSIZE 280
#define TOK_YYTERMINATE 281
#define CCE_ALNUM 282
#define CCE_ALPHA 283
#define CCE_BLANK 284
#define CCE_CNTRL 285
#define CCE_DIGIT 286
#define CCE_GRAPH 287
#define CCE_LOWER 288
#define CCE_PRINT 289
#define CCE_PUNCT 290
#define CCE_SPACE 291
#define CCE_UPPER 292
#define CCE_XDIGIT 293
#define CCE_NEG_ALNUM 294
#define CCE_NEG_ALPHA 295
#define CCE_NEG_BLANK 296
#define CCE_NEG_CNTRL 297
#define CCE_NEG_DIGIT 298
#define CCE_NEG_GRAPH 299
#define CCE_NEG_LOWER 300
#define CCE_NEG_PRINT 301
#define CCE_NEG_PUNCT 302
#define CCE_NEG_SPACE 303
#define CCE_NEG_UPPER 304
#define CCE_NEG_XDIGIT 305
#define CCL_OP_DIFF 306
#define CCL_OP_UNION 307
#define BEGIN_REPEAT_POSIX 308
#define END_REPEAT_POSIX 309
#define BEGIN_REPEAT_FLEX 310
#define END_REPEAT_FLEX 311

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef int YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE yylval;


int yyparse (void);


#endif /* !YY_YY_PARSE_H_INCLUDED  */
/* Symbol kind.  */
enum yysymbol_kind_t
{
  YYSYMBOL_YYEMPTY = -2,
  YYSYMBOL_YYEOF = 0,                      /* "end of file"  */
  YYSYMBOL_YYerror = 1,                    /* error  */
  YYSYMBOL_YYUNDEF = 2,                    /* "invalid token"  */
  YYSYMBOL_CHAR = 3,                       /* CHAR  */
  YYSYMBOL_NUMBER = 4,                     /* NUMBER  */
  YYSYMBOL_SECTEND = 5,                    /* SECTEND  */
  YYSYMBOL_SCDECL = 6,                     /* SCDECL  */
  YYSYMBOL_XSCDECL = 7,                    /* XSCDECL  */
  YYSYMBOL_NAME = 8,                       /* NAME  */
  YYSYMBOL_PREVCCL = 9,                    /* PREVCCL  */
  YYSYMBOL_EOF_OP = 10,                    /* EOF_OP  */
  YYSYMBOL_TOK_OPTION = 11,                /* TOK_OPTION  */
  YYSYMBOL_TOK_OUTFILE = 12,               /* TOK_OUTFILE  */
  YYSYMBOL_TOK_PREFIX = 13,                /* TOK_PREFIX  */
  YYSYMBOL_TOK_YYCLASS = 14,               /* TOK_YYCLASS  */
  YYSYMBOL_TOK_HEADER_FILE = 15,           /* TOK_HEADER_FILE  */
  YYSYMBOL_TOK_EXTRA_TYPE = 16,            /* TOK_EXTRA_TYPE  */
  YYSYMBOL_TOK_TABLES_FILE = 17,           /* TOK_TABLES_FILE  */
  YYSYMBOL_TOK_YYLMAX = 18,                /* TOK_YYLMAX  */
  YYSYMBOL_TOK_NUMERIC = 19,               /* TOK_NUMERIC  */
  YYSYMBOL_TOK_YYDECL = 20,                /* TOK_YYDECL  */
  YYSYMBOL_TOK_PREACTION = 21,             /* TOK_PREACTION  */
  YYSYMBOL_TOK_POSTACTION = 22,            /* TOK_POSTACTION  */
  YYSYMBOL_TOK_USERINIT = 23,              /* TOK_USERINIT  */
  YYSYMBOL_TOK_EMIT = 24,                  /* TOK_EMIT  */
  YYSYMBOL_TOK_BUFSIZE = 25,               /* TOK_BUFSIZE  */
  YYSYMBOL_TOK_YYTERMINATE = 26,           /* TOK_YYTERMINATE  */
  YYSYMBOL_CCE_ALNUM = 27,                 /* CCE_ALNUM  */
  YYSYMBOL_CCE_ALPHA = 28,                 /* CCE_ALPHA  */
  YYSYMBOL_CCE_BLANK = 29,                 /* CCE_BLANK  */
  YYSYMBOL_CCE_CNTRL = 30,                 /* CCE_CNTRL  */
  YYSYMBOL_CCE_DIGIT = 31,                 /* CCE_DIGIT  */
  YYSYMBOL_CCE_GRAPH = 32,                 /* CCE_GRAPH  */
  YYSYMBOL_CCE_LOWER = 33,                 /* CCE_LOWER  */
  YYSYMBOL_CCE_PRINT = 34,                 /* CCE_PRINT  */
  YYSYMBOL_CCE_PUNCT = 35,                 /* CCE_PUNCT  */
  YYSYMBOL_CCE_SPACE = 36,                 /* CCE_SPACE  */
  YYSYMBOL_CCE_UPPER = 37,                 /* CCE_UPPER  */
  YYSYMBOL_CCE_XDIGIT = 38,                /* CCE_XDIGIT  */
  YYSYMBOL_CCE_NEG_ALNUM = 39,             /* CCE_NEG_ALNUM  */
  YYSYMBOL_CCE_NEG_ALPHA = 40,             /* CCE_NEG_ALPHA  */
  YYSYMBOL_CCE_NEG_BLANK = 41,             /* CCE_NEG_BLANK  */
  YYSYMBOL_CCE_NEG_CNTRL = 42,             /* CCE_NEG_CNTRL  */
  YYSYMBOL_CCE_NEG_DIGIT = 43,             /* CCE_NEG_DIGIT  */
  YYSYMBOL_CCE_NEG_GRAPH = 44,             /* CCE_NEG_GRAPH  */
  YYSYMBOL_CCE_NEG_LOWER = 45,             /* CCE_NEG_LOWER  */
  YYSYMBOL_CCE_NEG_PRINT = 46,             /* CCE_NEG_PRINT  */
  YYSYMBOL_CCE_NEG_PUNCT = 47,             /* CCE_NEG_PUNCT  */
  YYSYMBOL_CCE_NEG_SPACE = 48,             /* CCE_NEG_SPACE  */
  YYSYMBOL_CCE_NEG_UPPER = 49,             /* CCE_NEG_UPPER  */
  YYSYMBOL_CCE_NEG_XDIGIT = 50,            /* CCE_NEG_XDIGIT  */
  YYSYMBOL_CCL_OP_DIFF = 51,               /* CCL_OP_DIFF  */
  YYSYMBOL_CCL_OP_UNION = 52,              /* CCL_OP_UNION  */
  YYSYMBOL_BEGIN_REPEAT_POSIX = 53,        /* BEGIN_REPEAT_POSIX  */
  YYSYMBOL_END_REPEAT_POSIX = 54,          /* END_REPEAT_POSIX  */
  YYSYMBOL_BEGIN_REPEAT_FLEX = 55,         /* BEGIN_REPEAT_FLEX  */
  YYSYMBOL_END_REPEAT_FLEX = 56,           /* END_REPEAT_FLEX  */
  YYSYMBOL_57_ = 57,                       /* '='  */
  YYSYMBOL_58_n_ = 58,                     /* '\n'  */
  YYSYMBOL_59_ = 59,                       /* '{'  */
  YYSYMBOL_60_ = 60,                       /* '}'  */
  YYSYMBOL_61_ = 61,                       /* '^'  */
  YYSYMBOL_62_ = 62,                       /* '<'  */
  YYSYMBOL_63_ = 63,                       /* '>'  */
  YYSYMBOL_64_ = 64,                       /* '*'  */
  YYSYMBOL_65_ = 65,                       /* ','  */
  YYSYMBOL_66_ = 66,                       /* '$'  */
  YYSYMBOL_67_ = 67,                       /* '|'  */
  YYSYMBOL_68_ = 68,                       /* '/'  */
  YYSYMBOL_69_ = 69,                       /* '+'  */
  YYSYMBOL_70_ = 70,                       /* '?'  */
  YYSYMBOL_71_ = 71,                       /* '.'  */
  YYSYMBOL_72_ = 72,                       /* '"'  */
  YYSYMBOL_73_ = 73,                       /* '('  */
  YYSYMBOL_74_ = 74,                       /* ')'  */
  YYSYMBOL_75_ = 75,                       /* '['  */
  YYSYMBOL_76_ = 76,                       /* ']'  */
  YYSYMBOL_77_ = 77,                       /* '-'  */
  YYSYMBOL_YYACCEPT = 78,                  /* $accept  */
  YYSYMBOL_goal = 79,                      /* goal  */
  YYSYMBOL_initlex = 80,                   /* initlex  */
  YYSYMBOL_sect1 = 81,                     /* sect1  */
  YYSYMBOL_sect1end = 82,                  /* sect1end  */
  YYSYMBOL_startconddecl = 83,             /* startconddecl  */
  YYSYMBOL_namelist1 = 84,                 /* namelist1  */
  YYSYMBOL_options = 85,                   /* options  */
  YYSYMBOL_optionlist = 86,                /* optionlist  */
  YYSYMBOL_option = 87,                    /* option  */
  YYSYMBOL_sect2 = 88,                     /* sect2  */
  YYSYMBOL_initforrule = 89,               /* initforrule  */
  YYSYMBOL_flexrule = 90,                  /* flexrule  */
  YYSYMBOL_scon_stk_ptr = 91,              /* scon_stk_ptr  */
  YYSYMBOL_scon = 92,                      /* scon  */
  YYSYMBOL_namelist2 = 93,                 /* namelist2  */
  YYSYMBOL_sconname = 94,                  /* sconname  */
  YYSYMBOL_rule = 95,                      /* rule  */
  YYSYMBOL_re = 96,                        /* re  */
  YYSYMBOL_re2 = 97,                       /* re2  */
  YYSYMBOL_series = 98,                    /* series  */
  YYSYMBOL_singleton = 99,                 /* singleton  */
  YYSYMBOL_fullccl = 100,                  /* fullccl  */
  YYSYMBOL_braceccl = 101,                 /* braceccl  */
  YYSYMBOL_ccl = 102,                      /* ccl  */
  YYSYMBOL_ccl_expr = 103,                 /* ccl_expr  */
  YYSYMBOL_string = 104                    /* string  */
};
typedef enum yysymbol_kind_t yysymbol_kind_t;




#ifdef short
# undef short
#endif

/* On compilers that do not define __PTRDIFF_MAX__ etc., make sure
   <limits.h> and (if available) <stdint.h> are included
   so that the code can choose integer types of a good width.  */

#ifndef __PTRDIFF_MAX__
# include <limits.h> /* INFRINGES ON USER NAME SPACE */
# if defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stdint.h> /* INFRINGES ON USER NAME SPACE */
#  define YY_STDINT_H
# endif
#endif

/* Narrow types that promote to a signed type and that can represent a
   signed or unsigned integer of at least N bits.  In tables they can
   save space and decrease cache pressure.  Promoting to a signed type
   helps avoid bugs in integer arithmetic.  */

#ifdef __INT_LEAST8_MAX__
typedef __INT_LEAST8_TYPE__ yytype_int8;
#elif defined YY_STDINT_H
typedef int_least8_t yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef __INT_LEAST16_MAX__
typedef __INT_LEAST16_TYPE__ yytype_int16;
#elif defined YY_STDINT_H
typedef int_least16_t yytype_int16;
#else
typedef short yytype_int16;
#endif

/* Work around bug in HP-UX 11.23, which defines these macros
   incorrectly for preprocessor constants.  This workaround can likely
   be removed in 2023, as HPE has promised support for HP-UX 11.23
   (aka HP-UX 11i v2) only through the end of 2022; see Table 2 of
   <https://h20195.www2.hpe.com/V2/getpdf.aspx/4AA4-7673ENW.pdf>.  */
#ifdef __hpux
# undef UINT_LEAST8_MAX
# undef UINT_LEAST16_MAX
# define UINT_LEAST8_MAX 255
# define UINT_LEAST16_MAX 65535
#endif

#if defined __UINT_LEAST8_MAX__ && __UINT_LEAST8_MAX__ <= __INT_MAX__
typedef __UINT_LEAST8_TYPE__ yytype_uint8;
#elif (!defined __UINT_LEAST8_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST8_MAX <= INT_MAX)
typedef uint_least8_t yytype_uint8;
#elif !defined __UINT_LEAST8_MAX__ && UCHAR_MAX <= INT_MAX
typedef unsigned char yytype_uint8;
#else
typedef short yytype_uint8;
#endif

#if defined __UINT_LEAST16_MAX__ && __UINT_LEAST16_MAX__ <= __INT_MAX__
typedef __UINT_LEAST16_TYPE__ yytype_uint16;
#elif (!defined __UINT_LEAST16_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST16_MAX <= INT_MAX)
typedef uint_least16_t yytype_uint16;
#elif !defined __UINT_LEAST16_MAX__ && USHRT_MAX <= INT_MAX
typedef unsigned short yytype_uint16;
#else
typedef int yytype_uint16;
#endif

#ifndef YYPTRDIFF_T
# if defined __PTRDIFF_TYPE__ && defined __PTRDIFF_MAX__
#  define YYPTRDIFF_T __PTRDIFF_TYPE__
#  define YYPTRDIFF_MAXIMUM __PTRDIFF_MAX__
# elif defined PTRDIFF_MAX
#  ifndef ptrdiff_t
#   include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  endif
#  define YYPTRDIFF_T ptrdiff_t
#  define YYPTRDIFF_MAXIMUM PTRDIFF_MAX
# else
#  define YYPTRDIFF_T long
#  define YYPTRDIFF_MAXIMUM LONG_MAX
# endif
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned
# endif
#endif

#define YYSIZE_MAXIMUM                                  \
  YY_CAST (YYPTRDIFF_T,                                 \
           (YYPTRDIFF_MAXIMUM < YY_CAST (YYSIZE_T, -1)  \
            ? YYPTRDIFF_MAXIMUM                         \
            : YY_CAST (YYSIZE_T, -1)))

#define YYSIZEOF(X) YY_CAST (YYPTRDIFF_T, sizeof (X))


/* Stored state numbers (used for stacks). */
typedef yytype_uint8 yy_state_t;

/* State numbers in computations.  */
typedef int yy_state_fast_t;

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif


#ifndef YY_ATTRIBUTE_PURE
# if defined __GNUC__ && 2 < __GNUC__ + (96 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_PURE __attribute__ ((__pure__))
# else
#  define YY_ATTRIBUTE_PURE
# endif
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# if defined __GNUC__ && 2 < __GNUC__ + (7 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_UNUSED __attribute__ ((__unused__))
# else
#  define YY_ATTRIBUTE_UNUSED
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YY_USE(E) ((void) (E))
#else
# define YY_USE(E) /* empty */
#endif

/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
#if defined __GNUC__ && ! defined __ICC && 406 <= __GNUC__ * 100 + __GNUC_MINOR__
# if __GNUC__ * 100 + __GNUC_MINOR__ < 407
#  define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                           \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")
# else
#  define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                           \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")              \
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# endif
# define YY_IGNORE_MAYBE_UNINITIALIZED_END      \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif

#if defined __cplusplus && defined __GNUC__ && ! defined __ICC && 6 <= __GNUC__
# define YY_IGNORE_USELESS_CAST_BEGIN                          \
    _Pragma ("GCC diagnostic push")                            \
    _Pragma ("GCC diagnostic ignored \"-Wuseless-cast\"")
# define YY_IGNORE_USELESS_CAST_END            \
    _Pragma ("GCC diagnostic pop")
#endif
#ifndef YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_END
#endif


#define YY_ASSERT(E) ((void) (0 && (E)))

#if !defined yyoverflow

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* !defined yyoverflow */

#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yy_state_t yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (YYSIZEOF (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (YYSIZEOF (yy_state_t) + YYSIZEOF (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYPTRDIFF_T yynewbytes;                                         \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * YYSIZEOF (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / YYSIZEOF (*yyptr);                        \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, YY_CAST (YYSIZE_T, (Count)) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYPTRDIFF_T yyi;                      \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  3
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   193

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  78
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  27
/* YYNRULES -- Number of rules.  */
#define YYNRULES  105
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  164

/* YYMAXUTOK -- Last valid token kind.  */
#define YYMAXUTOK   311


/* YYTRANSLATE(TOKEN-NUM) -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, with out-of-bounds checking.  */
#define YYTRANSLATE(YYX)                                \
  (0 <= (YYX) && (YYX) <= YYMAXUTOK                     \
   ? YY_CAST (yysymbol_kind_t, yytranslate[YYX])        \
   : YYSYMBOL_YYUNDEF)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex.  */
static const yytype_int8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
      58,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,    72,     2,    66,     2,     2,     2,
      73,    74,    64,    69,    65,    77,    71,    68,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
      62,    57,    63,    70,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,    75,     2,    76,    61,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    59,    67,    60,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56
};

#if YYDEBUG
/* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_int16 yyrline[] =
{
       0,   121,   121,   154,   161,   162,   163,   164,   168,   176,
     179,   183,   186,   189,   193,   196,   197,   200,   205,   207,
     211,   213,   215,   217,   219,   221,   223,   225,   227,   229,
     231,   235,   237,   239,   243,   255,   291,   315,   338,   343,
     346,   349,   367,   370,   372,   374,   378,   401,   457,   460,
     503,   521,   527,   532,   559,   567,   570,   598,   612,   634,
     641,   647,   653,   681,   695,   714,   748,   766,   776,   779,
     782,   797,   798,   799,   804,   806,   813,   873,   891,   899,
     907,   908,   909,   910,   911,   912,   913,   918,   919,   920,
     921,   922,   928,   929,   930,   931,   932,   933,   934,   935,
     936,   937,   938,   944,   952,   968
};
#endif

/** Accessing symbol of state STATE.  */
#define YY_ACCESSING_SYMBOL(State) YY_CAST (yysymbol_kind_t, yystos[State])

#if YYDEBUG || 0
/* The user-facing name of the symbol whose (internal) number is
   YYSYMBOL.  No bounds checking.  */
static const char *yysymbol_name (yysymbol_kind_t yysymbol) YY_ATTRIBUTE_UNUSED;

/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "\"end of file\"", "error", "\"invalid token\"", "CHAR", "NUMBER",
  "SECTEND", "SCDECL", "XSCDECL", "NAME", "PREVCCL", "EOF_OP",
  "TOK_OPTION", "TOK_OUTFILE", "TOK_PREFIX", "TOK_YYCLASS",
  "TOK_HEADER_FILE", "TOK_EXTRA_TYPE", "TOK_TABLES_FILE", "TOK_YYLMAX",
  "TOK_NUMERIC", "TOK_YYDECL", "TOK_PREACTION", "TOK_POSTACTION",
  "TOK_USERINIT", "TOK_EMIT", "TOK_BUFSIZE", "TOK_YYTERMINATE",
  "CCE_ALNUM", "CCE_ALPHA", "CCE_BLANK", "CCE_CNTRL", "CCE_DIGIT",
  "CCE_GRAPH", "CCE_LOWER", "CCE_PRINT", "CCE_PUNCT", "CCE_SPACE",
  "CCE_UPPER", "CCE_XDIGIT", "CCE_NEG_ALNUM", "CCE_NEG_ALPHA",
  "CCE_NEG_BLANK", "CCE_NEG_CNTRL", "CCE_NEG_DIGIT", "CCE_NEG_GRAPH",
  "CCE_NEG_LOWER", "CCE_NEG_PRINT", "CCE_NEG_PUNCT", "CCE_NEG_SPACE",
  "CCE_NEG_UPPER", "CCE_NEG_XDIGIT", "CCL_OP_DIFF", "CCL_OP_UNION",
  "BEGIN_REPEAT_POSIX", "END_REPEAT_POSIX", "BEGIN_REPEAT_FLEX",
  "END_REPEAT_FLEX", "'='", "'\\n'", "'{'", "'}'", "'^'", "'<'", "'>'",
  "'*'", "','", "'$'", "'|'", "'/'", "'+'", "'?'", "'.'", "'\"'", "'('",
  "')'", "'['", "']'", "'-'", "$accept", "goal", "initlex", "sect1",
  "sect1end", "startconddecl", "namelist1", "options", "optionlist",
  "option", "sect2", "initforrule", "flexrule", "scon_stk_ptr", "scon",
  "namelist2", "sconname", "rule", "re", "re2", "series", "singleton",
  "fullccl", "braceccl", "ccl", "ccl_expr", "string", YY_NULLPTR
};

static const char *
yysymbol_name (yysymbol_kind_t yysymbol)
{
  return yytname[yysymbol];
}
#endif

#define YYPACT_NINF (-88)

#define yypact_value_is_default(Yyn) \
  ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-35)

#define yytable_value_is_error(Yyn) \
  0

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
static const yytype_int16 yypact[] =
{
     -88,    15,    13,   -88,   -88,   127,   -88,   -88,   -88,   -88,
     -88,    53,   -88,    90,     5,   -88,   -88,    17,    -5,    -2,
       9,    52,    60,    73,    89,    91,    92,    93,    94,    95,
      96,    97,   -88,    81,   -88,     4,   -88,   139,   147,   148,
     149,   150,   151,   141,   153,   154,   155,   156,   157,   152,
     158,   104,    67,   -88,    -1,   -88,   -88,   -88,   -88,   -88,
     -88,   -88,   -88,   -88,   -88,   -88,   -88,   -88,   -88,   -88,
     -88,   -88,   -52,   -88,    62,   -88,   -88,   -88,   -88,    56,
     -88,   -88,    56,   107,   111,   -88,    69,    56,    48,   -48,
      88,   -88,   -88,   162,   -88,   -88,     1,    51,   -88,     0,
     -88,   -88,    56,   -88,    75,   168,   -48,   169,   -88,   -88,
     -88,    99,    99,   -88,   -88,   -88,   -88,    50,    98,   -88,
     -88,   -88,   -88,   -88,   -88,   -88,   -88,   -88,   -88,   -88,
     -88,   -88,   -88,   -88,   -88,   -88,   -88,   -88,   -88,   -88,
     -88,   -88,   -88,   -88,   -88,    48,   -88,   -42,   -39,   -88,
     -88,   -88,   173,   -88,     2,   -88,     6,   -88,   123,   -88,
     122,   -88,   -88,   -88
};

/* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
   Performed when YYTABLE does not specify something else to do.  Zero
   means the default is an error.  */
static const yytype_int8 yydefact[] =
{
       3,     0,     0,     1,     7,     0,     8,     9,    10,    16,
      33,     0,     5,    14,    42,    13,    12,     4,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,    15,    39,     2,    34,    11,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,    33,     0,    17,    19,    20,    21,    18,
      30,    22,    23,    24,    25,    28,    27,    26,    29,    41,
      45,    46,     0,    44,    42,    38,    70,    67,    37,     0,
      65,   105,     0,    79,     0,    36,    50,     0,    52,    55,
      66,    73,    40,     0,    32,    35,     0,     0,    79,     0,
      31,    49,     0,    53,    47,     0,    54,     0,    59,    60,
      61,     0,     0,    43,   104,    68,    69,     0,    77,    80,
      81,    82,    83,    84,    85,    86,    87,    88,    89,    91,
      90,    92,    93,    94,    95,    96,    97,   102,    98,    99,
     100,   103,   101,    74,    78,    51,    48,     0,     0,    71,
      72,    75,     0,    58,     0,    64,     0,    76,     0,    57,
       0,    63,    56,    62
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
     -88,   -88,   -88,   -88,   -88,   -88,   -88,   -88,   -88,   -88,
     126,   145,   -88,   -88,   -88,   -88,   100,   102,   -18,   -88,
      80,   -87,   -88,    32,    85,   -88,   -88
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_uint8 yydefgoto[] =
{
       0,     1,     2,     5,    10,    11,    17,    12,    13,    32,
      14,    34,    84,    52,    35,    72,    73,    85,    86,    87,
      88,    89,    90,    91,    99,   144,    96
};

/* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule whose
   number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
      75,   106,    76,   118,   114,   -34,   158,   107,    77,    78,
     160,    92,   153,    93,     4,     3,   108,   155,    -6,    -6,
      -6,   109,   110,   154,    -6,    36,   156,   119,   120,   121,
     122,   123,   124,   125,   126,   127,   128,   129,   130,   131,
     132,   133,   134,   135,   136,   137,   138,   139,   140,   141,
     142,    76,    37,   118,    15,    38,   159,    77,   106,    76,
      79,    16,   161,    53,    97,    77,    39,    33,    70,   104,
      80,    81,    82,   115,    83,    71,   143,   119,   120,   121,
     122,   123,   124,   125,   126,   127,   128,   129,   130,   131,
     132,   133,   134,   135,   136,   137,   138,   139,   140,   141,
     142,   105,    18,    19,    20,    21,    22,    23,    24,    40,
      25,    26,    27,    28,    29,    30,    31,    41,   102,    80,
      81,    82,    94,    83,    33,   116,   151,    80,    81,    82,
      42,    83,     6,     7,     8,   101,   102,   103,     9,   111,
     112,   146,   102,   149,   150,    51,    43,    55,    44,    45,
      46,    47,    48,    49,    50,    56,    57,    58,    59,    60,
      61,    62,    63,    64,    65,    66,    68,    69,    98,   100,
      71,    67,   147,   148,    83,   152,   157,   162,   163,    74,
      54,    95,   145,   117,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   113
};

static const yytype_int16 yycheck[] =
{
       1,    88,     3,     3,     3,     0,     4,    55,     9,    10,
       4,    63,    54,    65,     1,     0,    64,    56,     5,     6,
       7,    69,    70,    65,    11,     8,    65,    27,    28,    29,
      30,    31,    32,    33,    34,    35,    36,    37,    38,    39,
      40,    41,    42,    43,    44,    45,    46,    47,    48,    49,
      50,     3,    57,     3,     1,    57,    54,     9,   145,     3,
      61,     8,    56,    59,    82,     9,    57,    62,     1,    87,
      71,    72,    73,    72,    75,     8,    76,    27,    28,    29,
      30,    31,    32,    33,    34,    35,    36,    37,    38,    39,
      40,    41,    42,    43,    44,    45,    46,    47,    48,    49,
      50,    53,    12,    13,    14,    15,    16,    17,    18,    57,
      20,    21,    22,    23,    24,    25,    26,    57,    67,    71,
      72,    73,    60,    75,    62,    74,    76,    71,    72,    73,
      57,    75,     5,     6,     7,    66,    67,    68,    11,    51,
      52,    66,    67,   111,   112,    64,    57,     8,    57,    57,
      57,    57,    57,    57,    57,     8,     8,     8,     8,     8,
      19,     8,     8,     8,     8,     8,     8,    63,    61,    58,
       8,    19,     4,     4,    75,    77,     3,    54,    56,    53,
      35,    79,   102,    98,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    93
};

/* YYSTOS[STATE-NUM] -- The symbol kind of the accessing symbol of
   state STATE-NUM.  */
static const yytype_int8 yystos[] =
{
       0,    79,    80,     0,     1,    81,     5,     6,     7,    11,
      82,    83,    85,    86,    88,     1,     8,    84,    12,    13,
      14,    15,    16,    17,    18,    20,    21,    22,    23,    24,
      25,    26,    87,    62,    89,    92,     8,    57,    57,    57,
      57,    57,    57,    57,    57,    57,    57,    57,    57,    57,
      57,    64,    91,    59,    89,     8,     8,     8,     8,     8,
       8,    19,     8,     8,     8,     8,     8,    19,     8,    63,
       1,     8,    93,    94,    88,     1,     3,     9,    10,    61,
      71,    72,    73,    75,    90,    95,    96,    97,    98,    99,
     100,   101,    63,    65,    60,    95,   104,    96,    61,   102,
      58,    66,    67,    68,    96,    53,    99,    55,    64,    69,
      70,    51,    52,    94,     3,    72,    74,   102,     3,    27,
      28,    29,    30,    31,    32,    33,    34,    35,    36,    37,
      38,    39,    40,    41,    42,    43,    44,    45,    46,    47,
      48,    49,    50,    76,   103,    98,    66,     4,     4,   101,
     101,    76,    77,    54,    65,    56,    65,     3,     4,    54,
       4,    56,    54,    56
};

/* YYR1[RULE-NUM] -- Symbol kind of the left-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr1[] =
{
       0,    78,    79,    80,    81,    81,    81,    81,    82,    83,
      83,    84,    84,    84,    85,    86,    86,    87,    87,    87,
      87,    87,    87,    87,    87,    87,    87,    87,    87,    87,
      87,    88,    88,    88,    89,    90,    90,    90,    90,    91,
      92,    92,    92,    93,    93,    93,    94,    95,    95,    95,
      95,    96,    96,    97,    98,    98,    98,    98,    98,    99,
      99,    99,    99,    99,    99,    99,    99,    99,    99,    99,
      99,   100,   100,   100,   101,   101,   102,   102,   102,   102,
     103,   103,   103,   103,   103,   103,   103,   103,   103,   103,
     103,   103,   103,   103,   103,   103,   103,   103,   103,   103,
     103,   103,   103,   103,   104,   104
};

/* YYR2[RULE-NUM] -- Number of symbols on the right-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr2[] =
{
       0,     2,     5,     0,     3,     2,     0,     1,     1,     1,
       1,     2,     1,     1,     2,     2,     0,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     5,     5,     0,     0,     2,     1,     1,     1,     0,
       4,     3,     0,     3,     1,     1,     1,     2,     3,     2,
       1,     3,     1,     2,     2,     1,     6,     5,     4,     2,
       2,     2,     6,     5,     4,     1,     1,     1,     3,     3,
       1,     3,     3,     1,     3,     4,     4,     2,     2,     0,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     2,     0
};


enum { YYENOMEM = -2 };

#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab
#define YYNOMEM         goto yyexhaustedlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                    \
  do                                                              \
    if (yychar == YYEMPTY)                                        \
      {                                                           \
        yychar = (Token);                                         \
        yylval = (Value);                                         \
        YYPOPSTACK (yylen);                                       \
        yystate = *yyssp;                                         \
        goto yybackup;                                            \
      }                                                           \
    else                                                          \
      {                                                           \
        yyerror (YY_("syntax error: cannot back up")); \
        YYERROR;                                                  \
      }                                                           \
  while (0)

/* Backward compatibility with an undocumented macro.
   Use YYerror or YYUNDEF. */
#define YYERRCODE YYUNDEF


/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)




# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Kind, Value); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*-----------------------------------.
| Print this symbol's value on YYO.  |
`-----------------------------------*/

static void
yy_symbol_value_print (FILE *yyo,
                       yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep)
{
  FILE *yyoutput = yyo;
  YY_USE (yyoutput);
  if (!yyvaluep)
    return;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/*---------------------------.
| Print this symbol on YYO.  |
`---------------------------*/

static void
yy_symbol_print (FILE *yyo,
                 yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep)
{
  YYFPRINTF (yyo, "%s %s (",
             yykind < YYNTOKENS ? "token" : "nterm", yysymbol_name (yykind));

  yy_symbol_value_print (yyo, yykind, yyvaluep);
  YYFPRINTF (yyo, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yy_state_t *yybottom, yy_state_t *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yy_state_t *yyssp, YYSTYPE *yyvsp,
                 int yyrule)
{
  int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %d):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       YY_ACCESSING_SYMBOL (+yyssp[yyi + 1 - yynrhs]),
                       &yyvsp[(yyi + 1) - (yynrhs)]);
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, Rule); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args) ((void) 0)
# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif






/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg,
            yysymbol_kind_t yykind, YYSTYPE *yyvaluep)
{
  YY_USE (yyvaluep);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yykind, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/* Lookahead token kind.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;
/* Number of syntax errors so far.  */
int yynerrs;




/*----------.
| yyparse.  |
`----------*/

int
yyparse (void)
{
    yy_state_fast_t yystate = 0;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus = 0;

    /* Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* Their size.  */
    YYPTRDIFF_T yystacksize = YYINITDEPTH;

    /* The state stack: array, bottom, top.  */
    yy_state_t yyssa[YYINITDEPTH];
    yy_state_t *yyss = yyssa;
    yy_state_t *yyssp = yyss;

    /* The semantic value stack: array, bottom, top.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs = yyvsa;
    YYSTYPE *yyvsp = yyvs;

  int yyn;
  /* The return value of yyparse.  */
  int yyresult;
  /* Lookahead symbol kind.  */
  yysymbol_kind_t yytoken = YYSYMBOL_YYEMPTY;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;



#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yychar = YYEMPTY; /* Cause a token to be read.  */

  goto yysetstate;


/*------------------------------------------------------------.
| yynewstate -- push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;


/*--------------------------------------------------------------------.
| yysetstate -- set current state (the top of the stack) to yystate.  |
`--------------------------------------------------------------------*/
yysetstate:
  YYDPRINTF ((stderr, "Entering state %d\n", yystate));
  YY_ASSERT (0 <= yystate && yystate < YYNSTATES);
  YY_IGNORE_USELESS_CAST_BEGIN
  *yyssp = YY_CAST (yy_state_t, yystate);
  YY_IGNORE_USELESS_CAST_END
  YY_STACK_PRINT (yyss, yyssp);

  if (yyss + yystacksize - 1 <= yyssp)
#if !defined yyoverflow && !defined YYSTACK_RELOCATE
    YYNOMEM;
#else
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYPTRDIFF_T yysize = yyssp - yyss + 1;

# if defined yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        yy_state_t *yyss1 = yyss;
        YYSTYPE *yyvs1 = yyvs;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * YYSIZEOF (*yyssp),
                    &yyvs1, yysize * YYSIZEOF (*yyvsp),
                    &yystacksize);
        yyss = yyss1;
        yyvs = yyvs1;
      }
# else /* defined YYSTACK_RELOCATE */
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        YYNOMEM;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yy_state_t *yyss1 = yyss;
        union yyalloc *yyptr =
          YY_CAST (union yyalloc *,
                   YYSTACK_ALLOC (YY_CAST (YYSIZE_T, YYSTACK_BYTES (yystacksize))));
        if (! yyptr)
          YYNOMEM;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YY_IGNORE_USELESS_CAST_BEGIN
      YYDPRINTF ((stderr, "Stack size increased to %ld\n",
                  YY_CAST (long, yystacksize)));
      YY_IGNORE_USELESS_CAST_END

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }
#endif /* !defined yyoverflow && !defined YYSTACK_RELOCATE */


  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;


/*-----------.
| yybackup.  |
`-----------*/
yybackup:
  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either empty, or end-of-input, or a valid lookahead.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token\n"));
      yychar = yylex ();
    }

  if (yychar <= YYEOF)
    {
      yychar = YYEOF;
      yytoken = YYSYMBOL_YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else if (yychar == YYerror)
    {
      /* The scanner already issued an error message, process directly
         to error recovery.  But do not keep the error token as
         lookahead, it is too special and may lead us to an endless
         loop in error recovery. */
      yychar = YYUNDEF;
      yytoken = YYSYMBOL_YYerror;
      goto yyerrlab1;
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);
  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  /* Discard the shifted token.  */
  yychar = YYEMPTY;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
  case 2: /* goal: initlex sect1 sect1end sect2 initforrule  */
#line 122 "parse.y"
                        { /* add default rule */
			int def_rule;

			pat = cclinit();
			cclnegate( pat );

			def_rule = mkstate( -pat );

			/* Remember the number of the default rule so we
			 * don't generate "can't match" warnings for it.
			 */
			default_rule = num_rules;

			finish_rule( def_rule, false, 0, 0, 0);

			for ( i = 1; i <= lastsc; ++i )
				scset[i] = mkbranch( scset[i], def_rule );

			add_action("]]");

			if ( ctrl.spprdflt )
				add_action(
				"M4_HOOK_FATAL_ERROR(\"flex scanner jammed\")");
			else {
			    add_action("M4_HOOK_ECHO");
			}

			add_action( "\n\tM4_HOOK_STATE_CASE_BREAK\n" );
			}
#line 1557 "parse.c"
    break;

  case 3: /* initlex: %empty  */
#line 154 "parse.y"
                        { /* initialize for processing rules */

			/* Create default DFA start condition. */
			scinstal( "INITIAL", false );
			}
#line 1567 "parse.c"
    break;

  case 7: /* sect1: error  */
#line 165 "parse.y"
                        { synerr( _("unknown error processing section 1") ); }
#line 1573 "parse.c"
    break;

  case 8: /* sect1end: SECTEND  */
#line 169 "parse.y"
                        {
			check_options();
			scon_stk = allocate_integer_array( lastsc + 1 );
			scon_stk_ptr = 0;
			}
#line 1583 "parse.c"
    break;

  case 9: /* startconddecl: SCDECL  */
#line 177 "parse.y"
                        { sc_is_exclusive = false; }
#line 1589 "parse.c"
    break;

  case 10: /* startconddecl: XSCDECL  */
#line 180 "parse.y"
                        { sc_is_exclusive = true; }
#line 1595 "parse.c"
    break;

  case 11: /* namelist1: namelist1 NAME  */
#line 184 "parse.y"
                        { scinstal( nmstr, sc_is_exclusive ); }
#line 1601 "parse.c"
    break;

  case 12: /* namelist1: NAME  */
#line 187 "parse.y"
                        { scinstal( nmstr, sc_is_exclusive ); }
#line 1607 "parse.c"
    break;

  case 13: /* namelist1: error  */
#line 190 "parse.y"
                        { synerr( _("bad start condition list") ); }
#line 1613 "parse.c"
    break;

  case 17: /* option: TOK_OUTFILE '=' NAME  */
#line 201 "parse.y"
                        {
			env.outfilename = xstrdup(nmstr);
			env.did_outfilename = 1;
			}
#line 1622 "parse.c"
    break;

  case 18: /* option: TOK_EXTRA_TYPE '=' NAME  */
#line 206 "parse.y"
                        { extra_type = xstrdup(nmstr); }
#line 1628 "parse.c"
    break;

  case 19: /* option: TOK_PREFIX '=' NAME  */
#line 208 "parse.y"
                        { ctrl.prefix = xstrdup(nmstr);
                          if (strchr(ctrl.prefix, '[') || strchr(ctrl.prefix, ']'))
                              flexerror(_("Prefix must not contain [ or ]")); }
#line 1636 "parse.c"
    break;

  case 20: /* option: TOK_YYCLASS '=' NAME  */
#line 212 "parse.y"
                        { ctrl.yyclass = xstrdup(nmstr); }
#line 1642 "parse.c"
    break;

  case 21: /* option: TOK_HEADER_FILE '=' NAME  */
#line 214 "parse.y"
                        { env.headerfilename = xstrdup(nmstr); }
#line 1648 "parse.c"
    break;

  case 22: /* option: TOK_YYLMAX '=' TOK_NUMERIC  */
#line 216 "parse.y"
                        { ctrl.yylmax = nmval; }
#line 1654 "parse.c"
    break;

  case 23: /* option: TOK_YYDECL '=' NAME  */
#line 218 "parse.y"
                        { ctrl.yydecl = xstrdup(nmstr); }
#line 1660 "parse.c"
    break;

  case 24: /* option: TOK_PREACTION '=' NAME  */
#line 220 "parse.y"
                        { ctrl.preaction = xstrdup(nmstr); }
#line 1666 "parse.c"
    break;

  case 25: /* option: TOK_POSTACTION '=' NAME  */
#line 222 "parse.y"
                        { ctrl.postaction = xstrdup(nmstr); }
#line 1672 "parse.c"
    break;

  case 26: /* option: TOK_BUFSIZE '=' TOK_NUMERIC  */
#line 224 "parse.y"
                        { ctrl.bufsize = nmval; }
#line 1678 "parse.c"
    break;

  case 27: /* option: TOK_EMIT '=' NAME  */
#line 226 "parse.y"
                        { ctrl.emit = xstrdup(nmstr); backend_by_name(ctrl.emit); }
#line 1684 "parse.c"
    break;

  case 28: /* option: TOK_USERINIT '=' NAME  */
#line 228 "parse.y"
                        { ctrl.userinit = xstrdup(nmstr); }
#line 1690 "parse.c"
    break;

  case 29: /* option: TOK_YYTERMINATE '=' NAME  */
#line 230 "parse.y"
                        { ctrl.yyterminate = xstrdup(nmstr); }
#line 1696 "parse.c"
    break;

  case 30: /* option: TOK_TABLES_FILE '=' NAME  */
#line 232 "parse.y"
                        { tablesext = true; tablesfilename = xstrdup(nmstr); }
#line 1702 "parse.c"
    break;

  case 31: /* sect2: sect2 scon initforrule flexrule '\n'  */
#line 236 "parse.y"
                        { scon_stk_ptr = yyvsp[-3]; }
#line 1708 "parse.c"
    break;

  case 32: /* sect2: sect2 scon '{' sect2 '}'  */
#line 238 "parse.y"
                        { scon_stk_ptr = yyvsp[-3]; }
#line 1714 "parse.c"
    break;

  case 34: /* initforrule: %empty  */
#line 243 "parse.y"
                        {
			/* Initialize for a parse of one rule. */
			trlcontxt = variable_trail_rule = varlength = false;
			trailcnt = headcnt = rulelen = 0;
			current_state_type = STATE_NORMAL;
			previous_continued_action = continued_action;
			in_rule = true;

			new_rule();
			}
#line 1729 "parse.c"
    break;

  case 35: /* flexrule: '^' rule  */
#line 256 "parse.y"
                        {
			pat = yyvsp[0];
			finish_rule( pat, variable_trail_rule,
				headcnt, trailcnt , previous_continued_action);

			if ( scon_stk_ptr > 0 )
				{
				for ( i = 1; i <= scon_stk_ptr; ++i )
					scbol[scon_stk[i]] =
						mkbranch( scbol[scon_stk[i]],
								pat );
				}

			else
				{
				/* Add to all non-exclusive start conditions,
				 * including the default (0) start condition.
				 */

				for ( i = 1; i <= lastsc; ++i )
					if ( ! scxclu[i] )
						scbol[i] = mkbranch( scbol[i],
									pat );
				}

			if ( ! bol_needed )
				{
				bol_needed = true;

				if ( env.performance_hint > 1 )
					pinpoint_message(
			"'^' operator results in sub-optimal performance" );
				}
			}
#line 1768 "parse.c"
    break;

  case 36: /* flexrule: rule  */
#line 292 "parse.y"
                        {
			pat = yyvsp[0];
			finish_rule( pat, variable_trail_rule,
				headcnt, trailcnt , previous_continued_action);

			if ( scon_stk_ptr > 0 )
				{
				for ( i = 1; i <= scon_stk_ptr; ++i )
					scset[scon_stk[i]] =
						mkbranch( scset[scon_stk[i]],
								pat );
				}

			else
				{
				for ( i = 1; i <= lastsc; ++i )
					if ( ! scxclu[i] )
						scset[i] =
							mkbranch( scset[i],
								pat );
				}
			}
#line 1795 "parse.c"
    break;

  case 37: /* flexrule: EOF_OP  */
#line 316 "parse.y"
                        {
			if ( scon_stk_ptr > 0 )
				build_eof_action();
	
			else
				{
				/* This EOF applies to all start conditions
				 * which don't already have EOF actions.
				 */
				for ( i = 1; i <= lastsc; ++i )
					if ( ! sceof[i] )
						scon_stk[++scon_stk_ptr] = i;

				if ( scon_stk_ptr == 0 )
					lwarn(
			"all start conditions already have <<EOF>> rules" );

				else
					build_eof_action();
				}
			}
#line 1821 "parse.c"
    break;

  case 38: /* flexrule: error  */
#line 339 "parse.y"
                        { synerr( _("unrecognized rule") ); }
#line 1827 "parse.c"
    break;

  case 39: /* scon_stk_ptr: %empty  */
#line 343 "parse.y"
                        { yyval = scon_stk_ptr; }
#line 1833 "parse.c"
    break;

  case 40: /* scon: '<' scon_stk_ptr namelist2 '>'  */
#line 347 "parse.y"
                        { yyval = yyvsp[-2]; }
#line 1839 "parse.c"
    break;

  case 41: /* scon: '<' '*' '>'  */
#line 350 "parse.y"
                        {
			yyval = scon_stk_ptr;

			for ( i = 1; i <= lastsc; ++i )
				{
				int j;

				for ( j = 1; j <= scon_stk_ptr; ++j )
					if ( scon_stk[j] == i )
						break;

				if ( j > scon_stk_ptr )
					scon_stk[++scon_stk_ptr] = i;
				}
			}
#line 1859 "parse.c"
    break;

  case 42: /* scon: %empty  */
#line 367 "parse.y"
                        { yyval = scon_stk_ptr; }
#line 1865 "parse.c"
    break;

  case 45: /* namelist2: error  */
#line 375 "parse.y"
                        { synerr( _("bad start condition list") ); }
#line 1871 "parse.c"
    break;

  case 46: /* sconname: NAME  */
#line 379 "parse.y"
                        {
			if ( (scnum = sclookup( nmstr )) == 0 )
				format_pinpoint_message(
					"undeclared start condition %s",
					nmstr );
			else
				{
				for ( i = 1; i <= scon_stk_ptr; ++i )
					if ( scon_stk[i] == scnum )
						{
						format_warn(
							"<%s> specified twice",
							scname[scnum] );
						break;
						}

				if ( i > scon_stk_ptr )
					scon_stk[++scon_stk_ptr] = scnum;
				}
			}
#line 1896 "parse.c"
    break;

  case 47: /* rule: re2 re  */
#line 402 "parse.y"
                        {
			if ( transchar[lastst[yyvsp[0]]] != SYM_EPSILON )
				/* Provide final transition \now/ so it
				 * will be marked as a trailing context
				 * state.
				 */
				yyvsp[0] = link_machines( yyvsp[0],
						mkstate( SYM_EPSILON ) );

			mark_beginning_as_normal( yyvsp[0] );
			current_state_type = STATE_NORMAL;

			if ( previous_continued_action )
				{
				/* We need to treat this as variable trailing
				 * context so that the backup does not happen
				 * in the action but before the action switch
				 * statement.  If the backup happens in the
				 * action, then the rules "falling into" this
				 * one's action will *also* do the backup,
				 * erroneously.
				 */
				if ( ! varlength || headcnt != 0 )
					lwarn(
		"trailing context made variable due to preceding '|' action" );

				/* Mark as variable. */
				varlength = true;
				headcnt = 0;

				}

			if ( ctrl.lex_compat || (varlength && headcnt == 0) )
				{ /* variable trailing context rule */
				/* Mark the first part of the rule as the
				 * accepting "head" part of a trailing
				 * context rule.
				 *
				 * By the way, we didn't do this at the
				 * beginning of this production because back
				 * then current_state_type was set up for a
				 * trail rule, and add_accept() can create
				 * a new state ...
				 */
				add_accept( yyvsp[-1],
					num_rules | YY_TRAILING_HEAD_MASK );
				variable_trail_rule = true;
				}
			
			else
				trailcnt = rulelen;

			yyval = link_machines( yyvsp[-1], yyvsp[0] );
			}
#line 1955 "parse.c"
    break;

  case 48: /* rule: re2 re '$'  */
#line 458 "parse.y"
                        { synerr( _("trailing context used twice") ); }
#line 1961 "parse.c"
    break;

  case 49: /* rule: re '$'  */
#line 461 "parse.y"
                        {
			headcnt = 0;
			trailcnt = 1;
			rulelen = 1;
			varlength = false;

			current_state_type = STATE_TRAILING_CONTEXT;

			if ( trlcontxt )
				{
				synerr( _("trailing context used twice") );
				yyval = mkstate( SYM_EPSILON );
				}

			else if ( previous_continued_action )
				{
				/* See the comment in the rule for "re2 re"
				 * above.
				 */
				lwarn(
		"trailing context made variable due to preceding '|' action" );

				varlength = true;
				}

			if ( ctrl.lex_compat || varlength )
				{
				/* Again, see the comment in the rule for
				 * "re2 re" above.
				 */
				add_accept( yyvsp[-1],
					num_rules | YY_TRAILING_HEAD_MASK );
				variable_trail_rule = true;
				}

			trlcontxt = true;

			eps = mkstate( SYM_EPSILON );
			yyval = link_machines( yyvsp[-1],
				link_machines( eps, mkstate( '\n' ) ) );
			}
#line 2007 "parse.c"
    break;

  case 50: /* rule: re  */
#line 504 "parse.y"
                        {
			yyval = yyvsp[0];

			if ( trlcontxt )
				{
				if ( ctrl.lex_compat || (varlength && headcnt == 0) )
					/* Both head and trail are
					 * variable-length.
					 */
					variable_trail_rule = true;
				else
					trailcnt = rulelen;
				}
			}
#line 2026 "parse.c"
    break;

  case 51: /* re: re '|' series  */
#line 522 "parse.y"
                        {
			varlength = true;
			yyval = mkor( yyvsp[-2], yyvsp[0] );
			}
#line 2035 "parse.c"
    break;

  case 52: /* re: series  */
#line 528 "parse.y"
                        { yyval = yyvsp[0]; }
#line 2041 "parse.c"
    break;

  case 53: /* re2: re '/'  */
#line 533 "parse.y"
                        {
			/* This rule is written separately so the
			 * reduction will occur before the trailing
			 * series is parsed.
			 */

			if ( trlcontxt )
				synerr( _("trailing context used twice") );
			else
				trlcontxt = true;

			if ( varlength )
				/* We hope the trailing context is
				 * fixed-length.
				 */
				varlength = false;
			else
				headcnt = rulelen;

			rulelen = 0;

			current_state_type = STATE_TRAILING_CONTEXT;
			yyval = yyvsp[-1];
			}
#line 2070 "parse.c"
    break;

  case 54: /* series: series singleton  */
#line 560 "parse.y"
                        {
			/* This is where concatenation of adjacent patterns
			 * gets done.
			 */
			yyval = link_machines( yyvsp[-1], yyvsp[0] );
			}
#line 2081 "parse.c"
    break;

  case 55: /* series: singleton  */
#line 568 "parse.y"
                        { yyval = yyvsp[0]; }
#line 2087 "parse.c"
    break;

  case 56: /* series: series BEGIN_REPEAT_POSIX NUMBER ',' NUMBER END_REPEAT_POSIX  */
#line 571 "parse.y"
                        {
			varlength = true;

			if ( yyvsp[-3] > yyvsp[-1] || yyvsp[-3] < 0 )
				{
				synerr( _("bad iteration values") );
				yyval = yyvsp[-5];
				}
			else
				{
				if ( yyvsp[-3] == 0 )
					{
					if ( yyvsp[-1] <= 0 )
						{
						synerr(
						_("bad iteration values") );
						yyval = yyvsp[-5];
						}
					else
						yyval = mkopt(
							mkrep( yyvsp[-5], 1, yyvsp[-1] ) );
					}
				else
					yyval = mkrep( yyvsp[-5], yyvsp[-3], yyvsp[-1] );
				}
			}
#line 2118 "parse.c"
    break;

  case 57: /* series: series BEGIN_REPEAT_POSIX NUMBER ',' END_REPEAT_POSIX  */
#line 599 "parse.y"
                        {
			varlength = true;

			if ( yyvsp[-2] <= 0 )
				{
				synerr( _("iteration value must be positive") );
				yyval = yyvsp[-4];
				}

			else
				yyval = mkrep( yyvsp[-4], yyvsp[-2], INFINITE_REPEAT );
			}
#line 2135 "parse.c"
    break;

  case 58: /* series: series BEGIN_REPEAT_POSIX NUMBER END_REPEAT_POSIX  */
#line 613 "parse.y"
                        {
			/* The series could be something like "(foo)",
			 * in which case we have no idea what its length
			 * is, so we punt here.
			 */
			varlength = true;

			if ( yyvsp[-1] <= 0 )
				{
				  synerr( _("iteration value must be positive")
					  );
				yyval = yyvsp[-3];
				}

			else
				yyval = link_machines( yyvsp[-3],
						copysingl( yyvsp[-3], yyvsp[-1] - 1 ) );
			}
#line 2158 "parse.c"
    break;

  case 59: /* singleton: singleton '*'  */
#line 635 "parse.y"
                        {
			varlength = true;

			yyval = mkclos( yyvsp[-1] );
			}
#line 2168 "parse.c"
    break;

  case 60: /* singleton: singleton '+'  */
#line 642 "parse.y"
                        {
			varlength = true;
			yyval = mkposcl( yyvsp[-1] );
			}
#line 2177 "parse.c"
    break;

  case 61: /* singleton: singleton '?'  */
#line 648 "parse.y"
                        {
			varlength = true;
			yyval = mkopt( yyvsp[-1] );
			}
#line 2186 "parse.c"
    break;

  case 62: /* singleton: singleton BEGIN_REPEAT_FLEX NUMBER ',' NUMBER END_REPEAT_FLEX  */
#line 654 "parse.y"
                        {
			varlength = true;

			if ( yyvsp[-3] > yyvsp[-1] || yyvsp[-3] < 0 )
				{
				synerr( _("bad iteration values") );
				yyval = yyvsp[-5];
				}
			else
				{
				if ( yyvsp[-3] == 0 )
					{
					if ( yyvsp[-1] <= 0 )
						{
						synerr(
						_("bad iteration values") );
						yyval = yyvsp[-5];
						}
					else
						yyval = mkopt(
							mkrep( yyvsp[-5], 1, yyvsp[-1] ) );
					}
				else
					yyval = mkrep( yyvsp[-5], yyvsp[-3], yyvsp[-1] );
				}
			}
#line 2217 "parse.c"
    break;

  case 63: /* singleton: singleton BEGIN_REPEAT_FLEX NUMBER ',' END_REPEAT_FLEX  */
#line 682 "parse.y"
                        {
			varlength = true;

			if ( yyvsp[-2] <= 0 )
				{
				synerr( _("iteration value must be positive") );
				yyval = yyvsp[-4];
				}

			else
				yyval = mkrep( yyvsp[-4], yyvsp[-2], INFINITE_REPEAT );
			}
#line 2234 "parse.c"
    break;

  case 64: /* singleton: singleton BEGIN_REPEAT_FLEX NUMBER END_REPEAT_FLEX  */
#line 696 "parse.y"
                        {
			/* The singleton could be something like "(foo)",
			 * in which case we have no idea what its length
			 * is, so we punt here.
			 */
			varlength = true;

			if ( yyvsp[-1] <= 0 )
				{
				synerr( _("iteration value must be positive") );
				yyval = yyvsp[-3];
				}

			else
				yyval = link_machines( yyvsp[-3],
						copysingl( yyvsp[-3], yyvsp[-1] - 1 ) );
			}
#line 2256 "parse.c"
    break;

  case 65: /* singleton: '.'  */
#line 715 "parse.y"
                        {
			if ( ! madeany )
				{
				/* Create the '.' character class. */
                    ccldot = cclinit();
                    ccladd( ccldot, '\n' );
                    cclnegate( ccldot );

                    if ( ctrl.useecs )
                        mkeccl( ccltbl + cclmap[ccldot],
                            ccllen[ccldot], nextecm,
                            ecgroup, ctrl.csize, ctrl.csize );

				/* Create the (?s:'.') character class. */
                    cclany = cclinit();
                    cclnegate( cclany );

                    if ( ctrl.useecs )
                        mkeccl( ccltbl + cclmap[cclany],
                            ccllen[cclany], nextecm,
                            ecgroup, ctrl.csize, ctrl.csize );

				madeany = true;
				}

			++rulelen;

            if (sf_dot_all())
                yyval = mkstate( -cclany );
            else
                yyval = mkstate( -ccldot );
			}
#line 2293 "parse.c"
    break;

  case 66: /* singleton: fullccl  */
#line 749 "parse.y"
                        {
				/* Sort characters for fast searching.
				 */
				qsort( ccltbl + cclmap[yyvsp[0]], (size_t) ccllen[yyvsp[0]], sizeof (*ccltbl), cclcmp );

			if ( ctrl.useecs )
				mkeccl( ccltbl + cclmap[yyvsp[0]], ccllen[yyvsp[0]],
					nextecm, ecgroup, ctrl.csize, ctrl.csize);

			++rulelen;

			if (ccl_has_nl[yyvsp[0]])
				rule_has_nl[num_rules] = true;

			yyval = mkstate( -yyvsp[0] );
			}
#line 2314 "parse.c"
    break;

  case 67: /* singleton: PREVCCL  */
#line 767 "parse.y"
                        {
			++rulelen;

			if (ccl_has_nl[yyvsp[0]])
				rule_has_nl[num_rules] = true;

			yyval = mkstate( -yyvsp[0] );
			}
#line 2327 "parse.c"
    break;

  case 68: /* singleton: '"' string '"'  */
#line 777 "parse.y"
                        { yyval = yyvsp[-1]; }
#line 2333 "parse.c"
    break;

  case 69: /* singleton: '(' re ')'  */
#line 780 "parse.y"
                        { yyval = yyvsp[-1]; }
#line 2339 "parse.c"
    break;

  case 70: /* singleton: CHAR  */
#line 783 "parse.y"
                        {
			++rulelen;

			if (yyvsp[0] == nlch)
				rule_has_nl[num_rules] = true;

            if (sf_case_ins() && has_case(yyvsp[0]))
                /* create an alternation, as in (a|A) */
                yyval = mkor (mkstate(yyvsp[0]), mkstate(reverse_case(yyvsp[0])));
            else
                yyval = mkstate( yyvsp[0] );
			}
#line 2356 "parse.c"
    break;

  case 71: /* fullccl: fullccl CCL_OP_DIFF braceccl  */
#line 797 "parse.y"
                                       { yyval = ccl_set_diff  (yyvsp[-2], yyvsp[0]); }
#line 2362 "parse.c"
    break;

  case 72: /* fullccl: fullccl CCL_OP_UNION braceccl  */
#line 798 "parse.y"
                                       { yyval = ccl_set_union (yyvsp[-2], yyvsp[0]); }
#line 2368 "parse.c"
    break;

  case 74: /* braceccl: '[' ccl ']'  */
#line 804 "parse.y"
                        { yyval = yyvsp[-1]; }
#line 2374 "parse.c"
    break;

  case 75: /* braceccl: '[' '^' ccl ']'  */
#line 807 "parse.y"
                        {
			cclnegate( yyvsp[-1] );
			yyval = yyvsp[-1];
			}
#line 2383 "parse.c"
    break;

  case 76: /* ccl: ccl CHAR '-' CHAR  */
#line 814 "parse.y"
                        {

			if (sf_case_ins())
			  {

			    /* If one end of the range has case and the other
			     * does not, or the cases are different, then we're not
			     * sure what range the user is trying to express.
			     * Examples: [@-z] or [S-t]
			     */
			    if (has_case (yyvsp[-2]) != has_case (yyvsp[0])
				     || (has_case (yyvsp[-2]) && (b_islower (yyvsp[-2]) != b_islower (yyvsp[0])))
				     || (has_case (yyvsp[-2]) && (b_isupper (yyvsp[-2]) != b_isupper (yyvsp[0]))))
			      format_warn3 (
			      _("the character range [%c-%c] is ambiguous in a case-insensitive scanner"),
					    yyvsp[-2], yyvsp[0]);

			    /* If the range spans uppercase characters but not
			     * lowercase (or vice-versa), then should we automatically
			     * include lowercase characters in the range?
			     * Example: [@-_] spans [a-z] but not [A-Z]
			     */
			    else if (!has_case (yyvsp[-2]) && !has_case (yyvsp[0]) && !range_covers_case (yyvsp[-2], yyvsp[0]))
			      format_warn3 (
			      _("the character range [%c-%c] is ambiguous in a case-insensitive scanner"),
					    yyvsp[-2], yyvsp[0]);
			  }

			if ( yyvsp[-2] > yyvsp[0] )
				synerr( _("negative range in character class") );

			else
				{
				for ( i = yyvsp[-2]; i <= yyvsp[0]; ++i )
					ccladd( yyvsp[-3], i );

				/* Keep track if this ccl is staying in
				 * alphabetical order.
				 */
				cclsorted = cclsorted && (yyvsp[-2] > lastchar);
				lastchar = yyvsp[0];

                /* Do it again for upper/lowercase */
                if (sf_case_ins() && has_case(yyvsp[-2]) && has_case(yyvsp[0])){
                    yyvsp[-2] = reverse_case (yyvsp[-2]);
                    yyvsp[0] = reverse_case (yyvsp[0]);
                    
                    for ( i = yyvsp[-2]; i <= yyvsp[0]; ++i )
                        ccladd( yyvsp[-3], i );

                    cclsorted = cclsorted && (yyvsp[-2] > lastchar);
                    lastchar = yyvsp[0];
                }

				}

			yyval = yyvsp[-3];
			}
#line 2446 "parse.c"
    break;

  case 77: /* ccl: ccl CHAR  */
#line 874 "parse.y"
                        {
			ccladd( yyvsp[-1], yyvsp[0] );
			cclsorted = cclsorted && (yyvsp[0] > lastchar);
			lastchar = yyvsp[0];

            /* Do it again for upper/lowercase */
            if (sf_case_ins() && has_case(yyvsp[0])){
                yyvsp[0] = reverse_case (yyvsp[0]);
                ccladd (yyvsp[-1], yyvsp[0]);

                cclsorted = cclsorted && (yyvsp[0] > lastchar);
                lastchar = yyvsp[0];
            }

			yyval = yyvsp[-1];
			}
#line 2467 "parse.c"
    break;

  case 78: /* ccl: ccl ccl_expr  */
#line 892 "parse.y"
                        {
			/* Too hard to properly maintain cclsorted. */
			cclsorted = false;
			yyval = yyvsp[-1];
			}
#line 2477 "parse.c"
    break;

  case 79: /* ccl: %empty  */
#line 899 "parse.y"
                        {
			cclsorted = true;
			lastchar = 0;
			currccl = yyval = cclinit();
			}
#line 2487 "parse.c"
    break;

  case 80: /* ccl_expr: CCE_ALNUM  */
#line 907 "parse.y"
                        { CCL_EXPR(isalnum); }
#line 2493 "parse.c"
    break;

  case 81: /* ccl_expr: CCE_ALPHA  */
#line 908 "parse.y"
                                { CCL_EXPR(isalpha); }
#line 2499 "parse.c"
    break;

  case 82: /* ccl_expr: CCE_BLANK  */
#line 909 "parse.y"
                                { CCL_EXPR(IS_BLANK); }
#line 2505 "parse.c"
    break;

  case 83: /* ccl_expr: CCE_CNTRL  */
#line 910 "parse.y"
                                { CCL_EXPR(iscntrl); }
#line 2511 "parse.c"
    break;

  case 84: /* ccl_expr: CCE_DIGIT  */
#line 911 "parse.y"
                                { CCL_EXPR(isdigit); }
#line 2517 "parse.c"
    break;

  case 85: /* ccl_expr: CCE_GRAPH  */
#line 912 "parse.y"
                                { CCL_EXPR(isgraph); }
#line 2523 "parse.c"
    break;

  case 86: /* ccl_expr: CCE_LOWER  */
#line 913 "parse.y"
                                { 
                          CCL_EXPR(islower);
                          if (sf_case_ins())
                              CCL_EXPR(isupper);
                        }
#line 2533 "parse.c"
    break;

  case 87: /* ccl_expr: CCE_PRINT  */
#line 918 "parse.y"
                                { CCL_EXPR(isprint); }
#line 2539 "parse.c"
    break;

  case 88: /* ccl_expr: CCE_PUNCT  */
#line 919 "parse.y"
                                { CCL_EXPR(ispunct); }
#line 2545 "parse.c"
    break;

  case 89: /* ccl_expr: CCE_SPACE  */
#line 920 "parse.y"
                                { CCL_EXPR(isspace); }
#line 2551 "parse.c"
    break;

  case 90: /* ccl_expr: CCE_XDIGIT  */
#line 921 "parse.y"
                                { CCL_EXPR(isxdigit); }
#line 2557 "parse.c"
    break;

  case 91: /* ccl_expr: CCE_UPPER  */
#line 922 "parse.y"
                                {
                    CCL_EXPR(isupper);
                    if (sf_case_ins())
                        CCL_EXPR(islower);
				}
#line 2567 "parse.c"
    break;

  case 92: /* ccl_expr: CCE_NEG_ALNUM  */
#line 928 "parse.y"
                                { CCL_NEG_EXPR(isalnum); }
#line 2573 "parse.c"
    break;

  case 93: /* ccl_expr: CCE_NEG_ALPHA  */
#line 929 "parse.y"
                                        { CCL_NEG_EXPR(isalpha); }
#line 2579 "parse.c"
    break;

  case 94: /* ccl_expr: CCE_NEG_BLANK  */
#line 930 "parse.y"
                                        { CCL_NEG_EXPR(IS_BLANK); }
#line 2585 "parse.c"
    break;

  case 95: /* ccl_expr: CCE_NEG_CNTRL  */
#line 931 "parse.y"
                                        { CCL_NEG_EXPR(iscntrl); }
#line 2591 "parse.c"
    break;

  case 96: /* ccl_expr: CCE_NEG_DIGIT  */
#line 932 "parse.y"
                                        { CCL_NEG_EXPR(isdigit); }
#line 2597 "parse.c"
    break;

  case 97: /* ccl_expr: CCE_NEG_GRAPH  */
#line 933 "parse.y"
                                        { CCL_NEG_EXPR(isgraph); }
#line 2603 "parse.c"
    break;

  case 98: /* ccl_expr: CCE_NEG_PRINT  */
#line 934 "parse.y"
                                        { CCL_NEG_EXPR(isprint); }
#line 2609 "parse.c"
    break;

  case 99: /* ccl_expr: CCE_NEG_PUNCT  */
#line 935 "parse.y"
                                        { CCL_NEG_EXPR(ispunct); }
#line 2615 "parse.c"
    break;

  case 100: /* ccl_expr: CCE_NEG_SPACE  */
#line 936 "parse.y"
                                        { CCL_NEG_EXPR(isspace); }
#line 2621 "parse.c"
    break;

  case 101: /* ccl_expr: CCE_NEG_XDIGIT  */
#line 937 "parse.y"
                                        { CCL_NEG_EXPR(isxdigit); }
#line 2627 "parse.c"
    break;

  case 102: /* ccl_expr: CCE_NEG_LOWER  */
#line 938 "parse.y"
                                        { 
				if ( sf_case_ins() )
					lwarn(_("[:^lower:] is ambiguous in case insensitive scanner"));
				else
					CCL_NEG_EXPR(islower);
				}
#line 2638 "parse.c"
    break;

  case 103: /* ccl_expr: CCE_NEG_UPPER  */
#line 944 "parse.y"
                                        {
				if ( sf_case_ins() )
					lwarn(_("[:^upper:] ambiguous in case insensitive scanner"));
				else
					CCL_NEG_EXPR(isupper);
				}
#line 2649 "parse.c"
    break;

  case 104: /* string: string CHAR  */
#line 953 "parse.y"
                        {
			if ( yyvsp[0] == nlch )
				rule_has_nl[num_rules] = true;

			++rulelen;

            if (sf_case_ins() && has_case(yyvsp[0]))
                yyval = mkor (mkstate(yyvsp[0]), mkstate(reverse_case(yyvsp[0])));
            else
                yyval = mkstate (yyvsp[0]);

			yyval = link_machines( yyvsp[-1], yyval);
			}
#line 2667 "parse.c"
    break;

  case 105: /* string: %empty  */
#line 968 "parse.y"
                        { yyval = mkstate( SYM_EPSILON ); }
#line 2673 "parse.c"
    break;


#line 2677 "parse.c"

      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", YY_CAST (yysymbol_kind_t, yyr1[yyn]), &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;

  *++yyvsp = yyval;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */
  {
    const int yylhs = yyr1[yyn] - YYNTOKENS;
    const int yyi = yypgoto[yylhs] + *yyssp;
    yystate = (0 <= yyi && yyi <= YYLAST && yycheck[yyi] == *yyssp
               ? yytable[yyi]
               : yydefgoto[yylhs]);
  }

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYSYMBOL_YYEMPTY : YYTRANSLATE (yychar);
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
      yyerror (YY_("syntax error"));
    }

  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= YYEOF)
        {
          /* Return failure if at end of input.  */
          if (yychar == YYEOF)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval);
          yychar = YYEMPTY;
        }
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:
  /* Pacify compilers when the user code never invokes YYERROR and the
     label yyerrorlab therefore never appears in user code.  */
  if (0)
    YYERROR;
  ++yynerrs;

  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  /* Pop stack until we find a state that shifts the error token.  */
  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYSYMBOL_YYerror;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYSYMBOL_YYerror)
            {
              yyn = yytable[yyn];
              if (0 < yyn)
                break;
            }
        }

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
        YYABORT;


      yydestruct ("Error: popping",
                  YY_ACCESSING_SYMBOL (yystate), yyvsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", YY_ACCESSING_SYMBOL (yyn), yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturnlab;


/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturnlab;


/*-----------------------------------------------------------.
| yyexhaustedlab -- YYNOMEM (memory exhaustion) comes here.  |
`-----------------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  goto yyreturnlab;


/*----------------------------------------------------------.
| yyreturnlab -- parsing is finished, clean up and return.  |
`----------------------------------------------------------*/
yyreturnlab:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  YY_ACCESSING_SYMBOL (+*yyssp), yyvsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif

  return yyresult;
}

#line 971 "parse.y"



/* build_eof_action - build the "<<EOF>>" action for the active start
 *                    conditions
 */

void build_eof_action(void)
	{
	int i;
	char action_text[MAXLINE];

	for ( i = 1; i <= scon_stk_ptr; ++i )
		{
		if ( sceof[scon_stk[i]] )
			format_pinpoint_message(
				"multiple <<EOF>> rules for start condition %s",
				scname[scon_stk[i]] );

		else
			{
			sceof[scon_stk[i]] = true;

			if (previous_continued_action /* && previous action was regular */)
				add_action("YY_RULE_SETUP\n");

			snprintf( action_text, sizeof(action_text), "M4_HOOK_EOF_STATE_CASE_ARM(%s)\n",
				scname[scon_stk[i]] );
			add_action( action_text );
			}
		}

	line_directive_out(NULL, infilename, linenum);
        add_action("[[");

	/* This isn't a normal rule after all - don't count it as
	 * such, so we don't have any holes in the rule numbering
	 * (which make generating "rule can never match" warnings
	 * more difficult.
	 */
	--num_rules;
	++num_eof_rules;
	}


/* format_synerr - write out formatted syntax error */

void format_synerr( const char *msg, const char arg[] )
	{
	char errmsg[MAXLINE];

	(void) snprintf( errmsg, sizeof(errmsg), msg, arg );
	synerr( errmsg );
	}


/* synerr - report a syntax error */

void synerr( const char *str )
	{
	syntaxerror = true;
	pinpoint_message( str );
	}


/* format_warn - write out formatted warning */

void format_warn( const char *msg, const char arg[] )
	{
	char warn_msg[MAXLINE];

	snprintf( warn_msg, sizeof(warn_msg), msg, arg );
	lwarn( warn_msg );
	}


/* lwarn - report a warning, unless -w was given */

void lwarn( const char *str )
	{
	line_warning( str, linenum );
	}

/* format_pinpoint_message - write out a message formatted with one string,
 *			     pinpointing its location
 */

void format_pinpoint_message( const char *msg, const char arg[] )
	{
	char errmsg[MAXLINE*2];

	snprintf( errmsg, sizeof(errmsg), msg, arg );
	pinpoint_message( errmsg );
	}


/* pinpoint_message - write out a message, pinpointing its location */

void pinpoint_message( const char *str )
	{
	line_pinpoint( str, linenum );
	}


/* line_warning - report a warning at a given line, unless -w was given */

void line_warning( const char *str, int line )
	{
	char warning[MAXLINE*2];

	if ( ! env.nowarn )
		{
		snprintf( warning, sizeof(warning), "warning, %s", str );
		line_pinpoint( warning, line );
		}
	}


/* line_pinpoint - write out a message, pinpointing it at the given line */

void line_pinpoint( const char *str, int line )
	{
	fprintf( stderr, "%s:%d: %s\n", infilename, line, str );
	}


/* yyerror - eat up an error message from the parser;
 *	     currently, messages are ignore
 */

void yyerror( const char *msg )
	{
		(void)msg;
	}
