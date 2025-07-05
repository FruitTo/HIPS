/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison interface for Yacc-like parsers in C

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

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

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
