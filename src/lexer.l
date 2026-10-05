%option noyywrap
%option yylineno

%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "parser.tab.h"

static int expect_function_sig = 0;
%}

%%

[ \t\r\n]+          { /* skip whitespace */ }

";; Function".* {
    expect_function_sig = 1;
    yylval.str = strdup(yytext);
    return FUNCTION_HEADER;
}

"{"                 { return LBRACE; }
"}"                 { return RBRACE; }

"<bb"[ ]+[0-9]+">"[ ]*":" {
    char* p = strstr(yytext, "bb");
    if(p) yylval.num = atoi(p + 2);
    return BLOCK_HEADER;
}

"goto"[ ]+"<bb"[ ]+[0-9]+">"[^;\n]*";" {
    char* p = strstr(yytext, "bb");
    if(p) yylval.num = atoi(p + 2);
    return GOTO_STMT;
}

"return"[^\n]*";"   { yylval.str = strdup(yytext); return RETURN_STMT; }

[a-zA-Z0-9_._:*&<> ]+[ ]*=[^;\n]*";" {
    yylval.str = strdup(yytext);
    return TEXT_LINE;
}

[a-zA-Z0-9_:*&<> ]+[ \t]*\([^)\n]*\)[ \t]* {
    if (expect_function_sig) {
        expect_function_sig = 0;
        yylval.str = strdup(yytext);
        return FUNCTION_SIG;
    }
    yylval.str = strdup(yytext);
    return TEXT_LINE;
}

.                   { /* ignore punctuation */ }

%%