%{
#include <iostream>
#include <vector>
#include <string>
#include "ir.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

extern int yylex();
extern int yylineno;
void yyerror(const char *s);

ProgramIR program;
FunctionIR* current_function = nullptr;
int stmt_counter = 0;
int current_block_idx = -1;

StmtType classify_statement(const std::string& text) {
    if (text.find("= PHI") != std::string::npos) return STMT_PHI;
    if (text.find('=') != std::string::npos) {
        if (text.find('(') != std::string::npos) return STMT_CALL;
        return STMT_ASSIGN;
    }
    if (text.find("return") != std::string::npos) return STMT_RETURN;
    if (text.find("goto")   != std::string::npos) return STMT_GOTO;
    if (text.find("if")     != std::string::npos) return STMT_COND;
    if (text.find('(')      != std::string::npos) return STMT_CALL;
    return STMT_OTHER;
}
%}

%union {
    int num;
    char* str;
}

%token <str> FUNCTION_HEADER
%token <str> FUNCTION_SIG
%token LBRACE RBRACE
%token <num> BLOCK_HEADER
%token <num> GOTO_STMT
%token <str> RETURN_STMT
%token <str> TEXT_LINE

%%

program : noise functions ;

noise
    : /* empty */
    | noise TEXT_LINE { free($2); }
    | noise FUNCTION_SIG { free($2); }
    ;

functions
    : function
    | functions function
    ;

optional_lines
    : /* empty */
    | optional_lines TEXT_LINE { free($2); }
    | optional_lines RETURN_STMT { free($2); }
    ;

function
    : FUNCTION_HEADER
      {
          current_function = new FunctionIR();
          current_function->name = std::string($1);
          current_block_idx = -1;
      }
      optional_lines FUNCTION_SIG
      {
          current_function->name = std::string($4);
          free($1); free($4);
      }
      optional_lines LBRACE function_items RBRACE
      {
          for (size_t i = 0; i < current_function->blocks.size(); ++i) {
              BasicBlock& block = current_function->blocks[i];
              if (block.statements.empty()) continue;

              StmtType last_type = block.statements.back().type;
              if (last_type != STMT_GOTO && last_type != STMT_RETURN) {
                  if (i + 1 < current_function->blocks.size()) {
                      block.successors.push_back(current_function->blocks[i+1].id);
                  }
              }
          }
          program.functions.push_back(std::move(*current_function));
          delete current_function;
          current_function = nullptr;
      }
    ;

function_items
    : /* empty */
    | function_items function_item
    ;

function_item
    : TEXT_LINE
      {
          Statement stmt;
          stmt.id   = stmt_counter++;
          stmt.text = std::string($1);
          stmt.type = classify_statement(stmt.text);
          if (current_block_idx == -1) current_function->preamble.push_back(stmt);
          else current_function->blocks[current_block_idx].statements.push_back(stmt);
          free($1);
      }
    | BLOCK_HEADER
      {
          current_function->blocks.emplace_back();
          current_block_idx = current_function->blocks.size() - 1;
          current_function->blocks[current_block_idx].id = $1;
      }
    | RETURN_STMT
      {
          Statement stmt;
          stmt.id   = stmt_counter++;
          stmt.text = std::string($1);
          stmt.type = STMT_RETURN;
          if (current_block_idx != -1) current_function->blocks[current_block_idx].statements.push_back(stmt);
          free($1);
      }
    | GOTO_STMT
      {
          Statement stmt;
          stmt.id   = stmt_counter++;
          stmt.text = "goto <bb " + std::to_string($1) + ">;";
          stmt.type = STMT_GOTO;
          if (current_block_idx != -1) {
              current_function->blocks[current_block_idx].statements.push_back(stmt);
              current_function->blocks[current_block_idx].successors.push_back($1);
          }
      }
    ;

%%

void yyerror(const char *s) {
    fprintf(stderr, "Error at line %d: %s\n", yylineno, s);
}