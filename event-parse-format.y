%{
#include <stdio.h>
#include <stdlib.h>
#include "event-parse.h"
#include "event-parse-local.h"
void yyerror(struct tep_format_parser_context *context, const char *s);
void parse_new_field(struct tep_format_parser_context *context, char *field_string, int offset, int size);
void parse_set_field_signed(struct tep_format_parser_context *context, int is_signed);
void parse_new_print_str(struct tep_format_parser_context *context, char *field_string);
void parser_debug(const char *format, ...);
%}
%define parse.error verbose
%parse-param {struct tep_format_parser_context *context}
%lex-param {struct tep_format_parser_context *context}
%code provides {
   #define YY_DECL \
       int yylex(struct tep_format_parser_context *context)
   YY_DECL;
}
%union {
	int ival;
	char *sval;
}
%token <ival> INT
%token <sval> STRING
%token <sval> FIELD_UKNOWN
%token <sval> STRING_PRINT
%token <sval> STRING_PARAM
%token <sval> PARAM_ARG_FUNC
%token <sval> STRING_PARAM_REC
%token <sval> STRING_PARAM_OP
%token EVENT_NAME EVENT_ID FORMAT
%token FIELD FIELD_OFFSET FIELD_SIZE FIELD_SIGNED
%token PRINT_FMT COMMA DQUOTE
%token SEMICOLON ENDL 
%token PRINT_STRING_START PRINT_PARAM_START
%token PARAM_FUNC_END STRING_PARAM_NEW

%%
event:
	name id format fields prints
	;
name:	
	EVENT_NAME STRING ENDL 
	{ 
	  context->parsed->name = $2;
	  parser_debug("Got name %s\n", $2);
	}
	;
id:
	EVENT_ID INT ENDL  
	{
	  context->parsed->id = $2;
	  parser_debug("Got ID %d\n", $2);
	}
	;
format:
	FORMAT ENDL
	;
fields:
	fields field
	| field
	;	
field:
	FIELD STRING SEMICOLON 
	FIELD_OFFSET INT SEMICOLON 
	FIELD_SIZE INT SEMICOLON
	{ 
		parser_debug ("Got field %s offset %d, size %d\n", $2, $5, $8);
		parse_new_field(context, $2, $5, $8);
		context->blank_line = 0;
	 } 
	| FIELD_SIGNED INT SEMICOLON 
	{ 
	 	parse_set_field_signed(context, $2);
	 	context->blank_line =0;
		parser_debug ("\tGot signed %d\n", $2);}
	| FIELD_UKNOWN SEMICOLON 
	{ 	
		context->blank_line =0;
		parser_debug(", Got unknown %s", $1); 
	}
	| ENDL {
		context->blank_line++;
		if(context->blank_line > 1) 
			context->current_fields = &(context->parsed->format.fields);
		parser_debug ("\n\r"); }
	;
prints:
	prints print
	| print
	;
print:
	PRINT_FMT PRINT_STRING_START
	| PRINT_PARAM_START 
	| PARAM_ARG_FUNC { parser_debug(" Got param func [%s] \n", $1);}
	| STRING_PARAM_REC { parser_debug(" Got param REC [%s]\n", $1);}
	| STRING_PARAM_OP {parser_debug(" Got param OP [%s]\n", $1);}
	| STRING_PRINT { 
		parser_debug("Got print string: [%s]\n", $1); 
		parse_new_print_str(context, $1); }		
	| STRING_PARAM { parser_debug("Got print param: [%s]\n", $1); }
	| STRING_PARAM_NEW { parser_debug (" param NEW\n"); }
	| PARAM_FUNC_END { parser_debug("Func END\n"); }
	| ENDL { parser_debug("\n"); }	
	;
%%

void yyerror(struct tep_format_parser_context *context, const char *s) {
	printf("Parse error at line %d: %s\n\r", context->line_num, s);
	exit(-1);
}
