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
void parse_field_print_param(struct tep_format_parser_context *context, char *param);
void parse_op_print_param(struct tep_format_parser_context *context, char *param);
void parse_print_stack_pop(struct tep_format_parser_context *context);
void parse_flag_print_param(struct tep_format_parser_context *context,
			    char *value, char *name);
void parse_func_end_param(struct tep_format_parser_context *context);
void parse_func_end_file(struct tep_format_parser_context *context);
void parse_atom_print_param(struct tep_format_parser_context *context, char *param);
void parse_flags_print_param(struct tep_format_parser_context *context);
void parse_symbol_print_param(struct tep_format_parser_context *context);
void parse_typecast_print_param(struct tep_format_parser_context *context, char *type);
void parse_strfunc_print_param(struct tep_format_parser_context *context, char *string);

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
%token <sval> STRING_PARAM_OP
%token <sval> STRING_PARAM_ATOM
%token EVENT_NAME EVENT_ID FORMAT
%token FIELD FIELD_OFFSET FIELD_SIZE FIELD_SIGNED
%token PRINT_FMT COMMA DQUOTE
%token SEMICOLON ENDL 
%token PRINT_STRING_START PRINT_PARAM_START
%token PARAM_FUNC_END STRING_PARAM_NEW
%token PRINT_PARAMS_FUNC_CURLY_START
%token PRINT_PARAMS_FUNC_CURLY_END
%token PARAM_STR_FUNC PARAM_SYMB_FUNC PARAM_HEX_FUNC PARAM_HEXSTR_FUNC
%token PARAM_FLAGS_FUNC PARAM_ARRAY_FUNC PARAM_BITMASK_FUNC 
%token PARAM_DARRAY_FUNC PARAM_DARRAYLEN_FUNC
%token PARAM_TYPE FILE_END
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
	| PRINT_PARAMS_FUNC_CURLY_START 
	  STRING_PARAM STRING_PARAM 
	  PRINT_PARAMS_FUNC_CURLY_END {
	  				parser_debug("Got curly pair [%s],[%s]\n", 
	  					     $2, $3);
	  				parse_flag_print_param(context, $2, $3);
	  			      } 
	| PARAM_ARG_FUNC { 
				parser_debug(" Got param func [%s] \n", $1);
			 }
	| PARAM_FLAGS_FUNC { 
				parser_debug(" Got param flags func \n");
				parse_flags_print_param(context);
			   }
	| PARAM_STR_FUNC STRING_PRINT {
				parser_debug(" Got param string %s \n", $2);
				parse_strfunc_print_param(context, $2);
			 }
	| PARAM_SYMB_FUNC {
				parser_debug(" Got param symbolic func \n");
				parse_symbol_print_param(context);
			 }
	| PARAM_HEX_FUNC {
				parser_debug(" Got param hex func \n");
			 }
	| PARAM_HEXSTR_FUNC {
				parser_debug(" Got param hex string func \n");
			 }
	| PARAM_ARRAY_FUNC {
				parser_debug(" Got param array func \n");
			 }
	| PARAM_BITMASK_FUNC {
				parser_debug(" Got param bitmask func \n");
			 }
	| PARAM_DARRAY_FUNC {
				parser_debug(" Got param dynamic array func \n");
			 }
	| PARAM_DARRAYLEN_FUNC {
				parser_debug(" Got param dynamic array func \n");
			 }
	| STRING_PARAM_OP {
				parser_debug(" Got param OP [%s]\n", $1);
				parse_op_print_param(context, $1);
			  }
	| STRING_PRINT { 
				parser_debug("Got print string: [%s]\n", $1); 
				parse_new_print_str(context, $1); 
		       }
	| STRING_PARAM { 
				parser_debug("Got print param: [%s]\n", $1); 
				parse_field_print_param(context, $1);
			}
	| STRING_PARAM_ATOM { 
				parser_debug("Got ATOM string: [%s]\n", $1); 
				parse_atom_print_param(context, $1); 
		       }			
	| STRING_PARAM_NEW { 
			   	context->arg_completed=1;	
			   	parser_debug (" param NEW\n"); 
			   }
	| PARAM_FUNC_END { 
				parser_debug("Func END\n");
				parse_func_end_param(context); 
			}
	| PARAM_TYPE STRING_PRINT { 
			  parser_debug("Got TYPECAST %s\n", $2); 
			  parse_typecast_print_param(context, $2);				
			}
	| ENDL { parser_debug("\n"); }
	| FILE_END { 
			parser_debug("Got EOF\n");
			parse_func_end_file(context); 
		   }
	;
%%

void yyerror(struct tep_format_parser_context *context, const char *s) {
	printf("Parse error at line %d: %s\n\r", context->line_num, s);
	exit(-1);
}
