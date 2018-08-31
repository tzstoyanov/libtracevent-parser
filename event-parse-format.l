%{
#include "event-parse.h"
#include "event-parse-local.h"
#include "event-parse-format-bison.h"
extern int yylex(struct tep_format_parser_context *context);
%}
%option noyywrap
%x FORMAT_START
%x FIELD_START
%x INT_PARAM
%x PRINT
%x PRINT_STRING
%x PRINT_PARAMS
%x PRINT_PARAMS_FUNC
%x PRINT_PARAMS_FUNC_CURLY
%%
name\:				{ return EVENT_NAME; }
ID\:				{ return EVENT_ID; }
format\:			{ BEGIN(FORMAT_START); return FORMAT; }
<FORMAT_START>[ \t]+field\:	{ BEGIN(FIELD_START); return FIELD; }
<FORMAT_START>[ \t]+field[ \t]+special\: {
				  	BEGIN(FIELD_START); return FIELD; 
				  }
<FORMAT_START>[ \t]+offset\:	{ BEGIN(INT_PARAM); return FIELD_OFFSET; }
<FORMAT_START>[ \t]+size\:	{ BEGIN(INT_PARAM); return FIELD_SIZE; }
<FORMAT_START>[ \t]+signed\:	{ BEGIN(INT_PARAM); return FIELD_SIGNED; }
<INT_PARAM>[0-9]+		{ yylval.ival = atoi(yytext); 
				  BEGIN(FORMAT_START); return INT; 
				}
<FIELD_START,FORMAT_START,INT_PARAM>[\;] {
				 BEGIN(FORMAT_START); return SEMICOLON; 
				 }
<FIELD_START>[^\;]+ {
				 yylval.sval = strdup(yytext); return STRING; 
				 }
<*>print[ \t]fmt\:[ \t]		{ BEGIN(PRINT); return PRINT_FMT; }
<INITIAL>[0-9]+			{ yylval.ival = atoi(yytext); return INT; }
<INITIAL>[a-zA-Z0-9\_]+		{ yylval.sval = strdup(yytext); return STRING; }
<PRINT_PARAMS_FUNC>[ \t\[\],]*\( { 
				   context->bracket_count++; 
				   yylval.sval = strdup(yytext); 
				   return STRING_PARAM; 
				 }
<FORMAT_START>[a-zA-Z0-9\_\:]+	{ 
				  yylval.sval = strdup(yytext); 
				  return FIELD_UKNOWN; 
				}
<*>\n				{  context->line_num++;  return ENDL; }
<PRINT>\"			{ BEGIN(PRINT_STRING); return PRINT_STRING_START; }
<PRINT_STRING>\",		{ BEGIN(PRINT_PARAMS); return PRINT_PARAM_START; }
<PRINT_PARAMS_FUNC>\)		{ 
				  if(context->bracket_count > 0)
				  {
				  	context->bracket_count--;
				  	if(!context->bracket_count)
				  	{
				  		BEGIN(PRINT_PARAMS); 
				  	 	return PARAM_FUNC_END; 
				  	} else {
					  	yylval.sval = strdup(yytext); 
					  	return STRING_PARAM;
					}
				 }
				}
<PRINT_PARAMS,PRINT_PARAMS_FUNC>,[ \t]*	{ return STRING_PARAM_NEW; }
<PRINT_PARAMS>__print_flags\( 	{ 
				  context->bracket_count=1;
				  BEGIN(PRINT_PARAMS_FUNC);  
				  return PARAM_FLAGS_FUNC; 
				 }
<PRINT_PARAMS>__get_str\( 	{
				  context->bracket_count=1;
				  BEGIN(PRINT_PARAMS_FUNC);  
				  return PARAM_STR_FUNC; 
				 }
<PRINT_PARAMS>__print_symbolic\( {
				  context->bracket_count=1;
				  BEGIN(PRINT_PARAMS_FUNC);  
				  return PARAM_SYMB_FUNC; 
				 }
<PRINT_PARAMS>__print_hex\( 	{
				  context->bracket_count=1;
				  BEGIN(PRINT_PARAMS_FUNC);  
				  return PARAM_HEX_FUNC; 
				 }
<PRINT_PARAMS>__print_hex_str\( {
				  context->bracket_count=1;
				  BEGIN(PRINT_PARAMS_FUNC);  
				  return PARAM_HEXSTR_FUNC; 
				 }
<PRINT_PARAMS>__print_array\( 	{
				  context->bracket_count=1;
				  BEGIN(PRINT_PARAMS_FUNC);  
				  return PARAM_ARRAY_FUNC; 
				 }
<PRINT_PARAMS>__get_bitmask\( 	{
				  context->bracket_count=1;
				  BEGIN(PRINT_PARAMS_FUNC);  
				  return PARAM_BITMASK_FUNC; 
				 }
<PRINT_PARAMS>__get_dynamic_array\( {
				  context->bracket_count=1;
				  BEGIN(PRINT_PARAMS_FUNC);  
				  return PARAM_DARRAY_FUNC; 
				 }
<PRINT_PARAMS>__get_dynamic_array_len		{
				  context->bracket_count=1;
				  BEGIN(PRINT_PARAMS_FUNC);  
				  return PARAM_DARRAYLEN_FUNC; 
				 }
				 
<PRINT_PARAMS>[a-zA-Z0-9\_\-]+\( { 
				    yylval.sval = strdup(yytext); 
				    context->bracket_count=1;
				    BEGIN(PRINT_PARAMS_FUNC);  
				    return PARAM_ARG_FUNC; 
				  }
<PRINT_PARAMS>\(		{ 
				 yylval.sval = strdup(yytext); 
				 return STRING_PARAM; 
				}
<PRINT_PARAMS_FUNC>\{		{ 
					BEGIN(PRINT_PARAMS_FUNC_CURLY); 
					return  PRINT_PARAMS_FUNC_CURLY_START;
				}
<PRINT_PARAMS,PRINT_PARAMS_FUNC>REC\-\>[a-zA-Z0-9\_\-]+ {
					yylval.sval = strdup(yytext);
					return STRING_PARAM;
				}
<PRINT_PARAMS_FUNC_CURLY>[^,^\}]+ {
				   yylval.sval = strdup(yytext); 
				   return STRING_PARAM;
				 }
<PRINT_PARAMS_FUNC_CURLY>\}	{ 
					BEGIN(PRINT_PARAMS_FUNC);
					return  PRINT_PARAMS_FUNC_CURLY_END;
				}
<PRINT_STRING>[^"]*		{ 
				 yylval.sval = strdup(yytext); 
				 return STRING_PRINT; 
				}
<PRINT_PARAMS,PRINT_PARAMS_FUNC>\"[^"]*\" { 
				      yylval.sval = strdup(yytext); 
				      return STRING_PARAM_ATOM; 
				     }
<PRINT_PARAMS,PRINT_PARAMS_FUNC>[^,^\n^\r^\(^\)^ ^\t^-^+^\/^&^<^>^=^!^|^?^:]* { 
				      yylval.sval = strdup(yytext); 
				      return STRING_PARAM; 
				     }
<PRINT_PARAMS,PRINT_PARAMS_FUNC>[+\/&<>=!|?:]+ {
					yylval.sval = strdup(yytext); 
					return STRING_PARAM_OP; 
				}
				
<<EOF>>				{ static int end=0; if(!end++) return FILE_END; yyterminate();}
%%
