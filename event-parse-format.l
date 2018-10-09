%{
#include "event-parse.h"
#include "event-parse-local.h"
#include "event-parse-format-bison.h"
extern int yylex(struct tep_format_parser_context *context);
#define SET_STATE(__state__) if(YY_START != __state__) { \
	 		context->parse_context = YY_START; BEGIN(__state__); }
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
%x PRINT_PARAMS_STR_FUNC
%%
name\:				{ return EVENT_NAME; }
ID\:				{ return EVENT_ID; }
format\:			{ SET_STATE(FORMAT_START); return FORMAT; }
<FORMAT_START>[ \t]+field\:	{ SET_STATE(FIELD_START); return FIELD; }
<FORMAT_START>[ \t]+field[ \t]+special\: {
				  	SET_STATE(FIELD_START); return FIELD; 
				  }
<FORMAT_START>[ \t]+offset\:	{ SET_STATE(INT_PARAM); return FIELD_OFFSET; }
<FORMAT_START>[ \t]+size\:	{ SET_STATE(INT_PARAM); return FIELD_SIZE; }
<FORMAT_START>[ \t]+signed\:	{ SET_STATE(INT_PARAM); return FIELD_SIGNED; }
<INT_PARAM>[0-9]+		{ yylval.ival = atoi(yytext); 
				  SET_STATE(FORMAT_START); return INT; 
				}
<FIELD_START,FORMAT_START,INT_PARAM>[\;] {
				 SET_STATE(FORMAT_START); return SEMICOLON; 
				 }
<FIELD_START>[^\;]+ {
				 yylval.sval = strdup(yytext); return STRING; 
				 }
<*>print[ \t]fmt\:[ \t]		{ SET_STATE(PRINT); return PRINT_FMT; }
<INITIAL>[0-9]+			{ yylval.ival = atoi(yytext); return INT; }
<INITIAL>[a-zA-Z0-9\_]+		{ yylval.sval = strdup(yytext); return STRING; }
<FORMAT_START>[a-zA-Z0-9\_\:]+	{ 
				  yylval.sval = strdup(yytext); 
				  return FIELD_UKNOWN; 
				}
<*>\n				{  context->line_num++;  return ENDL; }
<PRINT>\"			{ SET_STATE(PRINT_STRING); return PRINT_STRING_START; }
<PRINT_STRING>\",		{ SET_STATE(PRINT_PARAMS); return PRINT_PARAM_START; }
<PRINT_PARAMS,PRINT_PARAMS_FUNC>,[ \t]*	{ return STRING_PARAM_NEW; }
<PRINT_PARAMS,PRINT_PARAMS_FUNC>__print_flags[ \t]*\( 	{ 
				  context->bracket_count++;
				  SET_STATE(PRINT_PARAMS_FUNC);  
				  return PARAM_FLAGS_FUNC; 
				 }
<PRINT_PARAMS,PRINT_PARAMS_FUNC>__get_str[ \t]*\( 	{
				  SET_STATE(PRINT_PARAMS_STR_FUNC);  
				  return PARAM_STR_FUNC; 
				}
<PRINT_PARAMS,PRINT_PARAMS_FUNC>__print_symbolic[ \t]*\( {
				  context->bracket_count++;
				  SET_STATE(PRINT_PARAMS_FUNC);  
				  return PARAM_SYMB_FUNC; 
				 }
<PRINT_PARAMS,PRINT_PARAMS_FUNC>__print_hex[ \t]*\( 	{
				  context->bracket_count++;
				  SET_STATE(PRINT_PARAMS_FUNC);  
				  return PARAM_HEX_FUNC; 
				 }
<PRINT_PARAMS,PRINT_PARAMS_FUNC>__print_hex_str[ \t]*\( {
				  context->bracket_count++;
				  SET_STATE(PRINT_PARAMS_FUNC);  
				  return PARAM_HEXSTR_FUNC; 
				 }
<PRINT_PARAMS,PRINT_PARAMS_FUNC>__print_array[ \t]*\( 	{
				  context->bracket_count++;
				  SET_STATE(PRINT_PARAMS_FUNC);  
				  return PARAM_ARRAY_FUNC; 
				 }
<PRINT_PARAMS,PRINT_PARAMS_FUNC>__get_bitmask[ \t]*\( 	{
				  context->bracket_count++;
				  SET_STATE(PRINT_PARAMS_STR_FUNC);  
				  return PARAM_BITMASK_FUNC; 
				 }
<PRINT_PARAMS,PRINT_PARAMS_FUNC>__get_dynamic_array[ \t]*\( {
				  context->bracket_count++;
				  SET_STATE(PRINT_PARAMS_FUNC);  
				  return PARAM_DARRAY_FUNC; 
				 }
<PRINT_PARAMS,PRINT_PARAMS_FUNC>__get_dynamic_array_len[ \t]*\(	{
				  context->bracket_count++;
				  SET_STATE(PRINT_PARAMS_FUNC);  
				  return PARAM_DARRAYLEN_FUNC; 
				 }
				 
<PRINT_PARAMS,PRINT_PARAMS_FUNC>[a-zA-Z0-9\_\-]+\( { 
				    yylval.sval = strdup(yytext); 
				    context->bracket_count++;
				    SET_STATE(PRINT_PARAMS_FUNC);  
				    return PARAM_ARG_FUNC; 
				  }
<PRINT_PARAMS,PRINT_PARAMS_FUNC>[ \t]*\(	{ 
				 context->bracket_count++;
				 return PARAM_BRACKET_OPEN; 
				}
<PRINT_PARAMS_STR_FUNC>[^\(^\)]* { 
				 	yylval.sval = strdup(yytext); 
				 	return STRING_PRINT; 
				 }
<PRINT_PARAMS_FUNC,PRINT_PARAMS_STR_FUNC,PRINT_PARAMS>\) { 
			  		if(context->bracket_count > 0) 
			  			context->bracket_count--;
		  			if(context->bracket_count == 0) {
		  				SET_STATE(PRINT_PARAMS);
			  			if (PRINT_PARAMS_FUNC == context->parse_context) {
			  				return PARAM_FUNC_END; 
			  			}
		  			} else {
		  				SET_STATE(PRINT_PARAMS_FUNC);
		  			}
		  			return PARAM_BRACKET_CLOSE;
				}
<PRINT_PARAMS,PRINT_PARAMS_FUNC>REC\-\>[a-zA-Z0-9\_\-]+ {
					yylval.sval = strdup(yytext);
					return STRING_PARAM;
				}
<PRINT_PARAMS_FUNC>\{		{ 
					return  PRINT_PARAMS_FUNC_CURLY_START;
				}
<PRINT_PARAMS_FUNC_CURLY>[^,^\}]+ {
				   yylval.sval = strdup(yytext); 
				   return STRING_PARAM;
				 }
<PRINT_PARAMS_FUNC>\}	{ 
					SET_STATE(PRINT_PARAMS_FUNC);
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
<PRINT_PARAMS,PRINT_PARAMS_FUNC>[0-9]* { 
				      yylval.sval = strdup(yytext); 
				      return STRING_PARAM_ATOM; 
				     }				     
<PRINT_PARAMS,PRINT_PARAMS_FUNC>[^,^\n^\r^\(^\)^ ^\t^-^+^\/^&^<^>^=^!^|^?^:^~^\{^\}]* { 
				      yylval.sval = strdup(yytext); 
				      return STRING_PARAM; 
				     }
<PRINT_PARAMS,PRINT_PARAMS_FUNC>\+\+ {
					yylval.sval = strdup(yytext); 
					return STRING_PARAM_OP; 
				}
<PRINT_PARAMS,PRINT_PARAMS_FUNC>\-\- {
					yylval.sval = strdup(yytext); 
					return STRING_PARAM_OP; 
				}
<PRINT_PARAMS,PRINT_PARAMS_FUNC>\<\< {
					yylval.sval = strdup(yytext); 
					return STRING_PARAM_OP; 
				}
<PRINT_PARAMS,PRINT_PARAMS_FUNC>\>\> {
					yylval.sval = strdup(yytext); 
					return STRING_PARAM_OP; 
				}
<PRINT_PARAMS,PRINT_PARAMS_FUNC>[<>=!][=] {
					yylval.sval = strdup(yytext); 
					return STRING_PARAM_OP; 
				}
<PRINT_PARAMS,PRINT_PARAMS_FUNC>\&\& {
					yylval.sval = strdup(yytext); 
					return STRING_PARAM_OP; 
				}
<PRINT_PARAMS,PRINT_PARAMS_FUNC>\|\| {
					yylval.sval = strdup(yytext); 
					return STRING_PARAM_OP; 
				}
<PRINT_PARAMS,PRINT_PARAMS_FUNC>[+\/&<>=!|?:~\-] {
					yylval.sval = strdup(yytext); 
					return STRING_PARAM_OP; 
				}
				
<<EOF>>				{ static int end=0; if(!end++) return FILE_END; yyterminate();}
%%
