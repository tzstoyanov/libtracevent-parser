// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (C) 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 */
#include <stdlib.h>
#include "event-parse.h"
#include "event-parse-local.h"

#define PARSER_DEBUG
void parser_debug(const char *format, ...)
{
#ifdef PARSER_DEBUG
	va_list args;

	va_start(args, format);
	vprintf(format, args);
	va_end(args);
#endif
}

static int field_is_string(struct tep_format_field *field)
{
	if ((field->flags & TEP_FIELD_IS_ARRAY) &&
	    (strstr(field->type, "char") || strstr(field->type, "u8") ||
	     strstr(field->type, "s8")))
		return 1;

	return 0;
}

static int field_is_dynamic(struct tep_format_field *field)
{
	if (strncmp(field->type, "__data_loc", 10) == 0)
		return 1;

	return 0;
}

static int field_is_long(struct tep_format_field *field)
{
	/* includes long long */
	if (strstr(field->type, "long"))
		return 1;

	return 0;
}

static unsigned int type_size(const char *name)
{
	/* This covers all TEP_FIELD_IS_STRING types. */
	static struct {
		const char *type;
		unsigned int size;
	} table[] = {
		{ "u8",   1 },
		{ "u16",  2 },
		{ "u32",  4 },
		{ "u64",  8 },
		{ "s8",   1 },
		{ "s16",  2 },
		{ "s32",  4 },
		{ "s64",  8 },
		{ "char", 1 },
		{ },
	};
	int i;

	for (i = 0; table[i].type; i++) {
		if (strstr(table[i].type, name))
			return table[i].size;
	}

	return 0;
}

int is_char_operator(char ch)
{
	switch (ch) {
	case '+':
	case '-':
	case '/':
	case '*':
		return 1;
	}
	return 0;
}


void parse_new_field(struct tep_format_parser_context *context,
			    char *field_string, int offset, int size)
{
	int str_len = 0, bracket = 0, i;
	char *saved_array_len = NULL;
	char *save_ptr, *save_digit;
	struct tep_format_field *new_field;

	if (!context || !context->parsed || !field_string)
		return;
	new_field = calloc(1, sizeof(*new_field));
	if (!new_field)
		return;
	/* Go to the end of the string */
	new_field->name = field_string + strlen(field_string);
	/* Search for the interval */
	while (bracket || (*(new_field->name) != ' ' && *(new_field->name) != '\t')) {
		if (new_field->name == field_string)
			goto fail;
		if (*new_field->name == ']')
			bracket++;
		if (*new_field->name == '[')
			bracket--;
		new_field->name--;
	}
	if (new_field->name == field_string)
		goto fail;
	new_field->name++ /* skip the interval  */;
	*(new_field->name-1)='\0';
	new_field->type = field_string;

	if (*(new_field->name) == '*') {
		*(new_field->name) = '\0';
		new_field->name++;
		new_field->type[strlen(new_field->type)] = '*';

	}

	if (strstr(new_field->type, "*"))
		new_field->flags |= TEP_FIELD_IS_POINTER;
	if (strstr(new_field->name, "[")) {
		save_ptr = new_field->name;
		while(*save_ptr != '[' && *save_ptr != '\0')
			save_ptr++;
		if (*save_ptr != '\0') {
			*save_ptr = '\0';
			save_ptr++;
			save_digit = save_ptr;
			while(*save_ptr != ']' && *save_ptr != '\0')
				save_ptr++;
			if (*save_ptr != '\0') {
				*save_ptr = '\0';
				new_field->flags |= TEP_FIELD_IS_ARRAY;
				new_field->arraylen = strtoul(save_digit, NULL, 0);
				saved_array_len = strdup(save_digit);
				str_len = 3 + strlen(save_digit);
				memmove(new_field->name + str_len,
					new_field->name, strlen(new_field->name)+1);
				new_field->name += str_len;
			}
		}
	}
	new_field->alias = new_field->name;

	if (field_is_string(new_field))
		new_field->flags |= TEP_FIELD_IS_STRING;
	if (field_is_dynamic(new_field))
		new_field->flags |= TEP_FIELD_IS_DYNAMIC;
	if (field_is_long(new_field))
		new_field->flags |= TEP_FIELD_IS_LONG;

	new_field->offset = offset;
	new_field->size = size;

	if (new_field->flags & TEP_FIELD_IS_ARRAY) {

		if (new_field->arraylen)
			new_field->elementsize = new_field->size / new_field->arraylen;
		else if (new_field->flags & TEP_FIELD_IS_DYNAMIC)
			new_field->elementsize = type_size(new_field->type);
		else if (new_field->flags & TEP_FIELD_IS_STRING)
			new_field->elementsize = 1;
		else if (new_field->flags & TEP_FIELD_IS_LONG)
			 new_field->elementsize = context->parsed->pevent ?
					 	  context->parsed->pevent->long_size :
						  sizeof(long);
		if (saved_array_len) {
			save_ptr = new_field->type + strlen(new_field->type);
#if 0
			sprintf(save_ptr, "[%s]", saved_array_len);
#else
			*save_ptr='[';
			save_ptr++;
			i = 0;
			while(*(saved_array_len+i) != '\0') {
				if (*(saved_array_len+i) == ' ' ||
				   *(saved_array_len+i) == '\t') {
					if (is_char_operator(*(saved_array_len+i+1))) {
						i++;
						continue;
					}
					if (is_char_operator(*(saved_array_len+i-1))) {
						i++;
						continue;
					}

				}
				*save_ptr=*(saved_array_len+i);
				save_ptr++;
				i++;
			}
			*save_ptr=']';
			save_ptr++;
			*save_ptr='\0';
#endif
			free(saved_array_len);
		}
	} else
		new_field->elementsize = new_field->size;

	*context->current_fields = new_field;
	context->current_fields = &new_field->next;

	return;
fail:
	free(field_string);
	free(new_field);
}

void parse_new_print_str(struct tep_format_parser_context *context,
			 char *print_string)
{
	if (!context || !context->parsed)
		return;
	if (context->parsed->print_fmt.format) {
		context->parsed->print_fmt.format =
				realloc(context->parsed->print_fmt.format,
					strlen(print_string)+1+
					strlen(context->parsed->print_fmt.format)+1);
		strcat(context->parsed->print_fmt.format, print_string);
		free(print_string);
	} else {
		context->parsed->print_fmt.format = print_string;
	}
}

struct tep_print_arg *parse_print_stack_pop(struct tep_format_parser_context *context)
{
	struct tep_print_arg *arg = NULL;
	struct tep_format_parser_stack *stack = context->stack;
	if (stack) {
		context->stack = stack->next;
		context->args = stack->args;
		context->current_arg = stack->arg;
		arg = stack->arg;
		free(stack);
	}
	return  arg;
}

struct tep_print_arg *parse_print_stack_try_pop(struct tep_format_parser_context *context)
{
	struct tep_print_arg *arg = NULL;
	struct tep_print_arg *arg_current = context->current_arg;
	if (context->stack && context->stack->arg) {
		switch (context->stack->arg->type) {
		case TEP_PRINT_OP:
			if (context->stack->arg->op.right) {
				arg = parse_print_stack_pop(context);
				if(arg) {
					*context->args = context->current_arg;
					context->args = &context->current_arg->next;
					context->current_arg = arg_current;
				}
			}
			break;
		case TEP_PRINT_FLAGS:
			if (context->stack->arg->flags.field) {
				arg = parse_print_stack_pop(context);
				if(arg) {
					*context->args = context->current_arg;
					context->args = &context->current_arg->next;
					context->current_arg = arg_current;
				}
			}
			break;
		case TEP_PRINT_SYMBOL:
			if (context->stack->arg->symbol.field) {
				arg = parse_print_stack_pop(context);
				if(arg) {
					*context->args = context->current_arg;
					context->args = &context->current_arg->next;
					context->current_arg = arg_current;
				}
			}
			break;
		default:
			break;
		}
	}
	return arg;
}


void parse_print_stack_push(struct tep_format_parser_context *context, struct tep_print_arg *arg)
{
	struct tep_format_parser_stack *stack;
	stack = calloc(1, sizeof(*stack));
	stack->arg = arg;
	stack->args = context->args;
	stack->next = context->stack;
	context->stack = stack;
}

void parse_print_getnext_arg(struct tep_format_parser_context *context)
{
	bool pushed = false;

	while(parse_print_stack_try_pop(context));

	if (context->current_arg) {
		switch (context->current_arg->type) {
		case TEP_PRINT_OP:
			if(!context->current_arg->op.right) {
				pushed = true;
				parse_print_stack_push(context, context->current_arg);
				context->args = &context->current_arg->op.right;
			}			break;
		case TEP_PRINT_FLAGS:
			if(!context->current_arg->flags.field) {
				pushed = true;
				parse_print_stack_push(context, context->current_arg);
				context->args = &context->current_arg->flags.field;
			}
			break;
		case TEP_PRINT_SYMBOL:
			if(!context->current_arg->symbol.field) {
				pushed = true;
				parse_print_stack_push(context, context->current_arg);
				context->args = &context->current_arg->symbol.field;
			}
			break;
		default:
			break;
		}
		if(!pushed) {
			*context->args = context->current_arg;
			context->args = &context->current_arg->next;
		}
	}
}

void parse_new_print_param(struct tep_format_parser_context *context,
			   enum tep_print_arg_type type)
{
	struct tep_print_arg *arg;

	if (!context || !context->parsed)
		return;

	if (!context->arg_completed && context->current_arg &&
	   (context->current_arg->type == TEP_PRINT_NULL ||
	    context->current_arg->type == type)) {
		context->current_arg->type = type;
		return;
	}

	arg = calloc(1, sizeof(*arg));
	arg->type = type;

	switch (arg->type) {
	case TEP_PRINT_OP:
		arg->op.left = context->current_arg;
		break;
	default:
		parse_print_getnext_arg(context);
		break;
	}

	context->current_arg = arg;
	context->arg_completed = 0;
}

void parse_func_end_param(struct tep_format_parser_context *context)
{
	context->arg_completed = 1;
	*context->args = context->current_arg;
	parse_print_stack_pop(context);
}

void parse_func_end_file(struct tep_format_parser_context *context)
{
	parse_print_getnext_arg(context);
}

void parse_flags_print_param(struct tep_format_parser_context *context)
{
	struct tep_print_arg *flags;

	parse_new_print_param(context, TEP_PRINT_FLAGS);

	flags = context->current_arg;
	context->flags = &flags->flags.flags;
}

void parse_symbol_print_param(struct tep_format_parser_context *context)
{
	struct tep_print_arg *flags;

	parse_new_print_param(context, TEP_PRINT_SYMBOL);

	flags = context->current_arg;
	context->flags = &flags->symbol.symbols;
}

#define REC_PREFIX	"REC->"
void parse_field_print_param(struct tep_format_parser_context *context, char *param)
{
	parse_new_print_param(context, TEP_PRINT_FIELD);

	if (!strncmp(REC_PREFIX, param, strlen(REC_PREFIX))) {
		memmove(param, param+strlen(REC_PREFIX),
			strlen(param)-strlen(REC_PREFIX));
		param[strlen(param)-strlen(REC_PREFIX)] = '\0';
	}
	if (context->current_arg->field.name) {
		context->current_arg->field.name =
			realloc(context->current_arg->field.name,
				strlen(param)+
				strlen(context->current_arg->field.name)+1);
		strcat(context->current_arg->field.name, param);
		free(param);
	} else {
		context->current_arg->type = TEP_PRINT_FIELD;
		context->current_arg->field.name = param;
	}
}

void parse_atom_print_param(struct tep_format_parser_context *context, char *param)
{
	int len=0;
	char *quote, *tmp;
	parse_new_print_param(context, TEP_PRINT_ATOM);

	/* remove quotes from the atom */
	quote = strstr(param, "\"");
	if(quote) {
		tmp = quote+1;
		while(*tmp != '\0') {
			if(*tmp == '\"')
				*tmp='\0';
			else
				tmp++;
			len++;
		}
		memmove(param, quote+1, len+1);
	}

	if (context->current_arg->field.name) {
		context->current_arg->field.name =
			realloc(context->current_arg->field.name,
				strlen(param)+
				strlen(context->current_arg->field.name)+1);
		strcat(context->current_arg->field.name, param);
		free(param);
	} else {
		context->current_arg->type = TEP_PRINT_ATOM;
		context->current_arg->field.name = param;
	}
}

void parse_op_print_param(struct tep_format_parser_context *context, char *param)
{
	if (context->stack && context->stack->arg &&
	   TEP_PRINT_FLAGS == context->stack->arg->type &&
	   NULL == context->stack->arg->flags.delim) {
		context->stack->arg->flags.delim = param;
		return;
	}

	parse_new_print_param(context, TEP_PRINT_OP);

	if (context->current_arg->op.op) {
		context->current_arg->op.op =
			realloc(context->current_arg->op.op,
				strlen(param)+
				strlen(context->current_arg->op.op)+1);
		strcat(context->current_arg->op.op, param);
		free(param);
	} else{
		context->current_arg->op.op = param;
	}
}

void parse_flag_print_param(struct tep_format_parser_context *context,
			    char *value, char *name)
{
	struct tep_print_flag_sym *flag;
	if (!context || !context->flags)
		return;
	flag = calloc(1, sizeof(*flag));
	*context->flags = flag;
	context->flags = &flag->next;
	flag->value = value;
	flag->str = name;
}

void parse_set_field_signed(struct tep_format_parser_context *context, int is_signed)
{
	if (!context || !context->current_fields || !(*(context->current_fields)) )
		return;
	if (is_signed)
		(*(context->current_fields))->flags |= TEP_FIELD_IS_SIGNED;
}

int count_parsed_fields(struct tep_format_field *fields)
{
	int count = 0;

	while (fields) {
		count++;
		fields = fields->next;
	}
	return count;
}
