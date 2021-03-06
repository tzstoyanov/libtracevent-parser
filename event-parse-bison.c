// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (C) 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 */
#include <stdlib.h>
#include "event-parse.h"
#include "event-parse-local.h"

/*#define PARSER_DEBUG*/
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

static int is_char_operator(char ch)
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

static bool is_operator_unary(char *op)
{
	if (!op)
		return false;
	if (op[1] == '\0') {
		switch (op[0])
		{
		case '~':
		case '!':
			return true;
		}
	} else if (op[0] == op[1]) {
		switch (op[0])
		{
		case '+':
		case '-':
			return true;
		}
	}
	return false;
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
		while (*save_ptr != '[' && *save_ptr != '\0')
			save_ptr++;
		if (*save_ptr != '\0') {
			*save_ptr = '\0';
			save_ptr++;
			save_digit = save_ptr;
			while (*save_ptr != ']' && *save_ptr != '\0')
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
			while (*(saved_array_len+i) != '\0') {
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

	/* fix for tep_free_format() function */
	new_field->name = strdup(new_field->name);
	new_field->alias = new_field->name;

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
		if (stack->arg->type != TEP_PRINT_NULL) {
			arg = stack->arg;
			context->current_arg = stack->arg;
		} else
			free(stack->arg);
		context->arg_completed = 1;
		free(stack);
	}
	return  arg;
}

void parse_print_func_params_set(struct tep_print_arg *func) {
	if (!func)
		return;
	switch (func->type) {
	case TEP_PRINT_HEX:
	case TEP_PRINT_HEX_STR:
		if (func->hex.field) {
			func->hex.size = func->hex.field->next;
			func->hex.field->next = NULL;
		}
		break;
	case TEP_PRINT_INT_ARRAY:
		if (func->int_array.field) {
			func->int_array.count = func->int_array.field->next;
			func->int_array.field->next = NULL;
		}
		if (func->int_array.count) {
			func->int_array.el_size = func->int_array.count->next;
			func->int_array.count->next = NULL;
		}
		break;
	default:
		break;
	}
}

struct tep_print_arg *parse_print_stack_try_pop(struct tep_format_parser_context *context)
{
	struct tep_print_arg *arg = NULL;

	if (context->stack && context->stack->arg &&
	    context->stack->bracket <= (1+context->bracket_count)) {
		switch (context->stack->arg->type) {
		case TEP_PRINT_OP:
			if (context->stack->arg->op.right)
				arg = parse_print_stack_pop(context);
			break;
		case TEP_PRINT_FLAGS:
			if (context->func_completed) {
				context->stack->arg->flags.completed=1;
				arg = parse_print_stack_pop(context);
				context->func_completed = 0;
			}
			break;
		case TEP_PRINT_SYMBOL:
			if (context->stack->arg->symbol.field)
				arg = parse_print_stack_pop(context);
			break;
		case TEP_PRINT_TYPE:
			if (context->stack->arg->typecast.item)
				arg = parse_print_stack_pop(context);
			break;
		case TEP_PRINT_HEX:
		case TEP_PRINT_HEX_STR:
			if (context->stack->arg->hex.field &&
			    context->stack->arg->hex.size)
				arg = parse_print_stack_pop(context);
			break;
		case TEP_PRINT_INT_ARRAY:
			if (context->stack->arg->int_array.field &&
			    context->stack->arg->int_array.count &&
			    context->stack->arg->int_array.el_size)
				arg = parse_print_stack_pop(context);
			break;
		case TEP_PRINT_DYNAMIC_ARRAY:
		case TEP_PRINT_DYNAMIC_ARRAY_LEN:
			if (context->stack->arg->dynarray.index)
				arg = parse_print_stack_pop(context);
			break;
		case TEP_PRINT_FUNC:
			if (context->func_completed) {
				arg = parse_print_stack_pop(context);
				if (!arg->func.args) {
					arg->func.args = calloc(1, sizeof(*(arg->func.args)));
					arg->func.args->type = TEP_PRINT_NULL;
				}
				context->func_completed = 0;
			}
			break;
		default:
			if (!context->stack->bracket ||
			   context->stack->bracket == (1+context->bracket_count))
				arg = parse_print_stack_pop(context);
			break;
		}
	}
	return arg;
}

void parse_print_stack_push(struct tep_format_parser_context *context,
			    struct tep_print_arg *arg, int bracket)
{
	struct tep_format_parser_stack *stack;
	if (context->stack && context->stack->arg == arg)
		return;
	stack = calloc(1, sizeof(*stack));
	stack->arg = arg;
	stack->args = context->args;
	stack->next = context->stack;
	stack->bracket = bracket;
	context->stack = stack;
}

#define REC_PREFIX	"REC->"
void parse_print_arg_completed(struct tep_format_parser_context *context, struct tep_print_arg *arg) {
	if (TEP_PRINT_TYPE == arg->type &&
	   NULL == arg->typecast.item) {
		arg->type = TEP_PRINT_FIELD;
		arg->field.name = arg->typecast.type;
		arg->field.field = NULL;
	}
	if (TEP_PRINT_FIELD == arg->type) {
		if (!strncmp(REC_PREFIX, arg->field.name, strlen(REC_PREFIX))) {
			memmove(arg->field.name, arg->field.name+strlen(REC_PREFIX),
				strlen(arg->field.name)-strlen(REC_PREFIX));
			arg->field.name[strlen(arg->field.name)-strlen(REC_PREFIX)] = '\0';
			arg->field.field = tep_find_any_field(context->parsed, arg->field.name);
		}
	}
	if (TEP_PRINT_FUNC == arg->type &&
	    arg->func.args && TEP_PRINT_NULL == arg->func.args->type) {
		free_args(arg->func.args);
		arg->func.args = NULL;
	}
	if (TEP_PRINT_OP == arg->type) {
		set_op_prio(arg);
		if (arg->op.left)
			arg->op.left->next = NULL;
		if (arg->op.right)
			arg->op.right->next = NULL;
	}
	if (context->stack && context->stack->arg == arg)
		parse_print_stack_try_pop(context);
}

void parse_print_getnext_arg(struct tep_format_parser_context *context)
{
	struct tep_print_arg *arg = NULL;
	bool pushed = false;

	do {
		if (!context->current_arg)
			break;
		switch (context->current_arg->type) {
		case TEP_PRINT_OP:
			if (!context->current_arg->op.right) {
				pushed = true;
				parse_print_stack_push(context, context->current_arg, 0);
				context->args = &context->current_arg->op.right;
			}			break;
		case TEP_PRINT_FLAGS:
			if (!context->current_arg->flags.completed) {
				pushed = true;
				parse_print_stack_push(context, context->current_arg, 0);
				context->args = &context->current_arg->flags.field;
			}
			break;
		case TEP_PRINT_SYMBOL:
			if (!context->current_arg->symbol.field) {
				pushed = true;
				parse_print_stack_push(context, context->current_arg, 0);
				context->args = &context->current_arg->symbol.field;
			}
			break;
		case TEP_PRINT_TYPE:
			if (!context->arg_completed && !context->current_arg->typecast.item) {
				pushed = true;
				parse_print_stack_push(context, context->current_arg, 0);
				context->args = &context->current_arg->typecast.item;
			}
			break;
		case TEP_PRINT_HEX:
		case TEP_PRINT_HEX_STR:
			if (!context->current_arg->hex.field) {
				pushed = true;
				parse_print_stack_push(context, context->current_arg, 0);
				context->args = &context->current_arg->hex.field;
			}
			break;
		case TEP_PRINT_INT_ARRAY:
			if (!context->current_arg->int_array.field) {
				pushed = true;
				parse_print_stack_push(context, context->current_arg, 0);
				context->args = &context->current_arg->int_array.field;
			}
			break;
		case TEP_PRINT_DYNAMIC_ARRAY:
		case TEP_PRINT_DYNAMIC_ARRAY_LEN:
			if (!context->current_arg->dynarray.index) {
				pushed = true;
				parse_print_stack_push(context, context->current_arg, 0);
				context->args = &context->current_arg->dynarray.index;
			}
			break;
		case TEP_PRINT_FUNC:
			if (!context->current_arg->func.args) {
				pushed = true;
				parse_print_stack_push(context, context->current_arg, 0);
				context->args = &context->current_arg->func.args;
			}
			break;
		default:
			break;
		}
		if (!pushed && TEP_PRINT_NULL != context->current_arg->type) {
			parse_print_arg_completed(context, context->current_arg);
			if (context->args != &(context->current_arg->next))
			{
				*context->args = context->current_arg;
				if (context->current_arg)
					context->args = &context->current_arg->next;
			}
		}
	arg = parse_print_stack_try_pop(context);
	} while (arg);
}

void parse_new_print_param(struct tep_format_parser_context *context,
			   enum tep_print_arg_type type, bool concat,
			   bool reuse, bool get_next)
{
	struct tep_print_arg *arg;

	if (!context || !context->parsed)
		return;

	if (reuse && context->current_arg && ((concat && !context->arg_completed &&
	     context->current_arg->type == type) ||
	     context->current_arg->type == TEP_PRINT_NULL )) {
		context->current_arg->type = type;
		return;
	}

	arg = calloc(1, sizeof(*arg));
	arg->type = type;
	if(get_next)
		parse_print_getnext_arg(context);

	context->current_arg = arg;
	context->arg_completed = 0;
}

void parse_func_flush_stack(struct tep_format_parser_context *context) {
	struct tep_format_parser_stack *stack;

	context->arg_completed = 1;
	context->func_completed = 1;
	parse_print_arg_completed(context, context->current_arg);
	*context->args = context->current_arg;
	stack = context->stack;
	while (stack) {
		parse_print_func_params_set(stack->arg);
		stack = stack->next;
	}
}

void parse_func_end_param(struct tep_format_parser_context *context)
{
	parse_func_flush_stack(context);
	parse_print_stack_try_pop(context);
}

void parse_func_end_file(struct tep_format_parser_context *context)
{
	parse_func_flush_stack(context);
	while (parse_print_stack_try_pop(context)) {
		parse_print_arg_completed(context, context->current_arg);
		*context->args = context->current_arg;
		context->args = &context->current_arg->next;
	}
}

void parse_flags_print_param(struct tep_format_parser_context *context)
{
	struct tep_print_arg *flags;

	parse_new_print_param(context, TEP_PRINT_FLAGS, true, true, true);

	flags = context->current_arg;
	context->flags = &flags->flags.flags;
}

void parse_symbol_print_param(struct tep_format_parser_context *context)
{
	struct tep_print_arg *flags;

	parse_new_print_param(context, TEP_PRINT_SYMBOL, true, true, true);

	flags = context->current_arg;
	context->flags = &flags->symbol.symbols;
}

void parse_hex_print_param(struct tep_format_parser_context *context)
{
	parse_new_print_param(context, TEP_PRINT_HEX, true, true, true);
}

void parse_hex_str_print_param(struct tep_format_parser_context *context)
{
	parse_new_print_param(context, TEP_PRINT_HEX_STR, true, true, true);
}

void parse_array_print_param(struct tep_format_parser_context *context)
{
	parse_new_print_param(context, TEP_PRINT_INT_ARRAY, true, true, true);
}

void parse_dynarray_print_param(struct tep_format_parser_context *context)
{
	parse_new_print_param(context, TEP_PRINT_DYNAMIC_ARRAY, true, true, true);
}

void parse_func_print_param(struct tep_format_parser_context *context, char *fname)
{
	char *brk;

	parse_new_print_param(context, TEP_PRINT_FUNC, false, true, true);
	brk = strstr(fname, "(");
	if (brk)
		*brk='\0';
	context->current_arg->func.func = find_func_handler(context->pevent, fname);
	if (!context->current_arg->func.func) {
		context->current_arg->func.func = calloc(1, sizeof(struct tep_function_handler));
		context->current_arg->func.func->name = fname;
	}
	context->func_completed = 0;
}

void parse_dynarray_len_print_param(struct tep_format_parser_context *context)
{
	parse_new_print_param(context, TEP_PRINT_DYNAMIC_ARRAY_LEN, true, true, true);
}

void parse_bracket_open_print_param(struct tep_format_parser_context *context)
{
	parse_new_print_param(context, TEP_PRINT_NULL, true, false, true);
	parse_print_stack_push(context, context->current_arg, context->bracket_count);
}

void parse_bracket_close_print_param(struct tep_format_parser_context *context)
{
	bool stack_pop=false;

	if (context->current_arg && context->stack &&
	    context->current_arg == context->stack->arg &&
	    context->stack->bracket == (1+context->bracket_count)) {
		stack_pop = true;
	}
	parse_print_arg_completed(context, context->current_arg);

	if (stack_pop) {
		if (TEP_PRINT_FIELD == context->current_arg->type) {
			context->current_arg->type = TEP_PRINT_TYPE;
			context->current_arg->typecast.type = context->current_arg->field.name;
			context->current_arg->typecast.item = NULL;
		}
	} else {
		parse_print_getnext_arg(context);
	}

	if (context->stack && context->stack->bracket == (1+context->bracket_count))
		context->stack->bracket = 0;
	context->arg_completed = 0;
}

void parse_strfunc_print_param(struct tep_format_parser_context *context, char *string)
{
	parse_new_print_param(context, TEP_PRINT_STRING, true, true, true);
	context->current_arg->string.string = string;
}

void parse_bitmask_print_param(struct tep_format_parser_context *context, char *bitmask)
{
	parse_new_print_param(context, TEP_PRINT_BITMASK, true, true, true);
	context->current_arg->bitmask.bitmask = bitmask;
}

void parse_print_param_new(struct tep_format_parser_context *context)
{
	context->arg_completed = 1;
}

void parse_field_print_param(struct tep_format_parser_context *context, char *param)
{
	if (context->current_arg &&
	   TEP_PRINT_TYPE == context->current_arg->type &&
	   NULL == context->current_arg->typecast.type) {
		context->current_arg->typecast.type = param;
		return;
	}

	parse_new_print_param(context, TEP_PRINT_FIELD, true, true, true);

	if (context->current_arg->field.name) {
		context->current_arg->field.name =
			realloc(context->current_arg->field.name,
				strlen(param)+
				strlen(context->current_arg->field.name)+2);
		strcat(context->current_arg->field.name, " ");
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

	/* remove quotes from the atom */
	quote = strstr(param, "\"");
	if (quote) {
		tmp = quote+1;
		while (*tmp != '\0') {
			if (*tmp == '\"')
				*tmp='\0';
			else
				tmp++;
			len++;
		}
		memmove(param, quote+1, len+1);
	}

	if (context->stack && context->stack->arg &&
	   TEP_PRINT_FLAGS == context->stack->arg->type &&
	   NULL == context->stack->arg->flags.delim) {
		context->stack->arg->flags.delim = param;
		return;
	}

	parse_new_print_param(context, TEP_PRINT_ATOM, true, true, true);

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
	struct tep_print_arg *current_arg;

	parse_print_arg_completed(context, context->current_arg);

	current_arg = context->current_arg;

	if (!is_operator_unary(param)) {
		if (context->stack && context->stack->arg == context->current_arg)
			parse_print_stack_pop(context);
		parse_new_print_param(context, TEP_PRINT_OP, false, true, false);
	}else
		parse_new_print_param(context, TEP_PRINT_OP, false, true, true);

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

	if (!is_operator_unary(param))
		context->current_arg->op.left = current_arg;
}

void parse_flag_print_param_new(struct tep_format_parser_context *context)
{
	struct tep_print_flag_sym *flag;
	if (!context || !context->flags)
		return;
	flag = calloc(1, sizeof(*flag));
	*context->flags = flag;
	context->args = &flag->value_arg;
}

void parse_flag_print_param_end(struct tep_format_parser_context *context)
{
	if (TEP_PRINT_ATOM == context->current_arg->type) {
		(*context->flags)->str = context->current_arg->atom.atom;
		free(context->current_arg);
		context->current_arg = NULL;
		parse_new_print_param(context, TEP_PRINT_NULL, false, false, false);
	}
	context->flags = &(*context->flags)->next;
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
