// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include "event-parse.h"
#include "event-parse-local.h"

#define PARSER_DEBUG

extern int yyparse(struct tep_format_parser_context *context);
extern FILE *yyin;
extern enum tep_errno __tep_parse_format(struct tep_event_format **eventp,
				  struct tep_handle *pevent, const char *buf,
				  unsigned long size, const char *sys);
/*

struct print_arg {
	struct print_arg		*next;
	enum print_arg_type		type;
	union {
		struct print_arg_atom		atom;
		struct print_arg_field		field;
		struct print_arg_typecast	typecast;
		struct print_arg_flags		flags;
		struct print_arg_symbol		symbol;
		struct print_arg_hex		hex;
		struct print_arg_int_array	int_array;
		struct print_arg_func		func;
		struct print_arg_string		string;
		struct print_arg_bitmask	bitmask;files=$((files+1))
		struct print_arg_op		op;
		struct print_arg_dynarray	dynarray;
	};
};

struct format_field {
	struct format_field	*next;
	struct event_format	*event;
	char			*type;
	char			*name;
	char			*alias;
	int			offset;
	int			size;
	unsigned int		arraylen;
	unsigned int		elementsize;
	unsigned long		flags;	enum tep_format_flags
			*			TEP_FIELD_IS_POINTER
			[			TEP_FIELD_IS_ARRAY
			signed:1		TEP_FIELD_IS_SIGNED
			field_is_string()	TEP_FIELD_IS_STRING
			field_is_dynamic()	TEP_FIELD_IS_DYNAMIC
			field_is_long()		TEP_FIELD_IS_LONG
			__print_flags(		TEP_FIELD_IS_FLAG	print fmt
			__print_symbolic(	TEP_FIELD_IS_SYMBOLIC	print fmt

};

 struct format {
	int			nr_common;
	int			nr_fields;
	struct format_field	*common_fields;
	struct format_field	*fields;
};

struct print_fmt {
	char			*format;
	struct print_arg	*args;
};

struct event_format {
	struct tep_handle	*pevent;
	char			*name;
	int			id;
	int			flags;	TEP_EVENT_FL_*
	struct format		format;
	struct print_fmt	print_fmt;
	char			*system;	strdup(sys)
	tep_event_handler_func	handler;
	void			*context;
};
 */

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
	char *token1, *token2, *save_ptr, *save_digit;
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
		if(new_field->name == field_string)
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
		if(saved_array_len) {
			save_ptr = new_field->type + strlen(new_field->type);
#if 0
			sprintf(save_ptr, "[%s]", saved_array_len);
#else
			*save_ptr='[';
			save_ptr++;
			i = 0;
			while(*(saved_array_len+i) != '\0') {
				if(*(saved_array_len+i) == ' ' ||
				   *(saved_array_len+i) == '\t') {
					if(is_char_operator(*(saved_array_len+i+1))) {
						i++;
						continue;
					}
					if(is_char_operator(*(saved_array_len+i-1))) {
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
	if(!context || !context->parsed)
		return;
	if(context->parsed->print_fmt.format) {
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

void parse_new_print_param(struct tep_format_parser_context *context,
			   char *print_param)
{
	struct tep_print_arg *arg;

	if(!context || !context->parsed)
		return;

	arg = calloc(1, sizeof(*arg));



	*context->args = arg;
	context->args = &arg->next;
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

void parser_debug(const char *format, ...)
{
#ifdef PARSER_DEBUG
	va_list args;

	va_start(args, format);
	vprintf(format, args);
	va_end(args);
#endif
}

#define STRERR_BUFSIZE  128     /* For the buffer size of strerror_r */
int filename_read(const char *filename, char **buf, size_t *sizep)
{
	size_t size = 0, alloc_size = 0;
	void *bf = NULL, *nbf;
	int fd, n, err = 0;
	char sbuf[STRERR_BUFSIZE];

	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return -errno;

	do {
		if (size == alloc_size) {
			alloc_size += BUFSIZ;
			nbf = realloc(bf, alloc_size);
			if (!nbf) {
				err = -ENOMEM;
				break;
			}

			bf = nbf;
		}

		n = read(fd, bf + size, alloc_size - size);
		if (n < 0) {
			if (size) {
				printf("read failed %d: %s\n", errno,
					 strerror_r(errno, sbuf, sizeof(sbuf)));
				err = 0;
			} else
				err = -errno;

			break;
		}

		size += n;
	} while (n > 0);

	if (!err) {
		*sizep = size;
		*buf   = bf;
	} else
		free(bf);

	close(fd);
	return err;
}

char *str_error_r(int errnum, char *buf, size_t buflen)
{
	int err = strerror_r(errnum, buf, buflen);
	if (err)
		snprintf(buf, buflen, "INTERNAL ERROR: strerror_r(%d, [buf], %zd)=%d", errnum, buflen, err);
	return buf;
}

void legacy_parser( const char *file_name, struct tep_event_format **event)
{
	size_t size;
	char *data;

	filename_read(file_name, &data, &size);
	__tep_parse_format(event, NULL, data, size, "test");
}

int events_format_fields_compare(char *name, struct tep_format_field *format1,
				 struct tep_format_field *format2, int count1, int count2)
{
	if(count1 != count2) {
		printf("ERROR: %s fields count mismatch: %d != %d\n", name, count1, count2);
		return 1;
	}
	while(format1) {
		if(!format2) {
			printf("ERROR: List mismatch");
			return 1;
		}
		if(strcmp(format1->name, format2->name)) {
			printf("ERROR: Field name mismatch [%s] != [%s]\n",
				format1->name, format2->name);
			return 1;
		}
		if(strcmp(format1->type, format2->type)) {
			printf("ERROR: Field type mismatch [%s] != [%s]\n",
				format1->type, format2->type);
			return 1;
		}
		if(format1->alias && format2->alias) {
			if(strcmp(format1->alias, format2->alias)) {
				printf("ERROR: Field alias mismatch [%s] != [%s]\n",
					format1->alias, format2->alias);
				return 1;
			}
		} else {
			printf("ERROR: Field alias not sset %p != %p\n",
				format1->alias, format2->alias);
			return 1;
		}
		if(format1->offset != format2->offset) {
			printf("ERROR: Field offset mismatch %d != %d\n",
				format1->offset, format2->offset);
			return 1;
		}
		if(format1->size != format2->size) {
			printf("ERROR: Field size mismatch %d != %d\n",
				format1->size, format2->size);
			return 1;
		}
		format1 = format1->next;
		format2 = format2->next;
	}
	if(format1 != format2) {
		printf("ERROR: %s fields list mismatch: %p != %p\n", format1, format2);
		return 1;
	}
	return 0;
}

void events_print_filed( char *indent, struct tep_format_field	*field)
{
	if(field)
		printf("\n%s filed %s (alias %s), type %s, offset %d, size %d, arrlen %d, elsize %d, flags 0x%X",
			indent, field->name,field->alias, field->type, field->offset,
			field->size, field->arraylen, field->elementsize, field->flags);
}


void events_print_fmt_sym_all(char *ident, struct tep_print_flag_sym *sym)
{
	while(sym) {
		printf("\n%s val: %s, ster: %s", ident, sym->value, sym->str);
		sym = sym->next;
	}
}

void events_print_fmt_func_handl(char *ident, struct tep_function_handler *fhandl)
{
	struct func_params *params;

	while(fhandl) {
		printf("\n%sFunc %s, ret %d, %d arguments of types:",
			ident, fhandl->name, fhandl->ret_type, fhandl->nr_args);
		params = fhandl->params;
		while(params) {
			printf("\n%s\t", ident, params->type);
			params = params->next;
		}
		fhandl = fhandl->next;
	}
}

void events_print_fmt_args_all(char *indent, struct tep_print_arg *arg);

void events_print_fmt_arg(char *indent, struct tep_print_arg *arg)
{
	char *indent2 = malloc(strlen(indent)+3);;
	sprintf(indent2, "%s\t", indent);
	printf("\n%s Arg type %d (%p ->next %p)",indent, arg->type, arg, arg->next);
	switch(arg->type) {
	case TEP_PRINT_NULL:
		break;
	case TEP_PRINT_ATOM:
		if(arg->atom.atom)
			printf("\n%s Atom: %s",indent2, arg->atom.atom);
		break;
	case TEP_PRINT_FIELD:
		if(arg->field.name)
			printf("\n%s\t Field: %s:",indent2, arg->field.name);
		events_print_filed(indent2, arg->field.field);
		break;
	case TEP_PRINT_FLAGS:
		printf("\n%s Flags: delimiter %s, fields:",indent2, arg->flags.delim);
		events_print_fmt_args_all(indent2, arg->flags.field);
		printf("\n%s Flags: flags:",indent2);
		events_print_fmt_sym_all(indent2, arg->flags.flags);
		break;
	case TEP_PRINT_SYMBOL:
		printf("\n%sSymbol fileds:", indent2);
		events_print_fmt_args_all(indent2, arg->symbol.field);
		printf("\n%sSymbol symbols:", indent2);
		events_print_fmt_sym_all(indent2, arg->symbol.symbols);
		break;
	case TEP_PRINT_HEX:
		printf("\n%sHex field:", indent2);
		events_print_fmt_args_all(indent2, arg->hex.field);
		printf("\n%sHex size:", indent2);
		events_print_fmt_args_all(indent2, arg->hex.size);
		break;
	case TEP_PRINT_INT_ARRAY:
		printf("\n%sInt array field:", indent2);
		events_print_fmt_args_all(indent2, arg->int_array.field);
		printf("\n%sInt array count:", indent2);
		events_print_fmt_args_all(indent2, arg->int_array.count);
		printf("\n%sInt array el_size:", indent2);
		events_print_fmt_args_all(indent2, arg->int_array.el_size);
		break;
	case TEP_PRINT_TYPE:
		printf("\n%sTypecast type %s, items:",
				indent2, arg->typecast.type);

		break;
	case TEP_PRINT_STRING:
	case TEP_PRINT_BSTRING:
		printf("\n%sString %d (offset %d):", indent2, arg->type,
			arg->string.offset, arg->string.string);
		break;
	case TEP_PRINT_DYNAMIC_ARRAY:
	case TEP_PRINT_DYNAMIC_ARRAY_LEN:
		printf("\n%sDynArray (%d) fileds:", indent2, arg->type);
		events_print_filed(indent2, arg->dynarray.field);
		printf("\n%sDynArray index:", indent2);
		events_print_fmt_args_all(indent2, arg->dynarray.index);
		break;
	case TEP_PRINT_OP:
		printf("\n%sOP %s, priority %d:", indent2, arg->op.op, arg->op.prio);
		printf("\n%sOP left:", indent2);
		events_print_fmt_args_all(indent2, arg->op.left);
		printf("\n%sOP right:", indent2);
		events_print_fmt_args_all(indent2, arg->op.right);
		break;
	case TEP_PRINT_FUNC:
		printf("\n%sFunc:", indent2);
		events_print_fmt_func_handl(indent2, arg->func.func);
		printf("\n%sFunc args:", indent2);
		events_print_fmt_args_all(indent2, arg->func.args);
		break;
	case TEP_PRINT_BITMASK:
		printf("\n%sBitMask %s, offset %d:",
			indent2, arg->bitmask.bitmask, arg->bitmask.offset);
		break;
	case TEP_PRINT_HEX_STR:
		printf("\n%shexStr fileds:", indent2);
		events_print_fmt_args_all(indent2, arg->hex.field);
		printf("\n%shexStr size:", indent2);
		events_print_fmt_args_all(indent2, arg->hex.size);
		break;
	default:
		printf("\n\t\t\tUknown type");
		break;
	}
	free(indent2);
}

void events_print_fmt_args_all(char *indent, struct tep_print_arg *arg)
{
	while(arg) {
		events_print_fmt_arg(indent, arg);
		arg = arg->next;
	}
}

void events_print_fmt_dump(struct tep_print_fmt *print)
{
	if(print) {
		printf("\n\n\t String %s", print->format);
		events_print_fmt_args_all("\t", print->args);
		printf("\n\n");
	}
}

int events_print_fmt_compare(struct tep_print_fmt *print1,
			     struct tep_print_fmt *print2)
{
	struct tep_print_arg *args1, *args2;

	if(!print1->format || !print2->format) {
		if(print1->format != print2->format)
			printf("ERROR: Print format mismatch [%p] != [%p]\n",
				print1->format, print2->format);
		return 1;
	}

	if(strcmp(print1->format, print2->format)) {
		printf("ERROR: Print format mismatch [%s] != [%s]\n",
			print1->format, print2->format);
		return 1;
	}
	args1 = print1->args;
	args2 = print2->args;
	while(args1) {
		if(!args2) {
			printf("ERROR: Args list mismatch");
			return 1;

		}

		args1 = args1->next;
		args2 = args2->next;
	}
	if(args1 != args2) {
		printf("ERROR: args list mismatch: %p != %p\n", args1, args2);
		return 1;
	}
	return 0;
}

int events_compare(struct tep_event_format *event1, struct tep_event_format *event2)
{
	int ret = 0;
	if(strcmp(event1->name, event2->name)) {
		printf("ERROR: Name mismatch %s != %s\n", event1->name, event2->name);
		return 1;
	}
	if(event1->id != event2->id) {
		printf("ERROR: ID mismatch %d != %d\n", event1->id, event2->id);
		return 1;
	}
	if(event1->flags & ~0x80000000 != event2->flags & ~0x80000000) {
		printf("ERROR: Flags mismatch 0x%X != 0x%X\n", event1->flags, event2->flags);
		return 1;
	}
	if(event1->system && event2->system && strcmp(event1->system, event2->system)) {
		printf("ERROR: System mismatch %s != %s\n", event1->system, event2->system);
		return 1;
	}
	ret = events_format_fields_compare("common", event1->format.common_fields,
				     event2->format.common_fields,
				     event1->format.nr_common,
				     event2->format.nr_common);
	ret += events_format_fields_compare("regular", event1->format.fields,
				     event2->format.fields,
				     event1->format.nr_fields,
				     event2->format.nr_fields);
//	ret += events_print_fmt_compare(&event1->print_fmt, &event2->print_fmt);
	return ret;
}

int main(int argc, char **argv)
{
	struct tep_format_parser_context context;
	struct tep_event_format *event_legacy = NULL;
	FILE *format_file = fopen(argv[1], "r");
//	struct tep_handle *pevent = tep_alloc();

	if (!format_file) {
		printf("ERROR: Cannot open %s\n", argv[1]);
		return -1;
	}
	parser_debug("Opened  %s\n\r", argv[1]);
	/* Set flex to read from it instead of defaulting to STDIN: */
	yyin = format_file;

	memset(&context, 0, sizeof(context));
	context.parsed = calloc(1, sizeof(*(context.parsed)));
	context.parsed->print_fmt.format = strdup("");
	context.current_fields = &(context.parsed->format.common_fields);
	context.args = &(context.parsed->print_fmt.args);
	/* Parse through the input: */
	yyparse(&context);

	context.parsed->format.nr_common =
			count_parsed_fields(context.parsed->format.common_fields);
	context.parsed->format.nr_fields =
			count_parsed_fields(context.parsed->format.fields);

//	tep_load_plugins(pevent);
	legacy_parser(argv[1], &event_legacy);
	printf("\n\r");

	events_print_fmt_dump(&event_legacy->print_fmt);

	return events_compare(context.parsed, event_legacy);
}
