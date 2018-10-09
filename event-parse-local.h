// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (C) 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 */
#ifndef _PARSE_EVENTS_INT_H
#define _PARSE_EVENTS_INT_H

struct cmdline;
struct cmdline_list;
struct func_map;
struct func_list;
struct event_handler;
struct func_resolver;

struct tep_handle {
	int ref_count;

	int header_page_ts_offset;
	int header_page_ts_size;
	int header_page_size_offset;
	int header_page_size_size;
	int header_page_data_offset;
	int header_page_data_size;
	int header_page_overwrite;

	int file_bigendian;
	int host_bigendian;

	int latency_format;

	int old_format;

	int cpus;
	int long_size;
	int page_size;

	struct cmdline *cmdlines;
	struct cmdline_list *cmdlist;
	int cmdline_count;

	struct func_map *func_map;
	struct func_resolver *func_resolver;
	struct func_list *funclist;
	unsigned int func_count;

	struct printk_map *printk_map;
	struct printk_list *printklist;
	unsigned int printk_count;


	struct tep_event_format **events;
	int nr_events;
	struct tep_event_format **sort_events;
	enum tep_event_sort_type last_type;

	int type_offset;
	int type_size;

	int pid_offset;
	int pid_size;

 	int pc_offset;
	int pc_size;

	int flags_offset;
	int flags_size;

	int ld_offset;
	int ld_size;

	int print_raw;

	int test_filters;

	int flags;

	struct tep_format_field *bprint_ip_field;
	struct tep_format_field *bprint_fmt_field;
	struct tep_format_field *bprint_buf_field;

	struct event_handler *handlers;
	struct tep_function_handler *func_handlers;

	/* cache */
	struct tep_event_format *last_event;

	char *trace_clock;
};

struct tep_format_parser_stack {
	struct tep_format_parser_stack *next;
	struct tep_print_arg *arg;
	int bracket;
	struct tep_print_arg **args;
};

struct tep_format_parser_context {
	int line_num;
	int blank_line;
	int bracket_count;
	int parse_context;
	struct tep_handle *pevent;
	struct tep_event_format *parsed;
	struct tep_print_arg **args;
	struct tep_format_parser_stack *stack;
	struct tep_print_arg *current_arg;
	struct tep_print_flag_sym **flags;
	int	arg_completed;
	int	func_completed;
	struct tep_format_field **current_fields;
};

struct event_handler {
	struct event_handler		*next;
	int				id;
	const char			*sys_name;
	const char			*event_name;
	tep_event_handler_func		func;
	void				*context;
};

struct func_params {
	struct func_params	*next;
	enum tep_func_arg_type	type;
};

struct tep_function_handler {
	struct tep_function_handler	*next;
	enum tep_func_arg_type		ret_type;
	char				*name;
	tep_func_handler		func;
	struct func_params		*params;
	int				nr_args;
};

void parser_debug(const char *format, ...);
int count_parsed_fields(struct tep_format_field *fields);
void parse_new_print_param(struct tep_format_parser_context *context,
			   enum tep_print_arg_type type, bool concat,
			   bool reuse, bool get_next);
struct tep_function_handler *
	find_func_handler(struct tep_handle *pevent, char *func_name);
void free_args(struct tep_print_arg *args);
int set_op_prio(struct tep_print_arg *arg);

#endif /* _PARSE_EVENTS_INT_H */
