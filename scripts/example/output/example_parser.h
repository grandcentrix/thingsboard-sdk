#ifndef EXAMPLE_PARSER_H
#define EXAMPLE_PARSER_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#define EXAMPLE_PARSER_STATUS_DESCR_INDEX 0
#define EXAMPLE_PARSER_CREDENTIALSTYPE_DESCR_INDEX 1
#define EXAMPLE_PARSER_CREDENTIALSVALUE_DESCR_INDEX 2
#define EXAMPLE_PARSER_EXTRA_VALUE_DESCR_INDEX 3

struct example {
	bool status_parsed;
	bool credentialsType_parsed;
	bool credentialsValue_parsed;
	bool extra_value_parsed;
	char *status;
	char *credentialsType;
	char *credentialsValue;
	char *extra_value;
};

int example_from_json(void *json, size_t len, struct example *v);

#endif /* EXAMPLE_PARSER_H */