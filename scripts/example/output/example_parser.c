#include "example_parser.h"

#include <zephyr/data/json.h>

static const struct json_obj_descr example_desc[] = {
	JSON_OBJ_DESCR_PRIM(struct example, status, JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct example, credentialsType, JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct example, credentialsValue, JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct example, extra_value, JSON_TOK_STRING)};

int example_from_json(void *json, size_t len, struct example *v)
{
	int ret;

	ret = json_obj_parse(json, len, example_desc, ARRAY_SIZE(example_desc), v);
	if (ret <= 0) {
		/* No objects have been parsed */
		return ret;
	}

	if (ret & (1 << EXAMPLE_PARSER_STATUS_DESCR_INDEX)) {
		v->status_parsed = true;
	}

	if (ret & (1 << EXAMPLE_PARSER_CREDENTIALSTYPE_DESCR_INDEX)) {
		v->credentialsType_parsed = true;
	}

	if (ret & (1 << EXAMPLE_PARSER_CREDENTIALSVALUE_DESCR_INDEX)) {
		v->credentialsValue_parsed = true;
	}

	if (ret & (1 << EXAMPLE_PARSER_EXTRA_VALUE_DESCR_INDEX)) {
		v->extra_value_parsed = true;
	}

	return 0;
}
