#!/usr/bin/env python3

# This script can generate code for the Zephyr OS JSON parser library
# to parse JSON according to supplied JSON schemas. It was mainly designed
# to facilitate parsing of Thingsboard attribute updates. Hence, schemas:
# This script will accept more than one schema path, merging them all into
# the first one. This is useful since some of the attributes sent by Thingsboard
# are generic in nature and should be consumed by the Thingsboard module, while
# others will be specific to the application. Users can provide a JSON schema
# for their application specific data and this script creates one big structure
# and json_obj_descr array to parse them.
# 
# Some notes:
# - The script currently expects all JSON schemas to be "type": "object" on the top
#   level. That's okay for this use case, Thingsboard doesn't supply anything else.
# - $refs and similar stuff is handled by the Python package json-ref-dict.
#   This also means that this script has no notion of refs, and will produce a new
#   struct declaration for every use of $ref. That could perhaps be optimized, but
#   struct declarations don't really cost anything - except for the parser descriptors.
# - Currently, no attempt is made to escape any names. Hence, all field names must be
#   valid C identifiers.
# - The name of all identifiers is derived from the filename (w/o extension) of the
#   first supplied JSON schema.

import json
import json_ref_dict as jrd
import sys
import os


class Property:
	def __init__(self, name, schema):
		self.parent = None
		self._name = name
		self.schema = schema

	@property
	def name(self):
		return self._name

	def make_descriptor(self):
		raise NotImplementedError()

	def make_member(self):
		raise NotImplementedError()

	def root_property(self):
		if not self.parent:
			return self
		return self.parent

	def module_name(self):
		return f"{self.root_property().name}_parser"

	def index_define_name(self):
		return f"{self.module_name().upper()}_{self._name.upper()}_DESCR_INDEX"

	@classmethod
	def create(cls, name, schema):
		klass = None
		type = schema["type"]
		if type == "object":
			klass = ObjectProperty
		elif type == "string":
			klass = StringProperty
		elif type == "number":
			klass = NumberProperty
		else:
			raise TypeError(f"Type {type} not supported")
		return klass(name, schema)


class ObjectProperty(Property):
	def __init__(self, name, schema):
		super().__init__(name, schema)
		self.properties = list()
		for prop, s in schema["properties"].items():
			self.add_property(Property.create(prop, s))

	@property
	def name(self):
		if self.parent and self.parent.name:
			return f"{self.parent.name}_{self._name}"
		return self._name

	def make_descriptor(self):
		return f"JSON_OBJ_DESCR_OBJECT(struct {self.parent.name}, {self._name}, {self.name}_desc)"

	def make_member(self):
		return f"struct {self.name} {self._name};"

	def add_property(self, prop):
		self.properties.append(prop)
		prop.parent = self

	def merge_with(self, prop):
		if not isinstance(prop, ObjectProperty):
			raise TypeError(f"{prop} is not an {self.__class__.__name__}")
		for p in prop.properties:
			self.add_property(p)

	def make_struct(self):
		delim = "\n\t"

		child_structs = ""

		for p in self.properties:
			if isinstance(p, ObjectProperty):
				child_structs += p.make_struct() + "\n\n"

		if not self.parent:
			flags = f"""\
{delim.join(map(lambda p: f"bool {p._name}_parsed;", self.properties))}
\t"""
		else:
			flags = ""

		return child_structs + f"""\
struct {self.name} {{
\t{flags}{delim.join([p.make_member() for p in self.properties])}
}};\
"""

	def make_descriptors(self):
		delim = ",\n\t"

		child_descr = ""

		for p in self.properties:
			if isinstance(p, ObjectProperty):
				child_descr += p.make_descriptors() + "\n\n"

		return child_descr + f"""\
static const struct json_obj_descr {self.name}_desc[] = {{
	{delim.join([d.make_descriptor() for d in self.properties])}
}};\
"""

	def make_indices(self):
		def index(i, prop):
			return f"#define {prop.index_define_name()} {i}"
		return "\n".join(index(*t) for t in enumerate(self.properties))


class StringProperty(Property):
	def make_descriptor(self):
		return f"JSON_OBJ_DESCR_PRIM(struct {self.parent.name}, {self.name}, JSON_TOK_STRING)"

	def make_member(self):
		return f"char *{self.name};"


class NumberProperty(Property):
	def make_descriptor(self):
		return f"JSON_OBJ_DESCR_PRIM(struct {self.parent.name}, {self.name}, JSON_TOK_NUMBER)"

	def make_member(self):
		return f"int32_t {self.name};"


def declare_parser(prop):
	return f"int {prop.name}_from_json(void *json, size_t len, struct {prop.name} *v)"


def define_parser(prop):
	delim = '\n'

	def parsed_check(prop):
		return f"""\
	if (ret & (1 << {prop.index_define_name()})) {{
		v->{prop._name}_parsed = true;
	}}
"""
	return f"""{declare_parser(prop)} {{
	int ret;

	ret = json_obj_parse(json, len, {prop.name}_desc, ARRAY_SIZE({prop.name}_desc), v);
	if (ret <= 0) {{
		/* No objects have been parsed */
		return ret;
	}}

{delim.join(map(parsed_check, prop.properties))}
	return 0;
}}"""


def write_header(path, prop):
	filename = prop.module_name() + ".h"
	guard = prop.module_name().upper() + "_H"
	outpath = os.path.abspath(os.path.join(path, filename))
	print(f"Generating {outpath}")
	with open(outpath, 'w') as h:
		h.write(f"""\
#ifndef {guard}
#define {guard}

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

{prop.make_indices()}

{prop.make_struct()}

{declare_parser(prop)};

#endif /* {guard} */""")


def write_source(path, prop):
	filename = prop.module_name() + ".c"
	outpath = os.path.abspath(os.path.join(path, filename))
	print(f"Generating {outpath}")
	with open(outpath, 'w') as src:
		src.write(f"""\
#include "{prop.module_name() + ".h"}"

#include <data/json.h>

{prop.make_descriptors()}

{define_parser(prop)}
""")


def load_schema(path):
	filename = os.path.basename(path)
	schema_name, ext = os.path.splitext(filename)
	print(f"Loading JSON schema from {path}")

	# normalize references
	schema = jrd.RefDict(path)
	schema = jrd.materialize(schema)

	prop = Property.create(schema_name, schema)
	if not isinstance(prop, ObjectProperty):
		raise TypeError("prop is of wrong type")
	return prop


if __name__ == '__main__':
	if len(sys.argv) < 3:
		raise ValueError("Usage: <outpath> JSON schema file(s)...")
	outpath = sys.argv[1]

	prop = load_schema(sys.argv[2])
	for path in sys.argv[3:]:
		prop.merge_with(load_schema(path))
	write_header(outpath, prop)
	write_source(outpath, prop)

