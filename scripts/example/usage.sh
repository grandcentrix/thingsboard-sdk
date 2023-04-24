#!/bin/bash

set -euo pipefail

scriptpath=$(readlink -f "$0")

dirpath=$(dirname ${scriptpath})

echo "Generating example output to ${dirpath}/output"

"${dirpath}/../gen_json_parser.py" "${dirpath}/output" "${dirpath}/example.jsonschema" "${dirpath}/extra.jsonschema"
