#!/bin/bash

set -e

show_help() {
	echo "Usage: $0 --proto_dir <dir> --python_out <dir> [--go_out <dir>] --proto_file <file>"
	echo
	echo "Options:"
	echo "  --proto_dir   Directory containing .proto files"
	echo "  --python_out  Output directory for Python files"
	echo "  --go_out      (Optional) Output directory for Go files"
	echo "  --proto_file  Proto filename to compile"
	exit 1
}

PROTO_DIR=""
PYTHON_OUT=""
GO_OUT=""
PROTO_FILE=""

# Parse arguments
while [[ "$#" -gt 0 ]]; do
	case $1 in
	--proto_dir)
		PROTO_DIR="$2"
		shift
		;;
	--python_out)
		PYTHON_OUT="$2"
		shift
		;;
	--go_out)
		GO_OUT="$2"
		shift
		;;
	--proto_file)
		PROTO_FILE="$2"
		shift
		;;
	*)
		echo "Unknown parameter passed: $1"
		show_help
		;;
	esac
	shift
done

if [[ -z "$PROTO_DIR" || -z "$PYTHON_OUT" || -z "$PROTO_FILE" ]]; then
	echo "Missing required arguments."
	show_help
fi

mkdir -p "$PYTHON_OUT"

# Compile Python protobuf files
python3 -m grpc_tools.protoc \
	-I"${PROTO_DIR}" \
	--python_out="${PYTHON_OUT}" \
	--grpc_python_out="${PYTHON_OUT}" \
	"${PROTO_DIR}/${PROTO_FILE}"

# Compile Go protobuf files (optional)
if [[ -n "$GO_OUT" ]]; then
	mkdir -p "$GO_OUT"
	protoc \
		--proto_path="${PROTO_DIR}" \
		--go_out="${GO_OUT}" \
		--go-grpc_out="${GO_OUT}" \
		"${PROTO_DIR}/${PROTO_FILE}"
fi

echo "Protobuf files compiled successfully."
