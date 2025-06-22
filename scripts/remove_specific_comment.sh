#!/bin/bash
echo "Starting comment removal process..."
# Define the target directory
TARGET_DIR="src/pyvider/rpcplugin"

# Define the comment to remove
COMMENT_TO_REMOVE="# 🐍🏗️🔌"
# Escape special characters for sed
ESCAPED_COMMENT_TO_REMOVE=$(sed 's/[&/\@]/\&/g' <<< "$COMMENT_TO_REMOVE")

# Find all .py files in the target directory and its subdirectories
# and remove the specified comment from the end of lines.
# Using a temporary file for sed's in-place editing to be safe.
find "$TARGET_DIR" -type f -name "*.py" -print0 | while IFS= read -r -d $'\0' file; do
  echo "Processing file: $file"
  # Check if the comment exists in the file
  if grep -q "$ESCAPED_COMMENT_TO_REMOVE" "$file"; then
    # Use sed to remove the comment.
    # This command looks for lines ending with the comment (and potentially whitespace before it)
    # and removes the comment and any preceding whitespace on that line.
    sed -i "s/^[[:space:]]*${ESCAPED_COMMENT_TO_REMOVE}[[:space:]]*$//g" "$file"
    # This command removes lines that ONLY contain the comment (and potentially whitespace)
    sed -i "/^[[:space:]]*${ESCAPED_COMMENT_TO_REMOVE}[[:space:]]*$/d" "$file"
    echo "Removed comment from $file"
  else
    echo "Comment not found in $file"
  fi
done

echo "Comment removal process completed."
