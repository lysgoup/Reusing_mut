#!/bin/bash

# Check if fuzzing output directory is provided
if [ $# -ne 1 ]; then
    echo "Usage: $0 <fuzzing_output_directory>"
    echo "Example: $0 libpng_fuzz_output"
    exit 1
fi

FUZZ_DIR="$1"
REUSING_LOG="${FUZZ_DIR}/reusing_success.log"
QUEUE_DIR="${FUZZ_DIR}/queue"
OUTPUT_DIR="${FUZZ_DIR}/reusing_success_inputs"

# Check if reusing_success.log exists
if [ ! -f "$REUSING_LOG" ]; then
    echo "Error: $REUSING_LOG not found"
    exit 1
fi

# Check if queue directory exists
if [ ! -d "$QUEUE_DIR" ]; then
    echo "Error: $QUEUE_DIR not found"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo "Extracting new_queue_input entries from $REUSING_LOG"
echo "Moving files from $QUEUE_DIR to $OUTPUT_DIR"
echo ""

# Extract new_queue_input values and move corresponding files
count=0
while IFS= read -r line; do
    # Extract the new_queue_input value using grep and sed
    input_id=$(echo "$line" | grep -o 'new_queue_input=id:[0-9]*' | sed 's/new_queue_input=//')

    if [ -n "$input_id" ]; then
        # Check if the file exists in queue
        queue_file="${QUEUE_DIR}/${input_id}"

        if [ -f "$queue_file" ]; then
            # Move the file to the output directory
            mv "$queue_file" "$OUTPUT_DIR/"
            echo "Moved: $input_id"
            ((count++))
        else
            echo "Warning: $queue_file not found in queue directory"
        fi
    fi
done < "$REUSING_LOG"

echo ""
echo "Done! Moved $count files to $OUTPUT_DIR"
