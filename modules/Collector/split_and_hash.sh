#!/bin/bash

# Input parameters
file_path=$1
chunk_size=$2

# Get original file name without the extension
file_name=$(basename "$file_path")
file_name_without_ext="${file_name%.*}"

# Create a temporary folder to hold split files
output_folder="${file_name_without_ext}_split_files"
mkdir -p "$output_folder"

# Get the file size and calculate the total number of parts
file_size=$(stat -c%s "$file_path")
total_parts=$(( ($file_size + $chunk_size - 1) / $chunk_size ))

# Split the file with custom naming
split -b $chunk_size -d --additional-suffix=.part \
    --numeric-suffixes=1 "$file_path" "$output_folder/${file_name_without_ext}-"

# Rename split files to match the pattern
part_counter=1
for file in "$output_folder/${file_name_without_ext}-"*; do
    new_name="${file_name_without_ext}-part-${part_counter}-${total_parts}.part"
    mv "$file" "$output_folder/$new_name"
    part_counter=$((part_counter + 1))
done

# Generate JSON for file names and their hashes
json="{"
for file in "$output_folder/"*; do
    hash=$(sha256sum "$file" | awk '{print $1}')
    json+="\"$(basename "$file")\":\"$hash\","
done

# Remove trailing comma and close JSON
json=${json%,}
json+="}"

# Save JSON file
json_file="${file_name_without_ext}-split-hash.json"
echo "$json" | jq '.' > "$json_file"

# Output completion message
echo "Splitting complete. Files saved in $output_folder."
echo "Hashes saved in $json_file."
