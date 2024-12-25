# Command-line arguments
param (
    [string]$filePath,        # Path to the original file
    [string]$outputFolder,    # Folder to save the split files
    [int]$chunkSizeMB         # Size of each chunk in MB
)

# Validate input
if (-not (Test-Path $filePath)) {
    Write-Error "The file '$filePath' does not exist."
    exit 1
}

if (-not (Test-Path $outputFolder)) {
    Write-Host "Output folder '$outputFolder' does not exist. Creating it..."
    New-Item -ItemType Directory -Path $outputFolder | Out-Null
}

# Convert chunk size to bytes
$chunkSizeBytes = $chunkSizeMB * 1MB

# Get the total size of the file
$fileInfo = Get-Item $filePath
$fileSize = $fileInfo.Length
$totalParts = [math]::Ceiling($fileSize / $chunkSizeBytes)

# Open the file for reading
$reader = [System.IO.FileStream]::new($filePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)

# Prepare JSON object
$jsonObject = @{}

# Split the file into chunks
$buffer = New-Object byte[] $chunkSizeBytes

for ($i = 0; $i -lt $totalParts; $i++) {
    $partFileName = "{0}-split-{1}-{2}.zip" -f ([System.IO.Path]::GetFileNameWithoutExtension($filePath)), ($i + 1), $totalParts
    $partFilePath = Join-Path $outputFolder $partFileName

    # Read the next chunk
    $bytesRead = $reader.Read($buffer, 0, $chunkSizeBytes)

    # Open a file for writing and write the chunk
    $writer = [System.IO.FileStream]::new($partFilePath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
    $writer.Write($buffer, 0, $bytesRead)
    $writer.Close()

    # Calculate hash value
    $hashValue = (Get-FileHash -Path $partFilePath -Algorithm SHA256).Hash

    # Add to JSON object
    $jsonObject[$partFileName] = $hashValue
}

# Close the reader
$reader.Close()

# Save the JSON file
$jsonFileName = "{0}-split-hash.json" -f ([System.IO.Path]::GetFileNameWithoutExtension($filePath))
$jsonFilePath = Join-Path $outputFolder $jsonFileName
$jsonObject | ConvertTo-Json -Depth 1 | Out-File -FilePath $jsonFilePath -Encoding UTF8

Write-Host "Splitting complete. Files saved in $outputFolder."
Write-Host "JSON file with hashes saved as $jsonFileName."
