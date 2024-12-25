import os
import sys
# Set the script directory and parent directory
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(script_dir, "../"))
os.chdir(parent_dir)

# Add parent directory to Python path
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

print(f"Current working directory: {os.getcwd()}")
import logging


def main():
    

if __name__ == "__main__":
    main()