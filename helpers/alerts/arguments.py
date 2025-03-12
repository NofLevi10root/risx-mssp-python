import argparse
import sys

def process_arguments():
    parser = argparse.ArgumentParser(description="Script requires either --modification or --update, but not both.")

    parser.add_argument("-m", "--modification", help="Specify modification argument", action="store_true")
    parser.add_argument("-u", "--update", help="Specify update argument", action="store_true")

    args = parser.parse_args()

    # Ensure only one argument is provided
    if args.modification == args.update:  # Both True or both False
        print("Error: You must provide either --modification (-m) OR --update (-u), but not both.")
        sys.exit(1)
    return args