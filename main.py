import argparse
import re
import logging
import os
from typing import Optional


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def setup_argparse() -> argparse.ArgumentParser:
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description="Replaces sensitive data matching regular expressions within files with a specified replacement string."
    )
    parser.add_argument("file_path", type=str, help="Path to the file to process.")
    parser.add_argument("regex_pattern", type=str, help="Regular expression pattern to match sensitive data.")
    parser.add_argument("replacement_string", type=str, help="String to replace the matched sensitive data with.")
    parser.add_argument(
        "-o",
        "--output_file",
        type=str,
        help="Optional: Path to the output file. If not specified, the input file is overwritten.",
        required=False,
    )
    return parser


def replace_sensitive_data(file_path: str, regex_pattern: str, replacement_string: str, output_file: Optional[str] = None) -> None:
    """
    Replaces sensitive data matching a regular expression in a file with a specified replacement string.

    Args:
        file_path (str): The path to the file to process.
        regex_pattern (str): The regular expression pattern to match sensitive data.
        replacement_string (str): The string to replace the matched sensitive data with.
        output_file (Optional[str]): The path to the output file. If None, the input file is overwritten.

    Raises:
        FileNotFoundError: If the specified file does not exist.
        IOError: If there is an error reading or writing the file.
        re.error: If the regex pattern is invalid.
        ValueError: If the file path or regex pattern are empty strings.
    """

    if not file_path:
        raise ValueError("File path cannot be empty.")
    if not regex_pattern:
        raise ValueError("Regex pattern cannot be empty.")

    try:
        with open(file_path, 'r') as file:
            file_content = file.read()
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        raise
    except IOError as e:
        logging.error(f"Error reading file: {file_path} - {e}")
        raise

    try:
        # Compile the regex pattern
        compiled_pattern = re.compile(regex_pattern)

        # Replace sensitive data
        modified_content = compiled_pattern.sub(replacement_string, file_content)

    except re.error as e:
        logging.error(f"Invalid regular expression: {regex_pattern} - {e}")
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred during regex processing: {e}")
        raise


    # Determine the output file path
    output_path = output_file if output_file else file_path

    try:
        # Write the modified content to the output file
        with open(output_path, 'w') as file:
            file.write(modified_content)

        logging.info(f"Sensitive data replaced successfully in {file_path}. Output written to {output_path}")

    except IOError as e:
        logging.error(f"Error writing to file: {output_path} - {e}")
        raise


def main() -> None:
    """
    Main function to parse arguments and execute the sensitive data replacement.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    try:
        replace_sensitive_data(args.file_path, args.regex_pattern, args.replacement_string, args.output_file)
    except (FileNotFoundError, IOError, re.error, ValueError) as e:
        logging.error(f"Operation failed: {e}")
        exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        exit(1)


if __name__ == "__main__":
    # Example usage:
    # python main.py input.txt "(\d{3}-\d{2}-\d{4})" "XXX-XX-XXXX" -o output.txt
    # python main.py input.txt "(email: )[\w\.-]+@[\w\.-]+" "email: REDACTED"
    main()