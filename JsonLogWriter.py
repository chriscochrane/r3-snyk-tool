import os
import json
import sys

class JsonLogWriter:
    """
    A class for writing data to JSON files in a specified log directory.
    """
    
    def __init__(self, base_log_path: str):
        """
        Initializes the LogWriter with a base path for logs.

        Args:
            base_log_path (str): The root directory where logs will be stored.
        """
        # Ensure the base log path exists, creating it if necessary.
        # os.makedirs is a safe way to create nested directories.
        os.makedirs(base_log_path, exist_ok=True)
        self.log_path = base_log_path

    def write_to_file(self, filename: str, data: dict) -> bool:
        """
        Writes a dictionary to a JSON file.

        The file is created in the directory defined by the class's log_path.

        Args:
            filename (str): The name of the file to create (e.g., 'data.json').
            data (dict): The dictionary to write to the file.

        Returns:
            bool: True if the write operation was successful, False otherwise.
        """
        # Create the full path to the file.
        full_path = os.path.join(self.log_path, f"{filename}.json")
        
        try:
            # Use a 'with' statement for safe file handling.
            # This automatically closes the file even if an error occurs.
            with open(full_path, 'w') as f:
                # json.dump() serializes the dictionary to a file object.
                # indent=4 makes the JSON file human-readable.
                json.dump(data, f, indent=4)
            return True
        except IOError as e:
            print(f"Error writing to file {full_path}: {e}", file=sys.stderr)
            return False

