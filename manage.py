#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
# This script is the entry point for all Django administrative commands,
# such as running the development server, migrations, or creating apps.

import os  # Provides a way to interact with environment variables and file paths
import sys  # Gives access to command-line arguments and system-level functions


def main():
    """Run administrative tasks."""
    # Set the default Django settings module if it's not already defined in the environment
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'app1.settings')

    try:
        # Import Django's command-line execution utility
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        # Provide a helpful error message if Django isn't installed or the environment isn't set up
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc

    # Execute the command-line utility using the arguments provided to the script
    execute_from_command_line(sys.argv)


# Only run the main function if this script is executed directly
# This prevents the code from running if the file is imported as a module
if __name__ == '__main__':
    main()
