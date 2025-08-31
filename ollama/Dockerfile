# Use the latest official Ollama image as the base for this container.
FROM ollama/ollama:latest 

# Update the package lists and install 'curl'.
# 'curl' is often used for making HTTP requests, downloading files, or checking URLs inside the container.
RUN apt-get update && apt-get install -y curl

# Copy the custom entrypoint script from the local context into the container at /root/entrypoint.sh.
# This script will be responsible for starting or configuring Ollama when the container launches.
COPY entrypoint.sh /root/entrypoint.sh

# Make sure the entrypoint script has execute permissions.
# Without this, the script wouldn't be able to run when the container starts.
RUN chmod +x /root/entrypoint.sh

# Set the entrypoint for the container to our script.
# This means whenever the container starts, it will automatically run this script.
ENTRYPOINT ["/root/entrypoint.sh"]
