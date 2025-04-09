# Use Alpine as the base image
FROM alpine:latest

# Update the package list
RUN apk update

# Install necessary dependencies
RUN apk add --no-cache \
    git \
    bash \
    python3 \
    py3-pip \
    sudo \
    nmap \
    nmap-scripts \
    coreutils \
    procps

RUN pip3 install --upgrade pip --break-system-packages

# Install additional dependencies (hexdump is part of 'bsdmainutils' in Debian, but on Alpine, 'coreutils' provides it)
RUN ln -s /usr/bin/hexdump /bin/hexdump

# Set working directory to /ReconRanger
WORKDIR /ReconRanger

# Copy all local files to /ReconRanger in the container
COPY src /ReconRanger

# Install Python dependencies
RUN pip3 install --no-cache-dir -r /ReconRanger/requirements.txt --break-system-packages

# Command to run the Python script when the container starts
ENTRYPOINT ["sudo", "python3", "/ReconRanger/ReconRanger.py"]
CMD ["-h"]  
