# Use the official Debian "bookworm" image as the base image
FROM debian:buster

# Set environment variables if needed
ENV DEBIAN_FRONTEND noninteractive

# Update package lists and install any necessary packages
RUN apt-get update && \
    apt-get install -y git \
    make \
    gcc \
    libc6-dev 

#&& \
    #rm -rf /var/lib/apt/lists/*

RUN apt-get install -y python3.7
RUN apt-get install -y python3-pip
RUN python3 -m pip install schedule
RUN python3 -m pip install requests
# Add your application's files to the container
RUN mkdir /data
RUN mkdir /output_data
RUN mkdir /temp
RUN git clone https://github.com/radareorg/radare2.git /radare2 && \
    cd /radare2 && \
    sys/install.sh 

RUN python3 -m pip install r2pipe
# Set the working directory
COPY ./app /app
WORKDIR /app

# Define the command to run when the container starts
##CMD ["tail", "-f", "/dev/null"]
CMD ["python3.7", "func_extract.py", "--input_path", "/input_data", "--output_path", "/output_data"]
#"--polling_time", "60", "--schedule_time", "12"]

# Expose any necessary ports
# EXPOSE <port>

# You can include additional Dockerfile instructions here as needed

