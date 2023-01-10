FROM ubuntu:18.04
ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update -y 
RUN apt-get install -y vim 
RUN apt-get install -y socat 
RUN apt-get install -y gdb
RUN apt-get update && apt-get install -y software-properties-common gcc && \
    add-apt-repository -y ppa:deadsnakes/ppa
RUN apt-get update && apt-get install -y python3.9 python3-distutils python3-pip python3-apt
RUN apt-get install -y python3-dev git libssl-dev libffi-dev build-essential
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install --upgrade pwntools

RUN apt install -y tmux 
  
RUN git clone https://github.com/pwndbg/pwndbg
RUN ./pwndbg/setup.sh
RUN apt-get clean -y

WORKDIR /malicious

