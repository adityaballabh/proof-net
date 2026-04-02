FROM ubuntu:24.04

RUN apt-get update && apt-get install -y g++ make
WORKDIR /app
COPY config_docker.txt config_docker.txt
COPY Makefile Makefile
COPY src src
COPY messages messages
RUN make node && cp /app/node /node

CMD ["/node"]