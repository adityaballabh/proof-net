FROM ubuntu:24.04

RUN apt-get update && apt-get install -y g++ make libsodium-dev
WORKDIR /app
COPY docker/config.txt config.txt
COPY Makefile Makefile
COPY src src
COPY messages messages
RUN make node && cp /app/node /node

CMD ["/node"]