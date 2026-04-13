FROM ubuntu:24.04

RUN apt-get update && apt-get install -y g++ make libsodium-dev
WORKDIR /app
COPY docker/nw_config.txt nw_config.txt
COPY docker/acct_config.txt acct_config.txt
COPY Makefile Makefile
COPY src src
COPY messages messages
COPY state state
RUN make && cp /app/node /node && cp /app/acct /acct && cp /app/gen_key /gen_key
