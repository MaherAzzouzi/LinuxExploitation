FROM ubuntu:noble-20240429

RUN apt update
RUN apt install socat make gcc curl -y

EXPOSE 1350

RUN useradd ctf

WORKDIR /chal
COPY flag.txt /chal
COPY makefile /chal
COPY main.c /chal

RUN make
RUN rm -rf makefile
USER ctf

CMD ["socat", "tcp-l:1350,reuseaddr,fork", "EXEC:./bytecode"]
