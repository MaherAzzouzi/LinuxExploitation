FROM ubuntu:latest

RUN apt update
RUN apt install socat make gcc -y

EXPOSE 1349

RUN useradd ctf

WORKDIR /chal
COPY main.c /chal
COPY makefile /chal
COPY pkzip.c /chal
COPY pkzip.h /chal
COPY flag.txt /chal
COPY base64.c /chal

RUN chmod 644 *
RUN mkdir content
RUN chown -R ctf:ctf content
RUN chmod 777 content

RUN make
RUN rm -rf makefile
USER ctf

CMD ["socat", "tcp-l:1349,reuseaddr,fork", "EXEC:./zop"]
