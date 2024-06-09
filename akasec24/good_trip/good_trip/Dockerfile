FROM fedora:rawhide

RUN yum update -y
RUN yum install socat -y

EXPOSE 1351

RUN useradd ctf

WORKDIR /chal
COPY flag.txt /chal
COPY good_trip /chal

USER ctf

CMD ["socat", "tcp-l:1351,reuseaddr,fork", "EXEC:./good_trip"]
