FROM archlinux


RUN pacman -Sy
RUN pacman -S --noconfirm socat

EXPOSE 1352

RUN useradd ctf

WORKDIR /chal
COPY bad_trip /chal
COPY flag.txt /chal

USER ctf

CMD ["socat", "tcp-l:1352,reuseaddr,fork", "EXEC:./bad_trip"]
