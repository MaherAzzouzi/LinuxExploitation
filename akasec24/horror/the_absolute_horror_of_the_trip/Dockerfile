FROM archlinux


RUN pacman -Sy
RUN pacman -S --noconfirm socat

EXPOSE 1369

RUN useradd ctf

WORKDIR /chal
COPY the_absolute_horror_of_the_trip /chal

USER ctf

CMD ["socat", "tcp-l:1369,reuseaddr,fork", "EXEC:./the_absolute_horror_of_the_trip"]
