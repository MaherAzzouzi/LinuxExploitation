SRC = main.c pkzip.c base64.c
NAME = zop

$(NAME): $(SRC)
	if [ ! -d "content/" ]; then \
		mkdir content; \
	fi
	gcc $(CFLAGS) $(SRC) -o $(NAME)

clean :
	rm -rf $(NAME)
	rm -rf content/*
