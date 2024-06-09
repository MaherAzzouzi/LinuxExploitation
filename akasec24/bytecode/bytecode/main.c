#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <err.h>

#define CODE_SIZE 4096
#define STACK_SIZE 4096

char stack[STACK_SIZE];
char *swap;

typedef enum INST {
	ADD,
	SUB,
	DIV,
	MUL,
	AND,			// and 0x4, 0x48
				// and two values and stores the result in $rax
	XOR,			// xor 0x19, 54
				// xors 2 values and stores the result in $rax
	OR,			// or 0x10, 48
				// or 2 values and stores the result in $rax
	PUSH,			// push 0x505
				// pushes the value to the stack
	POP,			// pop 
				// pops the first value on the stack to $rax
	PRT,			// prt 0x2f62696e2f7368
				// convert the arg to string and prints it
	PUTS,			// puts 0x69696969
				// dereferences an address then prints from it
				// dec 50
	DEC,			// decrements rax by x
	INC, 			// increments rax by x
	LEA,
	NOP,			// no operation
	HALT,
} INST;

uint64_t unpack(void *code, int size){
	uint64_t x = 0;
	memcpy(&x, code, size);

	return (x);
}

void right_shift(char *buffer) {
	memcpy(swap, buffer, STACK_SIZE);
	int starting_point = 0;

	while((starting_point + 8) < STACK_SIZE){
		memcpy(buffer + starting_point + 8 , swap + starting_point, 8 );
		starting_point += 8;
	}
	bzero(buffer, 8);
}

void left_shift(char *buffer) {
	memcpy(swap, buffer, STACK_SIZE);
	int starting_point = 0;

	while((starting_point + 8) < STACK_SIZE){
		memcpy(buffer + starting_point , swap + starting_point + 8, 8 );
		starting_point += 8;
	}
	bzero(buffer, 8);
}

void	interpret_code(int code_size, char *code, void *stack){
	int i = 0;
	register long long int rax asm("rax") = 0;
	while (i < code_size) {
		switch (code[i]){
			case ADD :
				i++;
				rax = unpack(code + i, sizeof(int)) +  unpack(code + i + 4, sizeof(int));
				i += 8;
				break;
			case SUB:
				i++;
				rax = unpack(code + i, sizeof(int)) -  unpack(code + i + 4, sizeof(int));
				i += 8;
				break;
			case MUL:
				i++;
				rax = unpack(code + i, sizeof(int)) *  unpack(code + i + 4, sizeof(int));
				i += 8;
				break;
			case DIV:
				i++;
				if ((int) *(code + i) != 0 && (int) *(code + i + 4) != 0){
					rax = unpack(code + i, sizeof(int)) / unpack(code + i + 4, sizeof(int));
				} else 
					rax = -1;
				i += 8;
				break;
			case AND:
				i++;
				rax = unpack(code + i, sizeof(int)) &  unpack(code + i + 4, sizeof(int));
				i += 8;
				break;
			case XOR:
				i++;
				rax = unpack(code + i, sizeof(int)) ^ unpack(code + i + 4, sizeof(int));
				i += 8;
				break;
			case OR:
				i++;
				rax = unpack(code + i, sizeof(int)) | unpack(code + i + 4, sizeof(int));
				i += 8;
				break;
			case PRT :
				i++;
				unsigned int size = unpack(code + i, sizeof(unsigned char));
				i++;
				fwrite((code + i), size, 1, stdout);
				i += size;
				break;
			case PUTS:		// puts only accepts addresses from bss
				i++;
				if ((unpack(code + i, sizeof(int)) & 0xffffff00) == 
						( (uint64_t)(stack) & 0xffffff00)
						&& (unpack(code + i, sizeof(int)) < (stack + STACK_SIZE))){
					puts((char *) unpack(code + i , sizeof(int)));
				}
				i += 4;
				break;
			case PUSH:
				i++;
				right_shift(stack);
				int length = strlen(&code[i]);
				memcpy(stack, (&code[i]), 8);
				i += 8;
				break;
			case POP :
				i++;
				rax = unpack(stack , sizeof(uint64_t));
				left_shift(stack);
				break;
			case DEC :
				i++;
				rax -= unpack(code + i , sizeof(int));
				i += 4;
				break;
			case INC :
				i++;
				rax += unpack(code + i , sizeof(int));
				i += 4;
				break;
			case LEA :
				i++;
				if ((unpack(code + i, sizeof(int)) & 0xffffff00) == 
						( (uint64_t)(stack) & 0xffffff00)
						&& (unpack(code + i, sizeof(int)) < (stack + STACK_SIZE))){
					char **dst = (char **) unpack(code + i , sizeof(char **));
					if ((long long) dst % 8 != 0)
						break;
					*dst = (char *) unpack(code + i + 8 , sizeof(char *));
				}
				i += 16;
				break;
			case NOP:
				i++;
				break;
			case HALT :
				exit(EXIT_SUCCESS);
			default : 
				errx(69, "Instruction not found %x", code[i]);
		}
	}
}

int	main(){
	char	tmp_swap[STACK_SIZE];
	int	code_size;
	void	*addrs[2];

	// ignore me 
	setvbuf(stdin, 0, _IONBF, 0);
	setvbuf(stdout, 0, _IONBF, 0);
	setvbuf(stderr, 0, _IONBF, 0);
	alarm(128);
	// ignore me 
	addrs[0] = mmap(0, CODE_SIZE, PROT_READ|PROT_WRITE,
			MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	addrs[1] = stack;
	swap = tmp_swap;

	if (addrs[0] == NULL || addrs[1] == NULL)
		err(1, "mmap failed");

	bzero(stack, STACK_SIZE);
	bzero(tmp_swap, STACK_SIZE);
	while (true){
		printf(">> ");
		mprotect(addrs[0], CODE_SIZE, PROT_READ | PROT_WRITE);
		code_size = read(0, addrs[0], CODE_SIZE);
		if ( code_size > 1 && ((char *)addrs[0])[code_size - 1] == '\n'){
			((char *)addrs[0])[code_size - 1] = '\0';
			code_size--;
		}
		else 
			break;
		mprotect(addrs[0], CODE_SIZE, PROT_READ);
		interpret_code(code_size, addrs[0], addrs[1]);
	}
}
