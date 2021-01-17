#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define MAX_NOTE 0x40

typedef struct {
  char *ptr;
  int  size;
  char is_used;
} Note;

Note note[MAX_NOTE] = { NULL };

void readline(char *buf, int size) {
  if (read(0, buf, size) == 0) _exit(0);
}

int read_int(void) {
  char buf[0x20];
  memset(buf, 0, 0x20);
  readline(buf, 0x1f);
  return atoi(buf);
}

void add(void) {
  int index = read_int();
  int size  = read_int();
  if (index < 0 || index >= MAX_NOTE) return;
  if (size < 0) return;
  if (note[index].is_used == 0) {
    note[index].ptr = (char*)malloc(size);
    note[index].size = size;
    note[index].is_used = 1;
  }
}

void edit(void) {
  int index = read_int();
  if (index < 0 || index >= MAX_NOTE) return;
  if (read(0, note[index].ptr, note[index].size) == 0) _exit(0);
}

void delete(void) {
  int index = read_int();
  if (index < 0 || index >= MAX_NOTE) return;
  if (note[index].is_used == 1) {
    free(note[index].ptr);
    note[index].is_used = 0;
  }
}

int main(void) {
  while(1) {
    int choice = read_int();
    switch(choice) {
    case 1: add(); break;
    case 2: edit(); break;
    case 3: delete(); break;
    }
  }
  return 0;
}
