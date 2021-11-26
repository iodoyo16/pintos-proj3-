#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H
#define INPUT_ARG_MAX 128
#define WORD_SIZE 4

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

int parse_file_name(char *input, char ***parsed_filename_argv);
void push_userstack(char** parsed_filename_argv, int argc,void **esp);

#endif /* userprog/process.h */
