#ifndef SAMPLE_H
#define SAMPLE_H

#include <sys/ioctl.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/* 
* Make sure these fields and values are in sync with 
* those in src/defines.h and src/ioctls.h
*/

#define WR_MESSAGE        _IOW('a','a',inet_message_t*)
#define RD_MESSAGE        _IOR('a','b',inet_message_t*)
#define PEEK_MESSAGE      _IOR('a','c',inet_message_t*)
#define INCOMING_MESSAGES _IOR('a','d',unsigned int*)

#define MESSAGE_DATA_BUF  64

typedef struct inet_message {
  unsigned long ip;
  int port;
  struct timespec time;
  unsigned int len;
  char data[MESSAGE_DATA_BUF];
} inet_message_t;

#endif