#ifndef TCPMOD_DEFS_H
#define TCPMOD_DEFS_H

#define RX_BUFFER_SIZE    50
#define TX_BUFFER_SIZE    50

#define MESSAGE_DATA_BUF  64

#define MAX(x,y) ( ((x) > (y)) ? (x) : (y) )
#define MIN(x,y) ( ((x) < (y)) ? (x) : (y) )

typedef struct inet_message {
  unsigned long ip;
  int port;
  char data[MESSAGE_DATA_BUF];
} inet_message_t;

struct kthread_t
{
        struct task_struct *thread;
        struct socket *sock_recv;
        struct sockaddr_in addr;
        int running;
};

#endif