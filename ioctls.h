#ifndef TCPMOD_IOCTLS_H
#define TCPMOD_IOCTLS_H

#include <linux/module.h>   /* Needed by all modules */
#include <linux/kernel.h>   /* Needed for KERN_INFO */
#include <linux/usb.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/moduleparam.h>
#include <linux/socket.h>
#include <linux/kthread.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/slab.h>

#include "defines.h"

#define WR_MESSAGE        _IOW('a','a',inet_message_t*)
#define RD_MESSAGE        _IOR('a','b',inet_message_t*)
#define PEEK_MESSAGE      _IOR('a','c',inet_message_t*)
#define INCOMING_MESSAGES _IOR('a','d',unsigned int*)

long mod_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

#endif