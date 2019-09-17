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

#include "ioctls.h"
#include "defines.h"

MODULE_LICENSE("GPL");

static struct kthread_t *kthread = NULL;

static char *ip = NULL;
static int port;

spinlock_t inet_mod_lock;
unsigned int inet_rx_idx = 0;
unsigned int inet_tx_idx = 0;

inet_message_t * rx_buffer;
inet_message_t * tx_buffer;

module_param(port, int,S_IRUSR|S_IWUSR);
module_param(ip, charp, S_IRUSR|S_IWUSR);

//#define _BSD_SOURCE

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Rickard");
MODULE_DESCRIPTION("TCP/IP module");

#define MODULE_NAME "mytcpmod"

static int major_number;

ssize_t mod_read (struct file *f, char *user, size_t size, loff_t *offset)
{
  static char buffer[15] = {'H', 'e', 'l', 'l', 'o', ',', ' ', 'w', 'o', 'r', 'l', 'd', '!', '\n', 0};
  size_t i = 0;
  int major_nbr;
  int minor_nbr;

  if ( size == 0 || user == NULL )
    return -EINVAL;

  while ( (i+*offset) < size && (i+*offset) < sizeof(buffer) ) {
    user[i] = buffer[i];
    ++i;
  }

  if ( *offset == 0 ) {
    // Learn stuff. Print stuff.

    major_nbr = imajor(f->f_inode);
    minor_nbr = iminor(f->f_inode);

    printk(KERN_INFO "%s size: %zu, offset: %llu\r\n", __func__, size, *offset);

    printk(KERN_INFO "f->i_uid: %u\n", f->f_inode->i_uid.val);
    printk(KERN_INFO "f->i_gid: %u\n", f->f_inode->i_gid.val);
    printk(KERN_INFO "file d_iname:  %s\n", f->f_path.dentry->d_iname);
    printk(KERN_INFO "file d_parent: %s\n", f->f_path.dentry->d_parent->d_iname);
    printk(KERN_INFO "i_rdev: %u\n", f->f_inode->i_rdev);
    printk(KERN_INFO "major: %u\n", major_nbr);
    printk(KERN_INFO "minor: %u\n", minor_nbr);
  }

  *offset += i;
  return i;
}

ssize_t mod_write (struct file *f, const char *user, size_t size, loff_t *offset)
{
  printk(KERN_INFO "%s size: %zu, offset: %llu\r\n", __func__, size, *offset);
  return size;
}

int mod_open(struct inode *node, struct file *f)
{
  printk(KERN_INFO "%s\n", __func__);
  return 0;
}

int mod_release(struct inode *node, struct file *f)
{
  printk(KERN_INFO "%s\n", __func__);
  return 0;
}

struct file_operations fops = {
   .read =  mod_read,
   .write = mod_write,
   .open = mod_open,
   .release = mod_release,
   .unlocked_ioctl = mod_ioctl
};

static int ksocket_receive(struct socket* sock, struct sockaddr_in* addr, unsigned char* buf, int len)
{
  mm_segment_t oldfs;
  int read_bytes = 0;

  unsigned long nr_segments = 1;
  size_t count = len;
  char *cbuf;
  struct msghdr __user msg = {};
  struct iovec iov = {};

  if (sock->sk==NULL) return 0;

  cbuf = kmalloc(500, GFP_USER);
  if ( cbuf < 0 ) {
    printk(KERN_ERR MODULE_NAME " failed to alloc mem for cbuf\n");
  }

  iov.iov_base = buf;
  iov.iov_len = len;

  msg.msg_flags = 0;
  msg.msg_name = addr;
  msg.msg_namelen  = sizeof(struct sockaddr_in);
  msg.msg_control = cbuf;
  msg.msg_controllen = 500;

  iov_iter_init(&msg.msg_iter, READ, &iov, nr_segments, count);

  msg.msg_control = NULL;

  printk(KERN_INFO MODULE_NAME "(1)\n");
  oldfs = get_fs();
  set_fs(KERNEL_DS);

  if ( sock == NULL ) {
    printk(KERN_INFO MODULE_NAME ": Error, sock == NULL\n");
    set_fs(oldfs);
    return -1;
  }

  if ( sock->ops == NULL ) {
    printk(KERN_INFO MODULE_NAME ": Error, sock->ops == NULL\n");
    set_fs(oldfs);
    return -1;
  }

  if ( sock->ops->recvmsg == NULL ) {
    printk(KERN_INFO MODULE_NAME ": Error, sock->ops->recvmsg == NULL\n");
    set_fs(oldfs);
    return -1;
  }

  read_bytes = sock_recvmsg(sock, &msg, 0);

  set_fs(oldfs);
  printk(KERN_INFO MODULE_NAME "(2)\n");
  printk(KERN_INFO MODULE_NAME " read_bytes: %d\n", read_bytes);

  kfree(cbuf);

  return read_bytes;
}

static void ksocket_start(void)
{
  int err;
  int size;
  int bufsize = 256;
  unsigned char *buf;

  struct socket *new_socket;

  buf = kmalloc(bufsize, GFP_USER);
  if ( !buf ) {
    printk(KERN_INFO MODULE_NAME ": Failed to allocate kmem for socket buffer\n");
    return;
  }

  new_socket=(struct socket*)kmalloc(sizeof(struct socket),GFP_KERNEL);

  if ( new_socket == NULL ) {
    printk(KERN_INFO MODULE_NAME ": Failed to allocate kmem for new socket\n");
    return;
  }

  err = sock_create(PF_INET,SOCK_STREAM,IPPROTO_TCP,&new_socket);

  if ( err < 0 ) {
    printk(KERN_INFO MODULE_NAME ": Failed to create new socket\n");
    return;
  }

  kthread->running = 1;

  /* create a socket */
  if ( ( (err = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &kthread->sock_recv)) < 0) )
  {
    printk(KERN_INFO MODULE_NAME ": Could not create IPPROTO_TCP socket, error = %d\n", -err);
    return;
  }

  memset(&kthread->addr, 0, sizeof(struct sockaddr));

  kthread->addr.sin_family           = AF_INET;
  kthread->addr.sin_addr.s_addr      = htonl(INADDR_ANY);
  kthread->addr.sin_port             = htons(port);

  if ( ( (err = kthread->sock_recv->ops->bind(kthread->sock_recv, 
    (struct sockaddr *)&kthread->addr, sizeof(struct sockaddr) ) 
    ) < 0) )
  {
    printk(KERN_INFO MODULE_NAME": Could not bind to socket, error = %d\n", -err);
    return;
  }

  set_current_state(TASK_INTERRUPTIBLE);

  if ( ( (err = kthread->sock_recv->ops->listen(kthread->sock_recv, 5) ) < 0) )
  {
    printk(KERN_INFO MODULE_NAME ": Could not listen to socket, error = %d\n", -err);
    sock_release(kthread->sock_recv);
    return;
  }

  printk(KERN_INFO MODULE_NAME ": listening on port %d\n", port);

  /* main loop */
  while (!kthread_should_stop())
  {
    struct sockaddr client_ip;
    struct sockaddr_in *inet_addr;
    int client_ip_len = sizeof(struct sockaddr);
    inet_message_t new_message;

    err = kernel_accept(kthread->sock_recv, &new_socket, O_NONBLOCK);

    if ( err == -EAGAIN ) {
      continue;
    }

    if ( err < 0 ) {
      printk(KERN_INFO MODULE_NAME ": Failed to accept (%d)\n", err);
    } else {
      printk(KERN_INFO MODULE_NAME ": accepted connection!\n");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
      // lenght is returned from now on instead
      client_ip_len = new_socket->ops->getname(new_socket, &client_ip, 2);
#else
      new_socket->ops->getname(new_socket, &client_ip, &client_ip_len, 2);
#endif

      if ( client_ip.sa_family == AF_INET ) {
        printk(KERN_INFO MODULE_NAME ": CLIENT IS AF_INET!\n");

        inet_addr = (struct sockaddr_in *)&client_ip;

        printk(KERN_INFO MODULE_NAME ": CLIENT PORT: %d\n", inet_addr->sin_port);
        printk(KERN_INFO MODULE_NAME ": CLIENT IP  : %d.%d.%d.%d\n", 
          (inet_addr->sin_addr.s_addr & 0x000000FF),
          (inet_addr->sin_addr.s_addr & 0x0000FF00) >> 8,
          (inet_addr->sin_addr.s_addr & 0x00FF0000) >> 16,
          (inet_addr->sin_addr.s_addr & 0xFF000000) >> 24
          );

        new_message.port = inet_addr->sin_port;
        new_message.ip   = inet_addr->sin_addr.s_addr;

      } else {
        printk(KERN_INFO MODULE_NAME ": CLIENT IS NOT AF_INET!\n");
      }

      memset(buf, 0, bufsize);
      size = ksocket_receive(new_socket, &kthread->addr, buf, bufsize);

      if (size < 0) {
        printk(KERN_INFO MODULE_NAME ": error getting stream, sock_recvmsg error = %d\n", size);
        //break;
      }
      else 
      {
        unsigned long flags;

        memcpy(new_message.data, buf, MIN(bufsize, MESSAGE_DATA_BUF));

        // Add new data to rx_buffer using the spin lock
        spin_lock_irqsave(&inet_mod_lock, flags);

        if ( inet_rx_idx < RX_BUFFER_SIZE ) {
          rx_buffer[inet_rx_idx] = new_message;
          inet_rx_idx++;
        }

        spin_unlock_irqrestore(&inet_mod_lock, flags);

        printk(KERN_INFO MODULE_NAME ": Message nbr %d received.\n", inet_rx_idx);
        /* data processing */

        sock_release(new_socket);

        break;
      }

    }

  }

  set_current_state(TASK_RUNNING);

  sock_release(kthread->sock_recv);

  kfree(new_socket);
  kfree(buf);
  kthread->running = 0;
}

int init_module(void)
{
  printk(KERN_INFO "Hello world 1.\n");

  // Register this driver
  major_number = register_chrdev(0, MODULE_NAME, &fops);

  printk(KERN_INFO "%s", __func__);
  printk(KERN_INFO "Major number assigned: %d\n", major_number);

  printk(KERN_INFO "port: %d, ip: %s\n", port, ip);

  /* Allocate kernel thread */
  kthread = kmalloc(sizeof(struct kthread_t), GFP_KERNEL);

  if ( kthread < 0 ) {
    printk(KERN_ERR MODULE_NAME ": Failed to allocate space for kthread. Will quit.");
    return -ENOMEM;
  }

  /* Initalize memory for the message buffers */
  rx_buffer = kmalloc(sizeof(inet_message_t)*RX_BUFFER_SIZE, GFP_KERNEL);

  if ( rx_buffer < 0 ) {
    printk(KERN_ERR MODULE_NAME ": Failed to allocate space for rx buffer. Will quit.");

    kfree(kthread);
    return -ENOMEM;
  }

  tx_buffer = kmalloc(sizeof(inet_message_t)*TX_BUFFER_SIZE, GFP_KERNEL);

  if ( tx_buffer < 0 ) {
    printk(KERN_ERR MODULE_NAME ": Failed to allocate space for tx buffer. Will quit.");
    
    kfree(rx_buffer);
    kfree(kthread);
    return -ENOMEM;
  }

  memset(kthread, 0, sizeof(struct kthread_t));

  /* start kernel thread */
  kthread->thread = kthread_run((void *)ksocket_start, NULL, MODULE_NAME);

  if (IS_ERR(kthread->thread)) 
  {
    printk(KERN_INFO MODULE_NAME ": unable to start kernel thread\n");
    kfree(kthread);
    kthread = NULL;
    return -ENOMEM;
  }

  spin_lock_init(&inet_mod_lock);
  /*
   * A non 0 return means init_module failed; module can't be loaded.
   */
  return 0;
}

void cleanup_module(void)
{
  int ret;

  printk(KERN_INFO "Goodbye world 1.\n");

  if ( kthread != NULL ) {
    if ( kthread->running ) {
      ret = kthread_stop(kthread->thread);
      if(!ret) {
        printk(KERN_INFO "kthread stopped");
      }
    }

    // Free the memory of the threads
    kfree(kthread);
  }

  // Free the memory of the buffers
  if ( rx_buffer != NULL )
    kfree(rx_buffer);
  if ( tx_buffer != NULL )
    kfree(tx_buffer);

  unregister_chrdev(major_number, MODULE_NAME);

}

//module_init(init_module);
//module_exit(cleanup_module);
