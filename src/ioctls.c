#include "ioctls.h"

extern spinlock_t inet_mod_rx_queue_lock;
extern unsigned int inet_rx_idx;
extern unsigned int inet_tx_idx;

extern inet_message_t * rx_buffer;
extern inet_message_t * tx_buffer;

long mod_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
  inet_message_t value;
  unsigned long flags;

  switch(cmd) {
    case WR_MESSAGE:
      copy_from_user(&value ,(inet_message_t*) arg, sizeof(value));
      tx_buffer[inet_tx_idx] = value;
      if ( inet_tx_idx < TX_BUFFER_SIZE )
        inet_tx_idx++;
      break;
    case RD_MESSAGE:
      spin_lock_irqsave(&inet_mod_rx_queue_lock, flags);
      value = rx_buffer[inet_rx_idx];
      if ( inet_rx_idx > 0 )
        inet_rx_idx--;
      copy_to_user((inet_message_t*) arg, &value, sizeof(value));
      spin_unlock_irqrestore(&inet_mod_rx_queue_lock, flags);
      break;
    case PEEK_MESSAGE:
      spin_lock_irqsave(&inet_mod_rx_queue_lock, flags);
      value = rx_buffer[inet_rx_idx];
      copy_to_user((inet_message_t*) arg, &value, sizeof(value));
      spin_unlock_irqrestore(&inet_mod_rx_queue_lock, flags);
    case INCOMING_MESSAGES:
      spin_lock_irqsave(&inet_mod_rx_queue_lock, flags);
      copy_to_user((unsigned int*) arg, &inet_rx_idx, sizeof(inet_rx_idx));
      spin_unlock_irqrestore(&inet_mod_rx_queue_lock, flags);
    default:
      break;
  }
  return 0;
}