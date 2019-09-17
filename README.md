This is a module I am making just to get a bit more
exeprience of Linux kernel space development. 
I have made a server that runs in kernel mode.
For now this server only works as an echo server.


You can read the latest incoming message
by the character device driver node created 
as "tcp[PORTNUMBER]". 


Only 64 bytes from incoming messages are 
stored to be able to be read. You don't want
to occupy too much memory in kernel space.


There are some IOCTLs one can use also.

If I find this inspiring to continue working
on I might add IOCTL support for acting as 
a client also.

This is just me exploring the world of Linux
a bit. 

# Install

```bash
# Build the kernel module files
make
# Install the module
sudo make install
```

# Uninstall

```bash
# Uninstall the module
sudo make uninstall
# Remove files not used anymore
make clean
```


