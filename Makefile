mymodule = mytcpmod

IP = 127.0.0.1
PORT = 8080

obj-m += $(mymodule).o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install:
	@insmod $(mymodule).ko port=$(PORT) ip=$(IP)

uninstall:
	@rmmod $(mymodule)
