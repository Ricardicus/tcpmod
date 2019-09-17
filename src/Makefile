mymodule = mytcpmod

IP = 127.0.0.1
PORT = 8080

obj-m += $(mymodule).o

$(mymodule)-objs := tcpmod.o ioctls.o

all:
	echo "$(shell pwd)" && make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
	rm -f ../tcp$(PORT)

install:
	./util.sh $@ $(mymodule) $(PORT) $(IP)

uninstall:
	./util.sh $@ $(mymodule)
