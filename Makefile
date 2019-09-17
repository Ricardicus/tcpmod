mymodule = mytcpmod

all:
	make -C src
	make -C sample

clean:
	make clean -C src
	make clean -C sample

install:
	make install -C src

uninstall:
	make uninstall -C src

sample: 
	make -C sample