mymodule = mytcpmod

all:
	$(MAKE) -C src

clean:
	make clean -C src

install:
	make install -C src

uninstall:
	make uninstall -C src
