STUB = stub.S

-: FORCE
	@echo "Run make stub or make stub32"

stub.inc: FORCE
	gcc $(CFLAGS) -nostdlib -Wl,-e0 $(STUB) -o stub
	objcopy --dump-section .text=/dev/stdout stub | xxd -i - >stub.inc

stub32: FORCE
	gcc $(CFLAGS) -m32 -nostdlib -Wl,-e0 $(STUB) -o stub32
	objcopy --dump-section .text=/dev/stdout stub32 | xxd -i - >stub32.inc

clean:
	rm -f stub *.inc

FORCE:
