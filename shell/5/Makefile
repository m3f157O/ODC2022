.PHONY: syscall
FLAG = -O0 -fno-stack-protector -fno-pie -z execstack -no-pie

syscall: syscall.c
    gcc $(FLAG) -o $@ $<

