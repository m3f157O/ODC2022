.PHONY: backtoshell

easyrop: backtoshell.o
    gcc -static -nostdlib -DSIZE=100 -o backtoshell backtoshell.c

clean:
    rm backtoshell

