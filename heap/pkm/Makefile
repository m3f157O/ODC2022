.PHONY: pkm
FLAG = -O0 -g

pkm: pkm.c
    gcc $(FLAG) -o $@ $<
    gcc $(FLAG) -no-pie -o $@_nopie $<
    patchelf --replace-needed libc.so.6 ./libc-2.27_notcache.so pkm_nopie
