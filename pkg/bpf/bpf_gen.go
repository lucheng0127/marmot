package bpf

//go:generate sh -c "cd .. && bpf2go -cc clang -cflags \"-O2 -g -Wall -Werror -I.\" Marmot ../bpf/tc_ingress.c"
