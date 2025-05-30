//gcc ./o2_pwn.c -o o2_pwn -fno-stack-protector  -no-pie -O2 -m32
#include<stdio.h>

char name[0x1000];

void backdoor() __attribute__((used));

void backdoor() {
    system("/bin/sh");
}

int main(){
    char buf[0x80];
    puts("Show me your name:");
    read(0,name,0x800);
    puts("Password:");
    read(0,buf,0x300);
}