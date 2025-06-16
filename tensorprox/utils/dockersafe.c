#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>

#ifndef EXPECTED_DOCKER_HASH_MACRO
#error "hash macro missing"
#endif
#ifndef ROUND_TOKEN_MACRO
#error "token macro missing"
#endif

static const char EXPECTED_HASH[] = EXPECTED_DOCKER_HASH_MACRO;
static const char ROUND_TOKEN[]   = ROUND_TOKEN_MACRO;
#define die(x) do{perror(x);exit(__LINE__);}while(0)

static void sha_fd(int fd,char out[65]){
    unsigned char buf[16384],dig[32];
    SHA256_CTX ctx; SHA256_Init(&ctx);
    lseek(fd,0,SEEK_SET);
    ssize_t n; while((n=read(fd,buf,sizeof buf))>0) SHA256_Update(&ctx,buf,n);
    SHA256_Final(dig,&ctx);
    for(int i=0;i<32;i++) sprintf(out+i*2,"%02x",dig[i]);
}

int main(int ac,char**av,char**env){
    if(ac<4||strcmp(av[1],"--nonce")){fprintf(stderr,"usage\n");return 97;}
    if(strcmp(av[2],ROUND_TOKEN)){fprintf(stderr,"nonce mismatch\n");return 98;}

    for(int i=1;i+2<ac;i++) av[i]=av[i+2]; av[ac-2]=av[ac-1]=NULL;

    char path[256]; char*home=getenv("HOME"); if(!home) die("HOME");
    snprintf(path,sizeof path,"%s/tensorprox/core/immutable/docker-cli",home);

    int fd=open(path,O_RDONLY|O_CLOEXEC); if(fd<0) die("open cli");
    char calc[65]={0}; sha_fd(fd,calc);
    if(strcmp(calc,EXPECTED_HASH)){fprintf(stderr,"hash mismatch\n");return 99;}

    int mfd=syscall(SYS_memfd_create,"dckr",MFD_CLOEXEC); if(mfd<0) die("memfd");
    lseek(fd,0,SEEK_SET);
    char buf[16384]; ssize_t n;
    while((n=read(fd,buf,sizeof buf))>0) if(write(mfd,buf,n)!=n) die("copy");
    unsigned seals=F_SEAL_SEAL|F_SEAL_WRITE|F_SEAL_SHRINK|F_SEAL_GROW;
    if(fcntl(mfd,F_ADD_SEALS,seals)) die("seal");

    printf("OK %s\n",ROUND_TOKEN); fflush(stdout);
    syscall(SYS_execveat,mfd,"",av+1,env,AT_EMPTY_PATH); die("execveat");
}