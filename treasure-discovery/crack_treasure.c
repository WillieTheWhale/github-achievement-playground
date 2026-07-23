#include <openssl/sha.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* Minimal legacy Keccak-256 used by the EVM (domain byte 0x01, not SHA3's 0x06). */
static inline uint64_t rol64(uint64_t x,unsigned y){return (x<<y)|(x>>(64-y));}
static uint64_t load64le(const unsigned char*p){uint64_t x=0;for(int i=0;i<8;i++)x|=((uint64_t)p[i])<<(8*i);return x;}
static void store64le(unsigned char*p,uint64_t x){for(int i=0;i<8;i++)p[i]=(unsigned char)(x>>(8*i));}
static void keccakf(uint64_t st[25]){
 static const uint64_t rc[24]={
  0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808aULL,0x8000000080008000ULL,
  0x000000000000808bULL,0x0000000080000001ULL,0x8000000080008081ULL,0x8000000000008009ULL,
  0x000000000000008aULL,0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000aULL,
  0x000000008000808bULL,0x800000000000008bULL,0x8000000000008089ULL,0x8000000000008003ULL,
  0x8000000000008002ULL,0x8000000000000080ULL,0x000000000000800aULL,0x800000008000000aULL,
  0x8000000080008081ULL,0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL};
 static const unsigned rotc[24]={1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44};
 static const unsigned piln[24]={10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1};
 for(int r=0;r<24;r++){
  uint64_t bc[5],t;
  for(int i=0;i<5;i++)bc[i]=st[i]^st[i+5]^st[i+10]^st[i+15]^st[i+20];
  for(int i=0;i<5;i++){t=bc[(i+4)%5]^rol64(bc[(i+1)%5],1);for(int j=0;j<25;j+=5)st[j+i]^=t;}
  t=st[1];for(int i=0;i<24;i++){unsigned j=piln[i];bc[0]=st[j];st[j]=rol64(t,rotc[i]);t=bc[0];}
  for(int j=0;j<25;j+=5){for(int i=0;i<5;i++)bc[i]=st[j+i];for(int i=0;i<5;i++)st[j+i]=bc[i]^((~bc[(i+1)%5])&bc[(i+2)%5]);}
  st[0]^=rc[r];
 }
}
static void khash(const unsigned char*in,size_t n,unsigned char out[32]){
 uint64_t st[25]={0};const size_t rate=136;
 while(n>=rate){for(int i=0;i<17;i++)st[i]^=load64le(in+8*i);keccakf(st);in+=rate;n-=rate;}
 unsigned char b[136]={0};memcpy(b,in,n);b[n]=0x01;b[rate-1]|=0x80;
 for(int i=0;i<17;i++)st[i]^=load64le(b+8*i);keccakf(st);for(int i=0;i<4;i++)store64le(out+8*i,st[i]);
}
static int hx(const char*s,unsigned char out[32]){for(int i=0;i<32;i++){unsigned x;if(sscanf(s+2*i,"%2x",&x)!=1)return 0;out[i]=x;}return 1;}
static void xorb(const unsigned char a[32],const unsigned char b[32],unsigned char o[32]){for(int i=0;i<32;i++)o[i]=a[i]^b[i];}
static int eq(const unsigned char a[32],const unsigned char b[32]){return memcmp(a,b,32)==0;}
static void printhex(FILE*f,const unsigned char x[32]){for(int i=0;i<32;i++)fprintf(f,"%02x",x[i]);}

struct Sub{int idx;int hunter;const char*e;};
static const char*hxs[4]={
 "78d8911025bf14e90b8566da2eb0ba4d03087a838b63e81d9319f941e4bfcb02",
 "449003c87c7ca9649dd6c6caa59b4d5c76fabffdfb0a35be5c8d25cc41e1752b",
 "04a4f5729c46202c24bda335ec3e15f79b1a18b588a2c613ed802331d31fee00",
 "00bae70d922c05c274bb9ae6fc87fa7434e467627e3e77bde7c7bbea3532f10e"};
static struct Sub ss[7]={
 {0,0,"38b18135753f7443ece52a5d9bfe6e765526eecbf11d06d9c19c3227f1bd8d3e"},
 {0,1,"e9daeed11cf588b72271dfbab2422fcc44c09f7ea77204c22106d1e82caf3dfb"},
 {0,2,"a5f3e4612e6b17146590bf74b687f2d45f9d4b262a33598369f8ac3f8fea82b8"},
 {1,0,"72b6bfc136fd76839efe3a1d0e89d511afd3247ef3b8fa82a58e51ca45ee766d"},
 {1,2,"a92191710c1ba64f1b945476e3d4a6471b8bbcdff64290702f6a70d7e1aee314"},
 {2,2,"a8a85478d2eca1c2929503663f7521579bc150650c41255d66094100ce79715a"},
 {3,2,"c3ecd55b0415e038a0e734dcf04678a07fddb1a72ab1b097b1e2a95a12f87feb"}};

int main(int argc,char**argv){
 if(argc<3){fprintf(stderr,"usage: %s candidates output\n",argv[0]);return 2;}
 unsigned char empty[32],expect[32];khash((const unsigned char*)"",0,empty);hx("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",expect);
 if(!eq(empty,expect)){fprintf(stderr,"Keccak self-test failed\n");return 2;}
 unsigned char H[4][32],E[7][32];for(int i=0;i<4;i++)hx(hxs[i],H[i]);for(int i=0;i<7;i++)hx(ss[i].e,E[i]);
 FILE*f=fopen(argv[1],"rb");if(!f){perror("open");return 2;}FILE*out=fopen(argv[2],"a");if(!out){perror("output");return 2;}
 char*line=NULL;size_t cap=0;ssize_t len;unsigned long long count=0;
 while((len=getline(&line,&cap,f))>=0){while(len>0&&(line[len-1]=='\n'||line[len-1]=='\r'))line[--len]=0;if(len==0)continue;count++;
  unsigned char variants[7][32];const char*names[7];int nv=0;
  khash((unsigned char*)line,len,variants[nv]);names[nv++]="keccak_utf8";
  SHA256((unsigned char*)line,len,variants[nv]);names[nv++]="sha256_utf8";
  if(len<=32){memset(variants[nv],0,32);memcpy(variants[nv]+32-len,line,len);names[nv++]="ascii_right";memset(variants[nv],0,32);memcpy(variants[nv],line,len);names[nv++]="ascii_left";}
  int digits=1;for(int i=0;i<len;i++)if(!isdigit((unsigned char)line[i]))digits=0;
  if(digits){unsigned long long v=strtoull(line,NULL,10);memset(variants[nv],0,32);for(int j=0;j<8;j++)variants[nv][31-j]=(v>>(8*j))&255;names[nv++]="raw_integer";}
  char hexbuf[65];for(int j=0;j<32;j++)sprintf(hexbuf+2*j,"%02x",variants[0][j]);
  khash((unsigned char*)hexbuf,64,variants[nv]);names[nv++]="keccak_hex_digest";
  char pref[67];pref[0]='0';pref[1]='x';memcpy(pref+2,hexbuf,64);khash((unsigned char*)pref,66,variants[nv]);names[nv++]="keccak_0xhex_digest";
  /* One representative submission per hunter is sufficient for a 256-bit equality test. */
  for(int vi=0;vi<nv;vi++)for(int si=0;si<3;si++){
   unsigned char x[32],d[32];xorb(E[si],variants[vi],x);khash(x,32,d);
   if(eq(d,H[0])){
    fprintf(out,"FOUND hunter=%d scheme=%s password=%s location0=",ss[si].hunter,names[vi],line);printhex(out,x);fprintf(out,"\n");
    for(int sj=3;sj<7;sj++)if(ss[sj].hunter==ss[si].hunter){xorb(E[sj],variants[vi],x);khash(x,32,d);fprintf(out,"VERIFY loc=%d ok=%d key=",ss[sj].idx,eq(d,H[ss[sj].idx]));printhex(out,x);fprintf(out,"\n");}
    fflush(out);
   }
  }
 }
 fprintf(out,"tested %llu candidate lines from %s\n",count,argv[1]);free(line);fclose(f);fclose(out);return 0;
}
