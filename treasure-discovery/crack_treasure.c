#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <omp.h>

static EVP_MD *KMD;
static void khash(const unsigned char *in,size_t n,unsigned char out[32]){
 unsigned int olen=0; EVP_MD_CTX *c=EVP_MD_CTX_new();
 EVP_DigestInit_ex(c,KMD,NULL); EVP_DigestUpdate(c,in,n); EVP_DigestFinal_ex(c,out,&olen); EVP_MD_CTX_free(c);
}
static int hx(const char *s,unsigned char out[32]){for(int i=0;i<32;i++){unsigned x;if(sscanf(s+2*i,"%2x",&x)!=1)return 0;out[i]=x;}return 1;}
static void xorb(const unsigned char a[32],const unsigned char b[32],unsigned char o[32]){for(int i=0;i<32;i++)o[i]=a[i]^b[i];}
static int eq(const unsigned char a[32],const unsigned char b[32]){return memcmp(a,b,32)==0;}
static void printhex(FILE *f,const unsigned char x[32]){for(int i=0;i<32;i++)fprintf(f,"%02x",x[i]);}

struct Sub{int idx;const char*e;};
static const char *hxs[4]={
 "78d8911025bf14e90b8566da2eb0ba4d03087a838b63e81d9319f941e4bfcb02",
 "449003c87c7ca9649dd6c6caa59b4d5c76fabffdfb0a35be5c8d25cc41e1752b",
 "04a4f5729c46202c24bda335ec3e15f79b1a18b588a2c613ed802331d31fee00",
 "00bae70d922c05c274bb9ae6fc87fa7434e467627e3e77bde7c7bbea3532f10e"};
static struct Sub ss[7]={
 {0,"38b18135753f7443ece52a5d9bfe6e765526eecbf11d06d9c19c3227f1bd8d3e"},
 {0,"e9daeed11cf588b72271dfbab2422fcc44c09f7ea77204c22106d1e82caf3dfb"},
 {0,"a5f3e4612e6b17146590bf74b687f2d45f9d4b262a33598369f8ac3f8fea82b8"},
 {1,"72b6bfc136fd76839efe3a1d0e89d511afd3247ef3b8fa82a58e51ca45ee766d"},
 {1,"a92191710c1ba64f1b945476e3d4a6471b8bbcdff64290702f6a70d7e1aee314"},
 {2,"a8a85478d2eca1c2929503663f7521579bc150650c41255d66094100ce79715a"},
 {3,"c3ecd55b0415e038a0e734dcf04678a07fddb1a72ab1b097b1e2a95a12f87feb"}};

int main(int argc,char**argv){
 if(argc<3){fprintf(stderr,"usage: %s candidates output\n",argv[0]);return 2;}
 KMD=EVP_MD_fetch(NULL,"KECCAK-256",NULL); if(!KMD){fprintf(stderr,"no KECCAK\n");return 2;}
 unsigned char H[4][32],E[7][32];for(int i=0;i<4;i++)hx(hxs[i],H[i]);for(int i=0;i<7;i++)hx(ss[i].e,E[i]);
 FILE*f=fopen(argv[1],"rb");if(!f){perror("open");return 2;}FILE*out=fopen(argv[2],"a");if(!out){perror("output");return 2;}
 char *line=NULL;size_t cap=0;ssize_t len;unsigned long long count=0;
 while((len=getline(&line,&cap,f))>=0){while(len>0&&(line[len-1]=='\n'||line[len-1]=='\r'))line[--len]=0;if(len==0)continue;count++;
  unsigned char variants[7][32];const char*names[7];int nv=0;
  khash((unsigned char*)line,len,variants[nv]);names[nv++]="keccak_utf8";
  SHA256((unsigned char*)line,len,variants[nv]);names[nv++]="sha256_utf8";
  if(len<=32){memset(variants[nv],0,32);memcpy(variants[nv]+32-len,line,len);names[nv++]="ascii_right";
    memset(variants[nv],0,32);memcpy(variants[nv],line,len);names[nv++]="ascii_left";}
  int all_digit=1;for(int i=0;i<len;i++)if(!isdigit((unsigned char)line[i]))all_digit=0;
  if(all_digit){unsigned long long v=strtoull(line,NULL,10);memset(variants[nv],0,32);for(int j=0;j<8;j++)variants[nv][31-j]=(v>>(8*j))&255;names[nv++]="raw_integer";}
  // Old web3 commonly hashes the hex text of a prior digest; cover both lowercase and 0x-prefixed forms.
  char hexbuf[67];unsigned char p0[32];khash((unsigned char*)line,len,p0);for(int j=0;j<32;j++)sprintf(hexbuf+2*j,"%02x",p0[j]);
  khash((unsigned char*)hexbuf,64,variants[nv]);names[nv++]="keccak_hex_digest";
  char pref[67];pref[0]='0';pref[1]='x';memcpy(pref+2,hexbuf,64);pref[66]=0;khash((unsigned char*)pref,66,variants[nv]);names[nv++]="keccak_0xhex_digest";
  for(int vi=0;vi<nv;vi++)for(int si=0;si<7;si++){
    unsigned char x[32],d[32];xorb(E[si],variants[vi],x);khash(x,32,d);
    if(eq(d,H[ss[si].idx])){#pragma omp critical
      {fprintf(out,"FOUND idx=%d sub=%d scheme=%s password=%s x=",ss[si].idx,si,names[vi],line);printhex(out,x);fprintf(out,"\n");fflush(out);}}
  }
 }
 fprintf(out,"tested %llu candidate lines from %s\n",count,argv[1]);fflush(out);free(line);fclose(f);fclose(out);EVP_MD_free(KMD);return 0;
}
