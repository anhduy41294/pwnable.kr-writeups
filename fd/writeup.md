This challenge reminds us about the [File Descriptor](https://en.wikipedia.org/wiki/File_descriptor). First of all, we check the existing file in server's folder. As usual, we have a C-program file `fd.c`, an excuatble file `fd` and a `flag` file. We check the C source code of file `fd.c`:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char buf[32];
int main(int argc, char* argv[], char* envp[]){
	if(argc<2){
		printf("pass argv[1] a number\n");
		return 0;
	}
	int fd = atoi( argv[1] ) - 0x1234;
	int len = 0;
	len = read(fd, buf, 32);
	if(!strcmp("LETMEWIN\n", buf)){
		printf("good job :)\n");
		system("/bin/cat flag");
		exit(0);
	}
	printf("learn about Linux file IO\n");
	return 0;

}
```

We focus on the condition which will help us to run the `/bin/cat flag`. This condition is the comparasonbetweed the string `LETMEWIN\n` and the content of the buffer `buf`. Therefore, our job is make the `buf` contains the string `LETMEWIN\n` and we'll be done. 

`read(fd, buf, 32)` reads the first 32 bytes of the content of **File Descriptor** `fd` to the `buf`. So we need to make this file has the string `LETMEWIN\n`. We can manually create a file, write this string into it. However, from the preceding link. We know that if the File Descriptor is `0`, the file stream comes from the `stdin`. Making `fd = 0`, then we can easily type the required string `LETMEWIN` from the command line. 

To do this, we make the `argv[1] = 0x1234 = 4660`, the code `int fd = atoi( argv[1] ) - 0x1234;` will make `fd = 0`.

```
fd@ubuntu:~$ ./fd 4660
LETMEWIN
good job :)
mommy! I think I know what a file descriptor is!!
fd@ubuntu:~$
```

We get the flag: `mommy! I think I know what a file descriptor is!!` 
