In the server, I found the source code of the malicous program.

```c
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
	int* ip = (int*)p;
	int i;
	int res=0;
	for(i=0; i<5; i++){
		res += ip[i];
	}
	return res;
}

int main(int argc, char* argv[]){
	if(argc<2){
		printf("usage : %s [passcode]\n", argv[0]);
		return 0;
	}
	if(strlen(argv[1]) != 20){
		printf("passcode length should be 20 bytes\n");
		return 0;
	}

	if(hashcode == check_password( argv[1] )){
		system("/bin/cat flag");
		return 0;
	}
	else
		printf("wrong passcode.\n");
	return 0;
}
```

We can clearly see that we need to provide a string that make the `check_password` function creates a `pass` which equals to hashcode.

The hashcode is `0x21DD09EC = 0x06C5CEC8 *4  + 0x06C5CECC`. In the `check_password` function, it convert `p` into `ip`. Every char occupies 1 bytes and every int takes 4 bytes. Therefore, the convertion split every 4 chars into 1 int. So, we have 5 int.

However, just make it simple. I had `0x21DD09EC = 0x06C5CEC8 *4  + 0x06C5CECC`. So the first 16 bytes contains the value of 0x06C5CEC8 (4 times) and the last 4 bytes contains the value of 0x06C5CECC in the little endian. The exploitation is simply using python.

```
col@ubuntu:~$ ./col $(python2 -c 'print "\xc8\xce\xc5\x06" * 4 + "\xcc\xce\xc5\x06";')
daddy! I just managed to create a hash collision :)
```


