#include <stdio.h>
#include <stdlib.h>

unsigned long check_pass(const char* p){
	int* ip = (int*) p;

}

int main(void){

	char *s = "AAAAAAAAAAAAAAAAAAAAA";
	int* a = (int*) s;
	for (int i =0; i < 20; i++){
		printf("%d\n", a[i]);	
	}
	//printf("%d %d %d \n", a[0], a[1], a[2]);
	return 0;
}

