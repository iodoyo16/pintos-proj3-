/*
    print the result of fibonacci system call using [num 1]
    and print the result of max_of_four_int system call using [num 1,2,3,4]
*/
#include<stdio.h>
#include<ctype.h>
#include<stdlib.h>
#include<syscall.h>

int main(int argc, char * argv[]){
    bool success=true;
    int arr[4];
    //printf("argc: %d\n",argc);
    if(argc!=5){
        success=false;
    }
    else{
        for(int i=0;i<4;i++){
            int sign=1;
            int val=0;
            char* tmp=argv[i+1];
            if(*tmp=='-'){
                sign=-1;
                tmp++;
            }
            while(*tmp!='\0'){
                if(*tmp>='0'&&*tmp<='9'){
                    val=val*10+(*tmp-'0');
                }
                else{
                    //printf("i: %d *tmp: %c\n",i,*tmp);
                    success=false;
                    break;
                }
                tmp++;
            }
            arr[i]=val*sign;
        }
    }
    if(!success){
        printf("Argument must be four integers\n");
        return EXIT_FAILURE;
    }
    if(arr[0]<0){
        printf("First Argumnet must be Nonnegativenumber\n");
        return EXIT_FAILURE;
    }
    printf("%d %d\n",fibonacci(arr[0]),max_of_four_int(arr[0],arr[1],arr[2],arr[3]));
    return EXIT_SUCCESS;
}