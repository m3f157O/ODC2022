#include <stdio.h>

int main()
{
    int magic0[]={27, 81, 23, 33, 30, 78, 62, 16, 23, 70, 73, 20, 61};
    char xx[6]="babuzz";
    
    for(int i=0;i<13;i++)
    {
        printf("%c",magic0[i]^xx[i%6]);
    }
    return 0;
}

