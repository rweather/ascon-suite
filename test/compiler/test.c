
#include <stdio.h>
#include <stdlib.h>

int switch_func(int x)
{
    switch (x) {
    case 1: return 103;
    case 2: return 203;
    case 3: return 303;
    case 4: return 403;
    case 5: return 503;
    case 6: return 603;
    case 7: return 703;
    case 8: return 903;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    int value = 3;
    if (argc > 1)
        value = atoi(argv[1]);
    printf("switch_func(%d) = %d\n", value, switch_func(value));
    return 0;
}
