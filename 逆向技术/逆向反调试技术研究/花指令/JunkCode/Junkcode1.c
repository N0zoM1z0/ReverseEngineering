#include<stdio.h>
#include<Windows.h>
void junkcode() {
    int r3 = 0;
    LoadLibraryA(NULL);
    __asm {
        cmp eax, 0;
        jne lebel2;
        je label;
    label:
        call label3;
    label3:
        add dword ptr ss : [esp] , 8;
        ret;
        _emit 0xE8;
    };

    
lebel2:
    __asm __emit 0xFF;
}
signed main() {
    fseek(2, 3, 2);
    __asm {
        _emit 75h;
        _emit 3;
        _emit 74h;
        _emit 2;
        _emit 0xFF
    };
    junkcode();
	return 0;
}