char unsigned cipher_wProcessMemory = "WriteProcessMemory";

void main(){
    for (int i =0 ; i< sizeof cipher_wProcessMemory; ++i){
        //cipher_wProcessMemory[i] = cipher_wProcessMemory[i] + 1;
        printf("%s", (char *)cipher_wProcessMemory[i]);
    }

    printf("cipher_wProcessMemory");

}
