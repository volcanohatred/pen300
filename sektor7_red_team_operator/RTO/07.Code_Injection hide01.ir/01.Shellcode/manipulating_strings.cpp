char unsigned cipher_wProcessMemory[] = {'W', 'r' , 'i' , 't' , 'e' , 'P' , 'r' , 'o', 'c', 'e', 's', 's', 'M', 'e', 'm', 'o', 'r', 'y' };

int main(){
    printf("\nHello World\n");

    printf("\nsize of string is %d \n", sizeof(cipher_wProcessMemory));

    char * result = malloc(strlen(cipher_wProcessMemory));

    char current_char;
    for (int i =0 ; i< sizeof(cipher_wProcessMemory); ++i){
        //cipher_wProcessMemory[i] = cipher_wProcessMemory[i] + 1;

        printf("\nfor %d : %c\n", i, (char *)cipher_wProcessMemory[i]);
        current_char = cipher_wProcessMemory[i];
        printf("\n Current char : %c : %c \n", current_char, cipher_wProcessMemory[i]);
        if((current_char >= 97 && current_char <= 122) || (current_char >= 65 && current_char <= 90)){
          if(current_char > 109 || (current_char > 77 && current_char < 91)){
            //Characters that wrap around to the start of the alphabet
            cipher_wProcessMemory[i] -= 13;
            printf(": decrement :");
          }else{
            //Characters that can be safely incremented
            cipher_wProcessMemory[i] += 13;
            printf(": increment :");
          }

        printf(": result :");
        //result[i] = cipher_wProcessMemory[i];
        
        }
    }

    printf("\ncipher_wProcessMemory : %s\n", (char *)cipher_wProcessMemory);
    printf("\ncipher_wProcessMemory : %s\n", (char *)result);
    return 0;
}
