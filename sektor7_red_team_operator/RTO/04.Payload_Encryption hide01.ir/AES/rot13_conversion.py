# text1 = "JevgrCebprffZrzbel"
# text1 = "WriteProcessMemory"

text1 = "CryptAcquireContextW"

result = []

for i,c_char in  enumerate(text1):
    current_char = ord(c_char)
    if((current_char >= 97 and current_char <= 122) or (current_char >= 65 and current_char <= 90)):
          if(current_char > 109 or (current_char > 77 and current_char < 91)):
            #Characters that wrap around to the start of the alphabet
            print(text1[i])
            # result += chr(ord(text1[i])-13)
            result.append(chr(ord(text1[i])-13))
          else:
            #Characters that can be safely incremented
            print(text1[i])
            result.append(chr(ord(text1[i])+13))
            # result += chr(ord(text1[i])+13)
            
print(result)      

# print(",".join(result))