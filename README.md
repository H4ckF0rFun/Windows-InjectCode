## Inject Shellcode or dll to target process by SetThreadContext on windows

## Support inject method
- 64-bit process injects 64-bit process
- 32-bit process injects 32-bit process
- 32-bit process injects 64-bit process

## Dependencies
- [loaddll_shellcode(the shellcode to load a specific dll)](https://github.com/H4ckF0rFun/LoadDll-Shellcode)
- [Exe2Shellcode(a stub to load exe)](https://github.com/H4ckF0rFun/Exe2Shellcode)

## How to use?
- 64-bit process inject dll to 64-bit explorer.exe
![image](https://github.com/user-attachments/assets/a9926032-e26d-4137-a839-f6dedb20e7a8)

- 32-bit process inject dll to 64-bit explorer.exe
![image](https://github.com/user-attachments/assets/4e453722-a52f-4421-b4ea-7e7b489407bc)

- 32-bit process inject shellcode(stub + exe) to 64-bit explorer.exe
![image](https://github.com/user-attachments/assets/f900dda6-7e31-4db5-8741-654c25e1a3af)


## Demo video
### inject dll to explorer.exe
https://github.com/user-attachments/assets/42bcb2c1-9382-402f-b202-4ef772acd1e1

### inject shellcode to explorer.exe
https://github.com/user-attachments/assets/67b880e6-a11b-4765-98cf-650c5d427217


