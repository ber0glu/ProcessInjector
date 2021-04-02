# ProcessInjector
C/C++ Windows Process Injector for Educational Purposes.

## What does this software do?
This is a simple process injector that uses the CreateRemoteThread method. Payload is obfuscated using Base64 encoding and single-byte XOR encryption for evasion. It downloads a payload from a remote address. You can use msfvenom payloads or other shellcodes.

payload_encoder will create payload with msfvenom; you can change the XOR key for both payload encoder and injector.

## Usage
Create your payload with payload_encoder or manually. Upload it to a web server.

In target machine execute it as following,

ProcessInjector.exe <target_process_name>

Example,

ProcessInjector.exe explorer.exe

## Responsibility Information

Please use this program for legal and educational purposes. I am not responsible for any illegal activity.
