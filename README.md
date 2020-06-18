# RTO-Implant 

This is an overview of my RTO-Implant from the [Malware Development Essentials Course](https://institute.sektor7.net/red-team-operator-malware-development-essentials?coupon=MALDEV-45FCB2WESI4) by [@Sektor7Net](https://twitter.com/Sektor7Net) 

## Intro 

My background is primarily in malware research and reverse engineering. This course was on sale during quarantine, so I thought it would be a good time to further my understanding of Windows internals and offensive techniques programmatically. The development of my implant was an iterative process; I was constantly making small tweaks and improvements along the way until I arrived at a stopping point that I was happy with. There are plenty of things to improve upon as well as expand the functionality of my loader / implant. If you have any thoughts or tips, I'd be more than happy to hear them! 

## RTO-Implant.cpp: 

This is the entry point for my loader, which I view as the table of contents for the rest of the project. The majority of strings in the binary are [z85](https://github.com/artemkin/z85) encoded, including our target process notepad.exe. The strings are decoded prior to being used by the binary. This idea came from a discussion about malicious delivery mechanisms used by the Lazarus Group. 

![Alt text](Screenshots/RTO-Implant.PNG?raw=true "RTO-Implant.cpp") 

## Resolve.cpp: 

This file is responsible for [dynamically resolving API's](https://blog.christophetd.fr/hiding-windows-api-imports-with-a-customer-loader/). I wanted to implement this anti-analysis technique to see what it would look like when the binary was loaded into a disassembler for static analysis. Many payloads I've reversed dynamically resolve API's including Dridex, Emotet, Qadars and many more. These payloads commonly use API hashing mechanisms to load imports and call API's during runtime. In my binary, the names of the API calls are z85 decoded before being dynamically resolved; however, not every API used in the binary is obfuscated. This is an area for potential improvement in the future. Additionally, a binary with no imports is suspicious and a binary with imports commonly used for malicious purposes will likely be under close watch. Attempting to populate the IAT with common / benign API's and dynamically resolve the ones used to achieve our goal seems to be a worthwhile balancing act.  
![Alt text](Screenshots/InitResolve.PNG?raw=true "Init GetProcAddress and GetModuleHandle") 

[GetProcAddress](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress) and [GetModuleHandle](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea) were resolved first to make loading the rest of the API's easier. All other API's were resolved by passing the module and API name to the ResolveAPI function below.  

![Alt text](Screenshots/ResolveAPI.PNG?raw=true "RTO Resolve API") 

## FindProcess.cpp: 

I believe that [CreateToolhelp32Snapshot](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot) and [Process32First](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first) / [Process32Next](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next) is the most common method of programatically identifying running processes on a system. I chose to use [NtQuerySystemInformation](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation) because of the opportunity to review [Windows internals structures](https://github.com/processhacker/phnt/blob/33cfd75a2be59bbde3aa4db3399a9e6bab66ae6a/ntexapi.h). The [SYSTEM_PROCESS_INFOMATION](http://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/process.htm) struct contains an ImageName member of type [UNICODE_STRING](https://docs.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_unicode_string). This is useful for identifying our target process.  

![Alt text](Screenshots/FindProcess.PNG?raw=true "FindProcess.h") 

## CreateMapInject.cpp: 

After acquiring the process ID (pid) of our target process, we can then attempt to achieve code execution in the context of the target. I wanted to stay away from [VirtualAllocEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) and [WriteProcessMemory](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) to avoid calling classic sequences of API's related to process injection. Thinking about how I should gain code execution in the context of the target process, a [technique](https://www.forrest-orr.net/post/malicious-memory-artifacts-part-i-dll-hollowing) I read about last year came to mind. Thankfully, [ired.team](https://ired.team/offensive-security/code-injection-process-injection/ntcreatesection-+-ntmapviewofsection-code-injection) did most of the leg work here.  

Opening IDA to view the strings present in the binary, we can see the strings used in our MessageBox shellcode, "RTO: MalDev" and "Hi from Red Team Operator!". Following where these strings are referenced in IDA leads us to our shellcode buffer. We can then identify which subroutine uses that buffer and begin analysis there. Obfuscating the shellcode buffer is another area for improvement. However, when looking at the "calls from" of this subroutine, we note there are only calls to "decode_string". This means the dynamic API resolution is working as expected.   

![Alt text](Screenshots/RTO_Strings.PNG?raw=true "Strings present within the binary") 
![Alt text](Screenshots/SC_IDB.PNG?raw=true "Shellcode buffer in IDA") 
![Alt text](Screenshots/CreateMapInjectCallTree.PNG?raw=true "CreateMapInject call tree") 

## Conclusions 

For a first iteration, I am happy with how my RTO implant turned out. The implant obtains code execution in the context of another process while implementing various obfuscation techniques. If notepad.exe is running on the system when the payload is executed, we will discover a newly created section mapped in memory with the RTO shellcode present. 

![Alt text](Screenshots/Injected_SC.PNG?raw=true "Notepad memory sections") 
![Alt text](Screenshots/SC_Memory.PNG?raw=true "Shellcode in notepad memory") 
![Alt text](Screenshots/Hi_from_RTO.PNG?raw=true "RTO MessageBox") 

Swapping out the MessageBox payload for a custom payload that implements a second stage is another future improvement. Thanks for reading :) 
