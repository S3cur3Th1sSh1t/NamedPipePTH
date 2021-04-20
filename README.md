# NamedPipePTH

This project is a PoC code to use Pass-the-Hash for authentication on a local Named Pipe user Impersonation. There also is a blog post for explanation:

[https://s3cur3th1ssh1t.github.io/Named-Pipe-PTH/](https://s3cur3th1ssh1t.github.io/Named-Pipe-PTH/)

It is heavily based on the code from the projects [Invoke-SMBExec.ps1](https://github.com/Kevin-Robertson/Invoke-TheHash/blob/master/Invoke-SMBExec.ps1) and [RoguePotato](https://github.com/antonioCoco/RoguePotato).

I faced certain Offensive Security project situations in the past, where I already had the NTLM-Hash of a `low privileged` user account and needed a shell for that user on the current compromised system - but that was not possible with the current public tools. Imagine two more facts for a situation like that - the NTLM Hash could not be cracked *and* there is no process of the victim user to execute shellcode in it or to migrate into that process. This may sound like an absurd edge-case for some of you. I still experienced that multiple times. Not only in one engagement I spend a lot of time searching for the right tool/technique in that specific situation.

My personal goals for a tool/technique were:

* Fully featured shell or C2-connection as the victim user-account
* It must to able to also Impersonate `low privileged` accounts - depending on engagement goals it might be needed to access a system with a specific user such as the CEO, HR-accounts, SAP-administrators or others
* The tool can be used as C2-module

There are two ways to use this technique. Either you can compile `\Resources\PipeServerImpersonate.sln` and drop the executable on the remote host and connect to the Named Pipe via `\Resources\Invoke-NamedPipePTH.ps1`:

![alt text](https://github.com/S3cur3Th1sSh1t/NamedPipePTH/blob/main/Resources/Example1.JPG?raw=true)

Or you can use the standalone script to stay in memory:

![alt text](https://github.com/S3cur3Th1sSh1t/NamedPipePTH/blob/main/Resources/Example2.JPG?raw=true)
