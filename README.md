# distributed-information-collection-system
## The implemented system contains servers that permanently operate based on the mechanism of "I/O completion ports" and clients that send the necessary requests to them. 
Servers, in turn, operate on the principle of stateless, in which information about requests is not stored on them. 
The choice of such a principle is justified by the variability of the requested data during operation, it allows you to send information relevant to the system.

### Server
The program implemented for servers using WSA (Windows Sockets API) for communication with the client and CryptoAPI, for connection security.
The work is carried out as follows: first, with the help of the conn command, the connection takes place and the remaining interaction commands based on the functions presented below.
##### *Function Description*
- ```void GetOsVersion()``` - Getting the OS version and type. It is based on a variety of conditions-checks for a particular supported version of Windows.
- ```void GetTimeElapsedSinceOsStartup()``` - The time elapsed since the system was started.
- ```void GetCurrTime()``` - Getting the current time and date of the system.
- ```void GetMemoryStatus()``` - Information about the memory associated with the system.
- ```void GetDisksInfo()``` - Getting information about disks connected to the system.
- ```void GetAccessRights()``` - Definition of access rights.
- ```void getOwner()``` - Definition of the file owner.

During operation, diagnostic information is displayed in the server console about which connections are available and which requests are being requested.
### Client
The program implemented for clients using WSA and CryptoAPI, similar to the server.

![image](https://github.com/nekitalek/distributed-information-collection-system/assets/59126116/c8ae03a2-561b-42b5-b2b9-8e2abb9b1c2b)

*Commands avaliable for client*

Initially, a connection to the server must be made from the client side, then messages can be exchanged, they are all transmitted in encrypted form, which is provided using CryptoAPI. 
Initially, at the beginning of the interaction, a pair of keys (public and private) is generated. 
One of them (public) goes to the server, which in turn generates a third key (session) sent to the client, which is decrypted by the second (private) generated initially. 
In the future, the third one (session) is used for encryption.
It is important to mention that there is a separate request with a unique number for transmitting information of each type, they are stored in the source codes.
The request response format has a structure similar to ".json" format files. This allows you to get information in a convenient way, suitable for machine processing, as well as comfortable for most users.
