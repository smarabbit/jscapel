#Usage
##Setup DECAF.

1.configure DECAF. 
```
cd ./decaf/
./configure --disable-vmi
make
```
2.Setup Guest OS.(Suppose the guest OS is Windows XP)
	For Windows XP, we provide a guest driver in order to support DECAF VMI.And also Jscapel need the support of Script debugging interface.So some additional libraries need to be installed.

  * Install driver for guest OS .
  ```
	cd to /shared/guest_driver/winxp/ and install the driver.
  ```

  * install the program /artifact/missing/scd10en.exe and scripting.exe.
  
  * move all the dll in /artifact/missing/ to C:/Winodws/system/system32/

  * Install BHO plugin for IE6 or IE7 or IE8. (We haven’t tested the plugins on the other version of IE)

   The BHO plugin code is stored at /artifact/browserstub/extension/ie/. Open this project using Microsoft Visual Studio and compile it.  Then install this BHO plugin for IE.

  * Compile stub.c to stub.dll and move it into c:/.

	The source code is located at /artifact/browserstub/dll


3. load the DECAF plugin browserstub to get the JavaScript trace and binary trace.

  * compile the decaf plugin
 ```
cd to /artifact/browserstub/ 
./configure --decaf-path=DECAF_LOCATION
make
```
  * start the DECAF and booting the Windows XP.
  ```
	./artifact/decaf/i386-softmmu/qemu-system-i386 -monitor stdio -m 512 -netdev user,id=mynet -device rtl8139,netdev=mynet <<img file>>
  ```

  * load the plugin
  ```
	load_plugin /artifact/browserstub/browserstub.dll
  ```
  
  * tracebyname IEXPLORE.EXE 
  * start the IE process and open the malicious page.
    Wait until the malicious page successfully exploited the IE. 

  * In the DECAF terminal, CFI violation point is printed out. From the violation point, we know the payload location it jump to and the EIP it manipulate. And for ROP attack, the CFI violation will also get the ROP chain gadgets.

  * unload the plugin.(unload_plugin) 

Under the folder /artifact/decaf/i386-softmmu/, you will find the logs. 
XXX.mem.bin is the binary trace for the javascript statement XXX. 
trace_log.txt stores the javascript execution trace. Every javascritpt statement is labeled as XXX.

4.Python slicing script

From the attack point discovered in step 3, this script can do the backward slicing to discover the the binary level dependency and then map back to the javascript level depedency. 
Since the attack eip is corrupted by exploiting the vulnerability, the slice from attack eip represents the code of triggering the vulnerability.  The slice starting from the shellcode location represents the code that injection the shellcode(HeapSpray). 
