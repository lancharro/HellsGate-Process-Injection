## Hell's Gate ##

Shellcode execution by using Direct System Calls, based on the C Implementation of the Hell's Gate VX Technique performed by Paul Laîné (@am0nsec) and smelly__vx (@RtlMateusz)
<br />
<br />
Link to the paper: https://vxug.fakedoma.in/papers/VXUG/Exclusive/HellsGate.pdf


Shellcode can be executed by using the following techniques:
- Create new thread
- Process injection to a defined PID
- Process injection to the first process with a defined name

The code also includes hooking detection and simple unhooking capabilities by restoring the expected systemcall ID to bypass AV or EDR.
