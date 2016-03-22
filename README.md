# anyKextLoader
anyKextLoader is a program that can be used to bypass SIP on OS X 10.11 - 10.11.3. This was patched in OS X 10.11.4.
A demonstration of an older version can be seen [here](https://youtu.be/dq0-0WVGyq4).
If used with [this Kext](https://github.com/LinusHenze/Unrootless-KEXT), you can disable SIP in Kernel without rebooting.

# Usage
Just use it like kextutil.

# How does it work?
On OS X < 10.11.4 task ports aren't deleted after using posix_spawn (except for binaries that have the suid bit set). This can be abused to get the taskport of a process that has private entitlements (like kextutil) and patch it. (e.g. remove code signing checks to load an unsigned kext).

# License
All files except libinject.m and libinject.h are released under the MIT-License (see License.txt).
libinject.h and libinject.m were taken from [https://github.com/kpwn/inj](https://github.com/kpwn/inj).
