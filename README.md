meow
=====

meow is an on-the-fly PatchGuard disabler for Windows 8.1 and RT which does not
depends on magic values specific to build versions.

A related blog entry can be found here:

    http://standa-note.blogspot.ca/2015/10/some-tips-to-analyze-patchguard.html


If you are targeting Windows 7 or older, you can use
[DisPG](https://github.com/tandasat/PgResarch) instead.


Important
----------

This program will not going to work as expected forever since PatchGuard is a
moving target and may not be perfect even now.


Installation and Uninstallation
--------------------------------

Get an archive file for compiled files form this link:

    https://github.com/tandasat/meow/releases/latest

On the x64 platform, you have to enable test signing to install the driver. To
do that, open the command prompt with the administrator privilege and type the
following command, and then restart the system to activate the change:

    bcdedit /set {current} testsigning on

On the ARM platform (ig, Windows RT), you may have to exploit CVE-2015-2552
(ms15-111) in order to enable test signing since the above command is not
allowed. For more details on the vulnerability, see the Bugtraq report
[Windows 8+ - Trusted Boot Security Feature Bypass Vulnerability]
(http://seclists.org/bugtraq/2015/Oct/70)

To install the driver, extract the archive file and make sure that internet
connection is available since this program needs to download symbol files unless
your system already has right symbol files.

Then, run install.bat with the administrator privilege. It installs and starts
the driver, launches PowerShell for displaying log and a support program
meow_client.exe to install hooks and deactivate PatchGuard.
![Typical output on RT](/img/RT.png)

It is advised to keep meow.sys running to make sure that PatchGuard is
completely disabled otherwise PatchGuard may detect your modification if you
uninstall meow before all of PatchGuard contexts are detected and dropped. If
you are not going to install your own patches, it is fine to stop and uninstall
meow because meow does not leave any changes in the kernel if it is unloaded.

To stop and uninstall the driver, execute uninstall.bat with the administrator
privilege.


Usage
------

Once you started and disabled PatchGuard, you are free to install your own tools
using hooks. [RemoteWriteMonitor](https://github.com/tandasat/RemoteWriteMonitor)
is an example of this type of tools.


Build
------

To download full source code, clone it with --recursive:

    git clone --recursive https://github.com/tandasat/meow.git

At the first time of build with Visual Studio, you will be prompted for a
password of the certificate. The password is 'password' (without quotes).


Supported Platform(s)
----------------------
- Windows 8.1 (x64/ARM)


License
--------
This software is released under the MIT License, see LICENSE.
