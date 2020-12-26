[IUP](http://webserver2.tecgraf.puc-rio.br/iup/) is a multi-platform toolkit for building graphical user interfaces.<BR>
The download site for pre-compiled binaries, documentation and sources is [SourceForge](http://sourceforge.net/projects/iup/files/).<BR>
Before downloading any precompiled binaries, you should read [the Tecgraf Library Download Tips](http://webserver2.tecgraf.puc-rio.br/iup/en/download_tips.html).

#### Downloading and installation (Linux)

The tested Linux precompiled IUP binaries (v. 3.30) can be downloaded from [this page](https://sourceforge.net/projects/iup/files/3.30/Linux%20Libraries/). Download and untar the package you need. Here is a list of the tested packages:
* iup-3.30_Linux44_64_lib.tar.gz: Ubuntu 16.04 Xenial (x64)
* iup-3.30_Linux415_64_lib.tar.gz: Ubuntu 18.04 Bionic (x64)
* iup-3.30_Linux54_64_lib.tar.gz: Ubuntu 20.04 Focal Fossa (x64)

To install the `run time` libraries in the system from the unpacked download:
```
$ sudo ./install
```
To install the `development` files in the system from the unpacked download:
```
$ sudo ./install_dev
```
Bsniffhubgui build process needs both the `run time` libraries and the `development` files in the system.

#### Downloading and installation (Windows)

The tested Windows precompiled IUP binaries (v. 3.30) can be downloaded from [this page](https://sourceforge.net/projects/iup/files/3.30/Linux%20Libraries/). Download and unzip the package you need. Here is a list of the tested packages:
* iup-3.30_Win64_vc15_lib.zip: MSVC 15 (2017) (x64)
* iup-3.30_Win64_vc16_lib.zip: MSVC 16 (2019) (x64)
* iup-3.30_Win32_vc15_lib.zip: MSVC 15 (2017) (x86)
* iup-3.30_Win32_vc16_lib.zip: MSVC 16 (2019) (x86)

To install the static libraries and the header files in the project file struct copy the following files from the unpacked download:
* All files from the `include` folder of the unpacked download to the `\lib\iup\include` folder of the project.
* `iup.lib` and `iupimglib.lib` libraries from the unpacked download to the appropriate `\lib\iup\lib\WinAA_vcBB` folder of the project, where AA = 64 or 32 (MSVC platform), and BB = 15 or 16 etc. (MSVC version)
