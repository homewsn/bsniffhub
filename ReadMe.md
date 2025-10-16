[![Release Status](https://img.shields.io/github/release/homewsn/bsniffhub.svg)](https://github.com/homewsn/bsniffhub/releases)
[![Github CI Build Status](https://github.com/homewsn/bsniffhub/actions/workflows/main.yml/badge.svg)](https://github.com/homewsn/bsniffhub/actions?workflow%3Atest)
[![Appveyor Build Status](https://ci.appveyor.com/api/projects/status/github/homewsn/bsniffhub?branch=master&svg=true)](https://ci.appveyor.com/project/homewsn/bsniffhub)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/22350/badge.svg?flat=1)](https://scan.coverity.com/projects/homewsn-bsniffhub)

### Bsniffhub

Bsniffhub is a utility that interfaces Bluetooth Low Energy (BLE) sniffer with Wireshark to capture, decrypt, and display wireless traffic.<br>
Bsniffhub combines the following features:
* Support for several types of BLE sniffers that use a virtual USB serial port for communication, such as Blesniff, Sniffle, nRF Sniffer, SmartRF Packet Sniffer 2 or STM32WB BLE Sniffer
* Ensuring the launch of Wireshark and feeding packets to it through a local pipe
* Support for several types of BLE link layer headers for PCAP files and Wireshark, such as LINKTYPE_BLUETOOTH_LE_LL, [LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR](https://www.tcpdump.org/linktypes/LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR.html), and [LINKTYPE_NORDIC_BLE](https://www.tcpdump.org/linktypes/LINKTYPE_NORDIC_BLE.html); dissectors for these types are already included in the Wireshark distributions
* The Temporary Key (TK) obtaining, the Short Term Key (STK) calculation and subsequent capture of the Long Term Key (LTK) if the BLE devices use the Legacy Pairing method with the Just Works or Passkey Entry association models
* The LTK calculation when the Secure Connection method is used and at least one of the BLE devices uses a debug key
* Decryption of the traffic, if LTK is already known or can be provided

Bsniffhub can be used both for working with the BLE sniffers and for decrypting the BLE traffic from the PCAP and PCAPNG files.
Bsniffhub has both a console version and a graphical user interface version, and it can be built for use on Linux or Windows.

#### Supported BLE sniffers:
* [Blesniff](https://github.com/homewsn/blesniff)
* [Sniffle](https://github.com/nccgroup/Sniffle) by Sultan Qasim Khan from NCC Group
* [nRF Sniffer for Bluetooth LE v3 or v4](https://www.nordicsemi.com/Products/Development-tools/nrf-sniffer-for-bluetooth-le) by Nordic Semiconductor
* [SmartRF Packet Sniffer 2](https://www.ti.com/tool/download/PACKET-SNIFFER-2) by Texas Instruments
* [STM32WB BLE Sniffer](https://github.com/stm32-hotspot/STM32WB-BLE-Sniffer) by STMicroelectronics

| Supported features | Blesniff | Sniffle | nRF Sniffer v3 | nRF Sniffer v4 | SmartRF Packet Sniffer 2 | STM32WB BLE Sniffer |
| ------ | :------: | :------: | :------: | :------: | :------: | :------: |
| PHY 1 Mbps | + | + | + | + | + | + |
| PHY 2 Mbps | + | + | + | + | - | + |
| PHY Coded S2 | + | + | - | + | - | - |
| PHY Coded S8 | + | + | - | + | - | - |
| CSA#1 | + | + | + | + | + | + |
| CSA#2 | + | + | + | + | - | + |
| Extended advertising | + | + | - | + | - | - |
| Follow AUX_CONNECT_REQ | + | + | - | +<sup>1</sup> | - | - |
| PA/PAwR | + | - | - | - | - | - |
| CIS/CIG | + | - | - | - | - | - |
| BIS/BIG | + | - | - | - | - | - |
| Decryption<sup>2</sup> | + | - | - | + | - | - |
| Hardware | nRF5340 | TI CC1352/CC26x2 | nRF51/nRF52 | nRF51/nRF52 | TI CC1352/CC26x2 | STM32WB55 |
| Serial port baud rate, bps | 1000000<sup>3</sup> | 2000000 (921600) | 1000000 | 1000000 | 3000000 | 921600 |

<sup>1</sup> Only when the device is selected<br>
<sup>2</sup> Only if LTK is known<br>
<sup>3</sup> UART version, USB version supports USB 2.0 full-speed

#### Dependencies
* [libpcap](https://www.tcpdump.org/#latest-releases) (or [Npcap SDK](https://nmap.org/npcap/#download) for Windows)
* [TinyCrypt Cryptographic Library](https://github.com/intel/tinycrypt)
* [IUP Portable User Interface](http://webserver2.tecgraf.puc-rio.br/iup/) for GUI version

#### Building (Linux)
Download [the latest release](https://github.com/homewsn/bsniffhub/releases) in tarball from github and untar it, or clone the bsniffhub repository.
Install a new version of the [pcap library](https://www.tcpdump.org/#latest-releases) if you want to load the pcapng files, and your version of the pcap library does not support them.
You need the appropriate [IUP library](lib/iup/ReadMe.md#downloading-and-installation-linux) to make the GUI version.
The TinyCrypt Cryptographic Library source files are already included in `bsniffhub/lib/tinycrypt`.

To build both console and GUI versions:
```sh
$ make
```
or 
```sh
$ make bsniffhub
$ make bsniffhubgui
```
Make sure you have Wireshark installed.

#### Building (Windows)
Download [the latest release](https://github.com/homewsn/bsniffhub/releases) in zip from github and unzip it, or clone the bsniffhub repository.
You need to download [Npcap SDK](https://nmap.org/npcap/#download) yourself, since its license prohibits distribution, and unzip it in `bsniffhub/msvs/lib/npcap` directory.
You need the appropriate [IUP library](lib/iup/ReadMe.md#downloading-and-installation-windows) to make the GUI version.
The TinyCrypt Cryptographic Library source files are already included in `bsniffhub/lib/tinycrypt`.<br>
Open the MSVC 2017 solution, change the path to the IUP libraries in the bsniffhubgui project properties if it's needed, then build the solution or the single project.<br>
Make sure you have Wireshark and Npcap runtime libraries installed.

#### Usage (Linux)
Console version has the following options:
```
$ ./bsniffhub
One of the options -s or -r is required.

Usage:
  bsniffhub -s <sniffer> -p <serport> [-b <baudrate>] [-c <channel(s)>] [-f <MODE>] [-R <RSSI>] [-m <MAC>] [-e] [-w <outfile>] [-l <link type>] [-n] [-L <LTK>] [-W <path to Wireshark>]
  bsniffhub -r <infile> [-w <outfile>] [-l <link type>] [-n] [-L <LTK>] [-W <path to Wireshark>]

Mandatory arguments for sniffer device input:
  -s <sniffer>       Sniffer device:
                     'B' - Blesniff
                     'N3' - nRF Sniffer v3
                     'N4' - nRF Sniffer v4
                     'S' - Sniffle
                     'T' - SmartRF Packet Sniffer 2
                     'WB' - STM32WB BLE Sniffer
  -p <serport>       Serial port name

Optional argument for sniffer device input:
  -b <baudrate>      Serial port baudrate (def: from sniffer guide)
  -c <channel(s)>    Primary advertising channel(s) to listen on: 37, 38 or 39
                     (def: 37,38,39 for Blesniff and nRF Sniffer, 37 for others)
  -R <RSSI>          Filter sniffer packets by minimum RSSI
  -m <MAC>           Filter sniffer packets by advertiser MAC
  -e                 Sniffle follow connections on secondary advertising channels
  -f <MODE>          Blesniff follow mode:
                     'conn' - connection
                     'pa' - periodic advertising
                     'cis' - connected isochronous stream ('conn' is also required)
                     'bis' - broadcast isochronous stream ('pa' is also required)
                     (def: conn,pa,cis,bis)

Mandatory argument for PCAP file input:
  -r <infile>        PCAP input file name

Optional arguments for output (def: output to Wireshark):
  -w <outfile>       PCAP output file name
  -l <link type>     Output link layer type number:
                     '251' - LINKTYPE_BLUETOOTH_LE_LL
                     '256' - LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR (def)
                     '272' - LINKTYPE_NORDIC_BLE
  -n                 Don't try to decrypt
  -L <LTK>           LTK key for decrypting packets

  -W <path to Wireshark>   Path to Wireshark.exe

Examples:
  bsniffhub -s B -l 272 -R -70 -c 37,38 -f conn,cis -L 6ab0580e966e7b61f4470dfb696b3799
  bsniffhub -s T -p COM5
  bsniffhub -s S -p COM40 -b 1000000 -W D:\Wireshark\Wireshark.exe
  bsniffhub -s N4 -p COM22 -l 251 -n -w C:\PCAP files\test.pcap
  bsniffhub -r input.pcap
  bsniffhub -r C:\PCAP files\input.pcap -l 272 -w C:\PCAP files\output.pcap
```

#### Usage (Windows)
See [Usage (Linux)](#usage-linux)
One additional optional arguments for output is added:
```
  -W <path to Wireshark>   Path to Wireshark.exe
```

#### Examples (Linux)
Run Wireshark, capture packets from `Blesniff` on `/dev/ttyUSB2` port and feed the captured packets with the  `LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR` packet header to `Wireshark`, ignore advertising packets on the primary advertising channels with RSSI less than `-70`, follow only connections `conn` and CIS packets `cis` (ignore periodic advertising and BIS packets), use LTK `6ab0580e966e7b61f4470dfb696b3799` for decryption:
```
$ ./bsniffhub -s B -p /dev/ttyUSB2 -R -70 -f conn,cis -L 6ab0580e966e7b61f4470dfb696b3799
```
Run Wireshark, capture packets from `SmartRF Packet Sniffer 2` on `/dev/ttyUSB2` port and feed the captured packets with the  `LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR` packet header to `Wireshark`:
```
$ ./bsniffhub -s T -p /dev/ttyUSB2
```
Run Wireshark, capture packets from `Sniffle` on `/dev/ttyACM0` port with baud rate `921600 bps` and feed the captured packets with the `LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR` packet header to `Wireshark`:
```
$ ./bsniffhub -s S -p /dev/ttyACM0 -b 921600
```
Capture packets from `nRF Sniffer 4` on `/dev/ttyUSB0` port and save the captured packets with the `LINKTYPE_BLUETOOTH_LE_LL` packet header to `test.pcap` file, don't try to decode:
```
$ ./bsniffhub -s N4 -p /dev/ttyUSB0 -l 251 -n -w test.pcap
```
Run Wireshark, open `input.pcap` file and feed the packets with the `LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR` packet header to `Wireshark`:
```
$ ./bsniffhub -r input.pcap
```
Open `input/input.pcap` file and save the packets with the `LINKTYPE_NORDIC_BLE` packet header to `output/output.pcap` file:
```
$ ./bsniffhub -r input/input.pcap -l 272 -w output/output.pcap
```
#### Examples (Windows)
See [Examples (Linux)](#examples-linux), but you can use the additional optional argument `-W` if Wireshark was installed in a path other than `C:\Program Files\Wireshark\Wireshark.exe`:
```
> bsniffhub -s S -p COM40 -W D:\\Wireshark\\Wireshark.exe
```

#### Obtaining LTK if BLE devices use Legacy Pairing
Bsniffhub can provide TK, STK and LTK if the `-n` option is not used and the BLE devices use the Legacy Pairing method with the Just Works or Passkey Entry association models. For demonstration, you can use the appropriate pcap files in the example directory.

The Legacy Pairing method with the Just Works association model:
```
$ ./bsniffhub -rexamples/lp-justworks.pcap -wout.pcap
examples/lp-justworks.pcap is loading ...
Creating the out.pcap file ...
File loading completed.
Connection created.
Channel selection algorithm #2 detected.
Connection established.
BLE Legacy pairing method detected.
Just Works association model used.
STK found: abfe42fb9efa80c5f0a0b92fd564ecad
Encryption start detected. STK used.
LTK found: 4cc7cbe225e6244cf5fae1b95021f080
Connection terminated.
File processing completed.
```
The Legacy Pairing method with the Passkey Entry association model:
```
$ ./bsniffhub -rexamples/lp-passkeyentry-393699-initiator-displays-responder-inputs.pcap -wout.pcap
examples/lp-passkeyentry-393699-initiator-displays-responder-inputs.pcap is loading ...
Creating the out.pcap file ...
File loading completed.
Connection created.
Channel selection algorithm #2 detected.
Connection established.
BLE Legacy pairing method detected.
Passkey Entry association model used.
Do you have the Passkey? No                            
Please wait. Brute force method will be used to find the Passkey.
The entered Passkey found: 393699
STK found: 6f4617cf841d5fdc4a4faac6bf4c521f
Encryption start detected. STK used.
LTK found: fd821e6a920e0339bbc9a27f4385a23d
Connection terminated.
File processing completed.
```
#### Obtaining LTK if BLE devices use Secure Connection with a debug key
Bsniffhub can provide LTK if the `-n` option is not used and the BLE devices use the Seciure Connection method and at least one of the  devices uses a debug key. For demonstration, you can use the appropriate pcap files in the example directory.

The Secure Connection method with the Just Works association model:
```
$ ./bsniffhub -rexamples/sc-justworks.pcap -wout.pcap
examples/sc-justworks.pcap is loading ...
Creating the out.pcap file ...
File loading completed.
Connection created.
Channel selection algorithm #2 detected.
Connection established.
BLE Secure Connection method detected.
Just Works association model used.
BLE Secure Connection Debug mode of the slave device detected.
LTK found: 7df27955f679736a7a286b0566f88ad8
Encryption start detected. LTK used.
Connection terminated.
File processing completed.
```
The Secure Connection method with the Numeric Comparison association model:
```
$ ./bsniffhub -rexamples/sc-numericcomparison-380717.pcap -wout.pcap
examples/sc-numericcomparison-380717.pcap is loading ...
Creating the out.pcap file ...
File loading completed.
Connection created.
Channel selection algorithm #2 detected.
Connection established.
BLE Secure Connection method detected.
Numeric Comparison association model used.
BLE Secure Connection Debug mode of the slave device detected.
LTK found: 1047e6f9fbf05a2bfb850e0f45b00f92
The numeric compare value found: 380717
Encryption start detected. LTK used.
Connection terminated.
File processing completed.
```
#### Decryption if LTK can be provided
By entering the key when prompted:
```
$ ./bsniffhub -rexamples/ltk-063F1154BC631D186D48A05B7F5DCD8F.pcap -wout.pcap
examples/ltk-063F1154BC631D186D48A05B7F5DCD8F.pcap is loading ...
Creating the out.pcap file ...
File loading completed.
Connection created.
Channel selection algorithm #2 detected.
Connection established.
Encryption request detected, but LTK unknown.
Do you have the Long Term Key (LTK)? Yes                            
Please enter the LTK: 063F1154BC631D186D48A05B7F5DCD8F                                             
Encryption start detected. LTK used.
Connection terminated.
File processing completed.
```
Using -L option on the command line:
```
$ ./bsniffhub -rexamples/ltk-063F1154BC631D186D48A05B7F5DCD8F.pcap -L063F1154BC631D186D48A05B7F5DCD8F -wout.pcap
examples/ltk-063F1154BC631D186D48A05B7F5DCD8F.pcap is loading ...
Creating the out.pcap file ...
File loading completed.
Connection created.
Channel selection algorithm #2 detected.
Connection established.
Encryption start detected. LTK used.
Connection terminated.
File processing completed.
```