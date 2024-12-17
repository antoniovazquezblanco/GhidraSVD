# Ghidra SVD

[![Build](https://github.com/antoniovazquezblanco/GhidraSVD/actions/workflows/main.yml/badge.svg)](https://github.com/antoniovazquezblanco/GhidraSVD/actions/workflows/main.yml)

<p align="center">
  <img width="400" src="doc/logo.png" alt="A red dragon tinkers with an IoT device">
</p>

Import CMSIS SVD information onto your Ghidra memory map. This is usefull when reversing firmware from devices that publish SVD files. This is a re-write of another [Ghidra SVD Loader](https://github.com/leveldown-security/SVD-Loader-Ghidra) plugin.

This is the preferred way to generate memory maps, but if no SVD files are available for your device you may want to try the [Ghidra DeviceTreeBlob plugin](https://github.com/antoniovazquezblanco/GhidraDeviceTreeBlob).

## Installing

Go to the [releases page](https://github.com/antoniovazquezblanco/GhidraSVD/releases) and download the latest version for your Ghidra distribution.

In Ghidra main window go to `File` > `Install extensions...`. In the new window press the `+` icon to import the downloaded zip.


## Usage

In a CodeBrowser window press `File` > `Import SVD...`.

A file dialog will allow you to select your SVD file and import it. Memory map will automatically be updated.

You may find SVD file sources in the following table:

| Manufacturer  | URL                                                                   | Notes                     |
|:--------------|:----------------------------------------------------------------------|:--------------------------|
| Espressif     | https://github.com/espressif/svd                                      |                           |
| ST            | https://github.com/modm-io/cmsis-svd-stm32                            |                           |
| ST            | https://github.com/morbos/STM32                                       |                           |
| NXP           | https://github.com/Masmiseim36/nxpSDK/tree/master/devices             | May have XML extension    |
| NXP           | https://mcuxpresso.nxp.com/en/welcome                                 | May have XML extension    |
| Various/ARM   | https://www.keil.arm.com/devices/                                     |                           |
| Various/ARM   | https://github.com/ARM-software/CMSIS_4/tree/master/Device/ARM/SVD    |                           |
| Various/ARM   | https://github.com/ARM-software/CMSIS_5/tree/develop/Device/ARM/SVD   |                           |
| Various/ARM   | https://github.com/ARM-software/Cortex_DFP/tree/main/SVD              |                           |

## Development

For development instructions checkout [doc/Develop.md](doc/Develop.md).
