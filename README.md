# Ghidra SVD

[![Build](https://github.com/antoniovazquezblanco/GhidraSVD/actions/workflows/main.yml/badge.svg)](https://github.com/antoniovazquezblanco/GhidraSVD/actions/workflows/main.yml)

Import CMSIS SVD information onto your Ghidra memory map. This is usefull when reversing firmware from devices that publish SVD files. This is a re-write of another [Ghidra SVD Loader](https://github.com/leveldown-security/SVD-Loader-Ghidra) plugin.

This is the preferred way to generate memory maps, but if no SVD files are available for your device you may want to try the [Ghidra DeviceTreeBlob plugin](https://github.com/antoniovazquezblanco/GhidraDeviceTreeBlob).

## Installing

Go to the [releases page](https://github.com/antoniovazquezblanco/GhidraSVD/releases) and download the latest version for your Ghidra distribution.

In Ghidra main window go to `File` > `Install extensions...`. In the new window press the `+` icon to import the downloaded zip.


## Usage

In a CodeBrowser window press `File` > `Import SVD...`.

A file dialog will allow you to select your SVD file and import it. Memory map will automatically be updated.


## Development

### Development environment

1. First, install [Eclipse for Java Developers](https://www.eclipse.org/downloads/packages/).
2. Once installed, open Eclipse and click on `Help` > `Install New Software...`. A window will pop up.
3. Click on `Add...` > `Archive...`. It will open a file selection dialog. In this dialog, please select `GhidraDev.zip` file from `<Your Ghidra install dir>/Extensions/Eclipse/GhidraDev/`.
4. Check Ghidra category (or GhidraDev entry).
5. Repeatedly click `Next`.
6. Accept the terms of the license agreement.
7. Check the `Unsigned` table entry and click `Trust Selected`.
8. Restart Eclipse...

### Importing the project

After all of that, if you still want to develop and/or contribute to the project, first clone this repository:
```bash
git clone git@github.com:antoniovazquezblanco/GhidraSVD.git
```

In Eclipse:
1. Click on `File` > `Import...`.
2. In the dialog click on `General` > `Projects from Folder or Archive` > `Next`.
3. Click on `Directory...` and select the `GhidraSVD` folder you have just cloned.
4. Click on `Finish`.
5. Right click on the just imported project `GhidraDev` > `Link Ghidra...`.
6. Select your desired Ghidra installation and click on `Finish`.

You are now ready to develop!
