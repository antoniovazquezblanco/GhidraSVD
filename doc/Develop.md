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
2. In the dialog click on `Ghidra` > `Ghidra Module Source` > `Next`.
3. Select the recently `GhidraSVD` and click on `Finish`.

You are now ready to develop!