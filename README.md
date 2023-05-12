# Ghidra GameCube Loader
A  Nintendo GameCube binary loader for [Ghidra](https://github.com/NationalSecurityAgency/ghidra).

Includes optional symbol map importing, automatic namespace creation, and demangling support.

## Supported Formats
* DOL Executables (.dol)
* Relocatable Modules (.rel)
* Apploaders
* RAM Dumps

## Building
- Ensure you have ``JAVA_HOME`` set to the path of your JDK 17 installation.
- Set ``GHIDRA_INSTALL_DIR`` to your Ghidra install directory. This can be done in one of the following ways:
    - **Windows**: Running ``set GHIDRA_INSTALL_DIR=<Absolute path to Ghidra without quotations>``
    - **macos/Linux**: Running ``export GHIDRA_INSTALL_DIR=<Absolute path to Ghidra>``
    - Using ``-PGHIDRA_INSTALL_DIR=<Absolute path to Ghidra>`` when running ``./gradlew``
    - Adding ``GHIDRA_INSTALL_DIR`` to your Windows environment variables.
- Run ``./gradlew``
- You'll find the output zip file inside `/dist`

## Installation
- Copy the zip file to ``<Ghidra install directory>/Extensions/Ghidra``.
- Start Ghidra and use the "Install Extensions" dialog to finish the installation. (``File -> Install Extensions...``).
