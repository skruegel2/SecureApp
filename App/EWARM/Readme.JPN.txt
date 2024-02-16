Secure Boot Manager Project
===========================

IMPORTANT
---------
Before you start configuring a Secure Boot Manager project, make sure that you
read the information regarding project configuration details and constraints,
applicable to your device. Some device-specific project configuration might be
required to achieve a functioning Secure Boot Manager project.

Device-specific information can be found in the release notes, available
from the Help menu:

- Choose Help > Embedded Trust Release Notes
- Browse to the device support information and look for details about your
  device.

Setting up the project
----------------------
To populate the project tree with the files needed to build
the Secure Boot Manager you need to:

1. Select a supported device in:
   Project > Options > General Options > Target

2. Set up a security context profile in:
   Project > Options > Security

This will generate a Project Connection file (sbm.ipcf) which
in turn will import all necessary files into your project.

The SBM project will require to be configured for use with the desired
hardware debugger driver.

The SBM can print out information that is very valuable when configuring and
troubleshooting your secure environment. To enable logging in your SBM project
choose Project > Options > Security > Edit to edit your Security Context.
When you select SBM Configuration > Logging in the list on the left you get a
list of logs you can enable on the right. Note that logging may not be
appropriate when using a device with a small amount of flash memory.
