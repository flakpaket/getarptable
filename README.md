# Get ARP Table
I wrote this tool while assisting a network team with a NAC implementation.  

It uses snmpbulkwalk to pull the ARP table from routers, and then looks up the device manufacturer based on MAC OUI. The goal was to help them get an inventory of existing devices since they weren't sure which ones were "approved" and which ones weren't.  

The list of MACs and manufactures could be compaired to the various inventory applications to help determine the "unapproved" devices.

## To Do
There are a few issues that should be addressed.  Most of them have to do with learning Python as I wrote the tool, and genreally having no clue what I was doing.  (My Python isn't much better now, but I can definitely see that I've learned a bit more.)

This is all based on my memory, so you should probably take these ramblings with a grain of salt and read the code yourself if you plan to use it.
### General
- [ ] Change the ouiQuery() function to download the Wireshark OUI MAC Database instead of using the current third party site.  (https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=manuf)
- [ ] It needs refactored.  At a minimum, the walk() and extract() functions should be in main().  bulkwalk() probably doesn't need to be it's own function.
- [ ] After #1 is done, the global variables wouldn't be necessary. 
- [ ] Change the in-file to YAML.
- [ ] Add a positional argument to accept a single IP addresses.
- [ ] Create a results db instead of a CSV and track "first seen" and "last seen" on a device.  It would also allow the ability to track devices as the move around the network. 
### Offensive Ideas/Features
* I'll convert this list to tasks if I ever actually get around to the items in General.
* Output the identified hosts in a format ready for the host inventory portion of a pen test report.
* Import host info to Metasploit DB?
