# stenotype
This is Google stenographer's Stenotype that can export to pcapng and its index

How to run:
- Command to run: `sudo ./stenotype -v --dir=PATH/TO/OUTPUT/ --dir_pcap=PATH/TO/PCAP/`
  - Need help? Run `sudo ./stenotype --help`
- Example: `sudo ./stenotype -v --dir=./log/ --dir_pcap=./Pcap/`
  - This will find and read all pcap files from `./Pcap/`
  - For each pcap file, it then export them as pcapng in `./log/PKT/`
  - For each pcapng exported into `./log/PKT/`, its index file is also created in `./log/IDX/`

Note:
- This can be run using only 2 paramters (mentioned as flags in source code):
  - `dir`: Directory of input and output files. This must contain 2 folder: `PKT/` and `IDX/`
  - `dir_pcap`: Directory of pcap files
- The file `read_byte` file is used to read byte from a file (compiled from `read_byte.cc`)
