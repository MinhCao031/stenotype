# stenotype
This is Google stenographer's Stenotype that can export to pcapng and its index

How to run:
- Command to run: `sudo ./stenotype -v --dir=PATH/TO/FOLDER --dir_pcap=PATH/FROM/DIR/TO/PCAP`
  - Need help? Run `sudo ./stenotype --help`
- Example: `sudo ./stenotype -v --dir=./log --dir_pcap=Pcap`
  - This will find and read all pcap files from `./log/Pcap/`
  - For each pcap file, it then export them as pcapng in `./log/PKT`
  - While writing to pcapng in `./log/PKT`, it also export the index file of that pcapng file in `./log/IDX`

Note:
- This can be run using only 2 paramters (mentioned as flags in source code):
  - `dir`: Directory of input and output files. This must contain 3 folder: `PKT`, `IDX`
  and 1 folder containing pcap files
  - `dir_pcap`: Directory of pcap files that is in `dir/` folder
- The file `read_byte` file is used to read byte from a file (compiled from `read_byte.cc`)
