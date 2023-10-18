# stenotype
This is Google stenographer's Stenotype that can export to pcapng and its index

Instead of listening for packet, this reads pcap files and export their pcapng version and its index file

Libraries needed:
  - g++
  - libaio-dev
  - libcap2-bin
  - libleveldb-dev
  - libseccomp-dev
  - libsnappy-dev

How to compile: `make all`

How to run:
- Command to run: `sudo ./stenotype -v --gid=GID --uid=UID --dir=PATH/TO/OUTPUT/ --dir_pcap=PATH/TO/PCAP/ --thread=THREADS`
  - Need help? Run `sudo ./stenotype --help`
- Example: `sudo ./stenotype -v --gid=root --uid=root --thread=2 --dir=./log/ --dir_pcap=/`
  - This will run using 2 threads
  - This will find and read all pcap files from `./`
  - For each pcap file, it then export them as pcapng in `./log/PKT/`
  - For each pcapng exported into `./log/PKT/`, its index file is also created in `./log/IDX/`
  - All mentioned folders are opened with root's permission

Note:
- The file `read_byte` file is used to read byte from a file (compiled from `read_byte.cc`)
- This can be run using these paramters (mentioned as flags in source code):
  - `dir`: Directory of input and output files. This must contain 2 folder: `PKT/` and `IDX/`
  - `dir_pcap`: Directory of pcap files
  - `thread`: Number of threads running in the same time
  - `gid`, `uid`
  - `-v`: Verbose
