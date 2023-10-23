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
- Need help? Run `./stenotype --help`
- Command to run:
```bash
`sudo ./stenotype -v --gid=GID --uid=UID --filesize_mb=SIZE --fileage_sec=SEC \
  --thread=THREADS --dir=PATH/TO/OUTPUT/ --dir_pcap=PATH/TO/PCAP/ `
```
- Example:
```bash
`sudo ./stenotype -v --gid=root --uid=root --filesize_mb=512 --fileage_sec=30 \
  --thread=4 --dir=/tmp/out --dir_pcap=/tmp/in`
```
  - This will run using 4 threads, with `-v` means verbose output
  - The threads will find and read all pcap files from `/tmp/in`, they also wait for new pcap after that
  - This will stop if there're no new files in a short time (in this case 3*30sec = 90sec)
  - For each pcap file, it then export its pcapng version in `./tmp/out/PKTj`. (j = 0,1,2,... is thread ID)
  - Each pcapng size is no more than 512MB. If the pcap is too big, its packets will be divided into many pcapng files.
  - For each pcapng exported into `./tmp/out/PKTj`, its index file with the same name is also created in `./tmp/out/IDXj`
  - All mentioned folders are opened with root's permission