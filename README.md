# stenotype
This is Google stenographer's Stenotype that can export to pcapng and its index

Note:
- Do not delete any folder inside `log` folder, as they're used to store input and output files
- The file `read_byte` in `log` folder is used to read byte from a file
- This can be run using only 2 flags (the rest are unnecessary for now):
  - `flag_dir`: Directory of input and output files. This should contain 3 folder: `Pcap`, `PKT` and `IDX`
  - `flag_src`: The name of pcap file that is in `flagdir/PKT` folder
- Command to run: `sudo ./stenotype -v --dir=PATH/TO/FILE --pcap_file=FILE.pcap`

