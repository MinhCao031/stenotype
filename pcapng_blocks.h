#ifndef PCAPNG_BLOCKS
#define PCAPNG_BLOCKS

#include <iostream>
#include <cstring>
#include <pcap.h>

#define MIN_SHB_LEN 28
#define MIN_IDB_LEN 20
#define MIN_SHB_IDB_LEN 48
#define EPB_HEADER_LEN 28
#define EPB_HDRPAD_LEN 32

/*
 * First block of any pcapng files
 * Including byte-order, version and section length
 * First 28 bytes can be converted into char*
 */
class SectionHdrBlock {
 public:
  SectionHdrBlock() {
    block_type = 0x0A0D0D0A;
    block_leng = 28;
    byte_order = 0x1A2B3C4D;
    mj_version = 1;
    mn_version = 0;
    sction_len = -1ull;
    redund_val = 28;
    padding = 0;
	}

 private: // Do not mess up the order of these variables!
  /* Bytes map of pcapng section header block
  *    0x0A0D0D0A  Block Type              (4 bytes)  0-3
  *    usually 28  Block Total Length      (4 bytes)  4-7
  *    ?-endian    Byte-Order Magic        (4 bytes)  8-11
  *    usually  1  Major Version           (2 bytes) 12-13
  *    usually  0  Minor Version           (2 bytes) 14-15
  *    usually -1  Section Length          (8 bytes) 16-23
  *    usually 28  Block Total Length      (redundant 4-byte value)
  */
  uint32_t block_type;
  uint32_t block_leng;
  uint32_t byte_order;
  uint16_t mj_version;
  uint16_t mn_version;
  uint64_t sction_len;
  uint32_t redund_val; // Char* until here
  uint32_t padding; // Padding to 8 bytes
};

/*
 * Block that describe the info of an interface.
 * Unlike pcap, pcapng can have more than 1 interface
 * Including link layer type and snap length
 * First 20 bytes can be converted into char*
 */
class IfaceDescBlock {
 public:
  IfaceDescBlock(pcap_t* pcap_handler) {
		blck_type = 1;
		blck_leng = MIN_IDB_LEN;
  	link_type = pcap_datalink(pcap_handler);
    reserved  = 0;
  	snap_leng = pcap_snapshot(pcap_handler);
    redundant = MIN_IDB_LEN;
    padding = 0;
	}

 private: // Do not mess up the order of these variables!
  /* Bytes map of simple interface description block (offset 28)
   *    usually  1  Block Type          (4 bytes)  0-3
   *    usually 20  Block Total Length  (4 bytes)  4-7
   *    link_typ    Link Layer Type     (2 bytes)  8-9
   *    must be  0  Reserved            (2 bytes) 10-11
   *    snap_len    SnapLen             (4 bytes) 12-15
   *    usually 20  Block Total Length  (redundant 4-byte value)
   */
  uint32_t blck_type;
  uint32_t blck_leng;
  uint16_t link_type;
  uint16_t reserved;
  uint32_t snap_leng;
  uint32_t redundant; // Char* until here
  uint32_t padding; // Padding to 8 bytes
};

/*
 * Enhanced Packet Block that store the raw packet.
 * Including Interface ID, Timestamp and Packet Length
 * First 28 bytes can be converted into char*
 */
class EnhancedPktBlock {
 public:
  EnhancedPktBlock(struct pcap_pkthdr *header_pcap, unsigned char const* full_packet) {
    blck_typ = 6;
    iface_id = 0;

    uint64_t ts_micro = header_pcap->ts.tv_sec * 1000000 + header_pcap->ts.tv_usec;
    ts_upper = ts_micro >> 32;
    ts_lower = ts_micro & ((1ll << 32) - 1);

    cap_leng = header_pcap->caplen;
    ori_leng = header_pcap->len;

    blocklen = ori_leng + EPB_HDRPAD_LEN;
    num_pads = blocklen & 3; // mod 4

    if (num_pads > 0) {
      num_pads = 4 - num_pads;
      blocklen += num_pads;
    }

    raw_data = full_packet;
	}

  uint32_t get_cap_leng() {
    return cap_leng;
  }
  uint32_t get_num_pads() {
    return num_pads;
  }
  uint32_t get_blocklen() {
    return blocklen;
  }
  uint32_t* getptr_blocklen() {
    return &blocklen;
  }
  const unsigned char* get_raw_data() {
    return raw_data;
  }

 private: // Do not mess up the order of these variables!
  /* Bytes map of pcapng enhanced packet block
   *    usually 6   Block Type              (4 bytes) 0-3
   *    block_len   Block Total Length (1)  (4 bytes) 4-7
   *    usually 0   Interface ID            (4 bytes) 8-11
   *    ts << 32    Timestamp Upper         (4 bytes) 12-15
   *    ts % 2^32   Timestamp Lower         (4 bytes) 16-19
   *    hdr.caplen  Captured Packet Length  (4 bytes) 20-23
   *    hdr.len     Original Packet Length  (4 bytes) 24-27
   *    raw_data    Packet Data             (x bytes) 28-(x+28)
   *    padding     Padding to 4 bytes      (0-3 bytes)
   *    caplen+32   Block Total Length (2)  (redundant 4-byte value)
   * Values of (1) & (2) should be the same
   */
  uint32_t blck_typ;
	uint32_t blocklen;
  uint32_t iface_id;
	uint32_t ts_upper;
	uint32_t ts_lower;
	uint32_t cap_leng;
	uint32_t ori_leng; // Char* until here
  uint32_t num_pads;
	const unsigned char* raw_data;
};

bool OpenOrCreateFolder(const std::string& folderPath);
bool isFilePcap(std::string s);

#endif /* PCAPNG_BLOCKS */