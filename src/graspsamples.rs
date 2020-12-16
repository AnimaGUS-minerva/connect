/* confirmed working */
pub static PACKET_000: [u8; 144] = [
    0x33, 0x33, 0x00, 0x00, 0x00, 0x13, 0x52, 0x54,
    0x00, 0x99, 0x9a, 0xba, 0x86, 0xdd,
    /* v6 header */
    0x60, 0x0b, 0x9f, 0x82, 0x00, 0x5a, 0x11, 0x01,
    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x50, 0x54, 0x00, 0xff, 0xfe, 0x99, 0x9a, 0xba,
    0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13,
    /* payload: UDP */
    0xe6, 0x7c, 0x1b, 0x69, 0x00, 0x5a, 0xff, 0x19,

    /* GRASP part */
    0x85, 0x09, 0x1a, 0xd6, 0x17, 0x85, 0xad, 0x50,
    0x26, 0x07, 0xf0, 0xb0, 0x00, 0x0f, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0xf7,
    0x1a, 0x00, 0x01, 0xd4, 0xc0, 0x82, 0x84, 0x71,
    0x41, 0x4e, 0x5f, 0x6a, 0x6f, 0x69, 0x6e, 0x5f,
    0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61,
    0x72, 0x05, 0x01, 0x67, 0x45, 0x53, 0x54, 0x2d,
    0x54, 0x4c, 0x53, 0x84, 0x18, 0x67, 0x50, 0x26,
    0x07, 0xf0, 0xb0, 0x00, 0x0f, 0x00, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0xf7, 0x06,
    0x18, 0x50,
];

/*
86                                      # array(6)
   09                                   # unsigned(9)
   1A D61785AD                          # unsigned(3591865773)
   50                                   # bytes(16)
      2607F0B0000F000200000000000005F7  # "&\a\xF0\xB0\x00\x0F\x00\x02\x00\x00\x00\x00\x00\x00\x05\xF7"
   1A 0001D4C0                          # unsigned(120000)
   82                                   # array(2)
      84                                # array(4)
         71                             # text(17)
            414E5F6A6F696E5F726567697374726172 # "AN_join_registrar"
         05                             # unsigned(5)
         01                             # unsigned(1)
         67                             # text(7)
            4553542D544C53              # "EST-TLS"
      84                                # array(4)
         18 67                          # unsigned(103)
         50                             # bytes(16)
            2607F0B0000F000200000000000005F7 # "&\a\xF0\xB0\x00\x0F\x00\x02\x00\x00\x00\x00\x00\x00\x05\xF7"
         06                             # unsigned(6)
         18 50                          # unsigned(80)
   82                                   # array(2)
      84                                # array(4)
         6C                             # text(12)
            414E5F6D6F72655F66756E72    # "AN_more_funr"
         05                             # unsigned(5)
         01                             # unsigned(1)
         67                             # text(7)
            4553542D544C53              # "EST-TLS"
      84                                # array(4)
         18 68                          # unsigned(104)
         44                             # bytes(4)
            2607F0B0                    # "&\a\xF0\xB0"
         06                             # unsigned(6)
         18 50                          # unsigned(80)
*/

/* raw CBOR packet, not IP/UDP header */
pub static PACKET_S01: [u8; 62] = [
    0x85, 0x09, 0x0E, 0x50, 0xFE, 0x80, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x11, 0x22, 0x01, 0x82, 0x84, 0x66,
    0x41, 0x4E, 0x5F, 0x41, 0x43, 0x50, 0x04, 0x01,
    0x65, 0x49, 0x4B, 0x45, 0x76, 0x32, 0x84, 0x18,
    0x67, 0x50, 0xFE, 0x80, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x11, 0x22, 0x11, 0x19, 0x01, 0xF4
];

pub static PACKET_420: [u8; 144] = [
         0x33, 0x33, 0x00, 0x00, 0x00, 0x13, 0x52, 0x54,
         0x00, 0x99, 0x9a, 0xba, 0x86, 0xdd,
        /* v6 header */
         0x60, 0x0b, 0x9f, 0x82, 0x00, 0x5a, 0x11, 0x01,
         0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x50, 0x54, 0x00, 0xff, 0xfe, 0x99, 0x9a, 0xba,
         0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13,
        /* payload   */
         0xe6, 0x7c, 0x1b, 0x69, 0x00, 0x5a, 0x08, 0x28,
         0x85, 0x09, 0x1a, 0xc2, 0x52, 0x8b, 0x69, 0x50,
         0x26, 0x07, 0xf0, 0xb0, 0x00, 0x0f, 0x00, 0x02,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0xf7,
         0x1a, 0x00, 0x01, 0xd4, 0xc0, 0x82, 0x84, 0x71,
         0x41, 0x4e, 0x5f, 0x6a, 0x6f, 0x69, 0x6e, 0x5f,
         0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61,
         0x72, 0x05, 0x01, 0x67, 0x45, 0x53, 0x54, 0x2d,
         0x54, 0x4c, 0x53, 0x84, 0x18, 0x67, 0x50, 0x26,
         0x07, 0xf0, 0xb0, 0x00, 0x0f, 0x00, 0x02, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0xf7, 0x06,
         0x18, 0x50,
];
