/*
 * Copyright [2021] <mcr@sandelman.ca>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 *
 */

extern crate nix;
extern crate tokio;
extern crate moz_cbor as cbor;
//use std::sync::Arc;
use std::net::Ipv6Addr;
//use std::fmt;
//use futures::stream::TryStreamExt;
//use futures::lock::{Mutex};
//use netlink_packet_sock_diag::constants::IPPROTO_UDP;
use std::collections::BTreeMap;
use tokio::time::{delay_for, Duration};
use tokio::net::UnixStream;
use cbor::CborType;
use tokio::io::AsyncWriteExt;
use tokio::io::AsyncReadExt;
use std::io::ErrorKind;
use std::process::{ExitStatus};
use tokio::process::{Command};
use crate::openswanwhack;

//use crate::dull::DullInterface;
//use crate::grasp;

pub struct OpenswanWhackInterface {
    pub ctrl_sock: UnixStream,
}

const OPENSWAN_CONTROL_PATH:   &str = "/run/acp/pluto.ctl";
const CBOR_SIGNATURE_TAG:      u64  = 55800;
const CBOR_OPENSWAN_TAG:       u64  = 0x4f50534e;
//const CborIPv4Tag:           u64  = 0x34;            /* IANA assigned! */
const CBOR_IPV6_TAG:           u64  = 0x36;
const PUBKEY_CERTIFICATE:      u64  =   3;    /* from enum pubkey_source */

impl OpenswanWhackInterface {
    pub async fn connect() -> Result<OpenswanWhackInterface, std::io::Error> {
        let ctrl_sock = UnixStream::connect(OPENSWAN_CONTROL_PATH).await?;
        return Ok(OpenswanWhackInterface { ctrl_sock: ctrl_sock });
    }

    pub fn openswan_tag() -> Vec<u8> {
        let cbor = CborType::Tag(CBOR_SIGNATURE_TAG,
                                 Box::new(CborType::Tag(CBOR_OPENSWAN_TAG,
                                                        Box::new(CborType::Bytes(vec![0x42, 0x4f, 0x52])))));
        return cbor.serialize();
    }

    pub fn openswan_encode_status() -> Vec<u8> {
        let mut statusoption_map: BTreeMap<CborType, CborType> = BTreeMap::new();
        statusoption_map.insert(CborType::Integer(openswanwhack::statusoptions_keys::WHACK_STAT_OPTIONS as u64),
                                CborType::Integer(1));
        let mut command_map: BTreeMap<CborType, CborType> = BTreeMap::new();

        command_map.insert(CborType::Integer(openswanwhack::whack_message_keys::WHACK_STATUS as u64),
                           CborType::Map(statusoption_map));

        return CborType::Map(command_map).serialize();
    }

    pub fn openswan_encode_linkandlisten() -> Vec<u8> {
        let mut option_map: BTreeMap<CborType, CborType> = BTreeMap::new();
        option_map.insert(CborType::Integer(openswanwhack::optionscommand_keys::WHACK_OPT_LISTEN_ON_LINK_SCOPE as u64),
                                CborType::Integer(1));

        let mut command_map: BTreeMap<CborType, CborType> = BTreeMap::new();
        command_map.insert(CborType::Integer(openswanwhack::whack_message_keys::WHACK_OPTIONS as u64),
                           CborType::Map(option_map));

        command_map.insert(CborType::Integer(openswanwhack::whack_message_keys::WHACK_LISTEN as u64),
                           CborType::Integer(1));

        return CborType::Map(command_map).serialize();
    }

    async fn openswan_send_cmd(cmdbytes: Vec<u8>) -> Result<String, std::io::Error> {
        let mut osw = OpenswanWhackInterface::connect().await?;

        let mut bytes1 = OpenswanWhackInterface::openswan_tag();

        bytes1.extend(cmdbytes);
        match osw.ctrl_sock.write_all(&bytes1).await {
            Err(e) if e.kind() == ErrorKind::BrokenPipe => {
                    return Ok("".to_string());
            }
            Err(e) => { return Err(e); }
            _      => {}
        }

        let mut results = String::new();
        osw.ctrl_sock.read_to_string(&mut results).await?;
        return Ok(results)
    }

    pub async fn openswan_stop() -> Result<(), std::io::Error> {
        let mut command_map: BTreeMap<CborType, CborType> = BTreeMap::new();
        command_map.insert(CborType::Integer(openswanwhack::whack_message_keys::WHACK_SHUTDOWN as u64),
                           CborType::Integer(1));

        OpenswanWhackInterface::openswan_send_cmd(CborType::Map(command_map).serialize()).await.expect("Openswan already shutdown");

        return Ok(());
    }

    pub async fn openswan_start() -> Result<ExitStatus, std::io::Error> {

        Command::new("modprobe")
            .arg("af_key").status().await.unwrap();

        let result = Command::new("/usr/local/libexec/ipsec/pluto")
            .arg("--ctlbase")
            .arg("/run/acp/pluto")    // .ctl is implied
            .arg("--stderrlog")
            .arg("--use-netkey")
            .arg("--nhelpers")
            .arg("1")
            .status()
            .await;

        // short delay to let Openswan start up.
        delay_for(Duration::from_millis(100)).await;
        // could check with ::connect to see if control socket is present yet.

        return result;
    }

    pub async fn openswan_setup() -> Result<(), std::io::Error> {
        // do two setup functions on Openswan pluto.

        // 1. tell it to pay attention to link-local addresses.
        // 2. tell it to scan the list of interfaces
        OpenswanWhackInterface::openswan_send_cmd(
            OpenswanWhackInterface::openswan_encode_linkandlisten()).await.unwrap();

        // 3. do it twice, because sometimes we get:
        //   bind() for dull004/dull004 [fe80::609c:62ff:fed8:abba%92]:500 in process_raw_ifaces(). Errno 99: Cannot assign requested address
        // and we have no idea why.
        delay_for(Duration::from_millis(100)).await;
        OpenswanWhackInterface::openswan_send_cmd(
            OpenswanWhackInterface::openswan_encode_linkandlisten()).await.unwrap();

        Ok(())
    }

    pub async fn openswan_status() -> Result<(), std::io::Error> {
        let results = OpenswanWhackInterface::openswan_send_cmd(OpenswanWhackInterface::openswan_encode_status()).await.unwrap();
        println!("status\n{}", results);

        Ok(())
    }

    pub fn encode_v6_addr(v6:    Ipv6Addr) -> CborType {
        let oct = v6.octets();
        return CborType::Tag(CBOR_IPV6_TAG, Box::new(CborType::Bytes(oct.to_vec())))
    }

    pub fn encode_v6_prefix(v6: Ipv6Addr, len: u64) -> CborType {
        let oct = v6.octets();
        return CborType::Tag(CBOR_IPV6_TAG,
                             Box::new(CborType::Array(vec![CborType::Integer(len),
                                                           CborType::Bytes(oct.to_vec())])));
    }

    pub fn encode_end_policy(v6: Ipv6Addr) -> BTreeMap<CborType, CborType> {
        let mut end_map: BTreeMap<CborType, CborType> = BTreeMap::new();
        end_map.insert(CborType::Integer(openswanwhack::connectionend_keys::WHACK_OPT_END_HOST_ADDR as u64),
                        OpenswanWhackInterface::encode_v6_addr(v6));
        end_map.insert(CborType::Integer(openswanwhack::connectionend_keys::WHACK_OPT_END_CLIENT as u64),
                        OpenswanWhackInterface::encode_v6_prefix(Ipv6Addr::UNSPECIFIED, 0));
        end_map.insert(CborType::Integer(openswanwhack::connectionend_keys::WHACK_OPT_HOST_PORT  as u64),
                        CborType::Integer(500));
        end_map.insert(CborType::Integer(openswanwhack::connectionend_keys::WHACK_OPT_HAS_CLIENT as u64),
                        CborType::Integer(1));

        end_map
    }

    pub fn encode_ll_policy(myllv6:    Ipv6Addr,
                            eyllv6:    Ipv6Addr,
                            vtinum:    u32) -> (Vec<u8>,String) {


        let mut octets_ey = eyllv6.octets();
        let mut octets_me = myllv6.octets();
        if octets_ey[15] > octets_me[15] {
            // swap them so that both ends come up with the same name.
            let tmp = octets_me;
            octets_me = octets_ey;
            octets_ey = tmp;
        }
        let policy_name = format!("c_{:02x}{:02x}{:02x}{:02x}_{:02x}{:02x}{:02x}{:02x}",
                                  octets_me[12], octets_me[13], octets_me[14], octets_me[15],
                                  octets_ey[12], octets_ey[13], octets_ey[14], octets_ey[15]);

        let mut left_map = OpenswanWhackInterface::encode_end_policy(myllv6);
        left_map.insert(CborType::Integer(openswanwhack::connectionend_keys::WHACK_OPT_KEYTYPE as u64),
                        CborType::Integer(PUBKEY_CERTIFICATE));
        left_map.insert(CborType::Integer(openswanwhack::connectionend_keys::WHACK_OPT_END_ID as u64),
                        CborType::String("%cert".to_string()));
        left_map.insert(CborType::Integer(openswanwhack::connectionend_keys::WHACK_OPT_END_CA as u64),
                        CborType::String("DC=ca/DC=sandelman/CN=fountain-test.example.com Unstrung Fountain Root CA".to_string()));
        left_map.insert(CborType::Integer(openswanwhack::connectionend_keys::WHACK_OPT_END_CERT as u64),
                        CborType::String("hostcert.pem".to_string()));
        left_map.insert(CborType::Integer(openswanwhack::connectionend_keys::WHACK_OPT_HOST_TYPE as u64),
                        CborType::Integer(255));  /* enum keyword_host == KH_IPADDR */
        left_map.insert(CborType::Integer(openswanwhack::connectionend_keys::WHACK_OPT_CERTPOLICY as u64),
                        CborType::Integer(3));    /* enum certpolicy == cert_alwayssend */
        if vtinum != 0 {
            left_map.insert(CborType::Integer(openswanwhack::connectionend_keys::WHACK_OPT_VTINUM as u64),
                            CborType::Integer(vtinum as u64));
        }

        let left_cbor = CborType::Map(left_map);

        let mut right_map= OpenswanWhackInterface::encode_end_policy(eyllv6);
        right_map.insert(CborType::Integer(openswanwhack::connectionend_keys::WHACK_OPT_END_ID as u64),
                         CborType::String("E=*".to_string()));
        right_map.insert(CborType::Integer(openswanwhack::connectionend_keys::WHACK_OPT_END_CA as u64),
                         CborType::String("%same".to_string()));
        right_map.insert(CborType::Integer(openswanwhack::connectionend_keys::WHACK_OPT_HOST_TYPE as u64),
                         CborType::Integer(2));   /* enum keyword_host == KH_ANY */
        let right_cbor = CborType::Map(right_map);

        let mut connection_map: BTreeMap<CborType, CborType> = BTreeMap::new();
        connection_map.insert(CborType::Integer(openswanwhack::connection_keys::WHACK_OPT_NAME as u64),
                              CborType::String(policy_name.clone()));

        connection_map.insert(CborType::Integer(openswanwhack::connection_keys::WHACK_OPT_LEFT as u64),
                              left_cbor);

        connection_map.insert(CborType::Integer(openswanwhack::connection_keys::WHACK_OPT_RIGHT as u64),
                              right_cbor);

        // IKE policy.  Not well expressed in CDDL yet.
        // comes from "enum pluto_policy" in pluto_constants.h:
	//     POLICY_RSASIG  = LELEM(1),
        //     POLICY_ENCRYPT = LELEM(2),	/* must be first of IPSEC policies */
	//     POLICY_AUTHENTICATE=LELEM(3),	/* must be second */
	//     POLICY_TUNNEL  = LELEM(5),
	//     POLICY_PFS     = LELEM(6),
	//     POLICY_UP      = LELEM(16),   /* do we want this up? */
	//     POLICY_OVERLAPIP=LELEM(23),
	//     POLICY_IKEV2_ALLOW   = LELEM(25), /* accept IKEv2?   0x0200 0000 */
	//     POLICY_IKEV2_PROPOSE = LELEM(26), /* propose IKEv2?  0x0400 0000 */
        let policy: u64 = (1<<1) | (1<<2) | (1<<3) | (1<<5) | (1<<6) |
                          (1<<16) | (1<<23) | (1<<25) | (1<<26);
        connection_map.insert(CborType::Integer(openswanwhack::connection_keys::WHACK_OPT_POLICY as u64),
                              CborType::Integer(policy));

        connection_map.insert(CborType::Integer(openswanwhack::connection_keys::WHACK_OPT_LIFETIME_IKE as u64),
                              CborType::Integer(14400));  // IKE lifetime, 4 hoursj

        connection_map.insert(CborType::Integer(openswanwhack::connection_keys::WHACK_OPT_LIFETIME_IPSEC as u64),
                              CborType::Integer(86400));  // IPsec lifetime, 1 day

        //  WHACK_OPT_IKE=>  tstr,
        //  WHACK_OPT_ESP=>  tstr,

        let mut command_map: BTreeMap<CborType, CborType> = BTreeMap::new();
        command_map.insert(CborType::Integer(openswanwhack::whack_message_keys::WHACK_CONNECTION as u64),
                           CborType::Map(connection_map));

        return (CborType::Map(command_map).serialize(), policy_name);

    }

    pub async fn add_adjacency(_vtiiface: &String,
                               vtinum:    u32,
                               myllv6:    Ipv6Addr,
                               eyllv6:    Ipv6Addr) -> Result<String, std::io::Error> {

        let (encoded_policy, policy_name) = OpenswanWhackInterface::encode_ll_policy(myllv6, eyllv6, vtinum);

        let results = OpenswanWhackInterface::openswan_send_cmd(encoded_policy).await.unwrap();
        println!("status\n{}", results);

        Ok(policy_name)
    }

    pub fn up_encoded(policy_name: &String) -> Vec<u8> {
        let mut initiate_map: BTreeMap<CborType, CborType> = BTreeMap::new();
        initiate_map.insert(CborType::Integer(openswanwhack::connection_keys::WHACK_OPT_NAME as u64),
                            CborType::String(policy_name.clone()));

        let mut command_map: BTreeMap<CborType, CborType> = BTreeMap::new();
        command_map.insert(CborType::Integer(openswanwhack::whack_message_keys::WHACK_INITIATE as u64),
                           CborType::Map(initiate_map));

        return CborType::Map(command_map).serialize();
    }


    pub async fn up_adjacency(policy_name: &String)-> Result<(), std::io::Error> {

        let encoded_up = OpenswanWhackInterface::up_encoded(policy_name);
        let results = OpenswanWhackInterface::openswan_send_cmd(encoded_up).await.unwrap();
        println!("status\n{}", results);
        Ok(())
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate hex_literal;
    use hex_literal::hex;

    #[allow(unused_macros)]
    macro_rules! aw {
        ($e:expr) => {
            tokio_test::block_on($e)
        };
    }

    #[test]
    fn test_openswan_tag() {
        let bytes = OpenswanWhackInterface::openswan_tag();
        assert_eq!(bytes, vec![0xd9,0xd9,0xf8,0xda,0x4f,0x50,0x53,0x4e,0x43,0x42,0x4f,0x52])
    }

    // this is here, because you can not test macros in the same crate
    #[test]
    fn test_hex_parsing() {
        let f1 = vec![0xd9,0xd9,0xf8,0xda,0x4f,0x50,0x53,0x4e,0x43,0x42,0x4f,0x52];
        let f2 = hex!("d9 d9 f8 da 4f 50 53 4e 43 42 4f 52");
        assert_eq!(f1, f2);
    }

    #[test]
    fn test_hex_parsing2() {
        let f1 = vec![0xd9,0xd9,0xf7,0xda,0x4f,0x50,0x53,0x4e,0x43,0x42,0x4f,0x52];
        let f2 = hex!("d9 d9 f7 # hello
da 4f 50 53 4e 43 42 4f 52");
        assert_eq!(f1, f2);
    }

    #[test]
    fn test_hex_parsing3() {
        let f1 = vec![0xd9,0xd9,0xf7,0xda,0x4f,0x50,0x53,0x4e,0x43,0x42,0x4f,0x52];
        let f2 = hex!("d9 d9 f7
da 4f 50 53 4e 43 42 4f 52  # hello");
        assert_eq!(f1, f2);
    }

    #[test]
    fn test_hex_parsing4() {
        let f1 = vec![0xA1,0x04,0xA3,0x01,0x78,0x18];
        let f2 = hex!("
A1                                      # map(1)
   04                                   # unsigned(4)
   A3                                   # map(3)
      01                                # unsigned(1)
        78 18                           # text(24)
");
        assert_eq!(f1, f2);
    }

    #[test]
    fn test_openswan_policy() {
        let myllv6 = "fe80::609c:62ff:fed8:abba".parse::<Ipv6Addr>().unwrap();
        let eyllv6 = "fe80::5835:02ff:fe16:885b".parse::<Ipv6Addr>().unwrap();

        let (encoded_policy,_policy_name) = OpenswanWhackInterface::encode_ll_policy(myllv6, eyllv6, 4);
        assert_eq!(encoded_policy, hex!("
a1                                      # map(1)
   04                                   # unsigned(4)
   a6                                   # map(6)
      01                                # unsigned(1)
      75                                # text(21)
         706565722d35383335303266666665313638383562 #
      03                                # unsigned(3)
      ab                                # map(11)
         05                             # unsigned(5)
         65                             # text(5)
            2563657274                  #
         06                             # unsigned(6)
         6c                             # text(12)
            686f7374636572742e70656d    #
         07                             # unsigned(7)
         78 49                          # text(73)
            44433d63612f44433d73616e64656c6d616e2f434e3d666f756e7461696e2d746573742e6578616d706c652e636f6d20556e737472756e6720466f756e7461696e20526f6f74204341 #
         0b                             # unsigned(11)
         d8 36                          # tag(54)
            50                          # bytes(16)
               fe80000000000000609c62fffed8abba #
         0e                             # unsigned(14)
         d8 36                          # tag(54)
            82                          # array(2)
               00                       # unsigned(0)
               50                       # bytes(16)
                  00000000000000000000000000000000 #
         0f                             # unsigned(15)
         18 ff                          # unsigned(255)
         10                             # unsigned(16)
         03                             # unsigned(3)
         11                             # unsigned(17)
         01                             # unsigned(1)
         14                             # unsigned(20)
         19 01f4                        # unsigned(500)
         18 8f                          # unsigned(143)
         03                             # unsigned(3)
         18 91                          # unsigned(145)
         04                             # unsigned(4)
      04                                # unsigned(4)
      a7                                # map(7)
         05                             # unsigned(5)
         63                             # text(3)
            453d2a                      #
         07                             # unsigned(7)
         65                             # text(5)
            2573616d65                  #
         0b                             # unsigned(11)
         d8 36                          # tag(54)
            50                          # bytes(16)
               fe80000000000000583502fffe16885b #
         0e                             # unsigned(14)
         d8 36                          # tag(54)
            82                          # array(2)
               00                       # unsigned(0)
               50                       # bytes(16)
                  00000000000000000000000000000000 #
         0f                             # unsigned(15)
         02                             # unsigned(2)
         11                             # unsigned(17)
         01                             # unsigned(1)
         14                             # unsigned(20)
         19 01f4                        # unsigned(500)
      18 7f                             # unsigned(127)
      1a 0601006e                       # unsigned(100728942)
      18 92                             # unsigned(146)
      19 3840                           # unsigned(14400)
      18 93                             # unsigned(147)
      1a 00015180                       # unsigned(86400)

"));
    }

    #[test]
    fn test_openswan_initiate() {
        let policy_name = "peer-ABCDEF";

        let encoded_initiate = OpenswanWhackInterface::up_encoded(&policy_name.to_string());
        assert_eq!(encoded_initiate, hex!("
a1                              # map(1)
   07                           # unsigned(7)
   a1                           # map(1)
      01                        # unsigned(1)
      6b                        # text(11)
         706565722d414243444546 #
"));
    }

    #[test]
    fn test_openswan_ipv6() {
        let myllv6 = "fe80::609c:62ff:fed8:abba".parse::<Ipv6Addr>().unwrap();
        let encoded = OpenswanWhackInterface::encode_v6_addr(myllv6).serialize();
        assert_eq!(encoded, vec![0xd8, 0x36, 0x50,
                                 0xfe, 0x80, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00,
                                 0x60, 0x9C, 0x62, 0xff,
                                 0xfe, 0xD8, 0xAB, 0xBA]);
    }

//    #[test]
//    fn test_toggling_options() {
//        let mut openswan_map: BTreeMap<CborType, CborType> = BTreeMap::new();
//        blah = CborType::Map()
//    }
//
    // requires manual setup of pluto
    //#[test]
    //fn test_getting_openswan_status() {
    //   assert_eq!(aw!(OpenswanWhackInterface::openswan_status()).unwrap(), ());
    //}

}


