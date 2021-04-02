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

const OPENSWAN_CONTROL_PATH:   &str = "/run/acp.ctl";
const CBOR_SIGNATURE_TAG:      u64  = 55799;
const CBOR_OPENSWAN_TAG:       u64  = 0x4f50534e;
//const CborIPv4Tag:           u64  = 261;            /* squatted */
const CBOR_IPV6_TAG:           u64  = 260;

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

        OpenswanWhackInterface::openswan_send_cmd(CborType::Map(command_map).serialize()).await.unwrap();

        return Ok(());
    }

    pub async fn openswan_start() -> Result<ExitStatus, std::io::Error> {

        Command::new("modprobe")
            .arg("af_key").status().await.unwrap();

        let result = Command::new("/usr/local/libexec/ipsec/pluto")
            .arg("--ctlbase")
            .arg("/run/acp")    // .ctl is implied
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

    pub fn encode_ll_policy(myllv6:    Ipv6Addr,
                            eyllv6:    Ipv6Addr) -> Vec<u8> {

        let mut left_map: BTreeMap<CborType, CborType> = BTreeMap::new();
        left_map.insert(CborType::Integer(openswanwhack::connectionend_keys::WHACK_OPT_END_HOST_ADDR as u64),
                        OpenswanWhackInterface::encode_v6_addr(myllv6));
        left_map.insert(CborType::Integer(openswanwhack::connectionend_keys::WHACK_OPT_END_CLIENT as u64),
                        OpenswanWhackInterface::encode_v6_prefix(Ipv6Addr::UNSPECIFIED, 0));
        left_map.insert(CborType::Integer(openswanwhack::connectionend_keys::WHACK_OPT_HAS_CLIENT as u64),
                        CborType::Integer(1));

        let mut right_map: BTreeMap<CborType, CborType> = BTreeMap::new();
        right_map.insert(CborType::Integer(openswanwhack::connectionend_keys::WHACK_OPT_END_HOST_ADDR as u64),
                         OpenswanWhackInterface::encode_v6_addr(eyllv6));
        right_map.insert(CborType::Integer(openswanwhack::connectionend_keys::WHACK_OPT_END_CLIENT as u64),
                         OpenswanWhackInterface::encode_v6_prefix(Ipv6Addr::UNSPECIFIED, 0));
        right_map.insert(CborType::Integer(openswanwhack::connectionend_keys::WHACK_OPT_HAS_CLIENT as u64),
                         CborType::Integer(1));

        let mut connection_map: BTreeMap<CborType, CborType> = BTreeMap::new();
        let octets = eyllv6.octets();
        connection_map.insert(CborType::Integer(openswanwhack::connection_keys::WHACK_OPT_NAME as u64),
                              CborType::String(format!("peer-{:02}{:02}{:02}{:02}{:02}{:02}{:02}{:02}",
                                                       octets[8], octets[9], octets[10], octets[11],
                                                       octets[12],octets[13],octets[14], octets[15])));

        connection_map.insert(CborType::Integer(openswanwhack::connection_keys::WHACK_OPT_LEFT as u64),
                              CborType::Map(left_map));

        connection_map.insert(CborType::Integer(openswanwhack::connection_keys::WHACK_OPT_RIGHT as u64),
                              CborType::Map(right_map));

        //  WHACK_OPT_IKE=>  tstr,
        //  WHACK_OPT_ESP=>  tstr,

        let mut command_map: BTreeMap<CborType, CborType> = BTreeMap::new();
        command_map.insert(CborType::Integer(openswanwhack::whack_message_keys::WHACK_CONNECTION as u64),
                           CborType::Map(connection_map));

        return CborType::Map(command_map).serialize();

    }

    pub async fn add_adjacency(_vtiiface: &String,
                               _vtinum:    u32,
                               myllv6:    Ipv6Addr,
                               eyllv6:    Ipv6Addr) -> Result<(), std::io::Error> {

        let encoded_policy = OpenswanWhackInterface::encode_ll_policy(myllv6, eyllv6);

        let results = OpenswanWhackInterface::openswan_send_cmd(encoded_policy).await.unwrap();
        println!("status\n{}", results);

        Ok(())
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(unused_macros)]
    macro_rules! aw {
        ($e:expr) => {
            tokio_test::block_on($e)
        };
    }

    #[test]
    fn test_openswan_tag() {
        let bytes = OpenswanWhackInterface::openswan_tag();
        assert_eq!(bytes, vec![0xd9,0xd9,0xf7,0xda,0x4f,0x50,0x53,0x4e,0x43,0x42,0x4f,0x52])
    }

    #[test]
    fn test_openswan_policy() {
        let myllv6 = "fe80::609c:62ff:fed8:abba".parse::<Ipv6Addr>().unwrap();
        let eyllv6 = "fe80::5835:02ff:fe16:885b".parse::<Ipv6Addr>().unwrap();

        let encoded_policy = OpenswanWhackInterface::encode_ll_policy(myllv6, eyllv6);
        assert_eq!(encoded_policy, vec![
            0xa1,0x04,0xa3,0x01, 0x78,0x18,0x70,0x65,
            0x65,0x72,0x2d,0x38, 0x38,0x35,0x33,0x30,
            0x32,0x32,0x35,0x35, 0x32,0x35,0x34,0x32,
            0x32,0x31,0x33,0x36, 0x39,0x31,0x03,0xa3,
            0x0b,0xd9,0x01,0x04, 0x50,0xfe,0x80,0x00,
            0x00,0x00,0x00,0x00, 0x00,0x60,0x9c,0x62,
            0xff,0xfe,0xd8,0xab, 0xba,0x0e,0xd9,0x01,
            0x04,0x82,0x00,0x50, 0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00, 0x11,0x01,0x04,0xa3,
            0x0b,0xd9,0x01,0x04, 0x50,0xfe,0x80,0x00,
            0x00,0x00,0x00,0x00, 0x00,0x58,0x35,0x02,
            0xff,0xfe,0x16,0x88, 0x5b,0x0e,0xd9,0x01,
            0x04,0x82,0x00,0x50, 0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00, 0x11,0x01

/*  decoded by cbor.me:
A1                                      # map(1)
   04                                   # unsigned(4)
   A3                                   # map(3)
      01                                # unsigned(1)
      78 18                             # text(24)
         706565722D38383533303232353532353432323133363931 # "peer-8853022552542213691"
      03                                # unsigned(3)
      A3                                # map(3)
         0B                             # unsigned(11)
         D9 0104                        # tag(260)
            50                          # bytes(16)
               FE80000000000000609C62FFFED8ABBA # "\xFE\x80\x00\x00\x00\x00\x00\x00`\x9Cb\xFF\xFE\xD8\xAB\xBA"
         0E                             # unsigned(14)
         D9 0104                        # tag(260)
            82                          # array(2)
               00                       # unsigned(0)
               50                       # bytes(16)
                  00000000000000000000000000000000 # "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
         11                             # unsigned(17)
         01                             # unsigned(1)
      04                                # unsigned(4)
      A3                                # map(3)
         0B                             # unsigned(11)
         D9 0104                        # tag(260)
            50                          # bytes(16)
               FE80000000000000583502FFFE16885B # "\xFE\x80\x00\x00\x00\x00\x00\x00X5\x02\xFF\xFE\x16\x88["
         0E                             # unsigned(14)
         D9 0104                        # tag(260)
            82                          # array(2)
               00                       # unsigned(0)
               50                       # bytes(16)
                  00000000000000000000000000000000 # "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
         11                             # unsigned(17)
         01                             # unsigned(1)
*/
        ]);
    }

    #[test]
    fn test_openswan_ipv6() {
        let myllv6 = "fe80::609c:62ff:fed8:abba".parse::<Ipv6Addr>().unwrap();
        let encoded = OpenswanWhackInterface::encode_v6_addr(myllv6).serialize();
        assert_eq!(encoded, vec![0xd9, 0x01, 0x04, 0x50,
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


