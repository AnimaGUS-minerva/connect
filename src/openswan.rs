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
//use std::net::Ipv6Addr;
//use std::fmt;
//use futures::stream::TryStreamExt;
//use futures::lock::{Mutex};
//use netlink_packet_sock_diag::constants::IPPROTO_UDP;
//use tokio::process::Command;
use std::collections::BTreeMap;
//use tokio::time::{delay_for, Duration};
use tokio::net::UnixStream;
use cbor::CborType;
use tokio::io::AsyncWriteExt;
use tokio::io::AsyncReadExt;
use std::process::{Command, ExitStatus};
use crate::openswanwhack;

//use crate::dull::DullInterface;
//use crate::grasp;

pub struct OpenswanWhackInterface {
    pub ctrl_sock: UnixStream,
}

const OPENSWAN_CONTROL_PATH:   &str = "/run/pluto/pluto.ctl";
const CBOR_SIGNATURE_TAG:      u64  = 55799;
const CBOR_OPENSWAN_TAG:       u64  = 0x4f50534e;
//const CborIPv4Tag:           u64  = 260;            /* squatted */
//const CborIPv6Tag:           u64  = 261;

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

        let bytes1 = OpenswanWhackInterface::openswan_tag();

        osw.ctrl_sock.write_all(&bytes1).await?;
        osw.ctrl_sock.write_all(&cmdbytes).await?;

        let mut results = String::new();
        osw.ctrl_sock.read_to_string(&mut results).await?;
        return Ok(results)
    }

    pub async fn openswan_start() -> Result<ExitStatus, std::io::Error> {

        Command::new("modprobe")
            .arg("af_key").status().unwrap();

        Command::new("/usr/local/libexec/ipsec/pluto")
            .arg("--ctlbase")
            .arg("/run/pluto")
            .arg("--stderrlog")
            .arg("--use-netkey")
            .arg("--nhelpers")
            .arg("1")
            .status()
    }

    pub async fn openswan_setup() -> Result<(), std::io::Error> {
        // do two setup functions on Openswan pluto.

        // 1. tell it to pay attention to link-local addresses.
        // 2. tell it to scan the list of interfaces
        OpenswanWhackInterface::openswan_send_cmd(
            OpenswanWhackInterface::openswan_encode_linkandlisten()).await.unwrap();

        Ok(())
    }

}

#[cfg(test)]
mod tests {
    use super::*;

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

//    #[test]
//    fn test_toggling_options() {
//        let mut openswan_map: BTreeMap<CborType, CborType> = BTreeMap::new();
//        blah = CborType::Map()
//    }
//
    async fn openswan_status() -> Result<(), std::io::Error> {
        let results = OpenswanWhackInterface::openswan_send_cmd(OpenswanWhackInterface::openswan_encode_status()).await.unwrap();
        println!("status\n{}", results);

        Ok(())
    }

    #[test]
    fn test_getting_openswan_status() {
        assert_eq!(aw!(openswan_status()).unwrap(), ());
    }

}


