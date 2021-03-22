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
use tokio::net::UnixStream;
use cbor::CborType;

//use crate::dull::DullInterface;
//use crate::grasp;

pub struct OpenswanWhackInterface {
    pub cntrl_sock: UnixStream,
}

const OPENSWAN_CONTROL_PATH: &str = "/var/run/pluto/pluto.ctl";
const CBOR_SIGNATURE_TAG:      u64  = 55799;
const CBOR_OPENSWAN_TAG:       u64  = 0x4f50534e;
//const CborIPv4Tag:           u64  = 260;            /* squatted */
//const CborIPv6Tag:           u64  = 261;

impl OpenswanWhackInterface {
    pub async fn connect(self: &mut OpenswanWhackInterface) -> Result<(), std::io::Error> {
        self.cntrl_sock = UnixStream::connect(OPENSWAN_CONTROL_PATH).await?;
        return Ok(())
    }

    pub fn openswan_tag() -> Vec<u8> {
        let cbor = CborType::Tag(CBOR_SIGNATURE_TAG,
                                 Box::new(CborType::Tag(CBOR_OPENSWAN_TAG,
                                                        Box::new(CborType::Bytes(vec![0x42, 0x4f, 0x52])))));
        return cbor.serialize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
//    #[test]
//    fn test_getting_openswan_status() {
//        let osw = OpenswanWhackInterface::new();
//        osw.connect().await?;
//
//    }

}


