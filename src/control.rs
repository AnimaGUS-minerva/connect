/*
 * Copyright [2020] <mcr@sandelman.ca>

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

extern crate serde;
extern crate serde_cbor;

//use futures::prelude::*;
use serde::{Serialize, Deserialize};
use serde_cbor::{to_vec,from_slice};
//use serde_cbor::Deserializer;
//use serde::de;
use std::io::{Error, ErrorKind};
//use tokio_serde::formats::*;
//use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};
use std::os::unix::net::UnixStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};

use crate::dull::Dull;

#[derive(Clone)]
pub struct DebugOptions {
    pub allow_router_advertisement: bool,
    pub debug_namespaces:  bool,
    pub debug_graspdaemon: bool
}
impl DebugOptions {
    pub fn empty() -> DebugOptions {
        DebugOptions {
            allow_router_advertisement: false,
            debug_namespaces:  false,
            debug_graspdaemon: false
        }
    }

    pub fn debug_info(self: &mut Self,
                      msg: String) {
        if self.debug_namespaces {
            println!("{}", msg);
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum DullControl {
    Exit,
    AdminDown { interface_index: u32 },
    GraspDebug { grasp_debug: bool },
    AutoAdjacency { adj_up: bool },
    DullNamespace { namespace_id: i32 },
    ChildReady
}

pub fn encode_msg(thing: &DullControl) -> Vec<u8> {
    // encode it in CBOR.
    return to_vec(&thing).unwrap();
}

pub fn decode_msg(msg: &[u8]) -> DullControl {
    // decode it from CBOR.
    return from_slice(msg).unwrap();
}

pub fn send_dull(_dull: &Dull, _thing: &DullControl) -> Result<bool, Error> {
    println!("send dull");
    return Ok(true);
}

pub async fn write_control(writer: &mut tokio::net::UnixStream, data: &DullControl) -> Result<(), std::io::Error> {
    let encoded = &encode_msg(data);
    let len     = encoded.len();
    let veclen = to_vec(&len).unwrap();
    writer.write_all(&veclen).await.unwrap();
    return writer.write_all(encoded).await;
}

pub async fn read_control(reader: &mut tokio::net::UnixStream) -> Result<DullControl, std::io::Error> {
    let mut control_buffer = [0; 256];

    let mut n = 0;
    while n == 0 {
        let sizevec = reader.read(&mut control_buffer[..]).await?;
        let size    = from_slice(&control_buffer[0..sizevec]).unwrap();

        // size is number of bytes to read now.
        let mut handle = reader.take(size);

        n = handle.read(&mut control_buffer[..]).await?;
        //println!("Got a message of length {}", n);
    }

    let dc = decode_msg(&control_buffer[0..n]);

    return Ok(dc);
}

pub async fn write_child_ready(mut writer: &mut tokio::net::UnixStream) -> Result<(), std::io::Error> {
    let result = write_control(&mut writer, &DullControl::ChildReady).await;

    match result  {
        Err(e) => match e.kind() {
            ErrorKind::BrokenPipe  => { return Ok(()); }, // maybe die?
            _                      => { return Ok(()); }  // maybe error.
        }
        _ => { return Ok(()); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_quit() {
        let data = DullControl::Exit;

        let e = encode_msg(&data);

        // decode it.
        let d: DullControl = from_slice(&e).unwrap();

        assert_eq!(d, data);
    }

    #[test]
    fn test_encode_decode_admindown() {
        let data = DullControl::AdminDown { interface_index: 5u32 };

        // encode it.
        let e = encode_msg(&data);

        // decode it.
        let d: DullControl = decode_msg(&e);

        assert_eq!(d, data);
    }

    #[test]
    fn test_decode_multi_message() {
        let data1 = DullControl::AdminDown { interface_index: 5u32 };
        let data2 = DullControl::AdminDown { interface_index: 6u32 };

        // encode two things
        let mut e1 = encode_msg(&data1);
        let e2 = encode_msg(&data2);
        e1.extend(e2);

        // decode it.
        let d: DullControl = decode_msg(&e1);

        assert_eq!(d, data1);
    }

    /* this function just helps the test case below, since tests can not do await */
    async fn read_write_admin_via_socket(data: &DullControl) -> Result<DullControl, std::io::Error> {
        let pair = UnixStream::pair().unwrap();

        let mut reader = tokio::net::UnixStream::from_std(pair.1).unwrap();
        let mut writer = tokio::net::UnixStream::from_std(pair.0).unwrap();

        write_control(&mut writer, data).await.unwrap();
        return read_control(&mut reader).await;
    }

    macro_rules! aw {
        ($e:expr) => {
            tokio_test::block_on($e)
        };
    }

    #[test]
    fn test_write_read_admin_via_socket() {
        let data = DullControl::AdminDown { interface_index: 5u32 };

        assert_eq!(aw!(read_write_admin_via_socket(&data)).unwrap(), data);
    }

    async fn write_admin_via_closed_socket(data: &DullControl) -> Result<(), std::io::Error> {
        let pair = UnixStream::pair().unwrap();

        //let reader = tokio::net::UnixStream::from_std(pair.1).unwrap();
        let mut writer = tokio::net::UnixStream::from_std(pair.0).unwrap();

        match write_control(&mut writer, data).await {
            Err(e) => match e.kind() {
                ErrorKind::BrokenPipe  => { return Ok(()); },
                _                      => { return Err(e); }
            }
            _ => { return Ok(()); }
        }
    }

    #[test]
    fn test_write_when_socket_closed() {
        let data = DullControl::AdminDown { interface_index: 5u32 };

        assert_eq!(aw!(write_admin_via_closed_socket(&data)).unwrap(), ());
    }
}
