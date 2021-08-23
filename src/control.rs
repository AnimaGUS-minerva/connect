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
use serde_cbor::Deserializer;
use serde::de;
use std::io::{Error, ErrorKind};
//use tokio_serde::formats::*;
//use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};
use std::os::unix::net::UnixStream;
use tokio::io::{AsyncWrite, AsyncRead, AsyncWriteExt, AsyncReadExt};
use tokio::io::DuplexStream;

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

pub fn send_dull(_dull: &Dull, _thing: &DullControl) -> Result<bool, Error> {
    println!("send dull");
    return Ok(true);
}

fn from_slice_limit<'a, T>(slice: &'a [u8]) -> Result<(T, u32), serde_cbor::Error>
where
    T: de::Deserialize<'a>,
{
    let mut deserializer = Deserializer::from_slice(slice);
    let value = de::Deserialize::deserialize(&mut deserializer)?;
    //let remaining = deserializer.read.offset;
    let remaining = 0;
    Ok((value, remaining))
}

#[derive(Debug)]
struct ControlStream {
    reader: DuplexStream,
    writer: DuplexStream,
}

impl ControlStream {
    pub fn empty() -> Self {
        let (client, server) = tokio::io::duplex(256);

        ControlStream {
            reader: client,
            writer: server
        }
    }

    pub fn encode_msg(thing: &DullControl) -> Vec<u8> {
        // encode it in CBOR.
        return to_vec(&thing).unwrap();
    }

    pub fn decode_msg(msg: &[u8]) -> DullControl {
        // decode it from CBOR.
        return from_slice(msg).unwrap();
    }

    pub async fn write_control(writer: &mut (dyn AsyncWrite + Unpin), data: &DullControl) -> Result<(), std::io::Error> {

        let mut veclenbuf: [u8; 4] = [0; 4];
        let encoded = &Self::encode_msg(data);
        let len     = encoded.len();
        let veclen  = to_vec(&len).unwrap();
        let mut i = 0;
        for byte in veclen {
            veclenbuf[i] = byte;
            i = i+1;
        }
        writer.write_all(&veclenbuf).await.unwrap();
        return writer.write_all(encoded).await;
    }

    pub async fn read_control(reader: &mut (dyn AsyncRead + Unpin)) -> Result<DullControl, std::io::Error> {
        let mut control_buffer = [0; 256];

        let mut n = 0;
        while n == 0 {

            let mut handle_size = reader.take(4);
            let sizevec         = handle_size.read(&mut control_buffer[..]).await?;
            let (size, _taken)  = from_slice_limit(&control_buffer[0..sizevec]).unwrap();

            println!("told to read {} bytes", size);
            // size is number of bytes to read now.
            let mut handle = reader.take(size);

            n = handle.read(&mut control_buffer[..]).await?;
            println!("Got a message of length {}", n);
        }

        let dc = decode_msg(&control_buffer[0..n]);

        return Ok(dc);
    }
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
    use super::{DullControl};
    use super::{encode_msg, from_slice, decode_msg};
    use super::{ControlStream, ErrorKind, UnixStream};

    macro_rules! aw {
        ($e:expr) => {
            tokio_test::block_on($e)
        };
    }

    async fn do_read_write_control_stream() {
        let mut fs = ControlStream::empty();
        let ex = DullControl::Exit;
        fs.write_control(&ex).await.unwrap();
    }

    #[test]
    fn test_read_write_control_stream() {
        aw!(do_read_write_control_stream());
    }

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

        //let pipe =

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
    #[allow(dead_code)]
    async fn read_write_admin_via_socket(data: &DullControl) -> Result<DullControl, std::io::Error> {

        let (mut reader, mut writer) = tokio::io::duplex(256);

        write_control(&mut writer, data).await.unwrap();
        return read_control(&mut reader).await;
    }

    #[allow(dead_code)]
    //#[test]
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
