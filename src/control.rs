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
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::io::{AsyncWriteExt, AsyncReadExt};
//use tokio::io::{AsyncRead, AsyncWrite};
//use tokio::io::DuplexStream;

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

//#[derive(Debug)]
pub struct ControlStream {
//    sock:   UnixStream,
    reader: OwnedReadHalf,
    writer: OwnedWriteHalf
//    reader: DuplexStream,
    //    writer: DuplexStream
//    reader: Box<(dyn AsyncRead  + Unpin)>,
//    writer: Box<(dyn AsyncWrite + Unpin)>
}

impl ControlStream {
    pub fn child(sock: UnixStream) -> ControlStream {
        let (r, w) = sock.into_split();
        ControlStream {
            reader: r,
            writer: w
        }
    }

    // mostly identical to client, but we'll see!
    pub fn parent(sock: UnixStream) -> ControlStream {
        let (r, w) = sock.into_split();
        ControlStream {
//            sock:   sock,
            reader: r,
            writer: w
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

    pub async fn write_control(self: &mut Self, data: &DullControl) -> Result<(), std::io::Error> {

        let mut veclenbuf: [u8; 4] = [0; 4];
        let encoded = &Self::encode_msg(data);
        let len     = encoded.len();
        let veclen  = to_vec(&len).unwrap();
        let mut i = 0;
        for byte in veclen {
            veclenbuf[i] = byte;
            i = i+1;
        }
        self.writer.write_all(&veclenbuf).await.unwrap();
        return self.writer.write_all(encoded).await;
    }

    pub async fn read_control(self: &mut Self) -> Result<DullControl, std::io::Error> {
        // let reader : &mut (dyn AsyncRead + Unpin)
        let mut size_buffer    = [0; 4];
        let mut control_buffer = [0; 256];

        let mut n = 0;
        while n == 0 {

            //let handle_size     = &mut self.reader.take(4);
            let size_n   = self.reader.read(&mut size_buffer[..]).await?;
            let (size, _taken)  = from_slice_limit(&size_buffer[0..size_n]).unwrap();

            println!("told to read {} bytes", size);
            // size is number of bytes to read now.
            n = self.reader.read(&mut control_buffer[0..size]).await?;

            println!("Got a message of length {}", n);
        }

        let dc = Self::decode_msg(&control_buffer[0..n]);

        return Ok(dc);
    }

    pub async fn write_child_ready(self: &mut Self) -> Result<(), std::io::Error> {
        // mut writer: &mut tokio::net::UnixStream
        let result = self.write_control(&DullControl::ChildReady).await;

        match result  {
            Err(e) => match e.kind() {
                ErrorKind::BrokenPipe  => { return Ok(()); }, // maybe die?
                _                      => { return Ok(()); }  // maybe error.
            }
            _ => { return Ok(()); }
        }
    }


}

#[cfg(test)]
mod tests {
    use super::{DullControl};
    use super::from_slice;
    use super::{ControlStream, ErrorKind};
    use tokio::net::UnixStream;

    macro_rules! aw {
        ($e:expr) => {
            tokio_test::block_on($e)
        };
    }

    async fn make_parent_child_streams(parent: UnixStream, child: UnixStream) -> (ControlStream, ControlStream) {
        let pfs = ControlStream::parent(parent);
        let cfs = ControlStream::child(child);
        return (cfs, pfs);
    }

    async fn do_read_write_control_stream() {
        let (parent,child)  = UnixStream::pair().unwrap();
        let (_cfs, mut pfs) = make_parent_child_streams(parent, child).await;

        let ex = DullControl::Exit;
        pfs.write_control(&ex).await.unwrap();
    }

    #[test]
    fn test_read_write_control_stream() {
        aw!(do_read_write_control_stream());
    }

    #[test]
    fn test_encode_decode_quit() {
        let data = DullControl::Exit;

           let e = ControlStream::encode_msg(&data);

        // decode it.
        let d: DullControl = from_slice(&e).unwrap();

        assert_eq!(d, data);
    }

    #[test]
    fn test_encode_decode_admindown() {
        let data = DullControl::AdminDown { interface_index: 5u32 };

        //note that encode/decode can only handle a single message

        // encode it.
        let e = ControlStream::encode_msg(&data);

        // decode it.
        let d: DullControl = ControlStream::decode_msg(&e);

        assert_eq!(d, data);
    }

    async fn do_decode_multi_message() {
        let data1 = DullControl::AdminDown { interface_index: 5u32 };
        let data2 = DullControl::AdminDown { interface_index: 6u32 };

        // setup the pipes for things.
        let (parent, child)  = UnixStream::pair().unwrap();
        let (mut cfs, mut pfs) = make_parent_child_streams(parent, child).await;

        pfs.write_control(&data1).await.unwrap();
        pfs.write_control(&data2).await.unwrap();

        // decode it.
        let d: DullControl = cfs.read_control().await.unwrap();

        assert_eq!(d, data1);
    }

    #[test]
    fn test_decode_multi_message() {
        aw!(do_decode_multi_message());
    }

    /* this function just helps the test case below, since tests can not do await */
    #[allow(dead_code)]
    async fn read_write_admin_via_socket(data: &DullControl) -> Result<DullControl, std::io::Error> {
        let (parent,child)  = UnixStream::pair().unwrap();
        let (mut cfs, mut pfs) = make_parent_child_streams(parent, child).await;

        pfs.write_control(data).await.unwrap();
        return cfs.read_control().await;
    }

    #[allow(dead_code)]
    //#[test]
    fn test_write_read_admin_via_socket() {
        let data = DullControl::AdminDown { interface_index: 5u32 };

        assert_eq!(aw!(read_write_admin_via_socket(&data)).unwrap(), data);
    }

    async fn write_admin_via_closed_socket(data: &DullControl) -> Result<(), std::io::Error> {
        let (parent,child)  = UnixStream::pair().unwrap();
        let (_cfs, mut pfs) = make_parent_child_streams(parent, child).await;

        match pfs.write_control(data).await {
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
