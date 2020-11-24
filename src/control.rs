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
use std::io::{Error, ErrorKind};
use std::net::Shutdown;
//use tokio_serde::formats::*;
//use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};
use std::os::unix::net::UnixStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};

use crate::dull::Dull;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum DullControl {
    Exit,
    AdminDown { interface_index: u32 }
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
    return writer.write_all(&encode_msg(data)).await;
}

pub async fn read_control(reader: &mut tokio::net::UnixStream) -> Result<DullControl, std::io::Error> {
    let mut control_buffer = [0; 256];
    let n = reader.read(&mut control_buffer[..]).await?;

    let dc = decode_msg(&control_buffer[0..n]);
    return Ok(dc);
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

    // encode it.
    let e = encode_msg(&data);

    // decode it.
    let d: DullControl = decode_msg(&e);

    assert_eq!(d, data);
}

/* this function just helps the test case below, since tests can not do await */
#[allow(dead_code)]
async fn read_write_admin_via_socket(data: &DullControl) -> Result<DullControl, std::io::Error> {
    let pair = UnixStream::pair().unwrap();

    let mut reader = tokio::net::UnixStream::from_std(pair.1).unwrap();
    let mut writer = tokio::net::UnixStream::from_std(pair.0).unwrap();

    write_control(&mut writer, data).await.unwrap();
    return read_control(&mut reader).await;
}

#[allow(unused_macros)]
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

#[allow(dead_code)]
async fn write_admin_via_closed_socket(data: &DullControl) -> Result<(), std::io::Error> {
    let pair = UnixStream::pair().unwrap();

    let reader = tokio::net::UnixStream::from_std(pair.1).unwrap();
    let mut writer = tokio::net::UnixStream::from_std(pair.0).unwrap();

    // kill the reading side.
    reader.shutdown(Shutdown::Both).unwrap();

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
