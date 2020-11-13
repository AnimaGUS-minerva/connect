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

use futures::prelude::*;
use serde::{Serialize, Deserialize};
use serde_cbor::{to_vec,from_slice};
use std::io::{Error, ErrorKind};
use tokio_serde::formats::*;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

use crate::dull::Dull;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum DullControl {
    Exit,
    AdminDown { interface_index: u32 }
}

pub fn encode_msg(thing: &DullControl) -> Vec<u8> {
    // encode it.
    return to_vec(&thing).unwrap();
}

pub fn decode_msg(msg: &Vec<u8>) -> DullControl {
    // decode it.
    return from_slice(msg).unwrap();
}

pub fn send_dull(_dull: &Dull, _thing: &DullControl) -> Result<bool, Error> {
    println!("send dull");
    return Ok(true);
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

async fn read_write_admin_via_socket(data: &DullControl) -> Result<DullControl, std::io::Error> {
    let pair = tokio::net::UnixStream::pair().unwrap();

    let my_write_stream = FramedWrite::new(pair.0, LengthDelimitedCodec::new());
    let mut serialized =
        tokio_serde::SymmetricallyFramed::new(my_write_stream, SymmetricalCbor::default());

    // write it. Assumes it does not block.
    serialized.send(&data).await.unwrap();

    // read it.
    //let d: DullControl = serde_cbor::from_reader(pair.1)?;
    let my_read_stream = FramedRead::new(pair.1, LengthDelimitedCodec::new());
    let mut deserialized =
        tokio_serde::SymmetricallyFramed::new(my_read_stream, SymmetricalCbor::default());

    if let Some(msg) = deserialized.try_next().await.unwrap() {
        return Ok(msg);
    } else {
        return Err(Error::new(ErrorKind::InvalidData, "failed to read"));
    }
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
