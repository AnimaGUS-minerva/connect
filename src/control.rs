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
use serde::{Serialize, Deserialize};

extern crate serde_cbor;
use serde_cbor::{to_vec,from_slice};

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


pub fn send_dull() {
    println!("send dull");
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
