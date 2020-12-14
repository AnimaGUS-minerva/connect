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
extern crate nix;
extern crate tokio;
extern crate moz_cbor as cbor;
use std::net::Ipv6Addr;
use std::net::Ipv4Addr;
use crate::error::ConnectError;
use cbor::CborType;

pub const GRASP_PORT: u32 = 7017;
pub const IPPROTO_TCP: u16 = 6;
pub const IPPROTO_UDP: u16 = 17;

type SessionID  = u32;
type Ttl        = u32;  /* miliseconds */

pub const M_NOOP:         u64 = 0;
pub const M_DISCOVERY:    u64 = 1;
pub const M_RESPONSE:     u64 = 2;
pub const M_REQ_NEG:      u64 = 3;
pub const M_REQ_SYN:      u64 = 4;
pub const M_NEGOTIATE:    u64 = 5;
pub const M_END:          u64 = 6;
pub const M_WAIT:         u64 = 7;
pub const M_SYNCH:        u64 = 8;
pub const M_FLOOD:        u64 = 9;
pub const M_INVALID:      u64 = 99;
pub const O_DIVERT:       u64 = 100;
pub const O_ACCEPT:       u64 = 101;
pub const O_DECLINE:      u64 = 102;
pub const O_IPV6_LOCATOR: u64 = 103;
pub const O_IPV4_LOCATOR: u64 = 104;
pub const O_FQDN_LOCATOR: u64 = 105;
pub const O_URI_LOCATOR:  u64 = 106;


#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq)]
enum GraspLocator {
    #[allow(dead_code)]
    O_IPv6_LOCATOR { v6addr: Ipv6Addr, transport_proto: u16, port_number: u16},  /* 103 */
    #[allow(dead_code)]
    O_IPv4_LOCATOR { v4addr: Ipv4Addr, transport_proto: u16, port_number: u16},  /* 104 */
    #[allow(dead_code)]
    O_FQDN_LOCATOR { fqdn: String, transport_proto: u16, port_number: u16 },     /* 105 */
    #[allow(dead_code)]
    O_URI_LOCATOR  { uri: String, transport_proto: u16, port_number: u16 }       /* 106 */
}

#[derive(Debug, PartialEq)]
pub struct GraspObjective {
    objective_name: String,
    objective_flags: u32,
    loop_count: u8,
    objective_value: Option<String>,
    locator: Option<GraspLocator>
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq)]
pub enum GraspMessage {
    M_NOOP,
    M_DISCOVERY,
    M_RESPONSE,
    M_REQ_NEG,
    M_REQ_SYN,
    M_NEGOTIATE,
    M_END,
    M_WAIT,
    M_SYNCH,
    M_FLOOD { session_id: SessionID, initiator: Ipv6Addr, ttl: Ttl, objectives: Vec<GraspObjective> },
}

fn decode_ipv6_bytes(bytes: &Vec<u8>) -> Result<Ipv6Addr, ConnectError> {
    if bytes.len() == 16 {
        let mut addrbytes = [0u8; 16];
        for b in 0..16 {
            addrbytes[b] = bytes[b];
        }
        Ok(Ipv6Addr::from(addrbytes))
    } else {
        return Err(ConnectError::MisformedIpv6Addr);
    }
}

fn decode_ipv6_cbytes(cbytes: &CborType) -> Result<Ipv6Addr, ConnectError> {
    match cbytes {
        CborType::Bytes(bytes) => decode_ipv6_bytes(&bytes),
        _ => Err(ConnectError::MisformedIpv6Addr)
    }
}

fn grasp_parse_ipv4_locator(_array: &Vec<CborType>) -> Result<Option<GraspLocator>, ConnectError>
{
    return Err(ConnectError::UnimplementedGraspStuff);
}

fn grasp_parse_fqdn_locator(_array: &Vec<CborType>) -> Result<Option<GraspLocator>, ConnectError>
{
    return Err(ConnectError::UnimplementedGraspStuff);
}

fn grasp_parse_uri_locator(_array: &Vec<CborType>) -> Result<Option<GraspLocator>, ConnectError>
{
    return Err(ConnectError::UnimplementedGraspStuff);
}

fn grasp_parse_ipv6_locator(array: &Vec<CborType>) -> Result<Option<GraspLocator>, ConnectError>
{
    /* draft-ietf-anima-grasp-15:
     * locator-option /= [O_IPv6_LOCATOR, ipv6-address,
     *        transport-proto, port-number]
     * ipv6-address = bytes .size 16
     */

    if array.len() < 4 {
        return Err(ConnectError::MisformedGraspObjective);
    }
    let _v6addrbytes = decode_ipv6_cbytes(&array[1])?;
    Err(ConnectError::MisformedGraspObjective)
}

fn grasp_parse_locator(ctlocator: &CborType) -> Result<Option<GraspLocator>, ConnectError>
{
    /* if it is not an array, then return None */
    let ctarray = match ctlocator {
        CborType::Array(obj) => obj,
        _ => return Ok(None)
    };

    match ctarray[0] {
        CborType::Integer(O_IPV6_LOCATOR) => grasp_parse_ipv6_locator(ctarray),
        CborType::Integer(O_IPV4_LOCATOR) => grasp_parse_ipv4_locator(ctarray),
        CborType::Integer(O_FQDN_LOCATOR) => grasp_parse_fqdn_locator(ctarray),
        CborType::Integer(O_URI_LOCATOR)  => grasp_parse_uri_locator(ctarray),
        _ => return Err(ConnectError::MisformedGraspObjective)
    }
}

fn grasp_parse_objective(ctobjpair: &Vec<CborType>) -> Result<GraspObjective, ConnectError>
{
    match &ctobjpair[0] {
        CborType::Array(obj) => {
            println!("name: {:?} size: {}", obj[0], obj.len());

            let name = match &obj[0] {
                CborType::String(name)    => name,
                _ => return Err(ConnectError::MisformedGraspObjective)
            };

            let flags = match &obj[1] {
                CborType::Integer(flags)  => flags,
                _ => return Err(ConnectError::MisformedGraspObjective)
            };

            let loopcnt = match &obj[2] {
                CborType::Integer(loopcnt) => loopcnt,
                _ => return Err(ConnectError::MisformedGraspObjective)
            };

            let locator = grasp_parse_locator(&ctobjpair[1])?;
            let value = if obj.len() >= 3 {
                match &obj[3] {
                    CborType::String(strvalue)=> Some(strvalue.clone()),
                    _ => None
                }
            } else {
                None
            };

            /* now look for a locator */
            Ok(GraspObjective { objective_name: name.to_string(),
                                objective_flags: (flags & 0xffffffff) as u32,
                                loop_count: (loopcnt & 0xff) as u8,
                                objective_value: value,
                                locator: locator
            })
        }
        _ => return Err(ConnectError::MisformedGraspObjective)
    }
}

fn decode_base_grasp(contents: &Vec<CborType>) -> Result<(u32, u32), ConnectError> {
    let msgtype = match contents[0] {
        CborType::Integer(num) => num as u32,
        _ => return Err(ConnectError::MisformedGraspMessage)
    };
    let session_id = match contents[1] {
        CborType::Integer(id) => id as u32,
        _ => return Err(ConnectError::MisformedGraspMessage)
    };
    Ok((msgtype, session_id))
}

impl GraspMessage {
    fn decode_grasp_noop(_session_id: SessionID, _contents: &Vec<CborType>) -> Result<GraspMessage, ConnectError> {
        Ok(GraspMessage::M_NOOP)
    }

    fn decode_grasp_discovery(_session_id: SessionID, _contents: &Vec<CborType>) -> Result<GraspMessage, ConnectError> {
        Err(ConnectError::MisformedGraspMessage)
    }

    fn decode_grasp_response(_session_id: SessionID, _contents: &Vec<CborType>) -> Result<GraspMessage, ConnectError> {
        Err(ConnectError::MisformedGraspMessage)
    }

    fn decode_grasp_req_neg(_session_id: SessionID, _contents: &Vec<CborType>) -> Result<GraspMessage, ConnectError> {
        Err(ConnectError::MisformedGraspMessage)
    }

    fn decode_grasp_req_syn(_session_id: SessionID, _contents: &Vec<CborType>) -> Result<GraspMessage, ConnectError> {
        Err(ConnectError::MisformedGraspMessage)
    }

    fn decode_grasp_negotiate(_session_id: SessionID, _contents: &Vec<CborType>) -> Result<GraspMessage, ConnectError> {
        Err(ConnectError::MisformedGraspMessage)
    }

    fn decode_grasp_end(_session_id: SessionID, _contents: &Vec<CborType>) -> Result<GraspMessage, ConnectError> {
        Err(ConnectError::MisformedGraspMessage)
    }

    fn decode_grasp_wait(_session_id: SessionID, _contents: &Vec<CborType>) -> Result<GraspMessage, ConnectError> {
        Err(ConnectError::MisformedGraspMessage)
    }

    fn decode_grasp_synch(_session_id: SessionID, _contents: &Vec<CborType>) -> Result<GraspMessage, ConnectError> {
        Err(ConnectError::MisformedGraspMessage)
    }

    fn decode_grasp_flood(session_id: SessionID, contents: &Vec<CborType>) -> Result<GraspMessage, ConnectError> {
        let initiator = match &contents[2] {
            CborType::Bytes(bytes) => {
                decode_ipv6_bytes(bytes)?
            },
            _ => return Err(ConnectError::MisformedGraspMessage)
        };

        let ttl = match contents[3] {
            CborType::Integer(num) => num,
            _ => return Err(ConnectError::MisformedGraspMessage)
        };

        let objectives = match &contents[4] {
            CborType::Array(stuff) => {
                println!("objectives: {:?}", stuff);
                let mut object_vec = Vec::<GraspObjective>::new();

                let mut objerror = None;

                for ctobjpair in stuff.iter() {
                    let objective = match ctobjpair {
                        CborType::Array(objective) => objective,
                        _ => {
                            objerror = Some(Err(ConnectError::MisformedGraspObjective));
                            continue;
                        }
                    };

                    if objective.len() <= 2 {
                        objerror = Some(Err(ConnectError::MisformedGraspObjective));
                        continue;
                    }
                    let mobj = grasp_parse_objective(objective);

                    if let Ok(obj) = mobj {
                        object_vec.push(obj);
                    } else {
                        objerror = Some(mobj);
                        continue;
                    }
                }
                // if no objectives, and saw an error, then return it.
                if object_vec.len() == 0 {
                    match objerror {
                        None => {},
                        _ => return Err(ConnectError::MisformedGraspMessage),
                    }
                }

                /* otherwise, return vector of objectives, even if empty. */
                object_vec
            }
            _ => return Err(ConnectError::MisformedGraspMessage)
        };

        Ok(GraspMessage::M_FLOOD { session_id: session_id,
                                   initiator: initiator,
                                   ttl: (ttl & 0xffffffff) as u32,
                                   objectives: objectives })
    }

    pub fn decode_grasp_message(thing: CborType) -> Result<GraspMessage, ConnectError> {
        match thing {
            CborType::Array(contents) if contents.len() >= 2 => {
                let (msgtype, session_id) = decode_base_grasp(&contents)?;
                match msgtype {
                    0 => Self::decode_grasp_noop(session_id, &contents),
                    1 => Self::decode_grasp_discovery(session_id, &contents),
                    2 => Self::decode_grasp_response(session_id, &contents),
                    3 => Self::decode_grasp_req_neg(session_id, &contents),
                    4 => Self::decode_grasp_req_syn(session_id, &contents),
                    5 => Self::decode_grasp_negotiate(session_id, &contents),
                    6 => Self::decode_grasp_end(session_id, &contents),
                    7 => Self::decode_grasp_wait(session_id, &contents),
                    8 => Self::decode_grasp_synch(session_id, &contents),
                    9 => Self::decode_grasp_flood(session_id, &contents),
                    _ => return Err(ConnectError::MisformedGraspMessage)
                }
            },
            _ => return Err(ConnectError::MisformedGraspMessage)
        }
    }

    pub fn decode_dull_grasp_message(thing: CborType) -> Result<GraspMessage, ConnectError> {
        match thing {
            CborType::Array(contents) if contents.len() >= 2 => {
                let (msgtype, session_id) = decode_base_grasp(&contents)?;
                match msgtype {
                    0 => Self::decode_grasp_noop(session_id, &contents),
                    9 => Self::decode_grasp_flood(session_id, &contents),
                    _ => return Err(ConnectError::IllegalDullGraspMessage)
                }
            },
            _ => return Err(ConnectError::MisformedGraspMessage)
        }
    }

}

#[allow(unused_imports)]
use crate::graspsamples;

#[allow(unused_imports)]
use cbor::decoder::decode;

#[test]
fn test_parse_grasp_001() -> Result<(), ConnectError> {
    let s001 = &graspsamples::PACKET_001;
    assert_eq!(s001[14], 0x60);   /* IPv6 packet */

    let slice = &s001[(54+8)..];
    assert_eq!(slice[0], 0x85);   /* beginning of array */
    let thing = decode(slice).unwrap();
    GraspMessage::decode_grasp_message(thing)?;

    Ok(())
}

#[test]
fn test_valid_ipv6_bytes() {
    let v6_01 = vec![0xfe, 0x80, 0,0,0,0,0,0,
                     0,    0,    0,0,0,0,0,1];
    let expected = "FE80::1".parse::<Ipv6Addr>().unwrap();
    assert_eq!(decode_ipv6_bytes(&v6_01).unwrap(), expected);

    let v6_02 = vec![0xfe, 0x80, 0,0,0,0,0,0,
                     0,    0,    0,0,0,0,0];  /* too short by one byte */
    let result = decode_ipv6_bytes(&v6_02);
    let expected = Err(ConnectError::MisformedIpv6Addr);
    assert_eq!(expected, result);

    let v6_03 = vec![0xfe, 0x80, 0,0,0,0,0,0,0,0,
                     0,    0,    0,0,0,0,0];  /* too long by one byte */
    let result = decode_ipv6_bytes(&v6_03);
    let expected = Err(ConnectError::MisformedIpv6Addr);
    assert_eq!(expected, result);
}

#[test]
fn test_valid_ipv6_cbor_bytes() {
    let v6_01  = vec![0xfe, 0x80,0,0, 0,0,0,0,
                      0,    0,   0,0, 0,0,0,1];
    let v6_b01 = CborType::Bytes(v6_01);
    let expected = "FE80::1".parse::<Ipv6Addr>().unwrap();
    assert_eq!(decode_ipv6_cbytes(&v6_b01).unwrap(), expected);

    let v6_02 = vec![0xfe, 0x80, 0,0,0,0,0,0,
                     0,    0,    0,0,0,0,0];  /* too short by one byte */
    let v6_b02 = CborType::Bytes(v6_02);
    let result = decode_ipv6_cbytes(&v6_b02);
    let expected = Err(ConnectError::MisformedIpv6Addr);
    assert_eq!(expected, result);

    let v6_03 = vec![0xfe, 0x80, 0,0,0,0,0,0,0,0,
                     0,    0,    0,0,0,0,0];  /* too long by one byte */
    let v6_b03 = CborType::Bytes(v6_03);
    let result = decode_ipv6_cbytes(&v6_b03);
    let expected = Err(ConnectError::MisformedIpv6Addr);
    assert_eq!(expected, result);
}
