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

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq)]
pub enum GraspMessageType {
    M_NOOP = 0,
    M_DISCOVERY = 1,
    M_RESPONSE =  2,
    M_REQ_NEG =   3,
    M_REQ_SYN =   4,
    M_NEGOTIATE = 5,
    M_END =       6,
    M_WAIT =      7,
    M_SYNCH =     8,
    M_FLOOD =     9
}
pub const M_INVALID:      u64 = 99;
pub const O_DIVERT:       u64 = 100;
pub const O_ACCEPT:       u64 = 101;
pub const O_DECLINE:      u64 = 102;

pub const O_IPV6_LOCATOR: u64 = 103;
pub const O_IPV4_LOCATOR: u64 = 104;
pub const O_FQDN_LOCATOR: u64 = 105;
pub const O_URI_LOCATOR:  u64 = 106;

pub const F_DISC: u32 = 1 << 0;     // valid for discovery
pub const F_NEG:  u32 = 1 << 1;     // valid for negotiation
pub const F_SYNC: u32 = 1 << 2;     // valid for synchronization
pub const F_NEG_DRY: u32 = 1 << 3;  // negotiation is dry-run


#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq)]
enum GraspLocator {
    O_IPv6_LOCATOR { v6addr: Ipv6Addr, transport_proto: u16, port_number: u16},  /* 103 */
    O_IPv4_LOCATOR { v4addr: Ipv4Addr, transport_proto: u16, port_number: u16},  /* 104 */
    O_FQDN_LOCATOR { fqdn: String, transport_proto: u16, port_number: u16 },     /* 105 */
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

#[derive(Debug, PartialEq)]
pub struct GraspMessage {
    pub mtype:      GraspMessageType,
    pub session_id: SessionID,
    pub initiator:  Ipv6Addr,
    pub ttl:        Ttl,
    pub objectives: Vec<GraspObjective>
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
    let v6addr = decode_ipv6_cbytes(&array[1])?;
    let transport_proto = match array[2] {
        CborType::Integer(num) => num,
        _ => return Err(ConnectError::MisformedGraspObjective)
    };
    let port_number = match array[3] {
        CborType::Integer(num) => num,
        _ => return Err(ConnectError::MisformedGraspObjective)
    };

    Ok(Some(GraspLocator::O_IPv6_LOCATOR { v6addr: v6addr,
                                           transport_proto: (transport_proto & 0xffff) as u16,
                                           port_number:     (port_number & 0xffff) as u16 }))
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

fn decode_objective(ctobjpair: &Vec<CborType>) -> Result<GraspObjective, ConnectError>
{
    match &ctobjpair[0] {
        CborType::Array(obj) => {
            //println!("name: {:?} size: {}", obj[0], obj.len());

            let name = match &obj[0] {
                CborType::String(name)    => name,
                _ => {
                    //println!("not a string");
                    return Err(ConnectError::MisformedGraspObjective)
                }
            };

            let flags = match &obj[1] {
                CborType::Integer(flags)  => flags,
                _ => {
                    //println!("not an int");
                    return Err(ConnectError::MisformedGraspObjective)
                }
            };

            let loopcnt = match &obj[2] {
                CborType::Integer(loopcnt) => loopcnt,
                _ => {
                    //println!("not an int");
                    return Err(ConnectError::MisformedGraspObjective)
                }
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
        _ => {
            //println!("not correct array");
            return Err(ConnectError::MisformedGraspObjective)
        }
    }
}

fn decode_objectives(objectives: &[CborType]) -> Result<Vec<GraspObjective>, ConnectError> {
    let mut object_vec = Vec::<GraspObjective>::new();
    let mut objerror = None;
    let mut _objcount = 0;

    for stuff in objectives {
        _objcount += 1;
        match stuff {
            CborType::Array(objective) => {
                //println!("{} len: {} objectives: {:?}", objcount, objective.len(), objective);

                if objective.len() < 2 {
                    objerror = Some(Err(ConnectError::MisformedGraspObjective));
                    continue;
                }
                let mobj = decode_objective(objective);

                if let Ok(obj) = mobj {
                    object_vec.push(obj);
                } else {
                    objerror = Some(mobj);
                    continue;
                }
            }
            _ => {
                return Err(ConnectError::MisformedGraspMessage)
            }
        }
    }

    // if no objectives, and saw an error, then return it.
    if object_vec.len() == 0 {
        match objerror {
            None => {},
            _ => {
                println!("no objectives, only errors");
                return Err(ConnectError::MisformedGraspMessage)
            },
        }
    }

    /* otherwise, return vector of objectives, even if empty. */
    Ok(object_vec)
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

/* this is dumb, but rust does not let one have distinguished unions which also have explicit values */
fn encode_grasp_mtype(msg: &GraspMessage) -> u64 {
    match msg.mtype {
        GraspMessageType::M_NOOP => 0,
        GraspMessageType::M_DISCOVERY => 1,
        GraspMessageType::M_RESPONSE  => 2,
        GraspMessageType::M_REQ_NEG   => 3,
        GraspMessageType::M_REQ_SYN   => 4,
        GraspMessageType::M_NEGOTIATE => 5,
        GraspMessageType::M_END       => 6,
        GraspMessageType::M_WAIT      => 7,
        GraspMessageType::M_SYNCH     => 8,
        GraspMessageType::M_FLOOD     => 9
    }
}

fn encode_grasp_locator(loc: &GraspLocator) -> CborType {
    match loc {
        GraspLocator::O_IPv6_LOCATOR { v6addr, transport_proto, port_number} => {
            CborType::Array(vec![CborType::Integer(O_IPV6_LOCATOR),
                                 CborType::Bytes(v6addr.octets().to_vec()),
                                 CborType::Integer(*transport_proto as u64),
                                 CborType::Integer(*port_number as u64)])
        },
        GraspLocator::O_IPv4_LOCATOR { v4addr, transport_proto, port_number} => {
            CborType::Array(vec![CborType::Integer(O_IPV4_LOCATOR),
                                 CborType::Bytes(v4addr.octets().to_vec()),
                                 CborType::Integer(*transport_proto as u64),
                                 CborType::Integer(*port_number as u64)])
        },
        GraspLocator::O_FQDN_LOCATOR { fqdn, transport_proto, port_number}   => {
            CborType::Array(vec![CborType::Integer(O_FQDN_LOCATOR),
                                 CborType::String(fqdn.to_string()),
                                 CborType::Integer(*transport_proto as u64),
                                 CborType::Integer(*port_number as u64)])
        },
        GraspLocator::O_URI_LOCATOR  { uri, transport_proto, port_number }   => {
            CborType::Array(vec![CborType::Integer(O_URI_LOCATOR),
                                 CborType::String(uri.to_string()),
                                 CborType::Integer(*transport_proto as u64),
                                 CborType::Integer(*port_number as u64)])
        },
    }
}

fn encode_grasp_objective(obj: &GraspObjective) -> CborType {
    let mut objbase = vec![CborType::String(obj.objective_name.clone()),
                           CborType::Integer(obj.objective_flags as u64),
                           CborType::Integer(obj.loop_count as u64)];
    if let Some(value) = &obj.objective_value {
        objbase.push(CborType::String(value.to_string()));
    }
    let mut objv = vec![CborType::Array(objbase)];
    if let Some(locator) = &obj.locator {
        objv.push(encode_grasp_locator(locator));
    }
    CborType::Array(objv)
}

impl GraspMessage {
    fn decode_grasp_noop(session_id: SessionID, _contents: &Vec<CborType>) -> Result<GraspMessage, ConnectError> {
        Ok(GraspMessage {
            mtype: GraspMessageType::M_NOOP,
            session_id: session_id,
            ttl: 0,
            initiator: Ipv6Addr::UNSPECIFIED,
            objectives: vec![]
        })
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

        let objectives = decode_objectives(&contents[4..])?;

        Ok(GraspMessage { mtype: GraspMessageType::M_FLOOD,
                          session_id: session_id,
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

    pub fn encode_dull_grasp_message(msg: GraspMessage) -> Result<CborType, ConnectError> {
        let mtype = encode_grasp_mtype(&msg);
        let mut msgvec = vec![CborType::Integer(mtype),
                          CborType::Integer(msg.session_id as u64),
                          CborType::Bytes(msg.initiator.octets().to_vec()),
                          CborType::Integer(msg.ttl as u64)];
        for obj in msg.objectives {
            msgvec.push(encode_grasp_objective(&obj));
        }
        let msg = CborType::Array(msgvec);
        Ok(msg)
    }

}

#[cfg(test)]
mod tests {
    use crate::graspsamples;
    use cbor::decoder::decode;
    use std::fs::File;
    use std::io::Write;
    use super::*;

    #[test]
    fn test_parse_grasp_000() -> Result<(), ConnectError> {
        let s000 = &graspsamples::PACKET_000;
        assert_eq!(s000[14], 0x60);   /* IPv6 packet */

        let slice = &s000[(54+8)..];
        assert_eq!(slice[0], 0x85);   /* beginning of array */
        let thing = decode(slice).unwrap();
        GraspMessage::decode_grasp_message(thing)?;

        Ok(())
    }

    #[test]
    fn test_parse_grasp_420() -> Result<(), ConnectError> {
        let s000 = &graspsamples::PACKET_420;
        assert_eq!(s000[14], 0x60);   /* IPv6 packet */

        let slice = &s000[(54+8)..];
        assert_eq!(slice[0], 0x85);   /* beginning of array */
        let thing = decode(slice).unwrap();
        GraspMessage::decode_grasp_message(thing)?;

        Ok(())
    }

    #[test]
    fn test_parse_grasp_s01() -> Result<(), ConnectError> {
        let s001 = &graspsamples::PACKET_S01;

        assert_eq!(s001[0], 0x85);   /* beginning of array */
        let thing = decode(s001).unwrap();
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

    fn build_locator_01() -> Vec<CborType> {
        let v6_01  = vec![0xfe, 0x80,0,0, 0,0,0,0,
                          0,    0,   0,0, 0,0,0x11,0x22];

        let v6_b01 = CborType::Bytes(v6_01);

        let locator = vec![CborType::Integer(O_IPV6_LOCATOR),
                           v6_b01,
                           CborType::Integer(IPPROTO_TCP as u64),
                           CborType::Integer(4598)];
        return locator;
    }

    fn build_locator_c02() -> CborType {
        return CborType::Array(build_locator_01());
    }

    #[test]
    fn test_ipv6_locator_01() {
        let locator = build_locator_01();
        let result = grasp_parse_ipv6_locator(&locator);
        let expectv6 = "FE80::1122".parse::<Ipv6Addr>().unwrap();
        let expected = Ok(Some(GraspLocator::O_IPv6_LOCATOR { v6addr: expectv6,
                                                              transport_proto: IPPROTO_TCP,
                                                              port_number: 4598} ));
        assert_eq!(result, expected);
    }

    #[test]
    fn test_ipv6_locator_02() {
        let locator  = build_locator_c02();

        let expectv6 = "FE80::1122".parse::<Ipv6Addr>().unwrap();
        let expected = Ok(Some(GraspLocator::O_IPv6_LOCATOR { v6addr: expectv6,
                                                              transport_proto: IPPROTO_TCP,
                                                              port_number: 4598} ));
        let result = grasp_parse_locator(&locator);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_ipv4_locator_03() {

        let locator4 = vec![CborType::Integer(O_IPV4_LOCATOR),
                            CborType::Bytes(vec![127,0,0,1]),
                            CborType::Integer(IPPROTO_TCP as u64),
                            CborType::Integer(4598)];
        let result = grasp_parse_ipv6_locator(&locator4);
        assert_eq!(result, Err(ConnectError::MisformedIpv6Addr));

        let result = grasp_parse_locator(&CborType::Array(locator4));
        assert_eq!(result, Err(ConnectError::UnimplementedGraspStuff));
    }

    fn build_objective_c01() -> CborType {
        let obj01 = CborType::Array(vec![CborType::String("EX1@example".to_string()),
                                         CborType::Integer(4),            /* F_SYNCH */
                                         CborType::Integer(32),           /* loop-count */
                                         CborType::String("HELP!".to_string())]);
        return obj01;
    }

    fn build_objective_c03() -> CborType {
        let obj03 = CborType::Array(vec![CborType::String("EX2@example".to_string()),
                                         CborType::Integer(6),            /* F_SYNCH */
                                         CborType::Integer(31),           /* loop-count */
                                         CborType::String("Goaway!".to_string())]);
        return obj03;
    }

    #[test]
    fn test_flood_objective() {
        let contents = vec![CborType::Array(vec![build_objective_c01(),
                                                 build_locator_c02()]),
                            CborType::Array(vec![build_objective_c03(),
                                                 build_locator_c02()])];
        let result = decode_objectives(&contents[..]);

        let expectv6 = "FE80::1122".parse::<Ipv6Addr>().unwrap();
        let exp_locator1 = Some(GraspLocator::O_IPv6_LOCATOR { v6addr: expectv6,
                                                               transport_proto: IPPROTO_TCP,
                                                               port_number: 4598} );

        let exp_locator2 = Some(GraspLocator::O_IPv6_LOCATOR { v6addr: expectv6,
                                                               transport_proto: IPPROTO_TCP,
                                                               port_number: 4598} );

        assert_eq!(result, Ok(vec![GraspObjective { objective_name: "EX1@example".to_string(),
                                                    objective_flags: 4,
                                                    loop_count: 32,
                                                    objective_value: Some("HELP!".to_string()),
                                                    locator: exp_locator1 },
                                   GraspObjective { objective_name: "EX2@example".to_string(),
                                                    objective_flags: 6,
                                                    loop_count: 31,
                                                    objective_value: Some("Goaway!".to_string()),
                                                    locator: exp_locator2 }]));
    }

    fn write_cbortype_to_file(cbor: &CborType, fname: &str) -> Result<(), std::io::Error> {
        let mut file = File::create(fname)?;

        let bytes = cbor.serialize();
        file.write_all(&bytes)?;
        Ok(())
    }

    #[test]
    fn test_create_mflood() -> Result<(), std::io::Error> {
        let expectv6 = "FE80::1122".parse::<Ipv6Addr>().unwrap();

        let myhost_locator = GraspLocator::O_IPv6_LOCATOR { v6addr: expectv6,
                                                            transport_proto: IPPROTO_UDP,
                                                            port_number: 500 };

        let flood_obj = GraspObjective { objective_name: "AN_ACP".to_string(),
                                         objective_flags: F_SYNC,
                                         loop_count: 1,             // link-local only!
                                         objective_value: Some("IKEv2".to_string()),
                                         locator: Some(myhost_locator) };

        let msg = GraspMessage { mtype: GraspMessageType::M_FLOOD,
                                 session_id: 14,
                                 initiator: expectv6,
                                 ttl: 1,
                                 objectives: vec![flood_obj] };

        let cbor  = GraspMessage::encode_dull_grasp_message(msg).unwrap();
        write_cbortype_to_file(&cbor, "samples/flood1.bin")?;

        let bytes = cbor.serialize();
        assert_eq!(bytes, graspsamples::PACKET_S01);
        Ok(())
    }

    #[test]
    fn test_locator_encoder() {
        let l1 = GraspLocator::O_IPv6_LOCATOR { v6addr: "FE80::1122".parse::<Ipv6Addr>().unwrap(),
                                                transport_proto: IPPROTO_TCP,
                                                port_number: 1234 };
        let _cbor1 = encode_grasp_locator(&l1);

        let l2 = GraspLocator::O_IPv4_LOCATOR { v4addr: "10.11.12.14".parse::<Ipv4Addr>().unwrap(),
                                                transport_proto: IPPROTO_TCP,
                                                port_number: 4567 };
        let _cbor2 = encode_grasp_locator(&l2);

        let l3 = GraspLocator::O_FQDN_LOCATOR { fqdn: "grasp.example".to_string(),
                                                transport_proto: IPPROTO_UDP,
                                                port_number: 6789 };
        let _cbor3 = encode_grasp_locator(&l3);

        let l4 = GraspLocator::O_URI_LOCATOR { uri: "http://grasp.example".to_string(),
                                                transport_proto: IPPROTO_TCP,
                                                port_number: 8080 };
        let _cbor4 = encode_grasp_locator(&l4);

    }

}



