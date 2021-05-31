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

//use nix::unistd::*;
use std::net::Ipv6Addr;
use tokio::net::UdpSocket;
use tokio::time::{delay_for, Duration};
use std::io::Error;
use std::io::ErrorKind;
//use std::net::SocketAddrV6;
use std::net::{SocketAddrV6,SocketAddr};
use std::sync::Arc;
use futures::lock::Mutex;
use tokio::process::{Command};
use rand::Rng;
use netlink_packet_sock_diag::constants::IPPROTO_UDP;

use cbor::CborType;
use cbor::decoder::decode as cbor_decode;

use crate::dull::{DullChild,DullInterface};
use crate::grasp;
use crate::grasp::{GraspMessage, GraspMessageType};
use crate::error::ConnectError;
use crate::adjacency::Adjacency;

#[derive(Debug)]
pub struct GraspDaemon {
    pub dullif:       Arc<Mutex<DullInterface>>,
    pub dullchild:    Arc<Mutex<DullChild>>,
    pub addr:         Ipv6Addr,
    pub grasp_dest:   std::net::SocketAddr
}

impl GraspDaemon {
    pub async fn initdaemon(lifn: Arc<Mutex<DullInterface>>,
                            child: Arc<Mutex<DullChild>>) -> Result<(GraspDaemon,
                                                                        tokio::net::UdpSocket,
                                                                        tokio::net::UdpSocket),Error> {

        let ifn  = lifn.lock().await;
        let llv6 = ifn.linklocal6;
        let ifindex = ifn.ifindex;

        use socket2::{Socket, Domain, Type};

        let rsin6 = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED,
                                      grasp::GRASP_PORT as u16, 0, ifindex);

        // create a UDP socket
        let rawfd = Socket::new(Domain::ipv6(), Type::dgram(), None).unwrap();

        // set port/address reuse options.
        rawfd.set_reuse_port(true).unwrap();
        rawfd.set_reuse_address(true).unwrap();
        rawfd.set_nonblocking(true).unwrap();
        match rawfd.bind(&socket2::SockAddr::from(rsin6)) {
            Ok(()) => {
                let udp1 = rawfd.into_udp_socket();
                let recv = UdpSocket::from_std(udp1).unwrap();

                // join it to a multicast group
                let grasp_mcast = "FF02:0:0:0:0:0:0:13".parse::<Ipv6Addr>().unwrap();
                recv.join_multicast_v6(&grasp_mcast, ifindex).unwrap();

                let ssin6 = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED,
                                              0 as u16, 0, ifindex);
                let send = UdpSocket::bind(ssin6).await.unwrap();

                let gp = GraspDaemon { addr: llv6,
                                       grasp_dest:  SocketAddr::V6(SocketAddrV6::new(grasp_mcast, grasp::GRASP_PORT as u16, 0, ifindex)),
                                       dullif: lifn.clone(),
                                       dullchild: child.clone(),
                };
                return Ok((gp, recv, send))
            }
            Err(err) => {
                if err.kind() == ErrorKind::AddrInUse {
                    println!("Address already in use?");
                }
                Command::new("ss")
                    .arg("-uan")
                    .status().await
                    .expect("ss command failed to start");
                Command::new("ip")
                    .arg("link")
                    .arg("ls")
                    .status().await
                    .expect("ss command failed to start");
                Command::new("ip")
                    .arg("addr")
                    .arg("ls")
                    .status().await
                    .expect("ss command failed to start");
                return Err(err);
            }
        }
    }

    pub async fn read_loop(gd: Arc<Mutex<GraspDaemon>>,
                           dd: Arc<Mutex<DullChild>>,
                           mut recv: tokio::net::UdpSocket /*tokio::net::udp::RecvHalf*/) {

        //let _runtime = { dd.lock().await.runtime.clone() };
        let mut cnt: u32 = 0;

        let mut debug_graspdaemon = {
            dd.lock().await.data.lock().await.debug.debug_graspdaemon
        };
        let mut auto_up_adj = {
            dd.lock().await.data.lock().await.auto_up_adj
        };
        loop {
            let mut bufbytes = [0u8; 2048];

            let (myll6addr,myifindex) = {
                let gdl = gd.lock().await;
                let ifn = gdl.dullif.lock().await;
                (ifn.linklocal6,ifn.ifindex)
            };

            if debug_graspdaemon {
                println!("listening on GRASP socket {:?}", recv);
            }
            let results = recv.recv_from(&mut bufbytes).await;
            match results {
                Ok((size, addr)) => {

                    // need to check to see if this might be an echo from self, so have to check
                    // through the linklocal6 for all our interfaces.
                    match addr {
                        SocketAddr::V6(addr6) => {
                            let v6origin = addr6.ip();
                            if addr6.scope_id() != myifindex {
                                if debug_graspdaemon {
                                    println!("GD: ignoring message from different ifindex: {} vs {}",
                                             addr6.scope_id(), myifindex);
                                }
                                continue;
                            }

                            // search list of interfaces now
                            let dcl  = dd.lock().await;
                            let data = dcl.data.lock().await;

                            for (k,ldi) in &data.interfaces {
                                let di = ldi.lock().await;
                                if di.linklocal6 == *v6origin {
                                    if debug_graspdaemon {
                                        println!("GD: ignoring announcement from self ({}: {})", k, addr);
                                    }
                                    continue;
                                }
                            }
                        }
                        SocketAddr::V4(_addr4) => { // not IPv6, so
                            continue;
                        }
                    }

                    if debug_graspdaemon {
                        println!("{}: grasp daemon read: {} bytes from {}", cnt, size, addr);
                    }
                    let graspmessage = match cbor_decode(&bufbytes) {
                        Ok(cbor) => {
                            match GraspMessage::decode_grasp_message(cbor) {
                                Ok(msg) => msg,
                                err @ _ => {
                                    println!("   invalid grasp message: {:?}", err);
                                    continue;
                                }
                            }
                        },
                        err @ _ => {
                            println!("   invalid cbor in message: {:?}", err);
                            continue;
                        }
                    };

                    if debug_graspdaemon {
                        // now we have a graspmessage which we'll do something with!
                        println!("{} grasp message: {:?}", cnt, graspmessage);
                    }

                    let ladj = {
                        let gdl = gd.lock().await;
                        let mut dil = gdl.dullif.lock().await;

                        /* insert into list of edges */
                        let sadj = Adjacency::adjacency_from_mflood(gdl.dullif.clone(), graspmessage);
                        if let Some(mut adj) = sadj {

                            // only pay attention to adjacencies that are from LLv6 addresses
                            // but this has been "unstable" for 5 years.
                            //if !adj.v6addr.is_unicast_link_local() {
                            // continue;
                            //}
                            if adj.v6addr.segments()[0] != 0xfe80 {
                                continue;
                            }

                            if adj.v6addr == myll6addr {
                                // self-announcment
                                continue;
                            }

                            /* make copy of ifindex, cause having it is cheap */
                            adj.ifindex = dil.ifindex;

                            let nadj = dil.adjacencies.entry(adj.v6addr).or_insert_with(|| {
                                Arc::new(Mutex::new(adj))
                            });

                            /* return the adjancy for further use */
                            nadj.clone()
                        } else {
                            /* something wrong, obviously not real/valid adjancency, go read more */
                            continue;
                        }
                    };

                    let mut adj = ladj.lock().await;
                    adj.increment();

                    /* bring the dang thing up!! */
                    let result = adj.up(auto_up_adj).await;
                    match result {
                        Err(stuff) => { println!("error: {:?}", stuff); }
                        Ok(_) => { }
                    }
                }
                Err(msg) => {
                    println!("{} grasp read got error: {:?}", cnt, msg);
                    // deal with socket closed?
                }
            }

            debug_graspdaemon = {
                dd.lock().await.data.lock().await.debug.debug_graspdaemon
            };

            auto_up_adj = {
                dd.lock().await.data.lock().await.auto_up_adj
            };

            cnt += 1;
        }
    }

    pub async fn construct_acp_mflood(gd: Arc<Mutex<GraspDaemon>>,
                                      _dd: Arc<Mutex<DullChild>>) -> Result<CborType, ConnectError>
    {
        let myllv6 = {
            let gdl = gd.lock().await;
            gdl.addr
        };

        let mut rng = rand::thread_rng();
        let sesid = rng.gen::<u32>();

        let ike_locator = grasp::GraspLocator::O_IPv6_LOCATOR { v6addr: myllv6,
                                                         transport_proto: IPPROTO_UDP,
                                                         port_number: 500 };
        let acp_objective =grasp::GraspObjective { objective_name: "AN_ACP".to_string(),
                                                   objective_flags: grasp::F_SYNC,
                                                   loop_count: 1,  /* do not leave link */
                                                   objective_value: Some("IKEv2".to_string()),
                                                   locator: Some(ike_locator) };
        let flood = grasp::GraspMessage { mtype: GraspMessageType::M_FLOOD,
                                          session_id: sesid,
                                          initiator: myllv6,
                                          ttl: 10000,
                                          objectives: vec![acp_objective] };

        GraspMessage::encode_dull_grasp_message(flood)
    }

    pub async fn announce_loop(gd: Arc<Mutex<GraspDaemon>>,
                               dd: Arc<Mutex<DullChild>>,
                               mut send: tokio::net::UdpSocket /*tokio::net::udp::SendHalf*/) {
        let v6mcast = {
            let gld = gd.lock().await;
            gld.grasp_dest
        };
        let mut loops = 0;

        loop {
            loops += 1;
            let mflood = Self::construct_acp_mflood(gd.clone(), dd.clone()).await.unwrap();
            let bytes = mflood.serialize();

            let exitnow = {
                let dcl = dd.lock().await;
                let ddl = dcl.data.lock().await;
                ddl.exit_now
            };

            if exitnow {
                std::process::exit(0);
            }

            send.send_to(&bytes, &v6mcast).await.unwrap();
            /*
            let size = match wsize {
                Ok(size) => size,
                _ => { println!("announce error: {:?}", wsize); }
            };
            if size != bytes.len() {
                println!("short write: {}", size);
            }
            */
            delay_for(Duration::from_millis(5000)).await;
            if (loops % 12) == 0 {
                /* every minutes, print out the list of all adjancies */
                let gdl = gd.lock().await;
                let dil = gdl.dullif.lock().await;

                let mut num = 0;
                println!("\nInterface #{} {} [{}]", dil.ifindex, dil.ifname, dil.linklocal6);
                for (_if6, ladj) in &dil.adjacencies {
                    let adj = ladj.lock().await;
                    println!("   {}: {}", num, *adj);
                    num += 1;
                };

            }
        }

    }

    pub async fn start_loop(gd: Arc<Mutex<GraspDaemon>>,
                            recv: /*tokio::net::udp::RecvHalf*/ tokio::net::UdpSocket,
                            send: /*tokio::net::udp::SendHalf*/ tokio::net::UdpSocket,
                            dd: Arc<Mutex<DullChild>>) {

        let child3  = dd.clone();
        let child4  = dd.clone();
        let gd3     = gd.clone();
        let gd4     = gd.clone();

        let runtime = dd.lock().await.runtime.clone();

        runtime.spawn(async move {
            GraspDaemon::announce_loop(gd4, child4, send).await;
        });

        runtime.spawn(async move {
            GraspDaemon::read_loop(gd3, child3, recv).await;
        });

    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dull;

    macro_rules! aw {
        ($e:expr) => {
            tokio_test::block_on($e)
        };
    }

    async fn construct_grasp_daemon(dc: Arc<Mutex<DullChild>>, addr: &str) -> Result<GraspDaemon, std::io::Error> {
        let mut dd = dull::DullData::empty();

        let val = addr.to_string().parse::<Ipv6Addr>().unwrap();
        let ifindex = 0;
        let lifn = dd.get_entry_by_ifindex(ifindex).await;
        {
            let mut ifn  = lifn.lock().await;
            ifn.linklocal6 = val;
        }

        let (gd, _, _) = GraspDaemon::initdaemon(lifn.clone(), dc.clone()).await.unwrap();
        return Ok(gd);
    }

    async fn send_mflood_message(dc: Arc<Mutex<DullChild>>) -> Result<(), std::io::Error> {
        let _gp = construct_grasp_daemon(dc, "fe80::11").await.unwrap();
        Ok(())
    }


    #[test]
    fn test_send_mflood() {
        let dc = DullChild::empty();
        aw!(send_mflood_message(dc.clone())).unwrap();
    }
}


