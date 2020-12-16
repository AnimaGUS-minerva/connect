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
use std::io::Error;
use std::net::SocketAddrV6;
use std::sync::Arc;
use futures::lock::Mutex;

use cbor::decoder::decode as cbor_decode;
use crate::dull::{DullChild,DullInterface};
use crate::grasp;
use crate::grasp::GraspMessage;

#[derive(Debug)]
pub struct GraspDaemon {
    pub dullif:       Arc<Mutex<DullInterface>>,
    pub addr:         Ipv6Addr,
    pub recv_socket:  tokio::net::udp::RecvHalf,
    pub send_socket:  tokio::net::udp::SendHalf
}

impl GraspDaemon {
    pub async fn initdaemon(lifn: Arc<Mutex<DullInterface>>) -> Result<GraspDaemon, Error> {

        let ifn  = lifn.lock().await;
        let llv6 = ifn.linklocal6;
        let ifindex = ifn.ifindex;
        //let sin6 = SocketAddrV6::new(llv6, GRASP_PORT as u16, 0, ifindex);
        let sin6 = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED,
                                     grasp::GRASP_PORT as u16, 0, ifindex);

        let sock = UdpSocket::bind(sin6).await.unwrap();

        // join it to a multicast group
        let grasp_mcast = "FF02:0:0:0:0:0:0:13".parse::<Ipv6Addr>().unwrap();
        sock.join_multicast_v6(&grasp_mcast, ifindex).unwrap();

        let (recv, send) = sock.split();

        let gp = GraspDaemon { addr: llv6,
                               recv_socket: recv,
                               send_socket: send,
                               dullif: lifn.clone()
        };

        return Ok(gp)
    }

    pub async fn read_loop(gd: Arc<Mutex<GraspDaemon>>,
                           dd: Arc<Mutex<DullChild>>) {

        let _runtime = dd.lock().await.runtime.clone();
        let gdd = gd.clone();
        let mut cnt: u32 = 0;
        loop {
            let mut bufbytes = [0u8; 2048];

            let results = {
                let mut gdl = gdd.lock().await;
                gdl.recv_socket.recv_from(&mut bufbytes).await
            };
            match results {
                Ok((size, addr)) => {
                    if dd.lock().await.data.lock().await.debug_graspdaemon {
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

                    // now we have a graspmessage which we'll do something with!
                    println!("{} grasp message: {:?}", cnt, graspmessage);

                }
                Err(msg) => {
                    println!("{} grasp read got error: {:?}", cnt, msg);
                    // deal with socket closed?
                }
            }
            cnt += 1;
        }
    }

    pub async fn announce_loop(_gd: Arc<Mutex<GraspDaemon>>,
                               _dd: Arc<Mutex<DullChild>>) {
            /*
        loop {
            let mut bufbytes = [0u8; 2048];
            let mflood = GraspMessage::construct_acp_account();
            GraspMessage::encode_grasp_mflood(cbor);
        }
             */

    }

    pub async fn start_loop(gd: Arc<Mutex<GraspDaemon>>,
                            dd: Arc<Mutex<DullChild>>) {

        let child3  = dd.clone();
        let runtime = dd.lock().await.runtime.clone();
        let gd3     = gd.clone();

        runtime.spawn(async move {
            GraspDaemon::read_loop(gd3, child3).await;
        });

        let child4  = dd.clone();
        runtime.spawn(async move {
            GraspDaemon::announce_loop(gd, child4).await;
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

    async fn construct_grasp_daemon(addr: &str) -> Result<GraspDaemon, std::io::Error> {
        let mut dd = dull::DullData::empty();

        let val = addr.to_string().parse::<Ipv6Addr>().unwrap();
        let ifindex = 0;
        let lifn = dd.get_entry_by_ifindex(ifindex).await;
        {
            let mut ifn  = lifn.lock().await;
            ifn.linklocal6 = val;
        }

        return GraspDaemon::initdaemon(lifn.clone()).await;
    }

    async fn send_mflood_message() -> Result<(), std::io::Error> {
        let _gp = construct_grasp_daemon("fe80::11").await.unwrap();
        Ok(())
    }


    #[test]
    fn test_send_mflood() {
        aw!(send_mflood_message()).unwrap();
    }
}


