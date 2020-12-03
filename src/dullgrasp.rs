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

use std::net::Ipv6Addr;
use tokio::net::UdpSocket;
use std::io::Error;
use std::net::SocketAddrV6;
use std::sync::Arc;
use futures::lock::Mutex;

use crate::dull::{IfIndex,DullChild};
use crate::grasp::GRASP_PORT;

#[derive(Debug)]
pub struct GraspDaemon {
    pub addr:    Ipv6Addr,
    pub socket:  Arc<tokio::net::UdpSocket>
}

impl GraspDaemon {
    pub async fn initdaemon(llv6: Ipv6Addr, ifindex: IfIndex) -> Result<GraspDaemon, Error> {

        let sin6 = SocketAddrV6::new(llv6, GRASP_PORT as u16, 0, ifindex);

        let sock = UdpSocket::bind(sin6).await.unwrap();

        // join it to a multicast group
        let grasp_mcast = "FF02:0:0:0:0:0:0:13".parse::<Ipv6Addr>().unwrap();
        sock.join_multicast_v6(&grasp_mcast, ifindex).unwrap();

        let gp = GraspDaemon { addr: llv6, socket: Arc::new(sock) };

        return Ok(gp)
    }

    pub async fn read_loop(_gd: Arc<Mutex<GraspDaemon>>,
                           dd: Arc<Mutex<DullChild>>) {

        let _runtime = dd.lock().await.runtime.clone();
        loop {
            println!("loop in grasp daemon");
        }
    }

}

#[allow(unused_imports)]
use crate::error::ConnectError;

#[allow(unused_macros)]
macro_rules! aw {
    ($e:expr) => {
        tokio_test::block_on($e)
    };
}

#[allow(dead_code)]
async fn construct_grasp_daemon() -> Result<(), std::io::Error> {
    let val = "::1".parse::<Ipv6Addr>().unwrap();

    let _gp = GraspDaemon::initdaemon(val, 0).await;
    Ok(())
}


#[test]
fn test_construct_grasp_daemon() {
    assert_eq!(aw!(construct_grasp_daemon()).unwrap(), ());
}
