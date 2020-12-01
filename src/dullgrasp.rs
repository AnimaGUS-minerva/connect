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

use nix::unistd::*;
//use libc::AF_INET6;
//use libc::in6_addr;

use net2::UdpBuilder;
use std::net::Ipv6Addr;
use tokio::net::UdpSocket;
use crate::dull::IfIndex;
use crate::grasp::GRASP_PORT;
use std::io::Error;
//use nix::sys::socket::sockaddr_in6;
//use std::net::SocketAddr;
use std::net::SocketAddrV6;

#[derive(Debug)]
pub struct GraspDaemon {
    pub addr:    Ipv6Addr,
    pub socket:  tokio::net::UdpSocket
}

impl GraspDaemon {
    pub fn initdaemon(llv6: Ipv6Addr, ifindex: IfIndex) -> Result<GraspDaemon, Error> {

        let sin6 = SocketAddrV6::new(llv6, GRASP_PORT as u16, 0, ifindex);

        let std_sock = UdpBuilder::new_v6().unwrap().bind(sin6)?;         // .reuse_address(true);
        let sock = UdpSocket::from_std(std_sock).unwrap();

        let gp = GraspDaemon { addr: llv6, socket: sock };

        return Ok(gp)
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

    let _gp = GraspDaemon::initdaemon(val, 0);
    Ok(())
}


#[test]
fn test_construct_grasp_daemon() {
    assert_eq!(aw!(construct_grasp_daemon()).unwrap(), ());
}
