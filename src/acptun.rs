/*
 * Copyright [2022] <mcr@sandelman.ca>

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

//use std::os::raw::{c_char, c_uint, c_int};
//use std::ffi::CString;
use std::net::Ipv6Addr;
//use std::io::Error;
use crate::dull::IfIndex;
use rtnetlink::{Handle};

pub fn create(_handle:  &Handle,
              _tunname: &str,
              _physdev_index: IfIndex,
              _tunloc: Ipv6Addr,
              _tunrem: Ipv6Addr,
              _tunkey: u16) -> Result<(), std::io::Error> {

    return Ok(());
}


/*
 * this test only works as root, and on Linux.
 *
 */
#[cfg(test)]
mod tests {
    use super::*;
    use nix::unistd::Uid;

    #[test]
    fn test_vtitun() {
        let tunname = "test6";
        let tunloc  = "fe80::5054:ff:fe51:12bc".parse::<Ipv6Addr>().unwrap();
        let tunrem  = "fe80::5054:ff:fe51:daff".parse::<Ipv6Addr>().unwrap();
        let physdev_ifindex = 1;  /* usually loopback */

        if Uid::current().is_root() {
            let x = create(tunname, physdev_ifindex, tunloc, tunrem, 7);
            assert_eq!(x.is_ok(), true);
        }
    }
}


