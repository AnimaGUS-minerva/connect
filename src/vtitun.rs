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

use std::os::raw::{c_char, c_uint, c_int};
use std::ffi::CString;
use std::net::Ipv6Addr;
use std::io::Error;
use crate::dull::IfIndex;

extern {
    fn create_vti6_tunnel(tunname: *const c_char,
                          tunkey:  c_uint,
                          physdev_ifindex: c_uint,
                          tunloc:  *const c_char,  /* should be IPv6 address, presentation form */
                          tunrem:  *const c_char) -> c_int;
}


pub fn create(tunname: &str,
              physdev_index: IfIndex,
              tunloc: Ipv6Addr,
              tunrem: Ipv6Addr,
              tunkey: u16) -> Result<(), std::io::Error> {

    let tunname_c = CString::new(tunname).unwrap();

    let tunloc_a  = tunloc.to_string();
    let tunrem_a  = tunrem.to_string();

    let tunloc_c  = CString::new(tunloc_a).unwrap();
    let tunrem_c  = CString::new(tunrem_a).unwrap();
    let result = unsafe {
        create_vti6_tunnel(tunname_c.as_ptr(), tunkey as u32,
                           physdev_index as u32,
                           tunloc_c.as_ptr(), tunrem_c.as_ptr())
    };
    if result == 0 {
        return Ok(());
    } else {
        return Err(Error::from_raw_os_error(result));
    }
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


