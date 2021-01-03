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

extern {
    fn create_vti6_tunnel(tunname: *const c_char,
                          tunkey:  c_uint,
                          tunloc:  *const c_char,  /* should be IPv6 address, presentation form */
                          tunrem:  *const c_char) -> c_int;
}

/*
 * this test only works as root, and on Linux.
 *
 */
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vtitun() {
        let tunname = "test6";
        let tunloc  = "fe80::5054:ff:fe51:12bc";
        let tunrem  = "fe80::5054:ff:fe51:daff";
        let tunname_c = CString::new(tunname).unwrap();
        let tunloc_c  = CString::new(tunloc).unwrap();
        let tunrem_c  = CString::new(tunrem).unwrap();
        let tunkey   = 7;
        let result = unsafe {
            create_vti6_tunnel(tunname_c.as_ptr(), tunkey,
                               tunloc_c.as_ptr(), tunrem_c.as_ptr())
        };
        assert_eq!(result, 0);
    }
}


