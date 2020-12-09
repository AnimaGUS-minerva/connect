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
extern crate num;

use num::FromPrimitive;

pub const GRASP_PORT: u32 = 7017;

enum_from_primitive! {
    #[allow(non_camel_case_types)]
    #[derive(Debug, PartialEq)]
    pub enum MESSAGE_TYPE {
        M_NOOP = 0,
        M_DISCOVERY = 1,
        M_RESPONSE = 2,
        M_REQ_NEG = 3,
        M_REQ_SYN = 4,
        M_NEGOTIATE = 5,
        M_END = 6,
        M_WAIT = 7,
        M_SYNCH = 8,
        M_FLOOD = 9,
        M_INVALID = 99
    }
}

#[test]
fn test_grasp_message_type() {
    assert_eq!(MESSAGE_TYPE::from_i32(9), Some(MESSAGE_TYPE::M_FLOOD));
}

