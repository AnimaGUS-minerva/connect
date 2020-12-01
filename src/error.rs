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
use std::fmt::Formatter;
use std::fmt::Error;

#[derive(Debug,Clone)]
pub enum ConnectError {
    NotIpV6Address,
}

fn fmt_connect_error(err: &ConnectError) -> &str {
    match err {
        ConnectError::NotIpV6Address => "Not an IPv6 Address"
    }
}

impl std::error::Error for ConnectError {
    fn description(&self) -> &str {
        fmt_connect_error(&self)
    }
}
impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "{}", fmt_connect_error(&self))
    }
}

