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
use std::sync::Arc;
use std::net::Ipv6Addr;
use futures::lock::Mutex;

use crate::dull::DullInterface;

#[derive(Debug)]
pub struct Adjacency {
    pub interface:     Arc<Mutex<DullInterface>>,
    pub v6addr:        Ipv6Addr,
    pub ikeport:       u16,
    pub tunnelup:      bool
}

impl Adjacency {
    pub fn empty(di: Arc<Mutex<DullInterface>>) -> Adjacency {
        Adjacency { interface: di.clone(),
                    v6addr:    Ipv6Addr::UNSPECIFIED,
                    ikeport:   0,
                    tunnelup:  false }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! aw {
        ($e:expr) => {
            tokio_test::block_on($e)
        };
    }

    #[test]
    fn test_adding_adjacency() {
        let di = DullInterface::empty(1);
        let _ad = Adjacency::empty(Arc::new(Mutex::new(di)));

    }
}


