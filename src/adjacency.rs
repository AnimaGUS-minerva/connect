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
use std::fmt;
use futures::lock::{Mutex};

use crate::dull::DullInterface;
use crate::grasp;

#[derive(Debug)]
pub struct Adjacency {
    pub interface:     Arc<Mutex<DullInterface>>,
    pub v6addr:        Ipv6Addr,
    pub ikeport:       u16,
    pub advertisement_count:      u32,
    pub tunnelup:      bool
}

impl fmt::Display for Adjacency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let updown = if self.tunnelup { "tun-up" } else { "tun-down" };
        write!(f, "cnt:{:05} v6:[{}]:{}  {}",
               self.advertisement_count, self.v6addr, self.ikeport, updown)
    }
}

impl Adjacency {
    pub fn empty(di: Arc<Mutex<DullInterface>>) -> Adjacency {
        Adjacency { interface: di.clone(),
                    v6addr:    Ipv6Addr::UNSPECIFIED,
                    ikeport:   0,
                    advertisement_count: 0,
                    tunnelup:  false }
    }

    pub fn increment(self: &mut Adjacency) {
        self.advertisement_count += 1;
    }

    pub fn adjacency_from_mflood(di: Arc<Mutex<DullInterface>>,
                               gm: grasp::GraspMessage) -> Option<Adjacency> {

        for obj in gm.objectives {
            if obj.objective_name != "AN_ACP" { continue; }
            if !obj.is_sync()                 { continue; }
            if obj.loop_count !=1             { continue; }
            if let Some(val) = obj.objective_value {
                if val != "IKEv2"             { continue; }
            } else                            { continue; }
            if let Some(loc1) = obj.locator {
                match loc1 {
                    grasp::GraspLocator::O_IPv6_LOCATOR { v6addr, transport_proto: grasp::IPPROTO_UDP, port_number } => {
                        return Some(Adjacency { interface: di.clone(),
                                                v6addr:    v6addr,
                                                ikeport:   port_number,
                                                advertisement_count: 0,
                                                tunnelup:  false })
                    }
                    _ => { continue; }
                }
            }
        }

        return None;
    }

}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adding_adjacency() {
        let di = DullInterface::empty(1);
        let amdi = Arc::new(Mutex::new(di));
        let ad = Adjacency::adjacency_from_mflood(amdi, grasp::tests::create_mflood()).unwrap();
        println!("mflood: {}", ad);
    }
}


