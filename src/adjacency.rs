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
//use std::io::{ErrorKind};
use futures::stream::TryStreamExt;
use futures::lock::{Mutex};
use netlink_packet_sock_diag::constants::IPPROTO_UDP;
use tokio::process::Command;

use crate::dull::DullInterface;
use crate::grasp;
use crate::vtitun;

#[derive(Debug)]
pub struct Adjacency {
    pub interface:     Arc<Mutex<DullInterface>>,
    pub ifindex:       u32,
    pub v6addr:        Ipv6Addr,                      // IPv6-LL of peer
    pub ikeport:       u16,
    pub advertisement_count:      u32,
    pub tunnelup:      bool,
    pub vti_iface:     String,
    pub vti_number:    Option<u16>
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
                    vti_number: None,
                    vti_iface:  "".to_string(),
                    ifindex:   0,
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
                    grasp::GraspLocator::O_IPv6_LOCATOR { v6addr, transport_proto: IPPROTO_UDP,
                                                          port_number } => {
                        let mut adj       = Self::empty(di);
                        adj.v6addr    = v6addr;
                        adj.ikeport   = port_number;
                        return Some(adj);
                    }
                    _ => { continue; }
                }
            }
        }

        return None;
    }

    pub async fn make_vti(self: &mut Adjacency) -> Result<(), rtnetlink::Error> {

        let handle;
        let vn;
        let ifn = self.interface.lock().await;

        let lgd = match &ifn.grasp_daemon {
            None => { return Ok(()); },
            Some(gd) => { gd.lock().await }
        };

        let mut dc = lgd.dullchild.lock().await;
        vn = dc.allocate_vti();
        self.vti_number = Some(vn);

        let dd = dc.data.lock().await;
        let acpns = dd.acpns;

        handle = match &dd.handle {
            None => { return Ok(()); },
            Some(handle) => handle
        };

        self.vti_iface  = format!("acp_{:03}", vn);
        let laddr = ifn.linklocal6.clone();
        let raddr = self.v6addr.clone();

        vtitun::create(&self.vti_iface, laddr, raddr, vn).unwrap();

        let mut vtiresult = handle.link().get().set_name_filter(self.vti_iface.clone()).execute();
        let vti_next = vtiresult.try_next().await;
        let vti_result = match vti_next {
            Err(repr) => { return Err(repr) },
            Ok(vtiresult) => vtiresult
        };
        let vti_link = match vti_result {
            Some(link) => link,
            None => {
                println!("did not find interface {}", self.vti_iface);
                return Err(rtnetlink::Error::RequestFailed);
            }
        };
        println!("created new ACP interface with ifindex: {}, moved to NS {}",
                 vti_link.header.index,
                 acpns);

        handle.link().set(vti_link.header.index).up().execute().await?;

        // now move this created entity to the ACP NS.
        handle
            .link()
            .set(vti_link.header.index)
            .setns_by_pid(acpns.as_raw() as u32)
            .execute()
            .await?;

        Ok(())
    }

    pub async fn up(self: &mut Adjacency) -> Result<(), rtnetlink::Error> {
        if self.vti_number == None {
            self.make_vti().await?;
        } else {
            return Ok(());
        }

        println!("adding adjancency on {} for {}", self.ifindex, self.v6addr);

        // see if we are trying to bring a tunnel up, and if not, then do so.
        let myll6addr = {
            let ifn = self.interface.lock().await;
            ifn.linklocal6
        };

        let vtinum = format!("{}", self.vti_number.unwrap());

        // but for now, run a script to do it manually.
        let _command = Command::new("/root/tunnel")
            .arg(self.vti_iface.to_string())
            .arg(vtinum)
            .arg(myll6addr.to_string())
            .arg(self.v6addr.to_string())
            .spawn().unwrap().await.unwrap();
        Ok(())
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

    #[test]
    fn test_adjacency_up() {
    }
}


