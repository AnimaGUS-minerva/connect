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
use tokio::time::{sleep, Duration};
use tokio::process::Command;

use crate::dull::DullInterface;
use crate::grasp;
use crate::acptun;
use crate::openswan::OpenswanWhackInterface;

#[derive(Debug)]
pub struct Adjacency {
    pub interface:     Arc<Mutex<DullInterface>>,
    pub ifindex:       u32,
    pub v6addr:        Ipv6Addr,                      // IPv6-LL of peer
    pub ikeport:       u16,
    pub advertisement_count:      u32,
    pub tunnelup:      bool,
    pub acp_iface:     String,
    pub acp_number:    Option<u16>,
    pub openswan_loaded: bool,
    pub pair_name:     String,
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
                    acp_number: None,
                    acp_iface:  "".to_string(),
                    ifindex:   0,
                    advertisement_count: 0,
                    openswan_loaded: false,
                    pair_name: "none".to_string(),
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

    pub async fn make_acp(self: &mut Adjacency) -> Result<(), rtnetlink::Error> {

        let handle;
        let vn;
        let ifn = self.interface.lock().await;

        let lgd = match &ifn.grasp_daemon {
            None => { return Ok(()); },
            Some(gd) => { gd.lock().await }
        };

        let mut dc = lgd.dullchild.lock().await;
        vn = dc.allocate_ifid();
        self.acp_number = Some(vn);

        let dd = dc.data.lock().await;
        let acpns = dd.acpns;

        handle = match &dd.handle {
            None => { return Ok(()); },
            Some(handle) => handle
        };

        let laddr = ifn.linklocal6.clone();
        let raddr = self.v6addr.clone();

        self.pair_name = OpenswanWhackInterface::pair_name(laddr, raddr);
        self.acp_iface  = format!("acp_{}", self.pair_name);

        println!("calling acp_tun with {} pair={}", self.acp_iface, self.pair_name);

        acptun::create(&handle, &self.acp_iface, ifn.ifindex, laddr, raddr, vn).await.unwrap();

        let mut acpresult = handle.link().get().match_name(self.acp_iface.clone()).execute();
        let acp_next  = acpresult.try_next().await;
        let acp_result = match acp_next {
            Err(repr) => { return Err(repr) },
            Ok(acpresult) => acpresult
        };
        let acp_link = match acp_result {
            Some(link) => link,
            None => {
                println!("did not find interface {}", self.acp_iface);
                return Err(rtnetlink::Error::RequestFailed);
            }
        };
        println!("created new ACP interface {} with ifindex: {} ({}), moved to NS {}",
                 self.acp_iface,
                 acp_link.header.index, vn,
                 acpns);

        handle.link().set(acp_link.header.index).up().execute().await?;

        if true {
            // now move this created entity to the ACP NS.
            handle
                .link()
                .set(acp_link.header.index)
                .setns_by_pid(acpns.as_raw() as u32)
                .execute()
                .await?;
        }

        Ok(())
    }

    pub async fn up(self: &mut Adjacency, auto_up: bool, disable_ikev2: bool) -> Result<(), rtnetlink::Error> {
        // A ACP will have been assigned already if we already trying to bring a tunnel up.
        if self.acp_number == None {
            self.make_acp().await?;
        } else {
            return Ok(());
        }

        let myll6addr = {
            let ifn = self.interface.lock().await;
            ifn.linklocal6
        };

        let ifid     = self.acp_number.unwrap();
        let ifid_str = format!("{}", ifid);

        println!("index: {} adding (adv:{}) for {} (ifid: {})", self.ifindex,
                 self.advertisement_count,
                 self.v6addr, ifid_str);

        if disable_ikev2 {
            // but for now, run a script to do it manually.
            let _command = Command::new("/root/tunnel")
                .arg(self.acp_iface.to_string())
                .arg(ifid_str)
                .arg(myll6addr.to_string())
                .arg(self.v6addr.to_string())
                .spawn().unwrap();
        } else {
            let policy_name = format!("c_{}", self.pair_name);
            OpenswanWhackInterface::add_adjacency(&self.acp_iface,
                                                  ifid as u32,
                                                  &policy_name,
                                                  myll6addr,
                                                  self.v6addr).await.unwrap();
            self.openswan_loaded = true;
            if auto_up {
                let myll6addr_str = format!("{}", myll6addr);
                let _adjacencycmd = Command::new("/root/newadj")
                                                 .arg(ifid_str)
                                                 .arg(myll6addr_str)
                                                 .arg(self.v6addr.to_string())
                                                 .spawn().unwrap();

                // now up the interface after a delay inspired by the
                // lowest octet of the IPv6-LL.   This results in both
                // sides deterministically agreeing on one side to initiate,
                // but both sides will try.  100 + 0-255 * 3 ~ 1s delay.
                let delay_time: u64 = 100 + (myll6addr.octets()[15] as u64) * 3;
                println!("waiting {}ms before activating {}", delay_time, policy_name);
                sleep(Duration::from_millis(delay_time)).await;

                OpenswanWhackInterface::up_adjacency(&policy_name).await.unwrap();
            } else {
                println!("Auto-Up is set to false");
            }
        }


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


