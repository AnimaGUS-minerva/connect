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

extern crate sysctl;

use std::sync::Arc;
use std::collections::HashMap;
use futures::stream::{StreamExt, TryStreamExt};
use futures::lock::Mutex;
//use tokio::process::{Command};
use netlink_packet_route::ErrorMessage;
use netlink_packet_route::constants::*;
use netlink_packet_route::link::nlas::State;
use rtnetlink::{
    constants::{RTMGRP_IPV6_ROUTE, RTMGRP_IPV6_IFADDR, RTMGRP_LINK},
    Error,  Error::NetlinkError,  Handle,
    new_connection,
    sys::SocketAddr,
};
use netlink_packet_route::{
    NetlinkPayload::InnerMessage,
    RtnlMessage::NewLink,
    RtnlMessage::NewAddress,
    RtnlMessage::NewRoute,
    RtnlMessage::DelRoute,
    RtnlMessage::DelAddress,
    RtnlMessage::DelLink,
    LinkMessage,
//    AddressMessage
};
//use std::os::unix::net::UnixStream;
//use sysctl::Sysctl;
use crate::dull;
use crate::dull::IfIndex;

#[derive(Debug)]
struct SystemInterface {
    pub ifindex:       IfIndex,
    pub ifname:        String,
    pub ignored:       bool,
    pub up:            bool,
    pub macvlan:       bool,
    pub bridge_master: bool,
    pub bridge_slave:  bool,
    pub ifchild:       Option<IfIndex>,   /* if we created an item to go with this one */
    pub ifmaster:      Option<IfIndex>,   /* if this is part of a bridge, then who it belongs to */
    pub mtu:           u32,
    pub deleted:       bool,
    pub has_dull_if:   bool,
}

/* so far only info we care about */
struct SystemInterfaces {
    pub system_interfaces:  HashMap<u32, Arc<Mutex<SystemInterface>>>,
    pub ifcount: u32,
}

impl SystemInterface {
    pub fn empty(ifi: IfIndex) -> SystemInterface {
        SystemInterface {
            ifindex: ifi,
            ifname:  "".to_string(),
            mtu:     0,
            up:      false,
            ignored: false,
            bridge_master:  false,
            bridge_slave:   false,
            ifchild:  None,
            ifmaster: None,
            deleted:  false,
            macvlan:  false,
            has_dull_if: false,
        }
    }
}

impl SystemInterfaces {
    pub fn empty() -> SystemInterfaces {
        SystemInterfaces {
            system_interfaces:  HashMap::new(), ifcount: 0
        }
    }

    pub async fn get_entry_by_ifindex<'a>(&'a mut self, ifindex: IfIndex) -> &'a Arc<Mutex<SystemInterface>> {
        let mut inc = 0;
        let ifnl = self.system_interfaces.entry(ifindex).or_insert_with(|| {
            inc += 1;
            Arc::new(Mutex::new(SystemInterface::empty(ifindex)))
        });
        self.ifcount += inc;
        return ifnl;
    }
}


pub async fn addremove_bridge(updown: bool,
                          handle: &Handle, _dull: &dull::Dull,
                          pname: &String, masterlink: u32) -> Result<(), Error> {

    let mut pull0 = handle.link().get().set_name_filter(pname.to_string()).execute();
    if let Some(link) = pull0.try_next().await? {
        // put the interface up or down
        if updown {
            handle
                .link()
                .set(link.header.index)
                .up()
                .execute()
                .await?;
        } else {
            handle
                .link()
                .set(link.header.index)
                .down()
                .execute()
                .await?;
        }

        // add/remove it into the trusted bridge
        handle
            .link()
            .set(link.header.index)
            .master(masterlink)
            .execute()
            .await?;
    }
    Ok(())
}

pub async fn setup_dull_bridge(handle: &Handle, dull: &dull::Dull, bridge: &String, name: &String) -> Result<(), Error> {

    let mut trusted = handle.link().get().set_name_filter(bridge.to_string()).execute();
    let trusted_link = match trusted.try_next().await? {
        Some(link) => link,
        None => { println!("did not find bridge {}", bridge); return Ok(()); }
    };

    let mut pname = name.clone();
    pname.insert(0, 'p');

    let result = handle
        .link()
        .add()
        .veth(name.clone().into(), pname.clone().into())
        .execute()
        .await;
    match result {
        Err(NetlinkError(ErrorMessage { code: -17, .. })) => { println!("network pair already created"); },
        Ok(_) => {},
        _ => {
            println!("new error: {:?}", result);
            std::process::exit(0);
        }
    };

    let mut dull0 = handle.link().get().set_name_filter(name.clone()).execute();
    if let Some(link) = dull0.try_next().await? {
        handle
            .link()
            .set(link.header.index)
            .up()
            .execute()
            .await?;
        handle
            .link()
            .set(link.header.index)
            .setns_by_pid(dull.dullpid.as_raw() as u32)
            .execute()
            .await?;
    } else {
        println!("no child link {} found", name);
        return Ok(());
    }

    addremove_bridge(true, handle, dull, &pname, trusted_link.header.index).await?;
    return Ok(());
}

async fn gather_parent_link_info(si: &mut SystemInterfaces,
                                 lm: &LinkMessage,
                                 newlink: bool) -> Result<(), Error> {
    let ifindex = lm.header.index;
    println!("processing ifindex: {:?} added={}", ifindex, newlink);

    /* look up reference this ifindex, or create it */
    let ifna = SystemInterfaces::get_entry_by_ifindex(si, ifindex).await;

    let mut ifn  = ifna.lock().await;

    /* see if we previously ignored it! */
    if ifn.ignored && newlink {
        println!("  ignored interface {}",ifn.ifname);
        return Ok(());
    }

    for nlas in &lm.nlas {
        use netlink_packet_route::link::nlas::Nla;
        match nlas {
            Nla::IfName(name) => {
                println!("  ifname: {}", name);
                if name == "lo" {
                    ifn.ignored = true;
                }
                ifn.ifname = name.to_string();
            },
            Nla::Mtu(bytes) => {
                println!("  mtu: {}", *bytes);
                ifn.mtu = *bytes;
            },
            Nla::OperState(state) => {
                match state {
                    State::Up => {
                        println!("  device is up");
                        ifn.up = true;
                    },
                    _ => { println!("  device in state {:?}", state); }
                }
            }
            Nla::Info(listofstuff) => {
                use netlink_packet_route::link::nlas::Info;
                //use netlink_packet_route::link::nlas::InfoData;
                use netlink_packet_route::link::nlas::InfoKind;
                for stuff in listofstuff {
                    match stuff {
                        Info::Kind(kind) => {
                            println!("  is it a bridge: {:?}", kind);
                            match kind {
                                InfoKind::Bridge => {
                                    ifn.bridge_master = true;
                                }
                                InfoKind::MacVlan => {
                                    ifn.macvlan = true;
                                }
                                _ => { println!("2 other kind {:?}", kind); }
                            }
                        }
                        Info::Data(_data) => { /* ignore bridge data */ }
                        Info::SlaveData(_data) => { /* ignore bridge data */ }
                        Info::SlaveKind(_data) => {
                            /* what exactly to do with this data? */
                            ifn.bridge_slave = true;
                        }
                        _ => { println!("other info: {:?}", stuff); }
                    }
                }
            }
            Nla::Link(ifmaster) | Nla::Master(ifmaster)     => {
                if newlink {
                    /* could be a bridge, or could be a MACvlan */
                    ifn.ifmaster = Some(*ifmaster);
                    println!("   master interface is {}", *ifmaster);
                } else {
                    println!("   removed interface {} from {}", ifindex, *ifmaster);
                    ifn.ifmaster = None;
                }
            }
            Nla::Address(_listofaddr) => { /* something with addresses */ }
            Nla::Carrier(_updown) => { /* something with the carrier */ }
            Nla::Qdisc(_) | Nla::Map(_) | Nla::Mode(_) | Nla::Broadcast(_) |
            Nla::CarrierChanges(_) | Nla::CarrierUpCount(_) | Nla::CarrierDownCount(_) |
            Nla::Other(_) | Nla::Group(_) | Nla::Promiscuity(_) |
            Nla::ProtoDown(_) | Nla::TxQueueLen(_) | Nla::NumTxQueues(_) | Nla::NumRxQueues(_) |
            Nla::GsoMaxSegs(_) | Nla::GsoMaxSize(_) | Nla::AfSpecInet(_) | Nla::AfSpecBridge(_) |
            Nla::ProtoInfo(_) | Nla::Event(_) |
            Nla::Stats64(_) | Nla::Stats(_) | Nla::Xdp(_) => { /* nothing */ }
            _ => { println!("index: {} system if nlas info: {:?}", ifindex, nlas); }
        }
    }

    if ifn.bridge_master {
        if let Some(childif) = ifn.ifchild {
            println!("  bridge parent interface {} has child pair {}", ifn.ifname, childif);
            return Ok(());
        }
    }

    if !newlink  {
        ifn.deleted = true;
    }

    Ok(())
}

async fn scan_interfaces(si: &mut SystemInterfaces, handle: &Handle) {
    let mut list = handle.link().get().execute();

    let mut cnt: u32 = 0;

    while let Some(link) = list.try_next().await.unwrap() {
        println!("message {}", cnt);
        gather_parent_link_info(si, &link, true).await.unwrap();
        cnt += 1;
    }
}


pub async fn parent_processing(rt: &Arc<tokio::runtime::Runtime>) -> Result<tokio::task::JoinHandle<Result<(),Error>>, String> {

    let rt1 = rt.clone();

    /* NETLINK listen_network activity daemon: process it all in the background */
    let listenhandle = rt.spawn(async move {

        let mut si = SystemInterfaces::empty();

        println!("opening netlink socket for monitor");

        // Open the netlink socket
        let (mut connection, handle, mut messages) = new_connection().map_err(|e| format!("{}", e)).unwrap();

        // These flags specify what kinds of broadcast messages we want to listen for.
        // we just care about LINK changes
        let mgroup_flags = RTMGRP_IPV6_ROUTE | RTMGRP_IPV6_IFADDR | RTMGRP_LINK;

        println!("starting parent processing loop");

        // A netlink socket address is created with said flags.
        let addr = SocketAddr::new(0, mgroup_flags);
        // Said address is bound so new conenctions and thus new message broadcasts can be received.
        connection.socket_mut().bind(&addr).expect("failed to bind");
        rt1.spawn(connection);

        /* first scan and process existing interfaces */
        scan_interfaces(&mut si, &handle).await;

        /* then process anything new that arrives */
        while let Some((message, _)) = messages.next().await {
            let payload = &message.payload;
            match payload {
                InnerMessage(NewLink(lm)) => {
                    gather_parent_link_info(&mut si, &lm, true).await.unwrap();
                }
                InnerMessage(NewAddress(_stuff)) => { /* nothing */ }
                InnerMessage(DelLink(lm)) => {
                    gather_parent_link_info(&mut si, &lm, false).await.unwrap();
                }
                InnerMessage(DelAddress(_stuff)) => { /* nothing */ }
                InnerMessage(NewRoute(_stuff)) => { /* nothing */ }
                InnerMessage(DelRoute(_stuff)) => { /* nothing */ }
                _ => { println!("msg type: {:?}", payload); }
            }
        };
        Ok(())
    });

    Ok(listenhandle)
}


#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_route::LinkHeader;
    use netlink_packet_route::link::nlas::Nla;

    fn make_eth0() -> netlink_packet_route::LinkMessage {
        LinkMessage {
            header: LinkHeader {
                interface_family: 0,
                index: 0,
                link_layer_type: ARPHRD_NETROM,
                flags: 0,
                change_mask: 0,
            },
            nlas: vec![
                Nla::IfName("eth0".to_string()),
                Nla::TxQueueLen(0),
            ],
        }
    }

    async fn a_basic_eth0() -> Result<(), std::io::Error> {
        let eth0 = make_eth0();
        let mut si = SystemInterfaces::empty();

        gather_parent_link_info(&mut si, &eth0, true).await.unwrap();
        assert_eq!(si.ifcount, 1);

        Ok(())
    }

    #[allow(unused_macros)]
    macro_rules! aw {
        ($e:expr) => {
            tokio_test::block_on($e)
        };
    }

    #[test]
    fn basic_eth0() {
        assert_eq!(aw!(a_basic_eth0()).unwrap(), ());
    }
}

