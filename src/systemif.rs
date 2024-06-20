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
use std::num::NonZeroI32;
use nix::unistd::Pid;
use std::net::Ipv6Addr;
use async_trait::async_trait;
use futures::stream::{StreamExt, TryStreamExt};
use futures::lock::Mutex;
//use tokio::process::{Command};
use netlink_packet_core::NetlinkMessage;
use netlink_packet_core::ErrorMessage;
use netlink_packet_route::link::State;
use rtnetlink::{
    constants::{RTMGRP_IPV6_ROUTE, RTMGRP_IPV6_IFADDR, RTMGRP_LINK},
    Error,  Error::NetlinkError,  Handle,
    new_connection,
};
use netlink_proto::sys::{AsyncSocket, SocketAddr};
use netlink_packet_route::link::{MacVlanMode, LinkLayerType};
use netlink_packet_core::{
    NetlinkPayload::InnerMessage
};
use netlink_packet_route::{
    RouteNetlinkMessage::NewLink,
    RouteNetlinkMessage::NewAddress,
    RouteNetlinkMessage::NewRoute,
    RouteNetlinkMessage::DelRoute,
    RouteNetlinkMessage::DelAddress,
    RouteNetlinkMessage::DelLink,
    link::LinkMessage,
    //address::AddressMessage,
    RouteNetlinkMessage
};
//use std::os::unix::net::UnixStream;
//use sysctl::Sysctl;
use crate::dull::IfIndex;

pub type NetlinkMessageQueue = futures::channel::mpsc::UnboundedReceiver<(NetlinkMessage<RouteNetlinkMessage>, netlink_proto::sys::SocketAddr)>;

#[async_trait]
pub trait NetlinkManager: Send + Sync {
    async fn create_ethernet_pair_for_bridge(self: &Self,
                                             dullpid:  Pid,
                                             bridgeif: IfIndex) -> Result<(), rtnetlink::Error>;
    async fn create_macvlan(self: &Self,
                            dullpid:  Pid,
                            physif: IfIndex) -> Result<(), rtnetlink::Error>;

    async fn add_abutment_address(self: &Self,
                                  abutmentif: IfIndex,
                                  addr:       Ipv6Addr)
                                  -> Result<(), rtnetlink::Error>;

    fn fetch_handle<'a>(self: &'a Self) -> Option<&'a Handle>;
    fn fetch_messages<'a>(self: &'a Self) -> Option<Arc<Mutex<NetlinkMessageQueue>>>;
}

pub struct NetlinkInterface {
    pub handle:     Handle,
    pub messages:   Arc<Mutex<NetlinkMessageQueue>>
}

impl NetlinkInterface {
    pub fn new(rt: Arc<tokio::runtime::Runtime>) -> NetlinkInterface {
        // Open the netlink socket
        let (mut connection, handle, messages) = new_connection().map_err(|e| format!("{}", e)).unwrap();

        // These flags specify what kinds of broadcast messages we want to listen for.
        // we just care about LINK changes
        let mgroup_flags = RTMGRP_IPV6_ROUTE | RTMGRP_IPV6_IFADDR | RTMGRP_LINK;

        // A netlink socket address is created with said flags.
        let addr = SocketAddr::new(0, mgroup_flags);
        // Said address is bound so new conenctions and thus new message broadcasts can be received.
        connection.socket_mut().socket_mut().bind(&addr).expect("failed to bind");

        rt.spawn(connection);

        NetlinkInterface { handle: handle, messages: Arc::new(Mutex::new(messages)) }
    }

    pub async fn find_interface_ifindex(self: &NetlinkInterface,
                                        ifname: &String) -> Result<Option<IfIndex>, rtnetlink::Error> {
        let mut ifentry = self.handle.link().get().match_name(ifname.to_string()).execute();
        if let Some(link) = ifentry.try_next().await? {
            return Ok(Some(link.header.index));
        } else {
            return Ok(None);   // ENOTFOUND might be better?
        }
    }

    pub async fn addremove_bridge(self: &NetlinkInterface,
                                  adding: bool,
                                  childlink: IfIndex, parentlink: IfIndex) -> Result<(), rtnetlink::Error> {

        // put the interface up or down
        if adding {
            self.handle
                .link()
                .set(childlink)
                .up()
                .execute()
                .await?;
        } else {
            self.handle
                .link()
                .set(childlink)
                .down()
                .execute()
                .await?;
        }

        // add/remove it into the bridge
        self.handle
            .link()
            .set(childlink)
            .controller(parentlink)
            .execute()
            .await?;
        Ok(())
    }

}

#[async_trait]
impl NetlinkManager for NetlinkInterface {
    fn fetch_handle<'a>(self: &'a NetlinkInterface) -> Option<&'a Handle> {
        Some(&self.handle)
    }
    fn fetch_messages<'a>(self: &'a Self) -> Option<Arc<Mutex<NetlinkMessageQueue>>> {
        Some(self.messages.clone())
    }

    async fn create_ethernet_pair_for_bridge(self: &Self,
                                             dullpid:  Pid,
                                             bridgeif: IfIndex) -> Result<(), rtnetlink::Error> {

        // need to generate a name for the interface.
        // use incrementing values with "pullXXX" and "dullXXX", where XXX is the bridge_ifindex.

        let pname = format!("pull{:03}", bridgeif);
        let dname = format!("dull{:03}", bridgeif);

        let result = self.handle
            .link()
            .add()
            .veth(dname.clone().into(), pname.clone().into())
            .execute()
            .await;

        match result {
            Err(NetlinkError(ErrorMessage { code: Some(sillynumber), .. }))
                if sillynumber == NonZeroI32::new(-17).unwrap() => {
                    println!("network pair already created");
                    return Ok(())
                },
            Err(NetlinkError(ErrorMessage { code: Some(code), .. }))
                if code == NonZeroI32::new(-19).unwrap() => {
                    println!("network pair already exists");
                    return Ok(())
                },
            Ok(_x) => { },
            _ => {
                println!("new error: {:?}", result);
                std::process::exit(0);
            }
        };

        let mut dull0 = self.handle.link().get().match_name(dname.clone()).execute();
        if let Some(link) = dull0.try_next().await? {
            self.handle
                .link()
                .set(link.header.index)
                .up()
                .execute()
                .await?;

            // Punt one into the DULL namespace!
            self.handle
                .link()
                .set(link.header.index)
                .setns_by_pid(dullpid.as_raw() as u32)
                .execute()
                .await?;
        } else {
            println!("no child link {} found", dname);
            return Ok(());
        }

        let somelink = self.find_interface_ifindex(&pname).await.unwrap();
        if let Some(pull0link) = somelink {
            self.addremove_bridge(true, pull0link, bridgeif).await?;
            return Ok(());
        }
        return Ok(());   // WRONG
    }

    async fn create_macvlan(self: &Self, dullpid: Pid, physif: IfIndex) -> Result<(), rtnetlink::Error> {
        let dname = format!("mull{:03}", physif);

        let result = self.handle
            .link()
            .add()
            .macvlan(dname.clone().into(), physif, MacVlanMode::Bridge)
            .execute()
            .await;

        match result {
            Err(NetlinkError(ErrorMessage { code: Some(code), .. })) => {
                if code == NonZeroI32::new(-16).unwrap() {
                    println!("network macvlan conflicts with bridge");
                    return Ok(())
                } else if code == NonZeroI32::new(-17).unwrap() {
                    println!("network macvlan conflicts with bridge");
                    return Ok(())
                } else if code == NonZeroI32::new(-19).unwrap() {
                    println!("network macvlan not valid");
                    return Ok(())
                } else if code == NonZeroI32::new(-22).unwrap() {
                    println!("network macvlan EINVAL");
                    return Ok(())
                } else {
                    println!("macvlan new error: {:?}", result);
                }
            }
            Ok(_x) => { },
            _ => {
                println!("macvlan new error: {:?}", result);
                std::process::exit(0);
            }
        };

        let mut mull0 = self.handle.link().get().match_name(dname.clone()).execute();
        if let Some(link) = mull0.try_next().await? {
            self.handle
                .link()
                .set(link.header.index)
                .up()
                .execute()
                .await?;

            // Punt one into the DULL namespace!
            self.handle
                .link()
                .set(link.header.index)
                .setns_by_pid(dullpid.as_raw() as u32)
                .execute()
                .await?;
        } else {
            println!("no child link {} found", dname);
            return Ok(());
        }

        return Ok(());
    }

    async fn add_abutment_address(self: &Self,
                                  abutmentif: IfIndex,
                                  addr:       Ipv6Addr)
                                  -> Result<(), rtnetlink::Error>
    {
        println!("adding {} to interface {}", addr, abutmentif);
        self.handle
            .address()
            .add(abutmentif, std::net::IpAddr::V6(addr), 128)
            .execute()
            .await
    }
}


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

    pub fn ignored_str(self: &Self) -> String {
        if self.ignored { "ignored".to_string() } else { "active".to_string() }
    }

    pub fn bridge_master_str(self: &Self) -> String {
        if self.bridge_master { "bridge".to_string() } else { "normal".to_string() }
    }

    pub fn log_if(self: &Self, k: u32) {
        println!(" {:03}: name: {} {} {}", k, self.ifname,
                 self.ignored_str(), self.bridge_master_str());
    }

}

/* so far only info we care about */
struct SystemInterfaces {
    pub system_interfaces:  HashMap<u32, Arc<Mutex<SystemInterface>>>,
    pub ifcount: u32,
    pub link_debugging: bool,
    pub ignored_interfaces: Vec<String>
}

impl SystemInterfaces {
    pub fn empty() -> SystemInterfaces {
        SystemInterfaces {
            system_interfaces:  HashMap::new(), ifcount: 0,
            link_debugging: false, ignored_interfaces: vec![]
        }
    }

    pub async fn get_entry_by_ifindex<'a>(&'a mut self, ifindex: IfIndex) -> Arc<Mutex<SystemInterface>> {
        let mut inc = 0;
        let ifnl = self.system_interfaces.entry(ifindex).or_insert_with(|| {
            inc += 1;
            Arc::new(Mutex::new(SystemInterface::empty(ifindex)))
        });

        /* have to increment down here, because block above can not use self */
        self.ifcount += inc;
        return ifnl.clone();
    }

    pub async fn calculate_needed_dull(self: &Self,
                                       ni: &dyn NetlinkManager,
                                       dull_pid: Pid) -> Result<u32, rtnetlink::Error> {

        let mut cnt = 0;

        for (k,ifnl) in &self.system_interfaces {
            let mut ifn = ifnl.lock().await;

            if ifn.ignored {
                continue;
            }

            if self.ignored_interfaces.contains(&ifn.ifname) {
                ifn.log_if(*k);
                println!("   ignored as requested");
                ifn.ignored=true;
                continue;
            }

            if !ifn.has_dull_if && !ifn.ignored {
                if ifn.bridge_master  {
                    ifn.log_if(*k);
                    println!("     creating new ethernet pair for {}", ifn.ifindex);
                    ni.create_ethernet_pair_for_bridge(dull_pid, ifn.ifindex).await.unwrap();
                    ifn.has_dull_if = true;
                    cnt += 1;
                } else if !ifn.bridge_slave && ifn.up {
                    ifn.log_if(*k);
                    println!("     creating new ethernet macvlan for {}", ifn.ifindex);
                    ni.create_macvlan(dull_pid, ifn.ifindex).await.unwrap();
                    ifn.has_dull_if = true;
                    cnt += 1;
                }
            }
        }
        Ok(cnt)
    }

    pub fn link_debug(self: &mut Self,
                      msg: String) {
        if self.link_debugging {
            println!("{}", msg);
        }
    }

}

async fn gather_parent_link_info(si: &mut SystemInterfaces,
                                 lm: &LinkMessage,
                                 newlink: bool) -> Result<(), Error> {
    let ifindex = lm.header.index;
    si.link_debug(format!("processing ifindex: {:?} added={} type={:?}", ifindex, newlink, lm.header.link_layer_type));

    /* only proceed if the interface type is ethernet */
    // other weird shit just probably will need specific code.
    match lm.header.link_layer_type {
        LinkLayerType::Ether => {},
        LinkLayerType::Ppp   => {},
        _ => { /* just finish */  return Ok(()); }
    }

    /* look up reference this ifindex, or create it */
    let ifna = SystemInterfaces::get_entry_by_ifindex(si, ifindex).await;
    let mut ifn = ifna.lock().await;

    /* see if we previously ignored it! */
    //if ifn.ignored && newlink {
    //        println!("  ignored interface {}",ifn.ifname);
    //    return Ok(());
    //}

    for nlas in &lm.attributes {
        use netlink_packet_route::link::LinkAttribute;
        match nlas {
            LinkAttribute::IfName(name) => {
                si.link_debug(format!("  ifname: {}", name));
                if name == "lo" {
                    ifn.ignored = true;
                }
                ifn.ifname = name.to_string();
            },
            LinkAttribute::Mtu(bytes) => {
                si.link_debug(format!("  mtu: {}", *bytes));
                ifn.mtu = *bytes;
            },
            LinkAttribute::OperState(state) => {
                match state {
                    State::Up => {
                        si.link_debug(format!("  device is up"));
                        ifn.up = true;
                    },
                    _ => { si.link_debug(format!("  device in state {:?}", state)); }
                }
            }
            LinkAttribute::LinkInfo(listofstuff) => {
                use netlink_packet_route::link::LinkInfo;
                use netlink_packet_route::link::InfoKind;
                for stuff in listofstuff {
                    match stuff {
                        LinkInfo::Kind(kind) => {
                            si.link_debug(format!("  is it a bridge: {:?}", kind));
                            match kind {
                                InfoKind::Bridge => {
                                    ifn.bridge_master = true;
                                }
                                InfoKind::MacVlan => {
                                    ifn.macvlan = true;
                                }
                                InfoKind::IpTun|
                                InfoKind::Dummy|
                                InfoKind::GreTap|
                                InfoKind::GreTun|
                                InfoKind::GreTun6|
                                InfoKind::Vti|
                                InfoKind::SitTun|
                                InfoKind::Veth => { ifn.ignored = true; }
                                _ => { si.link_debug(format!("2 other kind {:?}", kind)); }
                            }
                        },
                        LinkInfo::Data(_data) => { /* ignore bridge data */ }
                        // LinkInfo::SlaveData(_data) => { /* ignore bridge data */ }
                        /*
                        LinkInfo::SlaveKind(_data) => {
                            /* what exactly to do with this data? */
                            ifn.bridge_slave = true;
                    }
                         */
                        _ => { si.link_debug(format!("other info: {:?}", stuff)); }
                    }
                }
            }
            LinkAttribute::Link(ifmaster) | LinkAttribute::Controller(ifmaster)     => {
                if newlink {
                    /* could be a bridge, or could be a MACvlan */
                    ifn.ifmaster = Some(*ifmaster);
                    si.link_debug(format!("   master interface is {}", *ifmaster));
                } else {
                    si.link_debug(format!("   removed interface {} from {}", ifindex, *ifmaster));
                    ifn.ifmaster = None;
                }
            }
            LinkAttribute::Address(_listofaddr) => { /* something with addresses */ }
            LinkAttribute::Carrier(_updown) => { /* something with the carrier */ }

            LinkAttribute::Map(_) |
            // LinkAttribute::AfSpecInet(_) |
            LinkAttribute::AfSpecBridge(_) |
            LinkAttribute::ProtoDown(_) |
            //LinkAttribute::ProtoInfo(_) |
            LinkAttribute::Other(_) |
            LinkAttribute::PermAddress(_) | LinkAttribute::MinMtu(_) | LinkAttribute::MaxMtu(_) |
            LinkAttribute::Qdisc(_) | LinkAttribute::Mode(_) | LinkAttribute::Broadcast(_) |
            LinkAttribute::CarrierChanges(_) | LinkAttribute::CarrierUpCount(_) | LinkAttribute::CarrierDownCount(_) |
            LinkAttribute::Group(_) | LinkAttribute::Promiscuity(_) |
            LinkAttribute::TxQueueLen(_) | LinkAttribute::NumTxQueues(_) | LinkAttribute::NumRxQueues(_) |
            LinkAttribute::GsoMaxSegs(_) | LinkAttribute::GsoMaxSize(_) |
            LinkAttribute::Event(_) |
            LinkAttribute::Stats64(_) | LinkAttribute::Stats(_) | LinkAttribute::Xdp(_) => { /* nothing */ }
            _ => { si.link_debug(format!("index: {} system if nlas info: {:?}", ifindex, nlas)); }
        }
    }

    si.link_debug(format!("processed {:>16}[{}] added={} {}", ifn.ifname, ifindex, newlink, ifn.bridge_master_str()));

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
        si.link_debug(format!("message {}", cnt));
        gather_parent_link_info(si, &link, true).await.unwrap();
        cnt += 1;
    }
}


pub async fn parent_processing(rt: &Arc<tokio::runtime::Runtime>,
                               dull_pid: Pid,
                               link_debug: bool,
                               ignored_interfaces: Vec<String>) ->
    Result<tokio::task::JoinHandle<Result<(),Error>>, String>
{

    let rt1 = rt.clone();

    /* NETLINK listen_network activity daemon: process it all in the background */
    let listenhandle = rt.spawn(async move {

        let mut si = SystemInterfaces::empty();

        si.link_debugging = link_debug;
        si.ignored_interfaces = ignored_interfaces;

        println!("opening netlink socket for system interface monitor (debug={})", si.link_debugging);

        let nl = NetlinkInterface::new(rt1);

        /* first scan and process existing interfaces */
        scan_interfaces(&mut si, &nl.handle).await;

        /* now do any calculations needed */
        si.calculate_needed_dull(&nl, dull_pid).await.unwrap();

        /* then process anything new that arrives */
        let mut msg1 = nl.messages.lock().await;
        while let Some((message, _)) = msg1.next().await {
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

            /* now do any calculations needed */
            si.calculate_needed_dull(&nl, dull_pid).await.unwrap();
        };
        Ok(())
    });

    Ok(listenhandle)
}


#[cfg(test)]
pub mod tests {
    use super::*;
    use netlink_packet_route::link::{LinkAttribute,LinkHeader,LinkInfo};

    pub struct FakeNetlinkInterface {
    }
    #[async_trait]
    impl NetlinkManager for FakeNetlinkInterface {
        fn fetch_handle<'a>(self: &'a Self) -> Option<&'a Handle> {
            None
        }

        fn fetch_messages<'a>(self: &'a Self) -> Option<Arc<Mutex<NetlinkMessageQueue>>> {
            None
        }

        async fn create_ethernet_pair_for_bridge(self: &Self,
                                                 _dullpid:  Pid,
                                                 bridgeif: IfIndex) -> Result<(), rtnetlink::Error> {
            println!("creating new etherpair for {}", bridgeif);
            return Ok(());
        }
        async fn create_macvlan(self: &Self, _dullpid: Pid, _physif: IfIndex) -> Result<(), rtnetlink::Error> {
            return Ok(())
        }
        async fn add_abutment_address(self: &Self,
                                      _abutmentif: IfIndex,
                                      _addr:       Ipv6Addr)
                                      -> Result<(), rtnetlink::Error>
        {
            return Ok(())
        }
    }

    fn make_eth0() -> LinkMessage {
        use libc::ARPHRD_ETHER;
        LinkMessage {
            header: LinkHeader {
                interface_family: 0,
                index: 1,
                link_layer_type: ARPHRD_ETHER,
                flags: 0,
                change_mask: 0,
            },
            nlas: vec![
                LinkAttribute::IfName("eth0".to_string()),
                LinkAttribute::TxQueueLen(0),
            ],
        }
    }

    fn make_eth0_slave() -> LinkMessage {
        LinkMessage {
            header: LinkHeader {
                interface_family: 0,
                index: 1,
                link_layer_type: ARPHRD_ETHER,
                flags: 0,
                change_mask: 0,
            },
            nlas: vec![
                LinkAttribute::IfName("eth0".to_string()),
                LinkAttribute::TxQueueLen(0),
                LinkAttribute::Master(2)
            ],
        }
    }

    fn make_trusted() -> netlink_packet_route::link::LinkMessage {
        use netlink_packet_route::link::InfoKind;

        LinkMessage {
            header: LinkHeader {
                interface_family: 0,
                index: 2,
                link_layer_type: ARPHRD_ETHER,
                flags: 0,
                change_mask: 0,
            },
            nlas: vec![
                LinkAttribute::IfName("trusted".to_string()),
                LinkAttribute::OperState(State::Up),
                LinkAttribute::TxQueueLen(0),
                LinkAttribute::Info(vec![LinkInfo::Kind(InfoKind::Bridge)]),
            ],
        }
    }

    fn make_a_lone_if() -> LinkMessage {
        LinkMessage {
            header: LinkHeader {
                interface_family: 0,
                index: 1,
                link_layer_type: ARPHRD_ETHER,
                flags: 0,
                change_mask: 0,
            },
            nlas: vec![
                LinkAttribute::IfName("eth1".to_string()),
                LinkAttribute::OperState(State::Up),
                LinkAttribute::IfName("eth1".to_string()),
                LinkAttribute::TxQueueLen(0),
            ],
        }
    }

    async fn a_basic_eth0(si: &mut SystemInterfaces) -> Result<(), std::io::Error> {
        let eth0 = make_eth0();

        gather_parent_link_info(si, &eth0, true).await.unwrap();
        assert_eq!(si.ifcount, 1);

        // insert it again, but note how it does not add new things
        gather_parent_link_info(si, &eth0, true).await.unwrap();
        assert_eq!(si.ifcount, 1);

        Ok(())
    }

    async fn a_basic_bridge(si: &mut SystemInterfaces) -> Result<(), std::io::Error> {
        let trusted = make_trusted();

        gather_parent_link_info(si, &trusted, true).await.unwrap();
        assert_eq!(si.ifcount, 1);

        let trusted_l = si.get_entry_by_ifindex(2).await;
        {
            let trusted1 = trusted_l.lock().await;
            assert_eq!(trusted1.bridge_master, true);
            assert_eq!(trusted1.ifindex, 2);
            assert_eq!(trusted1.up, true);
            assert_eq!(trusted1.bridge_master, true);
            assert_eq!(trusted1.bridge_slave,  false);
            assert_eq!(trusted1.macvlan,       false);
            assert_eq!(trusted1.has_dull_if,   false);
            assert_eq!(trusted1.ignored,       false);
        }

        Ok(())
    }

    async fn a_lone_if(si: &mut SystemInterfaces) -> Result<(), std::io::Error> {
        let eth1 = make_a_lone_if();
        gather_parent_link_info(si, &eth1, true).await.unwrap();
        assert_eq!(si.ifcount, 1);
        Ok(())
    }

    async fn a_bridge(si: &mut SystemInterfaces) -> Result<(), std::io::Error> {
        let trusted = make_trusted();

        gather_parent_link_info(si, &trusted, true).await.unwrap();
        assert_eq!(si.ifcount, 1);

        let eth0_slave = make_eth0_slave();
        gather_parent_link_info(si, &eth0_slave, true).await.unwrap();
        assert_eq!(si.ifcount, 2);

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
        let mut si = SystemInterfaces::empty();
        si.link_debugging = true;
        assert_eq!(aw!(a_basic_eth0(&mut si)).unwrap(), ());
    }

    #[test]
    fn basic_bridge_trusted() {
        let mut si = SystemInterfaces::empty();
        assert_eq!(aw!(a_basic_bridge(&mut si)).unwrap(), ());
    }

    #[test]
    fn bridge_trusted_eth0() {
        let mut si = SystemInterfaces::empty();
        assert_eq!(aw!(a_bridge(&mut si)).unwrap(), ());
    }

    async fn do_calculate(si: &mut SystemInterfaces) -> Result<u32, std::io::Error> {

        let dull_pid = Pid::from_raw(1234);
        let ni = FakeNetlinkInterface {};
        return Ok(si.calculate_needed_dull(&ni, dull_pid).await.unwrap());
    }

    #[test]
    fn should_add_ethernet_pair() {
        let mut si = SystemInterfaces::empty();
        assert_eq!(aw!(a_bridge(&mut si)).unwrap(), ());
        assert_eq!(aw!(do_calculate(&mut si)).unwrap(), 1);
    }

    #[test]
    fn should_add_macvlan_if() {
        let mut si = SystemInterfaces::empty();
        assert_eq!(aw!(a_lone_if(&mut si)).unwrap(), ());
        assert_eq!(aw!(do_calculate(&mut si)).unwrap(), 1);
    }

    #[test]
    fn should_ignore_eth1_if() {
        let mut si = SystemInterfaces::empty();
        assert_eq!(aw!(a_lone_if(&mut si)).unwrap(), ());

        si.ignored_interfaces = vec!["eth1".to_string()];
        assert_eq!(aw!(do_calculate(&mut si)).unwrap(), 0);
    }
}

