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

use std::fs::OpenOptions;
//use std::fs::File;
use gag::Redirect;

use std::sync::Arc;
use crate::control;
use crate::dullgrasp;
use crate::dullgrasp::GraspDaemon;
use crate::adjacency::Adjacency;
use crate::control::DebugOptions;

use nix::unistd::*;
use nix::sched::unshare;
//use nix::sched::setns;
use nix::sched::CloneFlags;
use std::os::unix::net::UnixStream;
//use std::os::unix::io::AsRawFd;
use std::net::Ipv6Addr;
use std::collections::HashMap;
use std::process::Command;
use std::convert::TryInto;
use sysctl::Sysctl;

use futures::lock::Mutex;
use futures::stream::{StreamExt, TryStreamExt};
use netlink_packet_route::link::nlas::AfSpecInet;
use netlink_packet_route::link::nlas::State;
use rtnetlink::{
    constants::{RTMGRP_IPV6_ROUTE, RTMGRP_IPV6_IFADDR, RTMGRP_LINK},
    Handle, Error,
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
    LinkMessage, AddressMessage
};

/*
 * This function forks and creates a child process that will enter a new network namespace
 * using unshare(2).
 *
 * Prior to doing this, it will create a new dull instance object.
 */

/* This structure is present in the parent to represent the DULL, before tokio */
pub struct DullInit {
    pub child_io:      UnixStream,
    pub dullpid:       Pid
}

/* This structure is present in the parent to represent the DULL */
pub struct Dull {
    pub debug:         DebugOptions,
    pub child_stream:  tokio::net::UnixStream,
    pub dullpid:       Pid
}

impl Dull {
    pub fn from_dull_init(init: DullInit) -> Dull {
        Dull { child_stream: tokio::net::UnixStream::from_std(init.child_io).unwrap(),
               debug:        DebugOptions::empty(),
               dullpid:      init.dullpid }
    }
}

pub type IfIndex = u32;

#[derive(Debug)]
pub struct DullInterface {
    pub ifindex:       IfIndex,
    pub ifname:        String,
    pub is_acp:        bool,             /* true if this is a created ACP interface */
    pub mtu:           u32,
    pub linklocal6:    Ipv6Addr,
    pub oper_state:    State,
    pub grasp_daemon:  Option<Arc<Mutex<dullgrasp::GraspDaemon>>>,
    pub adjacencies:   HashMap<Ipv6Addr, Arc<Mutex<Adjacency>>>
}

impl DullInterface {
    pub fn empty(ifi: IfIndex) -> DullInterface {
        DullInterface {
            ifindex: ifi,
            ifname:  "".to_string(),
            mtu:     0,
            is_acp:     false,
            linklocal6: Ipv6Addr::UNSPECIFIED,
            oper_state: State::Down,
            grasp_daemon: None,
            adjacencies:  HashMap::new()
        }
    }
}

pub struct DullData {
    pub interfaces:    HashMap<u32, Arc<Mutex<DullInterface>>>,
    pub acpns:         Pid,
    pub cmd_cnt:       u32,
    pub debug:         DebugOptions,
    pub exit_now:      bool,
    pub handle:        Option<Handle>
}

pub async fn child_lo_up(handle: &Handle) {
    let mut lo = handle.link().get().set_name_filter("lo".to_string()).execute();
    if let Some(link) = lo.try_next().await.unwrap() {
        handle
            .link()
            .set(link.header.index)
            .up()
            .execute()
            .await.unwrap();
    }
}

impl DullData {
    pub fn empty() -> DullData {
        return DullData { interfaces: HashMap::new(), cmd_cnt: 0,
                          debug: DebugOptions::empty(),
                          exit_now:         false,
                          acpns:            Pid::this(),
                          handle: None
        }
    }

    pub async fn get_entry_by_ifindex(self: &mut DullData, ifindex: IfIndex) -> &Arc<Mutex<DullInterface>> {
        let ifnl = self.interfaces.entry(ifindex).or_insert_with(|| { Arc::new(Mutex::new(DullInterface::empty(ifindex)))});
        return ifnl;
    }

    pub async fn store_link_info(self: &mut DullData, lm: LinkMessage, ifindex: IfIndex) {

        let results = {
            let     ifna = self.get_entry_by_ifindex(ifindex).await;
            let mut ifn  = ifna.lock().await;

            for nlas in lm.nlas {
                use netlink_packet_route::link::nlas::Nla;
                match nlas {
                    Nla::IfName(name) => {
                        println!("ifname: {}", name);
                        if name.len() > 3 && name[0..4] == "acp_".to_string() {
                            ifn.is_acp = true;
                        }
                        ifn.ifname = name;
                    },
                    Nla::Mtu(bytes) => {
                        println!("mtu: {}", bytes);
                        ifn.mtu = bytes;
                    },
                    Nla::Address(addrset) => {
                        println!("lladdr: {:0x}:{:0x}:{:0x}:{:0x}:{:0x}:{:0x}", addrset[0], addrset[1], addrset[2], addrset[3], addrset[4], addrset[5]);
                    },
                    Nla::OperState(state) => {
                        match state {
                            State::Up => {
                                println!("device is up");
                                ifn.oper_state = state;
                            },
                            _ => {
                                println!("device is not up: {:?}", state);
                            }
                        };
                    },
                    Nla::AfSpecInet(inets) => {
                        for ip in inets {
                            match ip {
                                AfSpecInet::Inet(_v4) => { },
                                AfSpecInet::Inet6(_v6) => {
                                    //println!("v6: {:?}", v6);
                                }
                                _ => {}
                            }
                        }
                    },
                    _ => {
                        //print!("data: {:?} ", nlas);
                    }
                }
            }
            println!("");
            let action = match ifn.oper_state {
                State::Down => { true },
                _ => { false }
            };
            (action, ifn.ifindex.clone(), ifn.ifname.clone(), ifn.is_acp)
        };

        //println!("about interface {}: state: {:?} acp: {:?}", results.2, results.0, results.3);
        if results.3==false && results.0==true {
            /* results.3==is_acp (false), results.0==Down */
            println!("bringing interface {} up", results.2);

            let name = results.2;

            let handle = self.handle.as_ref().unwrap();

            let result = handle
                .link()
                .set(results.1)
                .up()
                .execute()
                .await;
            match result {
                Err(err) => { println!("bringing interface {}({}) up: {:?}", name, results.1, err); },
                _ => {}
            };

            /* the interface is now configured for not accept_ra, or accept_ra_dfl */
            if !self.debug.allow_router_advertisement {
                println!("turning off router advertisements");
                let acceptra = format!("net.ipv6.conf.{}.accept_ra", name);

                let ctl = sysctl::Ctl::new(&acceptra).expect(&format!("could not create sysctl '{}'", acceptra));
                let _ovalue = ctl.set_value_string("0").unwrap_or_else(|e| {
                    panic!("Could not set value. Error: {:?}", e);
                });

                let acceptra_defrtr = format!("net.ipv6.conf.{}.accept_ra_defrtr", name);

                let ctl = sysctl::Ctl::new(&acceptra_defrtr).expect(&format!("could not create sysctl '{}'", acceptra));
                let _ovalue = ctl.set_value_string("0").unwrap_or_else(|e| {
                    panic!("Could not set value. Error: {:?}", e);
                });
            }

        }
        return ();
    }

    pub async fn store_addr_info(self: &mut DullData, am: AddressMessage) -> Option<Arc<Mutex<DullInterface>>> {

        let lh = am.header;
        let ifindex = lh.index;
        println!("ifindex: {} family: {}", ifindex, lh.family);

        let     ifna = self.get_entry_by_ifindex(ifindex).await;
        let mut ifn  = ifna.lock().await;

        for nlas in am.nlas {
            use netlink_packet_route::address::Nla;
            match nlas {
                Nla::Address(addrset) => {
                    if addrset.len() != 16 {
                        continue;
                    }
                    let addrbytes: [u8; 16] = addrset.try_into().unwrap();
                    let llv6 = Ipv6Addr::from(addrbytes);
                    //if !llv6.is_unicast_link_local() {
                    // continue;
                    //}
                    if llv6.segments()[0] != 0xfe80 {
                        continue;
                    }
                    ifn.linklocal6 = llv6;
                    print!("llv6: {}", ifn.linklocal6);
                },
                Nla::CacheInfo(_info) => { /* nothing */},
                Nla::Flags(_info)     => { /* nothing */},
                _ => {
                    print!("data: {:?} ", nlas);
                }
            }
        }
        println!("");

        /* do nothing for ACP named interfaces */
        if ifn.is_acp {
            println!("ignoring acp interface[{}]: {}", ifn.ifindex, ifn.ifname);
            return None;
        }

        if ifn.oper_state == State::Up {
            match ifn.grasp_daemon {
                None => { return Some(ifna.clone()); }
                _    => { return None; }
            }
        }
        return None;
    }

}

async fn gather_link_info(ldull: &Arc<Mutex<DullChild>>, lm: LinkMessage) -> Result<(), Error> {
    let dull     = ldull.lock().await;
    let mut data = dull.data.lock().await;

    data.cmd_cnt += 1;
    println!("\ncommand {}", data.cmd_cnt);

    let ifindex = lm.header.index;
    println!("ifindex: {:?} ", ifindex);

    data.store_link_info(lm, ifindex).await;

    if data.debug.debug_namespaces {
        Command::new("ip")
            .arg("link")
            .arg("ls")
            .status()
            .expect("ls command failed to start");
    }

    Ok(())
}

async fn gather_addr_info(ldull: &Arc<Mutex<DullChild>>, am: AddressMessage) -> Result<Option<Arc<Mutex<DullInterface>>>, Error> {
    let dull     = ldull.lock().await;
    let mut data = dull.data.lock().await;

    data.cmd_cnt += 1;
    println!("\ncommand {}", data.cmd_cnt);
    Ok(data.store_addr_info(am).await)
}


pub struct DullChild {
    //pub parent_stream: Arc<tokio::net::UnixStream>,
    pub runtime:       Arc<tokio::runtime::Runtime>,
    pub data:          Mutex<DullData>,
    pub vti_number:     u16,
    pub netlink_handle: Option<tokio::task::JoinHandle<Result<(),Error>>>,
}

impl DullChild {
    // mostly used by unit test cases

    pub fn empty() -> Arc<Mutex<DullChild>> {
        let rt = tokio::runtime::Builder::new()
            .threaded_scheduler()
            .enable_all()
            .build()
            .unwrap();

        Arc::new(Mutex::new(DullChild { runtime:        Arc::new(rt),
                                        netlink_handle: None,
                                        vti_number:     1,
                                        data:           Mutex::new(DullData::empty()) }))
    }

    pub fn allocate_vti(self: &mut DullChild) -> u16 {
        let number = self.vti_number;
        self.vti_number += 1;
        return number;
    }
}


async fn listen_network(childinfo: &Arc<Mutex<DullChild>>) -> Result<tokio::task::JoinHandle<Result<(),Error>>, String> {

    let child = childinfo.clone();   /* take reference to childinfo, for move below */
    let (rt,rt2) = {
        let locked = child.lock().await;
        (locked.runtime.clone(), locked.runtime.clone())
    };

    /* NETLINK listen_network activity daemon: process it all in the background */
    let listenhandle = rt2.spawn(async move {               // moves _child_, and _rt_ into spawn.
        // Open the netlink socket
        let (mut connection, handle, mut messages) = new_connection().map_err(|e| format!("{}", e)).unwrap();

        // These flags specify what kinds of broadcast messages we want to listen for.
        let mgroup_flags = RTMGRP_IPV6_ROUTE | RTMGRP_IPV6_IFADDR | RTMGRP_LINK;

        // A netlink socket address is created with said flags.
        let addr = SocketAddr::new(0, mgroup_flags);
        // Said address is bound so new conenctions and thus new message broadcasts can be received.
        connection.socket_mut().bind(&addr).expect("failed to bind");
        rt.spawn(connection);

        child_lo_up(&handle).await;

        {
            let  mychild = child.lock().await;

            let mut data = mychild.data.lock().await;
            data.handle  = Some(handle);
        }

        while let Some((message, _)) = messages.next().await {
            let payload = message.payload;
            match payload {
                InnerMessage(DelRoute(_stuff)) => {
                    /* happens when acp_001 is moved to another namespace */
                    /* need to sort out when it is relevant */
                }
                InnerMessage(DelAddress(_stuff)) => {
                    /* happens when acp_001 is moved to another namespace */
                    /* need to sort out when it is relevant by looking at name and LinkHeader */
                }
                InnerMessage(DelLink(_stuff)) => {
                    /* happens when acp_001 is moved to another namespace */
                    /* need to sort out when it is relevant by looking at name and LinkHeader */
                }
                InnerMessage(NewLink(stuff)) => {
                    gather_link_info(&child, stuff).await.unwrap();
                }
                InnerMessage(NewAddress(stuff)) => {
                    let sifn = gather_addr_info(&child, stuff).await.unwrap();

                    if let Some(lifn) = sifn {
                        let (bgd, recv, send) = GraspDaemon::initdaemon(lifn.clone(), child.clone()).await.unwrap();
                        let gd = Arc::new(Mutex::new(bgd));
                        {
                            let mut ifn = lifn.lock().await;
                            ifn.grasp_daemon = Some(gd.clone());
                        }

                        GraspDaemon::start_loop(gd, recv, send, child.clone()).await;
                    }
                }
                InnerMessage(NewRoute(_thing)) => {
                    /* just ignore these! */
                }
                //_ => { println!("generic message type: {} skipped", payload.message_type()); }
                _ => { println!("msg type: {:?}", payload); }
            }
        };
        Ok(())
    });
    Ok(listenhandle)
}

pub async fn process_control(child: Arc<Mutex<DullChild>>, mut child_sock: tokio::net::UnixStream) {
    loop {
        if let Ok(thing) = control::read_control(&mut child_sock).await {
            match thing {
                control::DullControl::Exit => {
                    println!("DULL process exiting");
                    {
                        let cl = child.lock().await;
                        let mut dl = cl.data.lock().await;
                        dl.exit_now = true;

                        /* abort() supported on 0.3 only :-( */
                        /*
                        if let Some(nh) = cl.netlink_handle {
                            nh.abort();
                            cl.netlink_handle = None;
                        };
                         */
                    }
                    /* kill self and all threads */
                    std::process::exit(0);
                }
                control::DullControl::AdminDown { interface_index: ifn } => {
                    println!("DULL turning off interface {}", ifn);
                }
                control::DullControl::GraspDebug { grasp_debug: deb } => {
                    println!("Debug set to {}", deb);
                    let cl = child.lock().await;
                    let mut dl = cl.data.lock().await;
                    dl.debug.debug_graspdaemon = deb;
                }
                control::DullControl::DullNamespace { namespace_id: acpns } => {
                    println!("ACP namespace set to {}", acpns);
                    let cl = child.lock().await;
                    let mut dl = cl.data.lock().await;
                    dl.acpns = Pid::from_raw(acpns);
                }
                control::DullControl::ChildReady => {} // nothing to do
            }
        }
    }
}

/* this calls unshare(2) to create a new network namespace */
pub fn create_netns() -> Result<(), String> {

    // we will want CLONE_FS at some point, having first changed to
    // a directory suitable for core dumps.
    // Log files will mostly go via socket opened before this call.
    // probably want CLONE_NEWNS too

    // CLONE_NEWNET is the key thing, it requires root or CAP_SYS_ADMIN.
    // CLONE_NEWNS because we have to remount /sys to get updated info about
    //             the network devices in /sys
    unshare(CloneFlags::CLONE_NEWNET|CloneFlags::CLONE_NEWNS).unwrap();

    // stackoverflow article (can not find it) says to mount /sys again.
    Command::new("mount")
        .arg("-t")
        .arg("sysfs")
        .arg("none")
        .arg("/sys")
        .status()
        .expect("remount of /sys failed");

    /*
    Command::new("bash")
        .status()
        .expect("ls of /sys failed");
     */

    Ok(())
}

async fn child_processing(childinfo: Arc<Mutex<DullChild>>, sock: UnixStream) {
    let mut parent_stream = tokio::net::UnixStream::from_std(sock).unwrap();

    /* arrange to listen on network events in the new network namespace */
    let netlink_handle = listen_network(&childinfo).await.unwrap();

    {
        let mut cil = childinfo.lock().await;
        cil.netlink_handle = Some(netlink_handle);
    }

    /* let parent know that we ready */
    println!("tell parent, child is ready");
    control::write_child_ready(&mut parent_stream).await.unwrap();

    /* listen to commands from the parent */
    println!("child waiting for commands");
    process_control(childinfo, parent_stream).await;
}

pub fn namespace_daemon() -> Result<DullInit, std::io::Error> {

    //println!("daemon start");
    // set up a pair of sockets, connected
    // let pair = tokio::net::UnixStream::pair().unwrap();
    let pair = UnixStream::pair().unwrap();

    //println!("daemon fork");
    let result = unsafe{fork()}.expect("fork failed");


    match result {
        ForkResult::Parent{ child } => {

            let dull = DullInit { child_io: pair.0, dullpid: child };

            // close the childfd in the parent
            //pair.1.close().unwrap();

            println!("Hermes started new network namespace: {}", child);
            return Ok(dull);
        }
        ForkResult::Child => {

            // close the parentfd in the child
            //pair.0.close().unwrap();

            //println!("Child redirected");

            // Open a log
            let log = OpenOptions::new()
                .truncate(true)
                .read(true)
                .create(true)
                .write(true)
                .open("child_stdout.log")
                .unwrap();
            let _out_redirect = Redirect::stdout(log).unwrap();
            // Log for stderr
            let log = OpenOptions::new()
                .truncate(true)
                .read(true)
                .create(true)
                .write(true)
                .open("child_stderr.log")
                .unwrap();
            let _err_redirect = Redirect::stderr(log).unwrap();

            /* create a new network namespace... BEFORE initializing runtime */
            /* the runtime may call clone(2), which if not unshared() would  */
            /* retain the parent network name space */
            println!("In child: creating name space");
            create_netns().unwrap();

            let rt = tokio::runtime::Builder::new()
                .threaded_scheduler()
                .enable_all()
                .build()
                .unwrap();

            let childinfo = DullChild { runtime:        Arc::new(rt),
                                        vti_number:     1,
                                        netlink_handle: None,
                                        data:           Mutex::new(DullData::empty()),
            };

            let art = childinfo.runtime.clone();
            let child = Arc::new(Mutex::new(childinfo));

            let future1 = child_processing(child, pair.1);
            art.handle().block_on(future1);

            println!("now finished in child");
            std::process::exit(0);
        }
    }
}
