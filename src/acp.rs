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

use crate::sysctl::Sysctl;
use gag::Redirect;

use std::sync::Arc;
use crate::control;
use crate::control::DebugOptions;
use crate::control::ControlStream;
use crate::dull::IfIndex;
use crate::dull::child_lo_up;
use crate::control::{open_log, unset_cloexec};

use nix::unistd::*;
use nix::sched::unshare;
use std::process::Stdio;
//use nix::sched::setns;
use nix::sched::CloneFlags;
use std::os::unix::net::UnixStream;
//use std::os::unix::io::AsRawFd;
use std::net::Ipv6Addr;
use std::collections::HashMap;
use std::process::Command;
//use std::convert::TryInto;
use tokio::signal;
use tokio::time::{sleep, Duration};

use futures::lock::Mutex;
use futures::stream::StreamExt;
use netlink_packet_route::link::nlas::AfSpecInet;
use netlink_packet_route::link::nlas::State;
use rtnetlink::{
    constants::{RTMGRP_IPV6_ROUTE, RTMGRP_IPV6_IFADDR, RTMGRP_LINK},
    Handle, Error,
    new_connection,
    sys::{AsyncSocket, SocketAddr},
};
use netlink_packet_route::{
    NetlinkPayload::InnerMessage,
    RtnlMessage::NewLink,
    RtnlMessage::NewAddress,
    RtnlMessage::NewRoute,
    LinkMessage, AddressMessage
};

/*
 * This function forks and creates a child process that will enter a new network namespace
 * using unshare(2).
 *
 * This namespace is used as the ACP namespace environment.
 *
 */

/* This structure is present in the parent to represent the ACP, before tokio */
pub struct AcpInit {
    pub child_io:      UnixStream,
    pub dullpid:       Pid
}

/* This structure is present in the parent to represent the ACP */
pub struct Acp {
    pub debug:         DebugOptions,
    pub child_stream:  control::ControlStream,
    pub acppid:        Pid
}

impl Acp {
    pub fn from_acp_init(init: AcpInit) -> Acp {
        let c_socket    = tokio::net::UnixStream::from_std(init.child_io).unwrap();
        let c_stream    = control::ControlStream::parent(c_socket);
        let a1 = Acp { child_stream: c_stream,
                           debug:        DebugOptions::empty(),
                           acppid:       init.dullpid };
        return a1;
    }
}

#[derive(Debug)]
pub struct AcpInterface {
    pub ifindex:       IfIndex,
    pub ifname:        String,
    pub is_acp:        bool,             /* true if this is a created ACP interface */
    pub mtu:           u32,
    pub linklocal6:    Ipv6Addr,
    pub oper_state:    State,
}

impl AcpInterface {
    pub fn empty(ifi: IfIndex) -> AcpInterface {
        AcpInterface {
            ifindex: ifi,
            ifname:  "".to_string(),
            mtu:     0,
            is_acp:     false,
            linklocal6: Ipv6Addr::UNSPECIFIED,
            oper_state: State::Down,
        }
    }
}

pub struct AcpData {
    pub interfaces:    HashMap<u32, Arc<Mutex<AcpInterface>>>,
    pub cmd_cnt:       u32,
    pub debug:         DebugOptions,
    pub exit_now:      bool,
    pub handle:        Option<Handle>
}

// so this needs to become a trait, maybe called... NetLinkWatcher

impl AcpData {
    pub fn empty() -> AcpData {
        return AcpData { interfaces: HashMap::new(), cmd_cnt: 0,
                         debug: DebugOptions::empty(),
                         exit_now:         false,
                         handle: None
        }
    }

    pub async fn get_entry_by_ifindex(self: &mut AcpData, ifindex: IfIndex) -> &Arc<Mutex<AcpInterface>> {
        let ifnl = self.interfaces.entry(ifindex).or_insert_with(|| { Arc::new(Mutex::new(AcpInterface::empty(ifindex)))});
        return ifnl;
    }

    pub async fn store_link_info(self: &mut AcpData, lm: LinkMessage, ifindex: IfIndex) {

        let mut mydebug = self.debug.clone();
        let results = {
            let     ifna = self.get_entry_by_ifindex(ifindex).await;
            let mut ifn  = ifna.lock().await;

            for nlas in lm.nlas {
                use netlink_packet_route::link::nlas::Nla;
                match nlas {
                    Nla::IfName(name) => {
                        mydebug.debug_info(format!("ifname: {}", name));
                        if name.len() > 3 && name[0..4] == "acp_".to_string() {
                            ifn.is_acp = true;
                        }
                        ifn.ifname = name;
                    },
                    Nla::Mtu(bytes) => {
                        mydebug.debug_info(format!("mtu: {}", bytes));
                        ifn.mtu = bytes;
                    },
                    Nla::Address(addrset) => {
                        mydebug.debug_info(format!("lladdr: {:0x}:{:0x}:{:0x}:{:0x}:{:0x}:{:0x}", addrset[0], addrset[1], addrset[2], addrset[3], addrset[4], addrset[5]));
                    },
                    Nla::OperState(state) => {
                        if state == State::Up {
                            mydebug.debug_info(format!("device is up"));
                        }
                        ifn.oper_state = state;
                    },
                    Nla::AfSpecInet(inets) => {
                        for ip in inets {
                            match ip {
                                AfSpecInet::Inet(_v4) => { },
                                AfSpecInet::Inet6(_v6) => {
                                    //mydebug.debug_info(format!("v6: {:?}", v6));
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
            mydebug.debug_info(format!(""));
            (ifn.oper_state == State::Down, ifn.ifindex.clone(), ifn.ifname.clone(), ifn.is_acp)
        };

        if results.3 && results.0 {  /* results.3== is_acp, results.0== Down */
            mydebug.debug_info(format!("bringing interface {} up", results.2));

            let handle = self.handle.as_ref().unwrap();

            handle
                .link()
                .set(results.1)
                .up()
                .execute()
                .await.unwrap();
        }
        return ();
    }

    pub async fn store_addr_info(self: &mut AcpData, am: AddressMessage) -> Option<Arc<Mutex<AcpInterface>>> {

        let mut mydebug = self.debug.clone();
        let lh = am.header;
        let ifindex = lh.index;
        //println!("ifindex: {} family: {}", ifindex, lh.family);

        let     ifna = self.get_entry_by_ifindex(ifindex).await;
        let mut ifn  = ifna.lock().await;

        for nlas in am.nlas {
            use netlink_packet_route::address::Nla;
            match nlas {
                Nla::Address(addrset) => {
                    if addrset.len() != 16 {
                        continue;
                    }

                    let mut addrbytes: [u8; 16] = [0; 16];
                    for n in 0..=15 {
                        addrbytes[n] = addrset[n]
                    }
                    // this fails for Brian, not clear why yet.
                    //let addrbytes: [u8; 16] = addrset.try_into().unwrap();

                    let llv6 = Ipv6Addr::from(addrbytes);
                    //if !llv6.is_unicast_link_local() {
                    // continue;
                    //}
                    if llv6.segments()[0] != 0xfe80 {
                        continue;
                    }
                    ifn.linklocal6 = llv6;
                    mydebug.debug_info(format!("llv6: {}", ifn.linklocal6));
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
        if !ifn.is_acp {
            println!("ignoring not-acp interface[{}]: {}", ifn.ifindex, ifn.ifname);
            return None;
        }

        if ifn.oper_state == State::Up {
            println!("{} is up", ifn.ifname);
        }
        return None;
    }

}

async fn gather_link_info(lacp: &Arc<Mutex<AcpChild>>, lm: LinkMessage) -> Result<(), Error> {
    let acp      = lacp.lock().await;
    let mut data = acp.data.lock().await;

    let mut mydebug = data.debug.clone();

    data.cmd_cnt += 1;
    mydebug.debug_info(format!("\ncommand {}", data.cmd_cnt));

    let ifindex = lm.header.index;
    mydebug.debug_info(format!("\nifindex: {:?} ", ifindex));

    data.store_link_info(lm, ifindex).await;

    if data.debug.debug_namespaces {
        Command::new("ip")
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .arg("link")
            .arg("ls")
            .status()
            .expect("ls command failed to start");
    }

    Ok(())
}

async fn gather_addr_info(lacp: &Arc<Mutex<AcpChild>>, am: AddressMessage) -> Result<Option<Arc<Mutex<AcpInterface>>>, Error> {
    let acp     = lacp.lock().await;
    let mut data = acp.data.lock().await;

    data.cmd_cnt += 1;
    let mut mydebug = data.debug.clone();
    mydebug.debug_info(format!("\ncommand {}", data.cmd_cnt));

    Ok(data.store_addr_info(am).await)
}


pub struct AcpChild {
    //pub parent_stream: Arc<tokio::net::UnixStream>,
    pub runtime:       Arc<tokio::runtime::Runtime>,
    pub data:          Mutex<AcpData>,
    //pub vti_number:     u16,
    pub netlink_handle: Option<tokio::task::JoinHandle<Result<(),Error>>>,
}

impl AcpChild {
    // mostly used by unit test cases

    pub fn empty() -> Arc<Mutex<AcpChild>> {
        // tokio 1.7 with rt-multi-thread
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .thread_name("dull")
            .enable_all()
            .build()
            .unwrap();

        Arc::new(Mutex::new(AcpChild { runtime:        Arc::new(rt),
                                       netlink_handle: None,
                                       data:           Mutex::new(AcpData::empty()) }))
    }
}


async fn listen_network(childinfo: &Arc<Mutex<AcpChild>>) -> Result<tokio::task::JoinHandle<Result<(),Error>>, String> {

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
        connection.socket_mut().socket_mut().bind(&addr).expect("failed to bind");
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
                InnerMessage(NewLink(stuff)) => {
                    gather_link_info(&child, stuff).await.unwrap();
                }
                InnerMessage(NewAddress(stuff)) => {
                    let sifn = gather_addr_info(&child, stuff).await.unwrap();

                    if let Some(lifn) = sifn {
                        let ifn = lifn.lock().await;

                        if ifn.is_acp {
                            // do something with this interface
                            let policy6 = format!("net.ipv6.conf.{}.disable_policy", ifn.ifname);
                            let ctl = sysctl::Ctl::new(&policy6).expect(&format!("could not create sysctl '{}'", policy6));
                            let _ovalue = ctl.set_value_string("1").unwrap_or_else(|e| {
                                panic!("Could not set disable v6 policy value. Error: {:?}", e);
                            });

                            let policy4 = format!("net.ipv4.conf.{}.disable_policy", ifn.ifname);
                            let ctl = sysctl::Ctl::new(&policy4).expect(&format!("could not create sysctl '{}'", policy4));
                            let _ovalue = ctl.set_value_string("1").unwrap_or_else(|e| {
                                panic!("Could not set disable v4 policy value. Error: {:?}", e);
                            });
                        }
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

pub async fn process_control(child: Arc<Mutex<AcpChild>>, mut cs: ControlStream) {
    loop {
        if let Ok(thing) = cs.read_control().await {
            match thing {
                control::DullControl::Exit => {
                    println!("ACP process exiting");
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

                    let _result = Command::new("sbin/sunshine -K")
                        .stdin(Stdio::null())
                        .stdout(Stdio::inherit())
                        .stderr(Stdio::inherit())
                        .status().unwrap();

                    /* kill self and all threads */
                    std::process::exit(0);
                }
                control::DullControl::AdminDown { interface_index: ifn } => {
                    println!("ACP turning off interface {}", ifn);
                }
                control::DullControl::GraspDebug { grasp_debug: deb } => {
                    println!("Debug set to {}", deb);
                    let cl = child.lock().await;
                    let mut dl = cl.data.lock().await;
                    dl.debug.debug_graspdaemon = deb;
                }
                control::DullControl::AutoAdjacency { .. } => {}
                control::DullControl::DisableIKEv2  { .. } => {}
                control::DullControl::ChildReady => {} // nothing to do
                control::DullControl::DullNamespace { .. } => {} // nothing to do
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

/* duplicate code with dull.rs,  some kind of Template needed */
async fn ignore_sigint(childinfo: &Arc<Mutex<AcpChild>>) {

    let child2 = childinfo.clone();
    let rt = {
        let locked = childinfo.lock().await;
        locked.runtime.clone()
    };
    rt.spawn(async move {   // child2 moved
        loop {
            signal::ctrl_c().await.unwrap();
            {
                let cl = child2.lock().await;
                let mut dl = cl.data.lock().await;
                dl.exit_now = true;
            }
            sleep(Duration::from_millis(500)).await;
        }
    });
}

async fn child_processing(childinfo: Arc<Mutex<AcpChild>>, sock: UnixStream) {
    let parent_stream = tokio::net::UnixStream::from_std(sock).unwrap();
    let mut cs = ControlStream::child(parent_stream);

    ignore_sigint(&childinfo).await;

    /* arrange to listen on network events in the new network namespace */
    let netlink_handle = listen_network(&childinfo).await.unwrap();

    {
        let mut cil = childinfo.lock().await;
        cil.netlink_handle = Some(netlink_handle);
    }

    /* let parent know that we ready */
    println!("acp tell parent, child is ready");
    cs.write_child_ready().await.unwrap();

    // start up RFC6550/RPL daemon, Unstrung
    Command::new("/home/mcr/u")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .expect("Unstrung start");

    /* listen to commands from the parent */
    println!("acp child waiting for commands");
    process_control(childinfo, cs).await;
}

pub fn namespace_daemon() -> Result<AcpInit, std::io::Error> {

    //println!("daemon start");
    // set up a pair of sockets, connected
    // let pair = tokio::net::UnixStream::pair().unwrap();
    let pair = UnixStream::pair().unwrap();

    //println!("daemon fork");
    let result = unsafe{fork()}.expect("fork failed");

    match result {
        ForkResult::Parent{ child } => {

            let acp = AcpInit { child_io: pair.0, dullpid: child };

            // close the childfd in the parent
            //pair.1.close().unwrap();

            println!("Hermes started new ACP network namespace: {}", child);
            return Ok(acp);
        }
        ForkResult::Child => {

            // Open a log
            let stdoutlog = open_log("acp_stdout.log").unwrap();
            let _out_redirect = Redirect::stdout(stdoutlog).unwrap();
            unset_cloexec(1).unwrap();

            // Log for stderr
            let stderrlog = open_log("acp_stderr.log").unwrap();
            let _err_redirect = Redirect::stderr(stderrlog).unwrap();
            unset_cloexec(2).unwrap();

            /* create a new network namespace... BEFORE initializing runtime */
            /* the runtime may call clone(2), which if not unshared() would  */
            /* retain the parent network name space */
            println!("In child: creating name space");
            create_netns().unwrap();

            // tokio 1.7
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .thread_name("acp")
                .enable_all()
                .build()
                .unwrap();

            let childinfo = AcpChild { runtime:        Arc::new(rt),
                                       netlink_handle: None,
                                       data:           Mutex::new(AcpData::empty()),
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
