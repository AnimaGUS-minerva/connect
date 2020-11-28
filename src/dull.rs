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
use gag::Redirect;

use std::sync::Arc;
use crate::control;
use nix::unistd::*;
use nix::sched::unshare;
use nix::sched::CloneFlags;
use std::os::unix::net::UnixStream;
use std::net::Ipv6Addr;
use std::collections::HashMap;

use futures::lock::Mutex;
use futures::stream::StreamExt;
use netlink_packet_route::link::nlas::Nla;
use rtnetlink::{
    constants::{RTMGRP_IPV4_ROUTE, RTMGRP_IPV6_ROUTE, RTMGRP_LINK},
    new_connection,
    sys::SocketAddr,
};
use netlink_packet_route::{
    NetlinkPayload::InnerMessage,
    RtnlMessage::NewLink,
    LinkMessage,
};

/*
 * This function forks and creates a child process that will enter a new network namespace
 * using unshare(2).
 *
 * Prior to doing this, it will create a new dull instance object.
 */

/* This structure is present in the parent to represent the DULL */
pub struct Dull {
    pub child_stream:  tokio::net::UnixStream,
    pub dullpid:       Pid
}

/* This structure is present in the parent to represent the DULL, before tokio */
pub struct DullInit {
    pub child_io:      UnixStream,
    pub dullpid:       Pid
}

impl Dull {
    pub fn from_dull_init(init: DullInit) -> Dull {
        Dull { child_stream: tokio::net::UnixStream::from_std(init.child_io).unwrap(),
               dullpid:      init.dullpid }
    }
}

#[derive(Debug, PartialEq)]
pub struct DullInterface {
    pub ifindex:       u32,
    pub ifname:        String,
    pub mtu:           u32,
    pub linklayer6:    Ipv6Addr,
    pub oper_state:    bool,
}

pub struct DullData {
    pub interfaces:    HashMap<u32, DullInterface>
}

impl DullData {
    pub fn empty() -> DullData {
        return DullData { interfaces: HashMap::new() }
    }
}


pub struct DullChild {
    //pub parent_stream: Arc<tokio::net::UnixStream>,
    pub runtime:       Arc<tokio::runtime::Runtime>,
    pub data:          Mutex<DullData>
}

async fn dump_link_info(dull: &DullChild, lm: LinkMessage) {

    let lh = lm.header;
    let ifindex = lh.index;
    println!("ifindex: {:?} ", ifindex);

    let mut data = dull.data.lock().await;

    let ifn = data.interfaces.entry(ifindex).or_insert_with(|| { DullInterface {
        ifindex: ifindex,
        ifname:  "".to_string(),
        mtu:     0,
        linklayer6: Ipv6Addr::UNSPECIFIED,
        oper_state: false
    }});
    //ifn.ifindex = ifindex;

    for nlas in lm.nlas {
        match nlas {
            Nla::IfName(name) => {
                println!("ifname: {}", name);
                ifn.ifname = name;
            },
            Nla::Mtu(bytes) => {
                println!("mtu: {}", bytes);
                ifn.mtu = bytes;
            },
            _ => { println!("extra data: {:?} ", nlas); }
        }
    }
}

async fn listen_network(childinfo: &Arc<DullChild>) -> Result<(), String> {

    let child = childinfo.clone();   /* take reference to childinfo, for move below */
    let rt = child.runtime.clone();
    let rt2 = child.runtime.clone();

    /* process it all in the background */
    rt2.spawn(async move {               // moves child into spawn.
        // Open the netlink socket
        let (mut connection, _, mut messages) = new_connection().map_err(|e| format!("{}", e)).unwrap();

        // These flags specify what kinds of broadcast messages we want to listen for.
        let mgroup_flags = RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE | RTMGRP_LINK;

        // A netlink socket address is created with said flags.
        let addr = SocketAddr::new(0, mgroup_flags);
        // Said address is bound so new conenctions and thus new message broadcasts can be received.
        connection.socket_mut().bind(&addr).expect("failed to bind");
        rt.spawn(connection);

        while let Some((message, _)) = messages.next().await {
            let payload = message.payload;
            match payload {
                InnerMessage(NewLink(stuff)) => {
                    dump_link_info(&child, stuff).await;
                }
                _ => { println!("generic message type: {} skipped", payload.message_type()); }
            }
        }
    });
    Ok(())
}

pub async fn process_control(_child: Arc<DullChild>, mut child_sock: tokio::net::UnixStream) {
    loop {
        if let Ok(thing) = control::read_control(&mut child_sock).await {
            match thing {
                control::DullControl::Exit => {
                    println!("DULL process exiting");
                    std::process::exit(0);
                }
                control::DullControl::AdminDown { interface_index: ifn } => {
                    println!("DULL turning off interface {}", ifn);
                }
                control::DullControl::ChildReady => {} // nothing to do
            }
        }
    }
}

/* this calls unshare(2) to create a new network namespace */
pub async fn create_netns(_child: &DullChild) -> Result<(), String> {

    // we will want CLONE_FS at some point, having first changed to
    // a directory suitable for core dumps.
    // Log files will mostly go via socket opened before this call.
    // probably want CLONE_NEWNS too

    // CLONE_NEWNET is the key thing, it requires root or CAP_SYS_ADMIN.
    unshare(CloneFlags::CLONE_NEWNET).unwrap();
    Ok(())
}

async fn child_processing(childinfo: Arc<DullChild>, sock: UnixStream) {
    let mut parent_stream = tokio::net::UnixStream::from_std(sock).unwrap();

    /* create a new network namespace */
    println!("future0");
    create_netns(&childinfo).await.unwrap();

    /* arrange to listen on network events in the new network namespace */
    println!("future2");
    listen_network(&childinfo).await.unwrap();

    /* let parent know that we ready */
    println!("child says it is ready");
    control::write_child_ready(&mut parent_stream).await.unwrap();

    /* listen to commands from the parent */
    println!("blocking in child");
    process_control(childinfo, parent_stream).await;
}

pub fn namespace_daemon() -> Result<DullInit, std::io::Error> {

    println!("daemon start");
    // set up a pair of sockets, connected
    // let pair = tokio::net::UnixStream::pair().unwrap();
    let pair = UnixStream::pair().unwrap();

    println!("daemon fork");
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

            println!("Child redirected");

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

            println!("now in child");
            let rt = tokio::runtime::Builder::new()
                .threaded_scheduler()
                .enable_all()
                .build()
                .unwrap();

            let childinfo = DullChild { runtime:        Arc::new(rt),
                                        data:           Mutex::new(DullData::empty())
            };

            let art = childinfo.runtime.clone();
            let child = Arc::new(childinfo);

            let future1 = child_processing(child, pair.1);
            art.handle().block_on(future1);

            println!("now finished in child");
            std::process::exit(0);
        }
    }
}
