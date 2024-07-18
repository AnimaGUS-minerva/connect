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

/* THIS FILE SHOULD BE NAMED ABUTMENT.RS */
/* abutment is the "new" name for the namespace that can see the real
 * network interfaces, but is not the actual interfaces
 */

extern crate nix;
extern crate tokio;

//use std::fs::OpenOptions;
//use std::fs::File;
use gag::Redirect;

use std::sync::Arc;
use netlink_packet_core::NetlinkMessage;
use netlink_packet_route::RouteNetlinkMessage;
use crate::control;
use crate::dullgrasp;
use crate::dullgrasp::GraspDaemon;
use crate::adjacency::Adjacency;
use crate::control::DebugOptions;
use crate::control::ControlStream;
use crate::control::{open_log, unset_cloexec};
use crate::systemif::{NetlinkManager,NetlinkInterface};
use crate::openswan::OpenswanWhackInterface;

use crate::openswan;
use nix::unistd::*;
//use nix::fcntl::fcntl;
use nix::sched::unshare;
//use std::os::unix::io::AsRawFd;
//use nix::sched::setns;
use nix::sched::CloneFlags;
use std::os::unix::net::UnixStream;
//use std::os::unix::io::AsRawFd;
use std::net::Ipv6Addr;
use std::collections::HashMap;
use tokio::process::{Command};
use tokio::time::{sleep, Duration};
use tokio::signal;
//use std::convert::TryInto;
use sysctl::Sysctl;

use futures::lock::Mutex;
use futures::stream::{StreamExt, TryStreamExt};
//use futures::stream::{StreamExt};
//use netlink_packet_route::link::AfSpecInet;
use netlink_packet_route::link::State;
use rtnetlink::{
    Handle, Error,
    //sys::{AsyncSocket},
};
use netlink_packet_core::{
    NetlinkPayload::InnerMessage,
};
use netlink_packet_route::{
    RouteNetlinkMessage::NewLink,
    RouteNetlinkMessage::NewAddress,
    RouteNetlinkMessage::NewRoute,
    RouteNetlinkMessage::DelRoute,
    RouteNetlinkMessage::DelAddress,
    RouteNetlinkMessage::DelLink,
    link::LinkMessage,
    address::AddressMessage,
    address::AddressAttribute
};

/*
 * This function forks and creates a child process that will enter a new network namespace
 * using unshare(2).
 *
 * Prior to doing this, it will create a new dull (abutment) instance object.
 */

/* This structure is present in the parent to represent the DULL,
 * before tokio is initialized, and it becomes a struct Dull */
pub struct DullInit {
    pub child_io:      UnixStream,
    pub dullpid:       Pid
}

/*
 * This structure is present in the parent to represent the DULL, after
 * async/tokio is initialized
 */
pub struct Dull {
    pub debug:         DebugOptions,
    pub child_stream:  control::ControlStream,
    pub dullpid:       Pid,
    pub abutment_ula:  Option<Ipv6Addr>,        /* /48 prefix generated for numbering interfaces */
}

impl Dull {
    pub fn from_dull_init(init: DullInit) -> Dull {
        let c_socket     = tokio::net::UnixStream::from_std(init.child_io).unwrap();
        let child_stream = control::ControlStream::parent(c_socket);

        Dull { child_stream: child_stream,
               debug:        DebugOptions::empty(),
               dullpid:      init.dullpid,
               abutment_ula: None,
        }
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
    pub ula6:          Option<Ipv6Addr>,
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
            ula6:       None,
            oper_state: State::Down,
            grasp_daemon: None,
            adjacencies:  HashMap::new()
        }
    }
}

// DullData contains data that needs to be mutably available by the
// Abutment process (DULL).
pub struct DullData {
    pub runtime:       Arc<tokio::runtime::Runtime>,
    pub interfaces:    HashMap<u32, Arc<Mutex<DullInterface>>>,
    pub ifid_number:   u16,
    pub acpns:         Pid,
    pub cmd_cnt:       u32,
    pub debug:         DebugOptions,
    pub exit_now:      bool,
    pub auto_up_adj:   bool,
    pub disable_ikev2: bool,
    pub ikev2_started: bool,
    pub abutifprefix:  Option<Ipv6Addr>,
    pub netlink:       Arc<Mutex<dyn NetlinkManager>>,
    pub handle:        Option<Handle>,
}

pub async fn child_lo_up(handle: &Handle) {
    let mut lo = handle.link().get().match_name("lo".to_string()).execute();
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
    pub fn empty(rt: Arc<tokio::runtime::Runtime>,
                 nm: Arc<Mutex<dyn NetlinkManager>>) -> DullData {
        return DullData { interfaces:       HashMap::new(),
                          ifid_number:      1,
                          cmd_cnt:          0,
                          debug:            DebugOptions::empty(),
                          exit_now:         false,
                          auto_up_adj:      true,
                          disable_ikev2:    true,
                          ikev2_started:    false,
                          acpns:            Pid::this(),
                          abutifprefix:     None,
                          runtime:          rt.clone(),
                          netlink:          nm,
                          handle:           None
        }
    }

    pub fn allocate_ifid(self: &mut DullData) -> u16 {
        let number = self.ifid_number;
        self.ifid_number += 1;
        return number;
    }

    pub async fn get_entry_by_ifindex<'a>(self: &'a mut DullData, ifindex: IfIndex) -> Arc<Mutex<DullInterface>> {
        let ifnl = self.interfaces.entry(ifindex).or_insert_with(|| { Arc::new(Mutex::new(DullInterface::empty(ifindex)))});
        return ifnl.clone();
    }

    pub async fn store_link_info(self: &mut DullData,
                                 lm: LinkMessage, ifindex: IfIndex) {

        let mut mydebug = self.debug.clone();
        let results = {
            let     ifna = self.get_entry_by_ifindex(ifindex).await;
            let mut ifn  = ifna.lock().await;


            for nlas in lm.attributes {
                use netlink_packet_route::link::LinkAttribute;
                match nlas {
                    LinkAttribute::IfName(name) => {
                        mydebug.debug_info(format!("ifname: {}", name));
                        if name.len() > 3 && name[0..4] == "acp_".to_string() {
                            ifn.is_acp = true;
                        }
                        ifn.ifname = name;
                    },
                    LinkAttribute::Mtu(bytes) => {
                        mydebug.debug_info(format!("mtu: {}", bytes));
                        ifn.mtu = bytes;
                    },
                    LinkAttribute::Address(addrset) => {
                        mydebug.debug_info(format!("lladdr: {:0x}:{:0x}:{:0x}:{:0x}:{:0x}:{:0x}", addrset[0], addrset[1], addrset[2], addrset[3], addrset[4], addrset[5]));
                    },
                    LinkAttribute::OperState(state) => {
                        match state {
                            State::Up => {
                                mydebug.debug_info(format!("device is up"));
                                ifn.oper_state = state;
                            },
                            _ => {
                                mydebug.debug_info(format!("device is not up: {:?}", state));
                            }
                        };
                    },
                    LinkAttribute::TxQueueLen(_) => { /* nothing */ },
                    /*
                    AfSpecInet::DevConf(inets) => {
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
                    */
                    _ => {
                        print!("data: {:?} ", nlas);
                    }
                }
            }
            mydebug.debug_info(format!(""));
            let action = match ifn.oper_state {
                State::Down => { true },
                _ => { false }
            };
            (action, ifn.ifindex.clone(), ifn.ifname.clone(), ifn.is_acp)
        };

        //mydebug.debug_info(format!("about interface {}: state: {:?} acp: {:?}", results.2, results.0, results.3));
        if results.3==false && results.0==true {
            /* results.3==is_acp (false), results.0==Down */
            mydebug.debug_info(format!("bringing interface {} up", results.2));

            let name = results.2;

            {
                let lnm = self.netlink.lock().await;
                println!("locked netlink for up call");
                match lnm.fetch_handle() {
                    None => { return (); },
                    Some(handle) => {
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
                    }
                }
            }

            /* the interface is now configured for not accept_ra, or accept_ra_dfl */
            if !mydebug.allow_router_advertisement {
                mydebug.debug_info(format!("turning off router advertisements"));
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

    pub async fn store_addr_info(self: &mut DullData,
                                 am: AddressMessage) -> Option<Arc<Mutex<DullInterface>>> {
        let mut mydebug = self.debug.clone();
        let lh = am.header;
        let ifindex = lh.index;

        mydebug.debug_info(format!("ifindex: {} family: {:#?}", ifindex, lh.family));

        let     ifna = self.get_entry_by_ifindex(ifindex).await;
        let mut ifn  = ifna.lock().await;

        for nlas in am.attributes {
            use core::net::IpAddr::{V4,V6};
            match nlas {
                AddressAttribute::Address(addrset) => {
                    match addrset {
                        V4(_addr) => {},
                        V6(addr) => {

                            let mut addrbytes: [u8; 16] = [0; 16];
                            let addr0bytes = addr.octets();
                            // copy the bytes
                            for n in 0..=15 {
                                addrbytes[n] = addr0bytes[n]
                            }

                            let llv6 = Ipv6Addr::from(addrbytes);
                            //if !llv6.is_unicast_link_local() {
                            // continue;
                            //}
                            let fseg = llv6.segments()[0];
                            if fseg == 0xfe80 {
                                // IPv6 LL prefix
                                ifn.linklocal6 = llv6;
                                mydebug.debug_info(format!("llv6: {}", ifn.linklocal6));
                            } else if (fseg & 0xfd00) == 0xfd00 {
                                // IPv6 ULA prefix
                                mydebug.debug_info(format!("ula6: {}", llv6));
                                ifn.ula6 = Some(llv6);
                            } else {
                                continue;
                            }
                        }
                    }
                },
                //LinkAttribute::CacheInfo(_info) => { /* nothing */},
                //LinkAttribute::Flags(_info)     => { /* nothing */},
                _ => {
                    mydebug.debug_info(format!("link data: {:?} ", nlas));
                }
            }
        }
        mydebug.debug_info(format!(""));

        /* do nothing for ACP named interfaces */
        if ifn.is_acp {
            mydebug.debug_info(format!("ignoring acp interface[{}]: {}", ifn.ifindex, ifn.ifname));
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

async fn gather_link_info(ldc: &Arc<Mutex<DullData>>,
                          lm: LinkMessage) -> Result<(), Error> {
    let mut data = ldc.lock().await;
    let mut mydebug = data.debug.clone();

    data.cmd_cnt += 1;
    mydebug.debug_info(format!("\ncommand {}", data.cmd_cnt));

    let ifindex = lm.header.index;
    mydebug.debug_info(format!("ifindex: {:?} ", ifindex));

    data.store_link_info(lm, ifindex).await;

    if mydebug.debug_namespaces {
        Command::new("ip")
            .arg("link")
            .arg("ls")
            .status()
            .await
            .expect("ls command failed to start");
    }

    Ok(())
}

async fn gather_addr_info(ldc: &Arc<Mutex<DullData>>,
                          am: AddressMessage) -> Result<Option<Arc<Mutex<DullInterface>>>, Error> {
    let mut data = ldc.lock().await;
    let mut mydebug = data.debug.clone();

    data.cmd_cnt += 1;
    mydebug.debug_info(format!("\ncommand {}", data.cmd_cnt));
    Ok(data.store_addr_info(am).await)
}

async fn abutment_process_one_netlink(child: Arc<Mutex<DullData>>,
                                      mut debug: DebugOptions, ikev2_started: bool,
                                      message: NetlinkMessage<RouteNetlinkMessage>) {
        let payload = message.payload;
        match payload {
            InnerMessage(DelRoute(_stuff)) => {
                /* also happens when acp_001 is moved to another namespace */
                /* need to sort out when it is relevant->delete connection */
            }
            InnerMessage(DelAddress(_stuff)) => {
                /* also happens when acp_001 is moved to another namespace */
                /* need to sort out when it is relevant by looking at name and LinkHeader */
            }
            InnerMessage(DelLink(_stuff)) => {
                /* also happens when acp_001 is moved to another namespace */
                /* when not acp_001, then it's a real interface going away */
            }
            InnerMessage(NewLink(stuff)) => {
                gather_link_info(&child, stuff).await.unwrap();
            }
            InnerMessage(NewAddress(stuff)) => {
                let sifn = gather_addr_info(&child, stuff).await.unwrap();

                if let Some(lifn) = sifn {
                    let daemon_needed = {
                        let ifn = lifn.lock().await;
                        ifn.grasp_daemon.is_none()
                    };

                    if daemon_needed {
                        let (bgd, recv, send) =
                            GraspDaemon::initdaemon(lifn.clone(),
                                                    child.clone()).await.unwrap();
                        let gd = Arc::new(Mutex::new(bgd));
                        let mut ifn = lifn.lock().await;
                        ifn.grasp_daemon = Some(gd.clone());

                    //Command::new("/root/traceosw")
                    //.status()
                    //                            .await
                    //.expect("traceosw command failed to start");

                        GraspDaemon::start_loop(gd, recv, send, child.clone()).await;
                    }

                    // delay to let interfaces become stable.
                    sleep(Duration::from_millis(200)).await;

                    if ikev2_started {
                        // poke Openswan to rescan the list of interfaces
                        openswan::OpenswanWhackInterface::openswan_setup().await.unwrap();
                    }
                }
            }
            InnerMessage(NewRoute(_thing)) => {
                /* just ignore these! */
            }
            //_ => { println!("generic message type: {} skipped", payload.message_type()); }
            _ => { debug.debug_info(format!("listen_network msg type: {:?}", payload)); }
        }
}


async fn abutment_process_netlink(child: Arc<Mutex<DullData>>) -> ()
{

    let nl = {
        let dd = child.lock().await;
        dd.netlink.clone()
    };

    let msg1 = {
        let mnl = nl.lock().await;
        match mnl.fetch_messages() {
            None => { return (); },
            Some(messages) => {
                messages.clone()
            }
        }
    };

    {
        let mut lmsg1 = msg1.lock().await;
        while let Some((message, _)) = lmsg1.next().await {
            let (debug,ikev2_started) = {
                let data = child.lock().await;
                (data.debug.clone(), data.ikev2_started)
            };
            abutment_process_one_netlink(child.clone(), debug, ikev2_started, message).await;
        };
    }
    ()
}

async fn listen_network<'a>(childinfo: &'a Arc<Mutex<DullData>>) ->
    Result<tokio::task::JoinHandle<Result<(),Error>>, String>
{

    let child = childinfo.clone();   /* take reference to childinfo, for move below */
    let (rt, nm0) = {
        let locked = child.lock().await;
        (locked.runtime.clone(), locked.netlink.clone())
    };

    /* NETLINK listen_network activity daemon: process it all in the background */
    let listenhandle = rt.spawn(async move {
        // moves _child_, nm0, and _rt_ into spawn.

        // A locked netlink is already available as nm0.
        {
            let lnm = nm0.lock().await;
            match lnm.fetch_handle() {
                None => { return Ok(()); },
                Some(handle) => {
                    child_lo_up(&handle).await;
                }
            }
        }
        abutment_process_netlink(child).await;

        Ok(())
    });
    Ok(listenhandle)
}

pub async fn process_control(dd: Arc<Mutex<DullData>>,
                             mut child_stream: control::ControlStream) {
    loop {
        println!("DULL process reading control...");

        {
            // mutable because of write to ikev2_started
            let mut dl = dd.lock().await;

            if dl.disable_ikev2 == false && dl.ikev2_started == false {
                // start IKEv2 daemon
                openswan::OpenswanWhackInterface::openswan_start()
                    .await.expect("Openswan Did Not start correctly");

                dl.ikev2_started = true;

                // delay a bit to let it start up.
                sleep(Duration::from_millis(500)).await;

                // set some default cdebug options for now
                // DBG_CONTROL, bit 4
                // DBG_CONTROLMORE, bit 9
                //let oswdebug = (1<<4)|(1<<9);
                let oswdebug = (1<<4)|0;
                if oswdebug != 0 {
                    openswan::OpenswanWhackInterface::openswan_some_debug(oswdebug)
                        .await.unwrap();
                }

            } else if dl.disable_ikev2 == true && dl.ikev2_started == true {
                // stop  IKEv2 daemon
                openswan::OpenswanWhackInterface::openswan_stop()
                    .await.expect("openswan was not stopped");
            }
        }

        if let Ok(thing) = child_stream.read_control().await {
            match thing {
                control::DullControl::Exit => {
                    println!("DULL process shutting down pluto");

                    {
                        /* shutdown Openswan daemon if it is running */
                        let dl = dd.lock().await;
                        if dl.ikev2_started {
                            openswan::OpenswanWhackInterface::openswan_stop().await.expect("openswan was not stopped");
                            sleep(Duration::from_millis(100)).await;
                        }
                    }

                    println!("DULL process now dying");
                    {
                        let mut dl = dd.lock().await;
                        dl.exit_now = true;

                        /* abort() supported on 0.3 only :-( */
                        /*
                        if let Some(nh) = cl.netlink_handle {
                            nh.abort();
                            cl.netlink_handle = None;
                        };
                         */
                    }
                    sleep(Duration::from_millis(500)).await;
                    /* kill self and all threads */
                    std::process::exit(0);
                }
                control::DullControl::AdminDown { interface_index: ifn } => {
                    println!("DULL turning off interface {}", ifn);
                }
                control::DullControl::AutoAdjacency { adj_up: auto_up } => {
                    let mut dl = dd.lock().await;
                    dl.auto_up_adj = auto_up;
                    println!("DULL automatic tunnel enable: {}", auto_up);
                }
                control::DullControl::DisableIKEv2 { disable_ikev2: ikev2 } => {
                    let mut dl = dd.lock().await;
                    dl.disable_ikev2 = ikev2;
                    if ikev2 {
                        println!("DULL IKEv2 disabled");
                    } else {
                        println!("DULL starting IKEv2");
                    }
                }
                control::DullControl::GraspDebug { grasp_debug: deb } => {
                    println!("Debug set to {}", deb);
                    let mut dl = dd.lock().await;
                    dl.debug.debug_graspdaemon = deb;
                }
                control::DullControl::DullNamespace { namespace_id: acpns } => {
                    println!("ACP namespace set to {}", acpns);
                    let mut dl = dd.lock().await;
                    dl.acpns = Pid::from_raw(acpns);
                }
                control::DullControl::UlaNumbering { prefix } => {
                    println!("Abutment interfaces will be numbered with {}", prefix );
                    let mut dl = dd.lock().await;
                    dl.abutifprefix = Some(prefix);
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
    // can not use  the tokio version!
    std::process::Command::new("mount")
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

/* duplicate code with acp.rs,  some kind of Template needed */
async fn ignore_sigint(dd: &Arc<Mutex<DullData>>) {

    let child2 = dd.clone();
    let rt = {
        let locked = child2.lock().await;
        locked.runtime.clone()
    };
    rt.spawn(async move {   // child2 moved
        loop {
            signal::ctrl_c().await.unwrap();
            {
                let mut dl = child2.lock().await;
                dl.exit_now = true;
            }
            sleep(Duration::from_millis(500)).await;
        }
    });
}

    // This is the first async function in the Abutment (DULL) child process
async fn child_processing(rt: Arc<tokio::runtime::Runtime>,
                          sock: UnixStream) {

    let parent_stream = tokio::net::UnixStream::from_std(sock).unwrap();
    let mut cs = ControlStream::child(parent_stream);
    let nm = Arc::new(Mutex::new(NetlinkInterface::new(rt.clone())));

    /* arrange to listen on network events in the new network namespace */
    let dd = Arc::new(Mutex::new(DullData::empty(rt.clone(), nm)));
    let _netlink_future = listen_network(&dd).await.unwrap();

    ignore_sigint(&dd).await;

    /* let parent know that we ready */
    println!("tell parent, child is ready");
    cs.write_child_ready().await.unwrap();

    /* listen to commands from the parent */
    println!("child waiting for commands");

    process_control(dd, cs).await;

    // listen/join on netlink_future
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

            println!("Hermes started new DULL network namespace: {}", child);
            return Ok(dull);
        }
        ForkResult::Child => {

            // close the parentfd in the child
            //pair.0.close().unwrap();

            //println!("Child redirected");

            // Open a log
            let stdoutlog = open_log("child_stdout.log").unwrap();
            let _out_redirect = Redirect::stdout(stdoutlog).unwrap();
            unset_cloexec(1).unwrap();

            // Log for stderr
            let stderrlog = open_log("child_stderr.log").unwrap();
            let _err_redirect = Redirect::stderr(stderrlog).unwrap();
            unset_cloexec(2).unwrap();

            /* create a new network namespace... BEFORE initializing runtime */
            /* the runtime may call clone(2), which if not unshared() would  */
            /* retain the parent network name space */
            println!("In child: creating name space");
            create_netns().unwrap();

            // tokio 1.7
            let rt0 = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .thread_name("dull")
                .enable_all()
                .build()
                .unwrap();
            let rt = Arc::new(rt0);
            let art = rt.clone();

            let future1 = child_processing(rt.clone(), pair.1);
            art.handle().block_on(future1);

            println!("now finished in child");
            std::process::exit(0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_route::address::AddressHeader;
    use netlink_packet_core::{
        NetlinkHeader, NetlinkMessage, NetlinkPayload,
    };
    use crate::systemif::tests::FakeNetlinkInterface;
    use netlink_packet_route::AddressFamily;

    /* define a second interface with ifindex and a Link-Local address,
     * for Join messages
     */
    fn setup_am_2() -> AddressMessage {
        let mut header = AddressHeader::default();
        header.family = AddressFamily::Inet6;
        header.prefix_len = 64;
        header.index = 12;

        let mut amb = AddressMessage::default();
        amb.header = header;
        amb.attributes = vec![
            AddressAttribute::Address(std::net::IpAddr::V6(
                Ipv6Addr::new(0xfe80,0,0,0,
                              0x0,   0,0,2)))
        ];
        amb
    }

    #[test]
    fn test_process_one_netlink_message() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let rt0 = Arc::new(rt);

        let rt1 = rt0.clone();
        rt1.block_on(async {
            let ni = FakeNetlinkInterface {};
            let nm: Arc<Mutex<dyn NetlinkManager + Send + Sync>> =
                Arc::new(Mutex::new(ni));
            let child = Arc::new(Mutex::new(DullData::empty(rt0.clone(), nm)));
            let debug = DebugOptions::empty();

            let mut netlinkheader = NetlinkHeader::default();
            netlinkheader.length = 1;
            netlinkheader.message_type = 2;
            netlinkheader.flags = 3;
            netlinkheader.sequence_number = 4;
            netlinkheader.port_number = 1234;
            let pl = NetlinkPayload::InnerMessage(NewAddress(setup_am_2()));
            let msg = NetlinkMessage::new(netlinkheader, pl);

            abutment_process_one_netlink(child,
                                         debug, false /* ikev2_started */,
                                         msg).await;
        })
    }
}

