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
use std::path::Path;
use std::fs::File;
use std::io::prelude::*;
//use rtnetlink::{new_connection};
use std::io::ErrorKind;
use tokio::time::{delay_for, Duration};
//use std::os::unix::net::UnixStream;
//use sysctl::Sysctl;
use structopt::StructOpt;
use tokio::sync::mpsc;
use tokio::signal;
use nix::unistd::Pid;
use nix::sys::signal::Signal;
use nix::sys::signal::kill;
use nix::unistd::mkdir;
use nix::sys::stat;
use nix::Error;

pub mod dull;
pub mod acp;
pub mod control;
pub mod dullgrasp;
pub mod grasp;
pub mod error;
pub mod graspsamples;
pub mod adjacency;
pub mod vtitun;
pub mod openswan;
pub mod openswanwhack;
pub mod systemif;

static VERSION: &str = "0.9.0";
// static mut ARGC: isize = 0 as isize;
// static mut ARGV: *mut *mut i8 = 0 as *mut *mut i8;

static VARCONNECT: &str = "/run/acp";

// rewrite with new Trait that takes Acp or Dull.
async fn exit_child(stream: &mut tokio::net::UnixStream) {
    let result = control::write_control(stream, &control::DullControl::Exit).await;

    match result  {
        Err(e) => match e.kind() {
            ErrorKind::BrokenPipe  => { println!("child already exited");  return (); },
            _                      => { println!("another error {:?}", e); return (); }  // maybe error.
        }
        _ => { return (); }
    }
}

#[derive(StructOpt)]
// Hermes Connect Autonomic Control Plane (ACP) manager
struct ConnectOptions {
    // turn on debugging from Grasp DULL
    #[structopt(default_value = "false", long, parse(try_from_str))]
    debug_graspdaemon: bool,

    // permit created DULL interfaces to accept Router Advertisements
    #[structopt(default_value = "false", long, parse(try_from_str))]
    allow_ra: bool,

    // how long to remain running, in seconds
    #[structopt(default_value = "86400", long, parse(try_from_str))]
    salive: u32,

    // whether to bring IPsec SA up automatically
    #[structopt(default_value = "false", long, parse(try_from_str))]
    auto_up: bool,

    //    bridge_name: String

}

async fn set_debug(dull: &mut dull::Dull) {
    let opt = control::DullControl::GraspDebug { grasp_debug: dull.debug.debug_graspdaemon };

    let result = control::write_control(&mut dull.child_stream, &opt).await;

    match result  {
        Err(e) => match e.kind() {
            ErrorKind::BrokenPipe  => { return (); },
            _                      => { return (); }  // maybe error.
        }
        _ => { return (); }
    }
}

async fn set_acp_ns(dull: &mut dull::Dull, acpns: Pid) {
    let opt = control::DullControl::DullNamespace { namespace_id: acpns.as_raw() as i32};

    let result = control::write_control(&mut dull.child_stream, &opt).await;

    match result  {
        Err(e) => match e.kind() {
            ErrorKind::BrokenPipe  => { return (); },
            _                      => { return (); }  // maybe error.
        }
        _ => { return (); }
    }
}

async fn set_auto_up_adj(dull: &mut dull::Dull, auto_up: bool) {
    let opt = control::DullControl::AutoAdjacency { adj_up: auto_up };

    let result = control::write_control(&mut dull.child_stream, &opt).await;

    match result  {
        Err(e) => match e.kind() {
            ErrorKind::BrokenPipe  => { return (); },
            _                      => { return (); }  // maybe error.
        }
        _ => { return (); }
    }
}

async fn parents(rt: Arc<tokio::runtime::Runtime>,
                 dullinit: dull::DullInit,
                 acpinit:  acp::AcpInit,
                 args: ConnectOptions) -> Result<(), String> {

    let mut dull = dull::Dull::from_dull_init(dullinit);
    let mut acp  = acp::Acp::from_acp_init(acpinit);

    dull.debug.debug_graspdaemon           = args.debug_graspdaemon;
    dull.debug.allow_router_advertisement  = args.allow_ra;
    let mut alivecycles = args.salive * 1000 * 2;

    // tell the DULL namespace the debug values
    set_debug(&mut dull).await;

    // tell the DULL whether to bring up IPsec automatically
    set_auto_up_adj(&mut dull, args.auto_up).await;

    // wait for hello from ACP and then DULL namespace
    println!("waiting for ACP  startup");
    while let Ok(msg) = control::read_control(&mut acp.child_stream).await {
        match msg {
            control::DullControl::ChildReady => break,
            _ => {}
        }
    }

    println!("waiting for DULL startup");
    while let Ok(msg) = control::read_control(&mut dull.child_stream).await {
        match msg {
            control::DullControl::ChildReady => break,
            _ => {}
        }
    }

    // tell the DULL system about the namespace from the ACP.
    set_acp_ns(&mut dull, acp.acppid).await;

    println!("child ready, now starting netlink thread");

    // start up thread to listen to netlink in parent space, looking for new interfaces
    let _parentloop = systemif::parent_processing(&rt, dull.dullpid).await;
    println!("parent processing loop started");

    let (mut sender, mut receiver) = mpsc::channel(2);

    let mut ctrlsend = sender.clone();

    /* listen for ctrl_c signal, and send a signal when received */
    rt.spawn(async move {
        loop {
            signal::ctrl_c().await.unwrap();
            ctrlsend.send(1).await.unwrap();
            delay_for(Duration::from_millis(500)).await;
        }
    });

    /* send a signal every 500ms for various events */
    rt.spawn(async move {
        loop {
            //println!("spin");
            delay_for(Duration::from_millis(500)).await;
            sender.send(0).await.unwrap();
        }}
    );

    /* wait for signal to end */
    while let Some(value) = receiver.recv().await {
        //println!("spun {}", alivecycles);
        match value {
            0 => {
                alivecycles -= 1;
                if alivecycles == 0 {
                    break;
                }
            },
            1 => { break; }
            _ => {}
        }
    }

    println!("\nshutting down children");

    // remove from the bridge
    //systemif::addremove_bridge(false, &handle, &dull, &ifname, 0).await.unwrap();

    exit_child(&mut dull.child_stream).await;
    exit_child(&mut acp.child_stream).await;

    println!("\nwaiting for children to shutdown");
    delay_for(Duration::from_millis(1000)).await;
    kill(dull.dullpid, Signal::SIGINT).unwrap();
    kill(acp.acppid, Signal::SIGINT).unwrap();

    return Ok(());
}

fn write_pid(file: &str, pid: Pid) -> Result<(), std::io::Error> {

    let pidfilename = Path::new(VARCONNECT).join(file);
    let mut file = File::create(pidfilename)?;
    file.write(format!("{}\n", pid).as_bytes())?;
    Ok(())
}

fn main () -> Result<(), String> {

    println!("Hermes Connect {}", VERSION);

    let args = ConnectOptions::from_args();

    match mkdir(VARCONNECT, stat::Mode::S_IRWXU) {
        Ok(_) => { },
        Err(Error::Sys(x)) if x == nix::errno::Errno::EEXIST => { },
        Err(x) => { println!("can not create control directory {}: {:?}",
                             VARCONNECT, x);
        }
    }

    /* before doing any async stuff, start the ACP namespace child */
    let acp  = acp::namespace_daemon().unwrap();
    write_pid("acp.pid", acp.dullpid).unwrap();

    /* before doing any async stuff, start the DULL child */
    let dull = dull::namespace_daemon().unwrap();
    write_pid("dull.pid", dull.dullpid).unwrap();

    // tokio 0.2
    let brt = tokio::runtime::Builder::new()
        .threaded_scheduler()
        .enable_all()
        .build()
        .unwrap();

    let rt = Arc::new(brt);
    let future = parents(rt.clone(), dull, acp, args);
    rt.handle().block_on(future).unwrap();

    return Ok(());
}

/*
 * Local Variables:
 * mode: rust
 * compile-command: "cd .. && cargo build"
 * End:
 */
