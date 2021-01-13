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

use nix::unistd::Pid;
use futures::stream::TryStreamExt;
use rtnetlink::{new_connection, Error, Handle, Error::NetlinkError};
use netlink_packet_route::ErrorMessage;
use std::io::ErrorKind;
use tokio::time::{delay_for, Duration};
//use std::os::unix::net::UnixStream;
use sysctl::Sysctl;
use structopt::StructOpt;
use tokio::sync::mpsc;

pub mod dull;
pub mod acp;
pub mod control;
pub mod dullgrasp;
pub mod grasp;
pub mod error;
pub mod graspsamples;
pub mod adjacency;
pub mod vtitun;

static VERSION: &str = "1.0.0";
// static mut ARGC: isize = 0 as isize;
// static mut ARGV: *mut *mut i8 = 0 as *mut *mut i8;

async fn addremove_dull_bridge(handle: &Handle, _dull: &dull::Dull, _name: &String, masterlink: u32) -> Result<(), Error> {
    let mut pull0 = handle.link().get().set_name_filter("pull0".to_string()).execute();
    if let Some(link) = pull0.try_next().await? {
        // put the interface down
        handle
            .link()
            .set(link.header.index)
            .down()
            .execute()
            .await?;

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

async fn setup_dull_bridge(handle: &Handle, dull: &dull::Dull, name: &String) -> Result<(), Error> {
    let mut trusted = handle.link().get().set_name_filter("trusted".to_string()).execute();
    let trusted_link = match trusted.try_next().await? {
        Some(link) => link,
        None => { println!("did not find bridge \"trusted\""); return Ok(()); }
    };
    // if no such bridge, then do a macvlan on eth0!

    let result = handle
        .link()
        .add()
        .veth("dull0".into(), "pull0".into())
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

    /* the interface is configured for not accept_ra, or accept_ra_dfl */
    if !dull.debug.allow_router_advertisement {
        println!("turn off router advertisements");
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

    addremove_dull_bridge(handle, dull, name, trusted_link.header.index).await?;
    return Ok(());
}


// rewrite with new Trait that takes Acp or Dull.
async fn exit_child(stream: &mut tokio::net::UnixStream) {
    let result = control::write_control(stream, &control::DullControl::Exit).await;

    match result  {
        Err(e) => match e.kind() {
            ErrorKind::BrokenPipe  => { return (); },
            _                      => { return (); }  // maybe error.
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

async fn parents(rt: &tokio::runtime::Runtime,
                 dullinit: dull::DullInit,
                 acpinit:  acp::AcpInit,
                 args: ConnectOptions) -> Result<(), String> {

    let mut dull = dull::Dull::from_dull_init(dullinit);
    let mut acp  = acp::Acp::from_acp_init(acpinit);

    dull.debug.debug_graspdaemon           = args.debug_graspdaemon;
    dull.debug.allow_router_advertisement  = args.allow_ra;

    // tell the DULL namespace the debug values
    set_debug(&mut dull).await;

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
    // calling new_connection() causes a crash on the block_on() below!
    let (connection, handle, _) = new_connection().unwrap();
    rt.spawn(connection);

    //println!("creating dull0");
    let bridgename = "dull0".to_string();
    let bridge = setup_dull_bridge(&handle, &dull, &bridgename).await;
    match bridge {
        Err(e) => { println!("Failing to create dull: {}", e); return Ok(()); },
        _ => {}
    };
    //println!("created dull0");

    let (mut sender, mut receiver) = mpsc::channel(2);

    /* send a signal every 500ms */
    rt.spawn(async move {
        loop {
            delay_for(Duration::from_millis(500)).await;
            sender.send(0).await.unwrap();
        }}
    );

    /* wait for signal to end */
    let mut cycles_to_end = (200) * (2);  /* 200s * 1/2 tick */
    while let Some(value) = receiver.recv().await {
        match value {
            0 => {
                cycles_to_end -= 1;
                if cycles_to_end == 0 {
                    break;
                }
            },
            1 => { break; }
            _ => {}
        }
    }

    println!("child shutting down");

    // remove from the bridge
    addremove_dull_bridge(&handle, &dull, &bridgename, 0).await.unwrap();

    exit_child(&mut dull.child_stream).await;
    exit_child(&mut acp.child_stream).await;

    return Ok(());
}

fn main () -> Result<(), String> {

    println!("Hermes Connect {}", VERSION);

    let args = ConnectOptions::from_args();

    /* before doing any async stuff, start the ACP namespace child */
    let acp  = acp::namespace_daemon().unwrap();

    /* before doing any async stuff, start the DULL child */
    let dull = dull::namespace_daemon().unwrap();

    // tokio 0.2
    let rt = tokio::runtime::Builder::new()
        .threaded_scheduler()
        .enable_all()
        .build()
        .unwrap();

    let future = parents(&rt, dull, acp, args);
    rt.handle().block_on(future).unwrap();

    return Ok(());
}
