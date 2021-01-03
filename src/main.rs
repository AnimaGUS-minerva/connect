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

use futures::stream::TryStreamExt;
use rtnetlink::{new_connection, Error, Handle, Error::NetlinkError};
use netlink_packet_route::ErrorMessage;
use std::io::ErrorKind;
use tokio::time::{delay_for, Duration};
//use std::os::unix::net::UnixStream;

pub mod dull;
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

async fn setup_dull_bridge(handle: &Handle, dull: &dull::Dull, name: String) -> Result<(), Error> {
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

    let mut pull0 = handle.link().get().set_name_filter("pull0".to_string()).execute();
    if let Some(link) = pull0.try_next().await? {
        handle
            .link()
            .set(link.header.index)
            .up()
            .execute()
            .await?;
        handle
            .link()
            .set(link.header.index)
            .master(trusted_link.header.index)
            .execute()
            .await?;
    } else {
        println!("no link link {} found", "pull0");
        return Ok(());
    }



    return Ok(());
}

async fn exit_child(dull: &mut dull::Dull) {
    let result = control::write_control(&mut dull.child_stream, &control::DullControl::Exit).await;

    match result  {
        Err(e) => match e.kind() {
            ErrorKind::BrokenPipe  => { return (); },
            _                      => { return (); }  // maybe error.
        }
        _ => { return (); }
    }
}

async fn parent(rt: &tokio::runtime::Runtime, dullinit: dull::DullInit) -> Result<(), String> {

    let mut dull = dull::Dull::from_dull_init(dullinit);

    // wait for hello from child.
    //println!("waiting for hello from child");
    while let Ok(msg) = control::read_control(&mut dull.child_stream).await {
        match msg {
            control::DullControl::ChildReady => break,
            _ => {}
        }
    }

    println!("child ready, now starting netlink thread");
    // calling new_connection() causes a crash on the block_on() below!
    let (connection, handle, _) = new_connection().unwrap();
    rt.spawn(connection);

    //println!("creating dull0");
    let bridge = setup_dull_bridge(&handle, &dull, "dull0".to_string()).await;
    match bridge {
        Err(e) => { println!("Failing to create dull: {}", e); return Ok(()); },
        _ => {}
    };

    //println!("created dull0");

    /* now shutdown the child after the delay */
    delay_for(Duration::from_millis(200000)).await;
    exit_child(&mut dull).await;

    println!("child shutdown");
    return Ok(());
}


fn main () -> Result<(), String> {

    println!("Hermes Connect {}", VERSION);

    /* before doing any async stuff, start the child */
    let dull = dull::namespace_daemon().unwrap();

    // tokio 0.2
    let rt = tokio::runtime::Builder::new()
        .threaded_scheduler()
        .enable_all()
        .build()
        .unwrap();

    let future = parent(&rt, dull);
    rt.handle().block_on(future).unwrap();

    return Ok(());
}
