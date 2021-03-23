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
use futures::stream::{StreamExt, TryStreamExt};
//use std::process::{ExitStatus};
use tokio::process::{Command};
use netlink_packet_route::ErrorMessage;
use rtnetlink::{
    constants::{RTMGRP_LINK},
    Error,  Error::NetlinkError,  Handle,
    new_connection,
    sys::SocketAddr,
};
use netlink_packet_route::{
    NetlinkPayload::InnerMessage,
    RtnlMessage::NewLink,
//    RtnlMessage::NewAddress,
//    RtnlMessage::NewRoute,
//    RtnlMessage::DelRoute,
//    RtnlMessage::DelAddress,
    RtnlMessage::DelLink,
    LinkMessage,
//    AddressMessage
};
//use std::os::unix::net::UnixStream;
//use sysctl::Sysctl;
use crate::dull;

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

async fn gather_parent_link_info(_handle: &Handle, lm: LinkMessage) -> Result<(), Error> {
    let ifindex = lm.header.index;
    println!("ifindex: {:?} ", ifindex);

    //data.store_link_info(lm, ifindex).await;

    let _ifindex = lm.header.index;

    // add/remove it into the trusted bridge
    //let dev = handle
    //.link()
    //.get(ifindex).await.unwrap();

    Command::new("ip")
        .arg("link")
        .arg("ls")
        .status()
        .await
        .expect("ls command failed to start");

    Ok(())
}

pub async fn parent_processing(rt: &Arc<tokio::runtime::Runtime>) -> Result<tokio::task::JoinHandle<Result<(),Error>>, String> {

    let rt1 = rt.clone();

    /* NETLINK listen_network activity daemon: process it all in the background */
    let listenhandle = rt.spawn(async move {
        // Open the netlink socket
        let (mut connection, handle, mut messages) = new_connection().map_err(|e| format!("{}", e)).unwrap();

        // These flags specify what kinds of broadcast messages we want to listen for.
        // we just care about LINK changes
        let mgroup_flags = RTMGRP_LINK;

        // A netlink socket address is created with said flags.
        let addr = SocketAddr::new(0, mgroup_flags);
        // Said address is bound so new conenctions and thus new message broadcasts can be received.
        connection.socket_mut().bind(&addr).expect("failed to bind");
        rt1.spawn(connection);

        while let Some((message, _)) = messages.next().await {
            let payload = message.payload;
            match payload {
                InnerMessage(DelLink(_stuff)) => {
                    /* happens when we move an ethernet pair or macvlan to another namespace */
                    /* need to sort out when it is relevant by looking at name and LinkHeader */
                }

                InnerMessage(NewLink(stuff)) => {
                    // this is a new device
                    gather_parent_link_info(&handle, stuff).await.unwrap();
                }
                _ => { println!("msg type: {:?}", payload); }
            }
        };
        Ok(())
    });

    Ok(listenhandle)
}


