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

use crate::control;
use futures::prelude::*;
//use nix::sys::signal::*;
use nix::unistd::*;
//use socket2::{Socket, Domain, Type};
use std::os::unix::net::UnixStream;

// use futures::stream::TryStreamExt;
// use rtnetlink::{new_connection, Error, Handle};

/*
  match unsafe{fork()} {
   Ok(ForkResult::Parent { child, .. }) => {
       println!("Continuing execution in parent process, new child has pid: {}", child);
   }
   Ok(ForkResult::Child) => println!("I'm a new child process"),
   Err(_) => println!("Fork failed"),
}
 */

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


use tokio_serde::formats::*;
use tokio_util::codec::{FramedRead, LengthDelimitedCodec};

pub async fn dull_process_control(sock: UnixStream) {
    let child_sock = tokio::net::UnixStream::from_std(sock).unwrap();

    // stupid copy from read_control!
    let my_read_stream = FramedRead::new(child_sock, LengthDelimitedCodec::new());
    let mut deserialized =
        tokio_serde::SymmetricallyFramed::new(my_read_stream, SymmetricalCbor::default());

    loop {
        if let Ok(thing) = deserialized.try_next().await {
            match thing {
                Some(msg) =>
                    match msg {
                        control::DullControl::Exit => {
                            println!("DULL process exiting");
                            std::process::exit(0);
                        }
                        control::DullControl::AdminDown { interface_index: ifn } => {
                            println!("DULL turning off interface {}", ifn);
                        }
                    }
                None => {
                    println!("Got nothing reading from socket");
                }
            }
        }
    }
}


pub fn dull_namespace_daemon() -> Result<DullInit, std::io::Error> {

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

            println!("now in child");
            let rt = tokio::runtime::Runtime::new().unwrap();
            let future = dull_process_control(pair.1);
            println!("blocking in child");
            rt.block_on(future);
            println!("now finished in child");
            std::process::exit(0);
        }
    }
}
