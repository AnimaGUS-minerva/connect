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

use nix::sys::signal::*;
use nix::unistd::*;

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

pub struct Dull {
    parentfd: tokio::net::UnixStream,
    childfd:  tokio::net::UnixStream
}

pub fn dull_namespace_daemon() -> Result<(), String> {

    // set up a pair of sockets, connected
    let pair = tokio::net::UnixStream::pair().unwrap();

    let _d1 = Dull { parentfd: pair.0, childfd: pair.1 };

    match unsafe{fork()}.expect("fork failed") {
        ForkResult::Parent{ child } => {
            sleep(5);
            kill(child, SIGKILL).expect("kill failed");
        }
        ForkResult::Child => {
            loop {}  // until killed
        }
    }
    return Ok(());
}
