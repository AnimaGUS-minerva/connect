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
use rtnetlink::{new_connection, Error, Handle};

pub mod dull;
pub mod control;
//use std::env;

static VERSION: &str = "1.0.0";
// static mut ARGC: isize = 0 as isize;
// static mut ARGV: *mut *mut i8 = 0 as *mut *mut i8;

/*
async fn set_link_down(handle: Handle, name: String) -> Result<(), Error> {
    let mut links = handle.link().get().set_name_filter(name.clone()).execute();
    if let Some(link) = links.try_next().await? {
        handle
            .link()
            .set(link.header.index)
            .down()
            .execute()
            .await?
    } else {
        println!("no link link {} found", name);
    }
    Ok(())
}
*/

async fn setup_dull_bridge(handle: Handle, name: String) -> Result<(), Error> {
    let _result = handle
        .link()
        .add()
        .veth("dull0".into(), "pdull0".into())
        .execute()
        .await
        .map_err(|e| format!("{}", e));

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
            .setns_by_pid(1u32)
            .execute()
            .await?;
    } else {
        println!("no link link {} found", "dull0");
        return Ok(());
    }

    return Ok(());
}

#[tokio::main]
async fn main() -> Result<(), String> {
    println!("Hermes Connect {}", VERSION);

    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    let _dull = dull::dull_namespace_daemon();

    setup_dull_bridge(handle, "dull0".to_string()).await.unwrap();

    return Ok(());
}

