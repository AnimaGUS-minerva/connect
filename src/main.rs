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

use rtnetlink::new_connection;

static VERSION: &str = "1.0.0";
// static mut ARGC: isize = 0 as isize;
// static mut ARGV: *mut *mut i8 = 0 as *mut *mut i8;

async fn setup_dull_bridge() -> Result<(), String> {
    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    handle
        .link()
        .add()
        .veth("dull0".into(), "pdull0".into())
        .execute()
        .await
        .map_err(|e| format!("{}", e))
}

#[tokio::main]
async fn main() -> Result<(), String> {
    println!("Hermes Connect {}", VERSION);

    setup_dull_bridge().await.unwrap();

    return Ok(());
}

