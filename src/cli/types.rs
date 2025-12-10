use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Connection {
    pub proto: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub state: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConnectionsResponse {
    pub node_name: Option<String>,
    pub connections: Vec<Connection>,
}
