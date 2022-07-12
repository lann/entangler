use anyhow::{anyhow, bail, ensure, Context, Result};
use pcap::{Capture, Device};
use pnet_packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    tcp::TcpPacket,
    Packet,
};
use rustls::internal::msgs::{
    codec::Reader,
    enums::ContentType,
    handshake::{HandshakeMessagePayload, HandshakePayload},
    message::{Message, MessagePayload::Handshake, OpaqueMessage},
};

// TODO: validate this size
const MAX_PACKET_CAPTURE_SIZE: i32 = 1024;

struct Config {
    device_name: Option<String>,
    port: u16,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            device_name: None,
            port: 443,
        }
    }
}

impl Config {
    fn run(self) -> Result<()> {
        let device = self
            .device_name
            .as_deref()
            .map(|name| Ok(Device::from(name)))
            .unwrap_or_else(Device::lookup)?;

        println!("Opening device {}...", device.name);

        let mut cap = Capture::from_device(device)?
            .immediate_mode(true)
            .snaplen(MAX_PACKET_CAPTURE_SIZE)
            .open()?;

        // TODO: try to filter out non-handshake packets here
        let filter = format!("tcp dst port {}", self.port);
        cap.filter(&filter, true)?;

        println!("Listening for packets on port {}...", self.port);

        loop {
            if let Err(err) = self.handle_packet(cap.next()?) {
                println!("Error parsing packet: {:?}", err);
            }
        }
    }

    fn handle_packet(&self, packet: pcap::Packet) -> Result<()> {
        // NOTE: all of this _should_ be valid based on the pcap `tcp` filter
        let eth = EthernetPacket::new(packet.data).context("invalid ethernet")?;
        let ip: Box<dyn Packet> = match eth.get_ethertype() {
            EtherTypes::Ipv4 => Box::new(Ipv4Packet::new(eth.payload()).context("invalid ipv4")?),
            EtherTypes::Ipv6 => Box::new(Ipv6Packet::new(eth.payload()).context("invalid ipv6")?),
            _ => bail!("not an IP packet"),
        };
        let tcp = TcpPacket::new(ip.payload()).context("invalid tcp")?;

        // TLS decoding
        let opaque = OpaqueMessage::read(&mut Reader::init(tcp.payload()))
            .map_err(|err| anyhow!("invalid tls: {:?}", err))?;
        ensure!(
            opaque.typ == ContentType::Handshake,
            "not a handshake message"
        );
        let tls: Message = opaque.into_plain_message().try_into()?;
        let client_hello = match tls.payload {
            Handshake {
                parsed:
                    HandshakeMessagePayload {
                        payload: HandshakePayload::ClientHello(payload),
                        ..
                    },
                ..
            } => payload,
            _ => bail!("not a client hello message"),
        };
        for server_name in client_hello
            .get_sni_extension()
            .context("no SNI extension")?
        {
            if let rustls::internal::msgs::handshake::ServerNamePayload::HostName((_, ref name)) =
                server_name.payload
            {
                self.handle_sni_name(AsRef::<str>::as_ref(name))
            }
        }
        Ok(())
    }

    fn handle_sni_name(&self, name: &str) {
        println!("Got SNI name: {}", name);
    }
}

fn main() {
    let config = Config {
        device_name: std::env::args().nth(1),
        ..Default::default()
    };

    if let Err(err) = config.run() {
        println!("Error: {:?}", err);
    }
}
