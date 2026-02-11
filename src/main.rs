#![no_std]
#![no_main]

use core::mem::MaybeUninit;

use embassy_executor::Spawner;
use embassy_net::tcp::TcpSocket;
use embassy_net::{IpAddress, Ipv4Address, Stack, StackResources, dns};
use embassy_stm32::SharedData;
use embassy_stm32::eth::{Ethernet, GenericPhy, PacketQueue, Sma};
use embassy_stm32::flash::{BANK1_REGION, Flash, WRITE_SIZE};
use embassy_stm32::peripherals::{ETH, ETH_SMA, RNG};
use embassy_stm32::rng::Rng;
use embassy_stm32::{Config, bind_interrupts, eth, flash, peripherals, rng};
use embassy_time::Timer;

// MQTT support
use rust_mqtt::Bytes;
use rust_mqtt::buffer::BumpBuffer;
use rust_mqtt::client::{Client, options::ConnectOptions};
use rust_mqtt::config::{KeepAlive, SessionExpiryInterval};
use rust_mqtt::types::MqttString;

// TLS support
use embedded_tls::{
    Aes128GcmSha256, Certificate::X509, TlsConfig, TlsConnection, TlsContext, UnsecureProvider,
};

// Supplemental crates for network stack
use static_cell::StaticCell;

use defmt::{error, info, unwrap};
use {defmt_rtt as _, panic_probe as _};

// --- BEGIN PROTOBUF SETUP ---
use heapless::{String, format};
use micropb::{MessageDecode, PbDecoder};

mod proto {
    #![allow(clippy::all)]
    #![allow(nonstandard_style, unused, irrefutable_let_patterns)]
    include!(concat!(env!("OUT_DIR"), "/storage-proto.rs"));
}

use proto::storage_::{Credentials, Credentials_::Broker};
// --- END PROTOBUF SETUP ---

type EthernetDevice = Ethernet<'static, ETH, GenericPhy<Sma<'static, ETH_SMA>>>;
type ServerName = String<{ size_of::<Broker>() }>;
type TcpTlsConnection<'a> = TlsConnection<'a, TcpSocket<'a>, Aes128GcmSha256>;
type MqttClient<'a> = Client<'a, TcpTlsConnection<'a>, BumpBuffer<'a>, 1, 1, 1>;

#[unsafe(link_section = ".ram_d3.shared_data")]
static SHARED_DATA: MaybeUninit<SharedData> = MaybeUninit::uninit();

bind_interrupts!(struct Irqs {
    FLASH => flash::InterruptHandler;
    ETH => eth::InterruptHandler;
    HASH_RNG => rng::InterruptHandler<peripherals::RNG>;
});

const CREDENTIALS_OFFSET: u32 = BANK1_REGION.size / 2;

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let mut config = Config::default();
    {
        use embassy_stm32::rcc::*;
        config.rcc.hsi = Some(HSIPrescaler::DIV1);
        config.rcc.csi = true;
        config.rcc.pll1 = Some(Pll {
            source: PllSource::HSI,
            prediv: PllPreDiv::DIV4,
            mul: PllMul::MUL50,
            divp: Some(PllDiv::DIV2),
            divq: Some(PllDiv::DIV8), // 100mhz
            divr: None,
        });
        config.rcc.sys = Sysclk::PLL1_P; // 400 Mhz
        config.rcc.ahb_pre = AHBPrescaler::DIV2; // 200 Mhz
        config.rcc.apb1_pre = APBPrescaler::DIV2; // 100 Mhz
        config.rcc.apb2_pre = APBPrescaler::DIV2; // 100 Mhz
        config.rcc.apb3_pre = APBPrescaler::DIV2; // 100 Mhz
        config.rcc.apb4_pre = APBPrescaler::DIV2; // 100 Mhz
        config.rcc.voltage_scale = VoltageScale::Scale1;
        config.rcc.supply_config = SupplyConfig::DirectSMPS;
    }
    let p = embassy_stm32::init_primary(config, &SHARED_DATA);
    info!("Clock and peripherals ready!");

    // --- BEGIN READING CREDENTIALS ---
    let mut f = Flash::new(p.FLASH, Irqs);
    let mut credentials = Credentials::default();
    unwrap!(read_credentials(&mut f, &mut credentials));
    info!("Credentials read successfully!");
    // --- END READING CREDENTIALS ---

    // --- BEGIN NETWORK STACK SETUP ---
    // RNG peripheral needed for network stack
    let mut rng = Rng::new(p.RNG, Irqs);
    let mut seed = [0; 8];
    let _ = rng.async_fill_bytes(&mut seed).await;
    let seed = u64::from_le_bytes(seed);

    static PACKETS: StaticCell<PacketQueue<4, 4>> = StaticCell::new();
    static RESOURCES: StaticCell<StackResources<3>> = StaticCell::new();

    // Ethernet phy definition
    let mac_addr = [0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];
    let ethernet_device = Ethernet::new(
        PACKETS.init(PacketQueue::<4, 4>::new()),
        p.ETH,
        Irqs,
        p.PA1,
        p.PA7,
        p.PC4,
        p.PC5,
        p.PG13,
        p.PB13,
        p.PG11,
        mac_addr,
        p.ETH_SMA,
        p.PA2,
        p.PC1,
    );

    // Network stack defintion and initialization
    let net_conf = embassy_net::Config::dhcpv4(Default::default());
    let (stack, runner) = embassy_net::new(
        ethernet_device,
        net_conf,
        RESOURCES.init(StackResources::new()),
        seed,
    );
    unwrap!(spawner.spawn(net_task(runner)));
    stack.wait_config_up().await;
    info!("Network task initialized.");
    // --- END NETWORK STACK SETUP ---

    // --- BEGIN MQTT CLIENT ---
    loop {
        // Get endpoint information
        let port = *credentials.port() as u16;
        let (endpoint, server_name): ((Ipv4Address, u16), ServerName) =
            match get_ip_and_server_name(&stack, &credentials).await {
                Ok((ip_addr, server_name)) => ((ip_addr, port), server_name),
                Err(()) => continue,
            };

        // Establish TCP connection
        let mut rx_buffer = [0; 4096];
        let mut tx_buffer = [0; 4096];
        let socket = match connect_tcp_socket(stack, endpoint, &mut rx_buffer, &mut tx_buffer).await
        {
            Ok(s) => s,
            Err(()) => continue,
        };

        // Establish TLS handshake
        let mut rx_record_buffer = [0; 32768];
        let mut tx_record_buffer = [0; 32768];
        let tls = match open_tls_session(
            socket,
            &mut rng,
            &credentials,
            &server_name,
            &mut rx_record_buffer,
            &mut tx_record_buffer,
        )
        .await
        {
            Ok(tls) => tls,
            Err(()) => continue,
        };

        // Establish MQTT connection
        let mut mqtt_buf = [0; 4096];
        let mut mqtt_buf = BumpBuffer::new(&mut mqtt_buf);
        let mut mqtt_client = match connect_mqtt_client(tls, &credentials, &mut mqtt_buf).await {
            Ok(c) => c,
            Err(()) => continue,
        };

        loop {
            //let r = tls.write_all(&[0]).await;
            match mqtt_client.ping().await {
                Ok(()) => {
                    info!("MQTT ping to {} successful!", server_name);
                }
                Err(e) => {
                    info!("MQTT ping to {} failed, error: {:?}", server_name, e);
                    break;
                }
            }
            Timer::after_secs(1).await;
        }
    }
    // --- END MQTT CLIENT ---
}

#[embassy_executor::task]
async fn net_task(mut runner: embassy_net::Runner<'static, EthernetDevice>) -> ! {
    runner.run().await
}

async fn connect_mqtt_client<'a>(
    tls: TcpTlsConnection<'a>,
    credentials: &Credentials,
    buffer: &'a mut BumpBuffer<'a>,
) -> Result<MqttClient<'a>, ()> {
    info!("Establishing MQTT connection...");
    let mut mqtt_client: MqttClient = Client::<'_, _, _, 1, 1, 1>::new(buffer);
    let connect_options = ConnectOptions {
        clean_start: true,
        keep_alive: KeepAlive::Seconds(30),
        session_expiry_interval: SessionExpiryInterval::EndOnDisconnect,
        user_name: None,
        password: None,
        will: None,
    };
    // The client identifier should be test-device
    let ci: Bytes = credentials.client_id().as_bytes().into();
    let ci: MqttString = MqttString::new(ci).unwrap();
    match mqtt_client.connect(tls, &connect_options, Some(ci)).await {
        Ok(c) => {
            info!("Connected to server: {:?}", c);
            Ok(mqtt_client)
        }
        Err(e) => {
            error!("Failed to connect to server: {:?}", e);
            Err(())
        }
    }
}

async fn open_tls_session<'a>(
    socket: TcpSocket<'a>,
    rng: &'a mut Rng<'static, RNG>,
    credentials: &Credentials,
    server_name: &ServerName,
    rx_buffer: &'a mut [u8],
    tx_buffer: &'a mut [u8],
) -> Result<TcpTlsConnection<'a>, ()> {
    info!("Establishing TLS handshake...");
    let config = TlsConfig::new()
        .with_server_name(&server_name)
        .with_ca(X509(credentials.ca().as_slice()))
        .with_cert(X509(credentials.cert().as_slice()))
        .with_priv_key(credentials.key().as_slice());
    let mut tls = TlsConnection::new(socket, rx_buffer, tx_buffer);
    match tls
        .open(TlsContext::new(
            &config,
            UnsecureProvider::new::<Aes128GcmSha256>(rng),
        ))
        .await
    {
        Ok(()) => {
            info!("TLS handshake established!");
            Ok(tls)
        }
        Err(e) => {
            error!("Error establishing TLS handshake: {:?}", e);
            Err(())
        }
    }
}

async fn connect_tcp_socket<'a>(
    stack: Stack<'static>,
    endpoint: (Ipv4Address, u16),
    rx_buffer: &'a mut [u8],
    tx_buffer: &'a mut [u8],
) -> Result<TcpSocket<'a>, ()> {
    info!("Establishing TCP connection...");
    let mut socket = TcpSocket::new(stack, rx_buffer, tx_buffer);
    socket.set_timeout(Some(embassy_time::Duration::from_secs(10)));
    match socket.connect(endpoint).await {
        Ok(()) => {
            info!("Connected to endpoint: {:?}", endpoint);
            Ok(socket)
        }
        Err(e) => {
            error!("Connect error for endpoint {:?}: {:?}", endpoint, e);
            Err(())
        }
    }
}

async fn get_ip_and_server_name(
    stack: &Stack<'static>,
    credentials: &Credentials,
) -> Result<(Ipv4Address, ServerName), ()> {
    match credentials.broker {
        Some(Broker::Domain(ref domain)) => {
            let mut server_name: ServerName = String::new();
            info!("Broker's domain name: {}", domain.as_str());
            match stack.dns_query(domain.as_str(), dns::DnsQueryType::A).await {
                Ok(ip_addr) => match ip_addr[0] {
                    IpAddress::Ipv4(addr) => {
                        server_name.push_str(domain.as_str()).unwrap();
                        Ok((addr, server_name))
                    }
                },
                Err(e) => {
                    error!("DNS query failed for {}: {:?}", domain.as_str(), e);
                    Err(())
                }
            }
        }
        Some(Broker::Ipv4(ref ipv4)) => {
            let mut server_name: ServerName = String::new();
            if ipv4.len() != 4 {
                panic!(
                    "Broker's IPv4 address has invalid length: {}, expected 4",
                    ipv4.len()
                );
            }
            let octets = ipv4.as_slice();
            info!(
                "Broker's IPv4 address: {}.{}.{}.{}",
                octets[0], octets[1], octets[2], octets[3]
            );
            // Return string representation of IPv4 address as server name
            let ipv4_string: String<16> =
                format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]).unwrap();
            server_name.push_str(ipv4_string.as_str()).unwrap();
            Ok((
                Ipv4Address::new(octets[0], octets[1], octets[2], octets[3]),
                server_name,
            ))
        }
        None => {
            panic!("Credentials read from flash, but broker field is empty.");
        }
    }
}

fn read_credentials<'a>(f: &mut Flash<'a>, credentials: &mut Credentials) -> Result<(), ()> {
    // Declare a buffer to read the contents of flash into, this has to be byte aligned
    // to WRITE_SIZE bytes. We pad the buffer to the next WRITE_SIZE boundary.
    let mut buf =
        [0u8; size_of::<Credentials>() + (WRITE_SIZE - (size_of::<Credentials>() % WRITE_SIZE))];
    info!(
        "Size of credentials = {}, size of buffer = {}",
        size_of::<Credentials>(),
        buf.len()
    );

    // Attempt to read the contents of flash into the buffer
    match f.blocking_read(CREDENTIALS_OFFSET, &mut buf) {
        Ok(()) => {}
        Err(_) => {
            error!("Failed to read credentials from flash");
            return Err(());
        }
    }

    let mut decoder = PbDecoder::new(buf.as_slice());
    match credentials.decode_len_delimited(&mut decoder) {
        Ok(()) => {
            match &credentials.broker {
                Some(Broker::Domain(domain)) => {
                    info!("Broker's domain name: {}", domain.as_str());
                }
                Some(Broker::Ipv4(ipv4)) => {
                    if ipv4.len() != 4 {
                        error!(
                            "Broker's IPv4 address has invalid length: {}, expected 4",
                            ipv4.len()
                        );
                        return Err(());
                    }
                    let octets = ipv4.as_slice();
                    info!(
                        "Broker's IPv4 address: {}.{}.{}.{}",
                        octets[0], octets[1], octets[2], octets[3]
                    );
                }
                None => {
                    error!("Credentials read from flash, but broker field is empty.");
                    return Err(());
                }
            };
            info!("Credentials read from flash.");
            return Ok(());
        }
        Err(_) => {
            error!("Failed to read and decode credentials from flash.");
            return Err(());
        }
    }
}
