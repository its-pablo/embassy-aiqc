#![no_std]
#![no_main]

use core::mem::MaybeUninit;
use core::net::SocketAddr;

use embassy_executor::Spawner;
use embassy_net::tcp::TcpSocket;
use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{IpAddress, Ipv4Address, Stack, StackResources, dns};
use embassy_stm32::SharedData;
use embassy_stm32::eth::{Ethernet, GenericPhy, PacketQueue, Sma};
use embassy_stm32::flash::{BANK1_REGION, Flash, WRITE_SIZE};
use embassy_stm32::gpio::{AnyPin, Level, Output, Speed};
use embassy_stm32::peripherals::{ETH, ETH_SMA, RNG};
use embassy_stm32::rng::Rng;
use embassy_stm32::rtc::{Rtc, RtcConfig, RtcTimeProvider};
use embassy_stm32::{Config, Peri, bind_interrupts, eth, flash, peripherals, rng};
use embassy_sync::{
    blocking_mutex::raw::NoopRawMutex,
    channel::{Channel, Sender},
    once_lock::OnceLock,
};
use embassy_time::{Ticker, Timer, WithTimeout};

// MQTT support
use rust_mqtt::Bytes;
use rust_mqtt::buffer::BumpBuffer;
use rust_mqtt::client::{
    Client, event::Event, options::ConnectOptions, options::PublicationOptions,
    options::RetainHandling, options::SubscriptionOptions,
};
use rust_mqtt::config::{KeepAlive, SessionExpiryInterval};
use rust_mqtt::types::{MqttString, TopicName};

// TLS support
use embedded_tls::{Aes128GcmSha256, Certificate::X509, TlsConfig, TlsConnection, TlsContext};

// NTP and time support
use chrono::{DateTime, Duration, NaiveDateTime};
use sntpc::{NtpContext, NtpTimestampGenerator, fraction_to_nanoseconds, get_time};
use sntpc_net_embassy::UdpSocketWrapper;

// Supplemental crates for network stack
use static_cell::StaticCell;

use defmt::{error, info, unwrap, warn};
use {defmt_rtt as _, panic_probe as _};

// Pitchfork use statements
use crate::pitchfork::tls::PitchforkCryptoProvider;

// Pitchfork modules
mod pitchfork;

// --- BEGIN PROTOBUF SETUP ---
use heapless::{String, Vec, format};
use micropb::{MessageDecode, MessageEncode, PbDecoder, PbEncoder};

mod proto {
    #![allow(clippy::all)]
    #![allow(nonstandard_style, unused, irrefutable_let_patterns)]
    include!(concat!(env!("OUT_DIR"), "/aiqc-proto.rs"));
}

use proto::google_::protobuf_::Timestamp;
use proto::pitchfork_::{Credentials, Credentials_::Broker, Packet, Packet_::Payload};
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
const NTP_SERVER: &str = "time.google.com";

// Static RTC time provider for usage throughout the entire application
pub static TIME_PROVIDER: OnceLock<RtcTimeProvider> = OnceLock::new();

#[derive(Copy, Clone)]
struct TimestampGenerator<'a> {
    duration: Duration,
    time_provider: &'a RtcTimeProvider,
}

impl NtpTimestampGenerator for TimestampGenerator<'_> {
    fn init(&mut self) {
        let now: NaiveDateTime = self.time_provider.now().unwrap().into();
        self.duration = now.signed_duration_since(DateTime::UNIX_EPOCH.naive_utc());
    }

    fn timestamp_sec(&self) -> u64 {
        self.duration.num_seconds() as u64
    }

    fn timestamp_subsec_micros(&self) -> u32 {
        self.duration.subsec_micros() as u32
    }
}

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

    // Start blinky as proof that we aren't significantly stalling at any point
    unwrap!(spawner.spawn(blinky(p.PB0.into(), 200)));

    // --- BEGIN READING CREDENTIALS ---
    let mut f = Flash::new(p.FLASH, Irqs);
    let mut credentials = Credentials::default();
    unwrap!(read_credentials(&mut f, &mut credentials));
    info!("Credentials read successfully!");
    // --- END READING CREDENTIALS ---

    // Set up RTC for time keeping
    let (mut rtc, time_provider) = Rtc::new(p.RTC, RtcConfig::default());
    {
        let time_provider = TIME_PROVIDER.get_or_init(|| time_provider);
        let rtc_time = time_provider.now().unwrap();
        info!(
            "Current time from RTC at boot: {}-{}-{} {}:{}:{}",
            rtc_time.year(),
            rtc_time.month(),
            rtc_time.day(),
            rtc_time.hour(),
            rtc_time.minute(),
            rtc_time.second()
        );
    }

    // Set up channels for inter-task communication
    static CH: StaticCell<Channel<NoopRawMutex, Vec<u8, 128>, 4>> = StaticCell::new();
    let ch = CH.init(Channel::new());
    let ch_tx = ch.sender();
    let ch_rx = ch.receiver();

    // Start sender task to send messages to MQTT task
    unwrap!(spawner.spawn(sender(ch_tx)));

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
        // Buffers for TCP and UDP sockets
        let mut rx_buffer = [0; 4096];
        let mut tx_buffer = [0; 4096];

        // Get NTP time and set RTC
        {
            // Get NTP endpoint information
            let ntp_port = 123;
            let ntp_addr: Ipv4Address =
                match stack.dns_query(NTP_SERVER, dns::DnsQueryType::A).await {
                    Ok(addrs) => match addrs[0] {
                        IpAddress::Ipv4(addr) => addr,
                    },
                    Err(e) => {
                        error!("DNS query failed for {}: {:?}", NTP_SERVER, e);
                        continue;
                    }
                };

            let mut rx_meta = [PacketMetadata::EMPTY; 16];
            let mut tx_meta = [PacketMetadata::EMPTY; 16];
            let mut udp_socket = UdpSocket::new(
                stack,
                &mut rx_meta,
                &mut rx_buffer,
                &mut tx_meta,
                &mut tx_buffer,
            );
            udp_socket.bind(123).unwrap();
            let udp_socket = UdpSocketWrapper::new(udp_socket);
            let time_provider = TIME_PROVIDER.get().await;
            let ts_gen = TimestampGenerator {
                duration: Duration::zero(),
                time_provider: &time_provider,
            };
            let ntp_context = NtpContext::new(ts_gen);
            let ntp_result = get_time(
                SocketAddr::from((ntp_addr, ntp_port)),
                &udp_socket,
                ntp_context,
            )
            .await;
            match ntp_result {
                Ok(time) => {
                    info!("NTP time: {:?}", time);
                    let dt = DateTime::from_timestamp(
                        time.sec() as i64,
                        fraction_to_nanoseconds(time.sec_fraction()),
                    )
                    .unwrap();
                    let _ = rtc.set_datetime(dt.naive_utc().into());
                    let rtc_time = time_provider.now().unwrap();
                    info!(
                        "Current time from RTC after NTP sync: {}-{}-{} {}:{}:{}",
                        rtc_time.year(),
                        rtc_time.month(),
                        rtc_time.day(),
                        rtc_time.hour(),
                        rtc_time.minute(),
                        rtc_time.second()
                    );
                }
                Err(e) => {
                    error!("Failed to get NTP time: {:?}", e);
                    continue;
                }
            }
        }

        // Get endpoint information
        let port = *credentials.port() as u16;
        let (endpoint, server_name): ((Ipv4Address, u16), ServerName) =
            match get_ip_and_server_name(&stack, &credentials).await {
                Ok((ip_addr, server_name)) => ((ip_addr, port), server_name),
                Err(()) => continue,
            };

        // Establish TCP connection
        rx_buffer.fill(0);
        tx_buffer.fill(0);
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

        // Ping the broker once
        match mqtt_client.ping().await {
            Ok(()) => {
                info!("MQTT ping to {} successful!", server_name);
                loop {
                    match mqtt_client.poll().await {
                        Ok(Event::Pingresp) => {
                            info!("Ping response received");
                            break;
                        }
                        Ok(e) => info!("Received event {:?}", e),
                        Err(e) => {
                            error!("Failed to poll: {:?}", e);
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                error!("MQTT ping to {} failed, error: {:?}", server_name, e);
                continue;
            }
        }

        let tn: Bytes = b"test/topic".as_slice().into();
        let tn: MqttString = MqttString::new(tn).unwrap();
        let tn: TopicName = unsafe { TopicName::new_unchecked(tn) };
        let pub_opts = PublicationOptions {
            topic: tn,
            qos: rust_mqtt::types::QoS::AtLeastOnce,
            retain: false,
        };

        let tn: Bytes = b"test/topic".as_slice().into();
        let tn: MqttString = MqttString::new(tn).unwrap();
        let tn: TopicName = unsafe { TopicName::new_unchecked(tn) };
        let sub_opts = SubscriptionOptions {
            qos: rust_mqtt::types::QoS::AtLeastOnce,
            no_local: false,
            retain_as_published: false,
            retain_handling: RetainHandling::SendIfNotSubscribedBefore,
        };
        match mqtt_client.subscribe(tn.into(), sub_opts).await {
            Ok(_) => info!("MQTT subscription successful!"),
            Err(e) => {
                error!("MQTT subscription failed, error: {:?}", e);
                continue;
            }
        }

        let mut pub_ack_pending: Option<u16> = None;

        loop {
            // Poll cancel safe header to process any events
            let header = mqtt_client.poll_header();
            let header = header
                .with_timeout(embassy_time::Duration::from_millis(10))
                .await;
            match header {
                Ok(Ok(h)) => match mqtt_client.poll_body(h).await {
                    Ok(Event::PublishAcknowledged(pub_ack)) => {
                        if Some(pub_ack.packet_identifier) == pub_ack_pending {
                            info!(
                                "Publish acknowledged for packet identifier {}",
                                pub_ack.packet_identifier
                            );
                            pub_ack_pending = None;
                        } else {
                            warn!(
                                "Received publish acknowledgment for packet identifier {}, but no pending publish found",
                                pub_ack.packet_identifier
                            );
                        }
                    }
                    Ok(Event::Publish(publication)) => {
                        // Decode contents of publication.message as a Packet protobuf message
                        let message: &[u8] = publication.message.as_ref();
                        let mut packet = Packet::default();
                        let mut decoder = PbDecoder::new(message);
                        match packet.decode(&mut decoder, message.len()) {
                            Ok(()) => match packet.payload {
                                Some(Payload::Measurement(measurement)) => {
                                    info!(
                                        "Received measurement: moisture = {:?}, timestamp = {} seconds and {} nanos since UNIX epoch",
                                        measurement.moisture,
                                        packet.timestamp.seconds,
                                        packet.timestamp.nanos
                                    );
                                }
                                Some(Payload::Command(_)) => {
                                    info!("Received command!");
                                }
                                None => {
                                    warn!("Received packet with no payload");
                                }
                            },
                            Err(_) => error!("Failed to decode packet from publication!"),
                        }
                    }
                    Ok(e) => info!("Received event {:?}", e),
                    Err(e) => {
                        error!("Failed to poll body: {:?}", e);
                        break;
                    }
                },
                Ok(Err(e)) => {
                    error!("Failed to poll header: {:?}", e);
                    break;
                }
                // If no headers were received during this period of time move on and check if
                // there are messages to publish.
                Err(_) => {}
            }

            // Check if there are any messages pending to publish
            if pub_ack_pending.is_none() {
                let msg = ch_rx.try_receive();
                match msg {
                    Ok(m) => {
                        let msg: Bytes = m.as_slice().into();
                        let msg_size = msg.len();
                        match mqtt_client.publish(&pub_opts, msg).await {
                            Ok(packet_id) => {
                                info!(
                                    "MQTT publish to {} successful! Message size: {} bytes",
                                    server_name, msg_size
                                );
                                pub_ack_pending = Some(packet_id);
                            }
                            Err(e) => {
                                error!("MQTT publish to {} failed, error: {:?}", server_name, e);
                                break;
                            }
                        }
                    }
                    Err(_) => {}
                }
            }
        }
    }
    // --- END MQTT CLIENT ---
}

#[embassy_executor::task]
async fn net_task(mut runner: embassy_net::Runner<'static, EthernetDevice>) -> ! {
    runner.run().await
}

#[embassy_executor::task]
async fn blinky(led: Peri<'static, AnyPin>, period: u64) -> ! {
    let mut led = Output::new(led, Level::Low, Speed::Low);
    loop {
        led.set_high();
        Timer::after_millis(period / 2).await;

        led.set_low();
        Timer::after_millis(period / 2).await;
    }
}

#[embassy_executor::task]
async fn sender(ch_tx: Sender<'static, NoopRawMutex, Vec<u8, 128>, 4>) -> ! {
    let mut ticker = Ticker::every(embassy_time::Duration::from_secs(60));
    loop {
        ticker.next().await;
        let timestamp: NaiveDateTime = {
            let time_provider = TIME_PROVIDER.get().await;
            let rtc_time = time_provider.now().unwrap();
            rtc_time.into()
        };
        let dur = timestamp.signed_duration_since(DateTime::UNIX_EPOCH.naive_utc());
        let mut packet = Packet::default();
        let mut packet_ts = Timestamp::default();
        packet_ts.seconds = dur.num_seconds();
        packet_ts.nanos = dur.subsec_nanos();
        packet.set_timestamp(packet_ts);
        packet.payload = Some(proto::pitchfork_::Packet_::Payload::Measurement(
            proto::pitchfork_::Measurement { moisture: 0.42 },
        ));
        let mut msg: Vec<u8, 128> = Vec::new();
        let mut encoder = PbEncoder::new(&mut msg);
        packet.encode(&mut encoder).unwrap();
        ch_tx.send(msg).await;
    }
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
        keep_alive: KeepAlive::Seconds(90),
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
    let config = TlsConfig::new().with_server_name(&server_name);
    let provider = PitchforkCryptoProvider::new(rng)
        .with_ca(X509(credentials.ca().as_slice()))
        .with_cert(X509(credentials.cert().as_slice()))
        .with_priv_key(credentials.key().as_slice());
    let mut tls = TlsConnection::new(socket, rx_buffer, tx_buffer);
    match tls.open(TlsContext::new(&config, provider)).await {
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
    socket.set_timeout(Some(embassy_time::Duration::from_secs(90)));
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
