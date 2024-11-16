# Veloce

_Veloce_ is a C-ITS stack written in Rust. It is `#[no_std]` compatible although it requires `alloc`.

_Veloce_ stack architecture is based on [Smoltcp](https://github.com/smoltcp-rs/smoltcp).
Careful dependency management is used to keep the code simple and avoid bloating.

_Veloce_ supports the ETSI V2x protocols, including:
* Geonetworking
* CAM
* DENM

IEEE1609 protocol support is planned.

## Modules

The _Veloce_ project is composed of several modules:

* `veloce`: the core of the stack, containing the networking logic and higher level interfaces.
* `veloce-asn1`: the ASN.1 module, containing the Rust ASN.1 definitions of the C-ITS protocols.
* `veloce-chemistry`: A toy application written in Elixir to interface with the stack, through the IPC module definitions.
* `veloce-gnss`: the GNSS module, containing the interfaces with GPS receivers and an NMEA replayer for testing.
* `veloce-ipc`: the Inter Process Communication module, based on _protobuf_.
* `veloce-nxp-phy`: the NXP PHY module, interfacing V2x NXP SAF5x00 chips.

## Features

_Veloce_ has several features, which can be enabled or disabled at compile time.

### Medium

There are 3 supported mediums.

* Ethernet for conformance and/or testing
* IEEE 802.11p for WiFi based V2x communications
  * ETSI Decentralized Congestion Control (DCC) with the Limerick algorithm is supported.
* PC5 for LTE/5G V2x communications

### Protocols
#### Geonetworking

What is supported:

* Beacon
* Location Service request and reply
* GeoUnicast (GUC)
* GeoAnycast (GAC)
* GeoBroadcast (GBC)
* SingleHopBroadcast (SHB)
* TopoBroadcast (TSB)
* Security with certificate and signature generation/verification

What is not supported:
* IPv6 over Geonetworking
* Packet repetition (which must be handled at the application layer)

#### BTP

* BTP-A only with GUC transport.
* BTP-B with all Geonetworking transports.

#### CAM

What is supported:

* CAM message generation with dynamic transmission period for moving stations.
* CAM transmission period override
* Rx/Tx events notifications

What is not supported:

* Special containers management

#### DENM

What is supported:

* Trigger/Update/Cancel/Negate through the Socket API/IPC
* Rx/Tx events notifications

What is not supported:

* Keep alive forwarding (although it is possible to specify a keep-alive interval through the API)


## Examples
Two examples are provided in the `examples` directory for ease of testing:

* `obu`: a simple OBU (On Board Unit) example, which can run on a computer.
* `mk5`: make _Veloce_ run on a real V2x device from your favorite vendor.

## License

You can use _Veloce_ under ***any*** of the following licenses, at your choice:

1. Build open source embedded, desktop or mobile applications for free with the [GNU GPLv3](LICENSES/GPL-3.0-only.txt),
2. Build proprietary embedded, desktop or mobile applications with the [Paid license](LICENSES/LicenseRef-Veloce-Software-1.0.md).

## Support

Commercial support is available for customers of the Paid license.
Get in touch at [veloce@ferroxyde.com](mailto:veloce@ferroxyde.com).
