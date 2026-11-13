# Carrier Network Evidence

This context describes carrier services and the network evidence used to understand, deliver, and verify them. It gives operators and evidence records a shared vocabulary across access, transport, interconnect, and application boundaries.

## Service and resource

**Service**:
A customer-facing network capability with an agreed scope and expected behavior.

**Customer pseudonym**:
A non-identifying reference used to distinguish a customer in shared operational evidence.

**Site**:
A physical location where a service endpoint, network resource, or measurement vantage is situated.

**Circuit**:
A provider-managed logical or physical connectivity offering identified for service delivery or operations.

**Access line**:
The access-network connection that links a service endpoint or customer equipment to the provider network.

**Device**:
A network or customer-premises equipment item that forwards traffic, terminates a connection, or produces operational evidence.

**Interface**:
A named logical or physical attachment point on a device through which traffic or measurements are associated.

**VLAN**:
A Layer 2 broadcast-domain identifier used to distinguish traffic within an Ethernet service or network segment.

**VRF**:
A routing context that keeps a set of IP routes logically separate from other routing contexts.

**Session**:
A time-bounded subscriber or endpoint relationship established for access, authentication, or service use.

**Path**:
An ordered or partially known sequence of network resources or forwarding relationships between defined endpoints.

**Alarm**:
A source-reported indication that an observed condition crossed that source's reporting rule.

## Evidence and service criteria

**Measurement**:
A value or set of values observed over a stated scope, time, direction, and unit.

**SLA**:
An agreement that defines measurable service commitments and the conditions under which they apply.

**Acceptance criterion**:
A stated condition used to decide whether a service or delivery result meets its agreed requirements.

**Evidence binding**:
An explicit, time-bounded declaration associating a source observation with a service and resource.

**Optical profile**:
A sourced set of optical operating limits and applicability conditions for a specified equipment model.

**Control plane**:
The network functions that exchange and select reachability and forwarding information.

**Data plane**:
The network functions that forward and deliver service traffic.

**Measurement window**:
The stated time interval over which a measurement is observed or aggregated, distinct from the interval between samples.

## Network layers

**Endpoint/LAN**:
The customer endpoint and local network boundary where host, local-link, and customer-premises evidence originates.

**Access**:
The last-mile network segment connecting a site or endpoint to provider aggregation.

**Aggregation/subscriber edge**:
The provider boundary that gathers access traffic and may terminate subscriber sessions or apply service separation.

**IP bearer/transport**:
The routed or switched provider network that carries service traffic between access, edge, and interconnect points.

**Internet edge/interconnect**:
The boundary where provider traffic reaches peering, transit, shared Internet services, or other external networks.

**Destination/application**:
The remote service endpoint and application behavior observed by a user or measurement system.
