# FCM Data Factory: Engineering Specifications

## 🎯 Project Core Strategy

1. **Distributed Verification**: Harvesting is done globally (US), but validation MUST be done from within the target network (China BGP).
2. **TCP-Only Validation**: ICMP/Ping success does not guarantee FCM availability. Only a successful TCP handshake on Port 5228 is a valid metric.
3. **Dynamic Thresholding**: Avoid static latency limits. Use `max(min_latency + 50, min_latency * 1.3)` to adapt to fluctuating network conditions.

## 🛠 Technical Implementation Details

### Harvest (DNS Mechanics)

- **Library**: `dnspython`
- **Method**: `dns.edns.ECSOption.from_text`
- **Target Subnets**: Focus on CERNET2 (IPv6) and major provincial ISP backbones to trigger Google GTM's optimal Asia-Pacific routing.

### Sommelier (Verification Logic)

- **Concurrency**: Maintain 50+ threads for rapid scanning to minimize TTL expiration during the process.
- **Socket Tuples**:
  - **IPv4**: `sock.connect((ip, port))`
  - **IPv6**: `sock.connect((ip, port, 0, 0))`
- **Independent Grading**: Grade IPv4 and IPv6 separately to prevent "IPv4 latency discrimination."

### Load Balancing

- **Round-Robin**: Distribute premium IPs across `mtalk` and `alt1-8` domains.
- **Availability First**: Even a single valid IP should trigger a complete Hosts file generation to prevent client-side blackouts.
