
module NetAnt



  # Gets all available interfaces
  def self.get_interfaces

    ifaces = Hash.new

    # Extract data from ifaddrs and pack 'em in a hash
    Socket.getifaddrs.each do |ifaddr|

      if ifaddr.addr.ip?
        ifaces[ifaddr.name] = {
          :index => ifaddr.ifindex,
          :selected => ifaddr.name == PacketFu::Utils.default_int ? true : false,
          :flags => ifaddr.flags,
          :name => ifaddr.name,
          :hosts => Hash.new,
          :pcap => nil,
          :thread => nil
        } if ifaces[ifaddr.name].nil?

        # TODO Add more platforms
        case RUBY_PLATFORM
        when /linux/i
          ifaces[ifaddr.name][:ether] = `cat /sys/class/net/#{ifaddr.name}/address`[/([0-9a-zA-Z]{2}:?){6}/] unless `cat /sys/class/net/#{ifaddr.name}/address`.nil?
        else
          ifaces[ifaddr.name][:ether] = `cat /sys/class/net/#{ifaddr.name}/address`[/([0-9a-zA-Z]{2}:?){6}/] unless `cat /sys/class/net/#{ifaddr.name}/address`.nil?
        end

        if ifaddr.addr.ipv4?
          ifaces[ifaddr.name][:inet] = ifaddr.addr.ip_address
          ifaces[ifaddr.name][:netmask] = ifaddr.netmask.ip_address
          ifaces[ifaddr.name][:broadcast] = ifaddr.broadaddr.ip_address unless ifaddr.broadaddr.nil?
        end
        if ifaddr.addr.ipv6?
          ifaces[ifaddr.name][:inet6] = ifaddr.addr.ip_address[/([a-f0-9:]*)/,1]
          ifaces[ifaddr.name][:netmask6] = ifaddr.netmask.ip_address
          ifaces[ifaddr.name][:prefixlen] = ifaddr.netmask.ip_address.split(':').select{'ffff'}.size * 16
          ifaces[ifaddr.name][:broadcast6] = ifaddr.broadaddr.ip_address unless ifaddr.broadaddr.nil?
        end
      end
    end

    return ifaces
  end

  # Send a packet of a type to all hosts in an interface's network
  def self.send_packet_to_all_hosts(packet_type, iface)

    addr_infos = NetAnt::find_network_address(iface[:inet],iface[:netmask])
    curr_ip = NetAnt::next_ip(addr_infos[:network_address])
    host_number = (addr_infos[:broadcast_address_raw] - addr_infos[:network_address_raw])-2

    for i in 0..host_number
      # Thread.new{

          if packet_type == :arp
            pkt = PacketFu::ARPPacket.new
            pkt.arp_saddr_mac = iface[:ether]
            pkt.eth_saddr = iface[:ether]
            pkt.eth_daddr = 'ff:ff:ff:ff:ff:ff'
            pkt.arp_saddr_ip = iface[:inet]
            pkt.arp_daddr_ip = curr_ip
            pkt.arp_opcode = 1                    # Arp request
            pkt.payload = '0123456789abcdef'      # Hosts may not respond without a payload..
          elsif packet_type == :icmp
            pkt = PacketFu::ICMPPacket.new
            pkt.eth_saddr = iface[:ether]
            pkt.ip_saddr = iface[:inet]
            pkt.icmp_type = 0x08                  # Echo request
            pkt.payload = '0123456789abcdef'      # Hosts may not respond without a payload..
            pkt.ip_daddr = curr_ip
            # pkt.eth_daddr = PacketFu::Utils.arp(curr_ip, :iface => iface[:name])
            pkt.eth_daddr = 'ff:ff:ff:ff:ff:ff'
          end

          # Reaclulate sumchecks and send packet
          pkt.recalc
          pkt.to_w(iface[:name])
          curr_ip = next_ip(curr_ip)

      sleep 0.3

    end
  end

  # TODO refactor for good
  # Calculates network and broadcast address from a given ip and netmask
  def self.find_network_address(ip,netmask=24)
    if ip == /([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\/([0-9]{1,2})/
      ip = $1
      nmask = 2 ** 32 - 2 ** (32 - $2.to_i)
    elsif netmask.class == Integer
      ip = ip[/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/,1]
      nmask = 2 ** 32 - 2 ** (32 - netmask.to_i)
    elsif netmask.class == String
      ip = ip[/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/,1]
      octsm = netmask.split('.').map { |o| o.to_i}
      nmask = 0
      for i in 0..3
        nmask += octsm[i] * (2 ** ((3-i)*8))
      end
    end
    octsi = ip.split('.').map { |o| o.to_i}
    nip = 0
    for i in 0..3
      nip += octsi[i] * (2 ** ((3-i)*8))
    end

    if nip.nil? || nmask.nil?
      raise "Invalid arguments: #{ip}, #{netmask}"
    end
    net_address = nip & nmask

    broadcast = net_address + ((2**32 -1) & ~nmask)

    n_ip_address = "#{(nip & (2 ** 32 - 2 ** 24)) >> 24 }.#{(nip & (2 ** 24 - 2 ** 16))>> 16 }.#{(nip & (2 ** 16 - 2 ** 8))>> 8}.#{nip & (2 ** 8 - 1)}"
    n_mask = "#{(nmask & (2 ** 32 - 2 ** 24)) >> 24 }.#{(nmask & (2 ** 24 - 2 ** 16))>> 16 }.#{(nmask & (2 ** 16 - 2 ** 8))>> 8}.#{nmask & (2 ** 8 - 1)}"
    naddress = "#{(net_address & (2 ** 32 - 2 ** 24)) >> 24}.#{(net_address & (2 ** 24 - 2 ** 16)) >> 16}.#{(net_address & (2 ** 16 - 2 ** 8)) >> 8}.#{(net_address) & (2 ** 8 - 1)}"
    nbroadcast = "#{(broadcast & (2 ** 32 - 2 ** 24))>> 24}.#{(broadcast & (2 ** 24 - 2 ** 16))>> 16}.#{(broadcast & (2 ** 16 - 2 ** 8))>> 8}.#{(broadcast) & (2 ** 8 - 1)}"

    return {network_address: naddress, network_address_raw: net_address, broadcast_address: nbroadcast, broadcast_address_raw: broadcast, netmask: n_mask, netmask_raw: nmask}
  end


  # TODO calculate with netmask, refactor for good
  # Calculates the next ip
  def self.next_ip(addr)
    octs = addr.split('.').map{|o| o.to_i}
    octs[3] += 1
    if octs[3] > 255
      octs[3] = 0
      octs[2] += 1
      if octs[2] > 255
        octs[2] = 0
        octs[1] += 1
        if octs[1] > 255
           octs[1] = 0
           octs[0] += 1
           if octs[0] > 255
             raise "Next ip not valid. #{addr}"
           end
        end
      end
    end
    return octs.join('.')
  end

end
