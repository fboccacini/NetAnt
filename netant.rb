#!/usr/bin/env ruby
require 'socket'
require 'io/console'
require 'packetfu'

# Search network interfaces
ifaces = Hash.new

# TODO put in a library and refactor
Socket.getifaddrs.each do |ifaddr|

  if ifaddr.addr.ip?
    ifaces[ifaddr.name] = {
      :index => ifaddr.ifindex,
      :selected => ifaddr.name == PacketFu::Utils.default_int ? true : false,
      :flags => ifaddr.flags,
      :name => ifaddr.name,
      :hosts => Hash.new,
      :pcap => nil
    } if ifaces[ifaddr.name].nil?

    case RUBY_PLATFORM
    when /linux/i
      ifaces[ifaddr.name][:ether] = `cat /sys/class/net/#{ifaddr.name}/address`[/([0-9a-zA-Z]{2}:?){6}/] unless `cat /sys/class/net/#{ifaddr.name}/address`.nil?
    else
      # TODO more OSs
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

# TODO put in a library and refactor
# Send a packet to all addresses within a range
def send_packet_to_all_hosts(packet_type, iface)

  addr_infos = find_network_address(iface[:inet],iface[:netmask])
  curr_ip = next_ip(addr_infos[:network_address])
  host_number = (addr_infos[:broadcast_address_raw] - addr_infos[:network_address_raw])-2

  for i in 0..host_number
    Thread.new{
      @curr_ips[iface[:name]] = curr_ip

      begin
        if packet_type == :arp
          pkt = PacketFu::ARPPacket.new
          pkt.arp_saddr_mac = iface[:ether]
          pkt.eth_saddr = iface[:ether]
          pkt.eth_daddr = 'ff:ff:ff:ff:ff:ff'
          pkt.arp_saddr_ip = iface[:inet]
          pkt.arp_daddr_ip = curr_ip
          pkt.arp_opcode = 1                    # Arp request
          pkt.payload = '0123456789abcdef'      # Hosts may not respond without payload
        elsif packet_type == :icmp
          pkt = PacketFu::ICMPPacket.new
          pkt.eth_saddr = iface[:ether]
          pkt.ip_saddr = iface[:inet]
          pkt.icmp_type = 0x08                  # Echo request
          pkt.payload = '0123456789abcdef'      # Hosts may not respond without payload
          pkt.ip_daddr = curr_ip
          # pkt.eth_daddr = PacketFu::Utils.arp(curr_ip, :iface => iface[:name])
          pkt.eth_daddr = 'ff:ff:ff:ff:ff:ff'
        end
        pkt.recalc
        pkt.to_w(iface[:name])
        curr_ip = next_ip(curr_ip)
      rescue Exception => e
        # puts curr_ip
        # puts e.message
        # puts e.backtrace.join("\n")
      end

    }
    sleep 0.5
  end
end

# TODO put in a library and refactor
# Calculates network and broadcast address from a given ip and netmask
def find_network_address(ip,netmask=24)
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
def next_ip(addr)
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
           raise 'Next ip not valid.'
         end
      end
    end
  end
  return octs.join('.')
end

# Scan methods: (defaults to active arp)
# Ping - finds all hosts that respond to ping
# Active arp - sends ARP requests and catches responses
# Passive arp - slow stealth mode, just listens for arp responses hoping they happen
methods = [
  {name: 'Ping', selected: false},
  {name: 'Active arp', selected: true},
  {name: 'Passive arp', selected: false}
]
scan_method = 'Active arp'

system "cls" or system "clear"

# Create the interactive command control thread
thread = Thread.new {

  begin
    # Raw console for direct commands control
    STDIN.raw!

    # Choose interfaces to scan from
    loop do
      puts "Choose interfaces (hit enter when done):\r"
      puts
      ifaces.each do |k,iface|
        puts "[#{iface[:selected] ? 'X' :  ' '}] #{iface[:index]}: #{iface[:name]}\r"
      end

      com = STDIN.getc.chr

      ifaces.each do |k,iface|
        iface[:selected] = !iface[:selected] if iface[:index] == com.to_i
      end
      system "clear" or system "cls"
      if com == "\r"
        break
      end
    end

    # Choose scanning method
    loop do
      puts "Choose a scan method (hit enter when done):\r"
      puts
      methods.each_with_index do |method,i|
        puts "[#{method[:selected] ? 'X' :  ' '}] #{i+1}: #{method[:name]}\r"
      end

      com = STDIN.getc.chr

      if com.to_i+1 > 0 && com.to_i+1 <= methods.size+1
        methods.each_with_index do |method,i|
          if i + 1 == com.to_i
            method[:selected] = true
            scan_method = method[:name]
          else
            method[:selected] = false
          end
        end
      end
      system "clear" or system "cls"
      if com == "\r"
        break
      end
    end

    # Create the scanner Thread
    scanner = Thread.new{
      @curr_ips = Hash.new
      ifaces.select{ |name,iface| iface[:selected] }.each do |name,iface|
        @curr_ips[iface[:name]] = nil

        # For every selected interface start a capture thread
        # and register every found host a mac key and array with IPs and last contact timestamp
        if scan_method == 'Ping'

          # Ping method recover only IPs which respond to ping
          iface[:pcap] = Thread.new {

            cap = PacketFu::Capture.new(:iface => iface[:name], :promisc => true, :filter => 'icmp', :start => true)
            cap.stream.each do |packet|
              pkt = PacketFu::Packet.parse(packet)
              unless pkt.nil? || pkt.icmp_type != 0x00
                iface[:hosts][pkt.eth_saddr] = Hash.new if iface[:hosts][pkt.eth_saddr].nil?
                iface[:hosts][pkt.eth_saddr][pkt.ip_saddr] = {eth: pkt.eth_saddr, ip: pkt.ip_saddr, last_timestamp: Time.now, type: pkt.icmp_type}
              end
            end
          }

          Thread.new{
            # Ping every address in the network
            send_packet_to_all_hosts(:icmp, iface)
          }
        elsif scan_method == 'Active arp' || scan_method == 'Passive arp'

          # Arp methods finds all addresses that respond to arp
          iface[:pcap] = Thread.new {

            cap = PacketFu::Capture.new(:iface => iface[:name], :promisc => true, filter: 'arp', :start => true)
            cap.stream.each do |packet|
              pkt = PacketFu::Packet.parse(packet)
              unless pkt.nil?
                unless pkt.nil? || pkt.arp_opcode != 2
                  iface[:hosts][pkt.arp_src_mac_readable] = Hash.new if iface[:hosts][pkt.arp_src_mac_readable].nil?
                  iface[:hosts][pkt.arp_src_mac_readable][pkt.arp_src_ip_readable] = {eth: pkt.arp_src_mac_readable, ip: pkt.arp_src_ip_readable, last_timestamp: Time.now, opcode: pkt.arp_opcode}
                end
              end
            end
          }
          if scan_method == 'Active arp'
            Thread.new{
              # Arp request every address in the network
              send_packet_to_all_hosts(:arp, iface)
            }
          end
        end
        sleep 0.5
      end

    }

    # TODO revise visualization
    # Screen thread
    show = Thread.new{
      loop do
        ips = Array.new

        puts "Scanning #{ifaces.select{ |name,iface| iface[:selected] }.map{ |k,i| i[:name]}.join(', ')} with #{scan_method} method (q to exit):"\
              "          current ips: #{@curr_ips.inspect}\r"
        puts
        ifaces.select{ |name,iface| iface[:selected] }.each do |name,iface|
          puts "#{iface[:name]} (#{iface[:ether]}):\r"
          puts
          iface[:hosts].each do |k,host|
            STDIN.cooked!
            # puts iface.inspect
            puts "#{k} -> #{host.map {|k,v| k}.join(', ')}\r"
            STDIN.raw!
          end
          puts
        end
        sleep 1
        system "clear" or system "cls"
      end
    }

    # TODO better interface, with arrows
    # Get commands
    com = STDIN.getc.chr
    if com == "q"
      STDIN.cooked!         #Let's not compromise the console in case of error..

      # kill all threads
      ifaces.each do |name,iface|
        Thread.kill(iface[:pcap]) unless iface[:pcap].nil?
      end
      Thread.kill(scanner)
      Thread.kill(show)
      Thread.exit
    end
  rescue Exception => e
    STDIN.cooked!         #Let's not compromise the console in case of error..
    puts e.message
    puts
    puts e.backtrace.join("\n\n")
  end
}

thread.join
