#!/usr/bin/env ruby
require 'socket'
require 'io/console'
require 'packetfu'
require 'byebug'
require_relative './lib/netant'

# Search network interfaces
ifaces = NetAnt::get_interfaces

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
main_thread = Thread.new {



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
    # scanner = Thread.new{

      ifaces.select{ |name,iface| iface[:selected] }.each do |name,iface|

        # For every selected interface start a capture thread
        # and register every found host a mac key and array with IPs and last contact timestamp
        if scan_method == 'Ping'
          packet_type = :icmp

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

          # Ping every address in the network
          Thread.new(NetAnt::send_packet_to_all_hosts(:icmp, iface))

        elsif scan_method == 'Active arp' || scan_method == 'Passive arp'
          packet_type = :arp
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

            # Arp request every address in the network
            iface[:thread] = Thread.new{

              addr_infos = NetAnt::find_network_address(iface[:inet],iface[:netmask])
              Thread.current['curr_ip'] = curr_ip = NetAnt::next_ip(addr_infos[:network_address])
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
                    Thread.current['curr_ip'] = curr_ip = NetAnt::next_ip(curr_ip)

                sleep 0.5

              end
            }
          end
        end
        sleep 0.5
      end

    # }


    # TODO revise visualization
    # Screen thread
    show = Thread.new{

      loop do
        sel_ifaces = ifaces.select{ |name,iface| iface[:selected] }
        curr_ips = sel_ifaces.map { |name,iface| "#{iface[:name]}: #{iface[:thread]['curr_ip'] unless iface[:thread].nil? }"}
        puts "Scanning #{sel_ifaces.map{ |k,i| i[:name]}.join(', ')} with #{scan_method} method (q to exit):"\
              "          current ips: #{curr_ips.inspect}\r"
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
    Thread.exit
  end
}

main_thread.join
