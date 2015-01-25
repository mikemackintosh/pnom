require 'rubygems'
require 'ffi/pcap'
require 'ipaddress'
require 'hexdump'

module Kn0x
    
    class Packet
        
        class Eth

            # Attributes
            attr_accessor :dst
            attr_accessor :src
            attr_accessor :type

            # Initialize the packet
            def initialize( bytes )
                @packet = bytes
                
                # Layer 2
                @dst = bytes[0..5].join(':')
                @src = bytes[6..11].join(':')
                @type = bytes[12..13].join() # http://en.wikipedia.org/wiki/EtherType
   
            end

            def type
               types = {
                    "0800" => "ip",
                }

                types[ @type ]
            end
            alias_method :ethertype, :type

        end

    end

end

module Kn0x
    
    class Packet
        
        class Ip

            # Attributes
            attr_accessor :version
            attr_accessor :ihl
            attr_accessor :ds
            attr_accessor :len
            attr_accessor :id
            attr_accessor :flags
            attr_accessor :offset
            attr_accessor :ttl
            attr_accessor :proto
            attr_accessor :sum
            attr_accessor :src
            attr_accessor :dst

            # Initialize the packet
            def initialize( bytes )
                @packet = bytes
                
                @version = bytes[14].split(//)[0]
                @ihl = bytes[14].split(//)[1]
                @ds = bytes[15]
                @len = bytes[16..17].join().to_i(16)
                @id = bytes[18..19].join()

                @flags = bytes[20].split(//)[0].to_i(16) #todo
                @offset = "#{bytes[20].split(//)[1]}#{bytes[21]}".to_i(16) #todo

                @ttl = bytes[22].to_i(16)
                @proto = bytes[23].to_i(16)
                @sum = bytes[24..25].join().to_i(16)
                @src = bytes[26..29].map{|octet| octet.to_i(16).to_s(10)}.join('.')
                @dst = bytes[30..33].map{|octet| octet.to_i(16).to_s(10)}.join('.')
               
            end

            alias_method :length, :len
            alias_method :checksum, :sum

            def proto
                protocol( @proto.to_i )
            end
            alias_method :protocol, :proto

            def src
               IPAddress @src
            end
            alias_method :source, :src
            alias_method :from, :src


            def dst
                IPAddress @dst
            end
            alias_method :dest, :dst
            alias_method :target, :dst

        private

            def protocol( proto )
               protocols = {
                    6 => "tcp",
                    17 => "udp",
                }

                protocols[ proto ]
            end

        end

    end

end

module Kn0x
    
    class Packet
        
        class Tcp
            
            # Attributes
            attr_accessor :src_port
            attr_accessor :dst_port
            attr_accessor :seq
            attr_accessor :ack
            attr_accessor :offset
            attr_accessor :reserved
            attr_accessor :ecn
            attr_accessor :cbits
            attr_accessor :win
            attr_accessor :sum
            attr_accessor :uptr

            # Initialize the packet
            def initialize( bytes )
                @packet = bytes
                
                @src_port = bytes[34..35].join().to_i(16).to_s(10).to_i
                @dst_port = bytes[36..37].join().to_i(16).to_s(10).to_i
                
                @seq = bytes[38..41].join().to_i(16).to_s(10).to_i

                @ack = bytes[42..45].join().to_i(16).to_s(10).to_i

                @offset = bytes[46].split(//)[0].to_i(16).to_s(10)

                @reserved = bytes[46].split(//)[1].to_i(16).to_s(10)
                @ecn = bytes[47].split(//)[0].to_i(16).to_s(10)
                @cbits = bytes[47].split(//)[1].to_i(16).to_s(10)

                @win = bytes[48..49].join().to_i(16)
                @sum = bytes[50..51].join().to_i(16)
                @uptr = bytes[52..53].join().to_i(16)
            end

            alias_method  :source_port, :src_port
            alias_method  :sport, :src_port

            alias_method  :dest_port, :dst_port
            alias_method  :dport, :dst_port

            alias_method :window, :win
            alias_method :windowsize, :win
            alias_method :size, :win

            alias_method :checksum, :sum
            alias_method :urgent, :uptr

            def cbits
                @cbits
            end
            alias_method :controlbits, :cbits
            alias_method :control, :cbits

        end

    end

end

module Kn0x
    
    class Packet
        
        class Udp
            
            # Attributes
            attr_accessor :src_port
            attr_accessor :dst_port
            attr_accessor :seq
            attr_accessor :ack
            attr_accessor :offset
            attr_accessor :reserved
            attr_accessor :ecn
            attr_accessor :cbits
            attr_accessor :win
            attr_accessor :sum
            attr_accessor :uptr

            # Initialize the packet
            def initialize( bytes )
                @packet = bytes
                
                @src_port = bytes[34..35].join().to_i(16).to_s(10).to_i
                @dst_port = bytes[36..37].join().to_i(16).to_s(10).to_i
                
                @seq = bytes[38..41].join().to_i(16).to_s(10).to_i

                @ack = bytes[42..45].join().to_i(16).to_s(10).to_i

                @offset = bytes[46].split(//)[0].to_i(16).to_s(10)

                @reserved = bytes[46].split(//)[1].to_i(16).to_s(10)
                @ecn = bytes[47].split(//)[0].to_i(16).to_s(10)
                @cbits = bytes[47].split(//)[1].to_i(16).to_s(10)

                @win = bytes[48..49].join().to_i(16)
                @sum = bytes[50..51].join().to_i(16)
                @uptr = bytes[52..53].join().to_i(16)
            end

            alias_method  :source_port, :src_port
            alias_method  :sport, :src_port

            alias_method  :dest_port, :dst_port
            alias_method  :dport, :dst_port

            alias_method :window, :win
            alias_method :windowsize, :win
            alias_method :size, :win

            alias_method :checksum, :sum
            alias_method :urgent, :uptr

            def cbits
                @cbits
            end
            alias_method :controlbits, :cbits
            alias_method :control, :cbits

        end

    end

end

pcap =
  FFI::PCap::Live.new(:dev => 'en0',
                      :timeout => 1,
                      :promisc => true,
                      :handler => FFI::PCap::Handler)

pcap.setfilter("")

pcap.loop(count: 7){|t,p|
    
    mac = {}

    bytes = p.body.bytes.map{|sym| sym.to_s(16).rjust(2, '0') }

    eth = Kn0x::Packet::Eth.new bytes

    ip = Kn0x::Packet::Ip.new bytes
    puts "#{p.time} - #{eth.src} -> #{eth.dst}\n"

    case ip.proto
    when 'tcp'
        tcp = Kn0x::Packet::Tcp.new bytes
        puts "#{ip.proto}  #{ip.src}:#{tcp.sport} to #{ip.dest}:#{tcp.dport}\n"
    when 'udp'
        udp = Kn0x::Packet::Udp.new bytes
        puts "#{ip.proto} #{ip.src}:#{udp.sport} to #{ip.dest}:#{udp.dport}\n"
    else
        puts "#{ip.proto} #{ip.src} to #{ip.dest}\n"
    end

    puts Hexdump.dump(p.body); puts "\n"
}
