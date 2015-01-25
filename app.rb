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
                puts "OMFG!?!"
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
                
                self.src_port = bytes[34..35].join().to_i(16).to_s(10)
                self.dst_port = bytes[36..37].join().to_i(16).to_s(10) 
                
                self.seq = bytes[38..41].join().to_i(16).to_s(10)

                self.ack = bytes[42..45].join().to_i(16).to_s(10)

                self.offset = bytes[46].split(//)[0].to_i(16).to_s(10)

                self.reserved = bytes[46].split(//)[1].to_i(16).to_s(10)
                self.ecn = bytes[47].split(//)[0].to_i(16).to_s(10)
                self.cbits = bytes[47].split(//)[1].to_i(16).to_s(10)

                self.win = bytes[48..49].join().to_i(16)
                self.sum = bytes[50..51].join().to_i(16)
                self.uptr = bytes[52..53].join().to_i(16)
            end


            # src_port
            def self.src_port=(val)
                self[:src_port] = val.to_i
            end

            def self.src_port
                self[:src_port]
            end
            alias_method  :source_port, :src_port
            alias_method  :sport, :src_port


            # dst_port
            def self.dst_port=(val)
                self[:dst_port] = val.to_i
            end

            def self.dst_port
                self[:dst_port]
            end
            alias_method  :dest_port, :dst_port
            alias_method  :dport, :dst_port


            # seq
            def self.seq=(val)
                self[:seq] = val.to_i
            end

            def self.seq
                self[:seq]
            end


            # ack
            def self.ack=(val)
                self[:ack] = val.to_i
            end

            def self.ack
                self[:ack]
            end


            # offset
            def self.offset=(val)
                self[:offset] = val.to_i
            end

            def self.offset
                self[:offset]
            end

            # reserved
            def self.reserved=(val)
                self[:reserved] = val.to_i
            end

            def self.reserved
                self[:reserved]
            end


            # ecn
            def self.ecn=(val)
                self[:ecn] = val.to_i
            end

            def self.ecn
                self[:ecn]
            end


            # cbits
            def self.cbits=(val)
                self[:cbits] = val.to_i
            end

            def self.cbits
                self[:cbits]
            end
            alias_method :controlbits, :cbits
            alias_method :control, :cbits


            # win
            def self.win=(val)
                self[:win] = val.to_i
            end

            def self.win
                self[:win]
            end
            alias_method :window, :win
            alias_method :windowsize, :win
            alias_method :size, :win


            # sum
            def self.sum=(val)
                self[:sum] = val.to_i
            end

            def self.sum
                self[:sum]
            end
            alias_method :checksum, :sum


            # uptr
            def self.uptr=(val)
                self[:uptr] = val.to_i
            end

            def self.uptr
                self[:uptr]
            end
            alias_method :urgent, :uptr

        end

    end

end

pcap =
  FFI::PCap::Live.new(:dev => 'en0',
                      :timeout => 1,
                      :promisc => true,
                      :handler => FFI::PCap::Handler)

pcap.setfilter("tcp")

# 167838971 => 10.1.4.251
pcap.loop(count: 5){|t,p|
    
    mac = {}

    bytes = p.body.bytes.map{|sym| sym.to_s(16).rjust(2, '0') }

    eth = Kn0x::Packet::Eth.new bytes
    puts eth.ethertype

    ip = Kn0x::Packet::Ip.new bytes
    puts ip.proto
    if ip.proto.eql? 'tcp'
        tcp = Kn0x::Packet::Tcp.new bytes
        puts tcp.inspect
    end

    puts bytes.inspect

    puts Hexdump.dump(p.body); puts "\n"
}
