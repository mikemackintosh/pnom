require 'rubygems'
require 'ffi/pcap'
require 'ipaddress'
require 'hexdump'

pcap =
  FFI::PCap::Live.new(:dev => 'en0',
                      :timeout => 1,
                      :promisc => true,
                      :handler => FFI::PCap::Handler)

pcap.setfilter("tcp")

# 167838971 => 10.1.4.251
pcap.loop(count: 5){|t,p|
    
    mac = {}
    ip = {}
    tcp = {}

    bytes = p.body.bytes.map{|sym| sym.to_s(16).rjust(2, '0') }
    puts bytes.inspect

    # Layer 2
    mac[:src] = bytes[0..5].join(':')
    mac[:dst] = bytes[6..11].join(':')

    # Layer 3
    ip[:src] = bytes[26..29].map{|octet| octet.to_i(16).to_s(10)}.join('.')
    ip[:dst] = bytes[30..33].map{|octet| octet.to_i(16).to_s(10)}.join('.')
    
    # Layer 4
    tcp[:src_port] = bytes[34..35].join().to_i(16).to_s(10)
    tcp[:dst_port] = bytes[36..37].join().to_i(16).to_s(10)

    puts mac.inspect
    puts ip.inspect
    puts tcp.inspect

    puts Hexdump.dump(p.body); puts "\n"
}
