require 'rubygems'
require 'ffi/pcap'
require 'ffi/packets'
require 'ipaddress'
require 'hexdump'


pcap =
  FFI::PCap::Live.new(:dev => 'en0',
                      :timeout => 1,
                      :promisc => true,
                      :handler => FFI::PCap::Handler)

pcap.setfilter("tcp")

pcap.loop(count: 20){|t,p| 
    ip = FFI::Packets::Ip::Hdr.new raw: p.body
    tcp = FFI::Packets::TCP::Hdr.new raw: p.body
    puts "#{p.time}: #{ip.src} --> #{ip.dst}"
    Hexdump.dump(p.body); puts "\n"
}

