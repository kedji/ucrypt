#!/usr/bin/env ruby
# encoding: ASCII-8BIT

# Tool for querying and directing a remote UCrypt service for AES encryption/
# decryption auditing.

require 'socket'
require 'timeout'

class UCrypt

  def initialize
    @extra = 0
    @flags = 0
    @key = "\x01\x01\x02\x03\x05\x08\x0d\x15" * 4
    @iv = "\0" * 16
    @host = 'localhost'
    @trim = 0

    @udp = UDPSocket.new
  end
  attr_accessor :extra, :flags, :key, :iv, :host, :trim

  # Request a packet's worth of data be en/decrypted.  This function returns a
  # 2-tuple: the crypto result and the locally measured time (in seconds).
  def request(payload)
    payload = payload + "\0" * ((16 - payload.length) % 16)
    req = [ @extra ].pack('S>')
    blocks = payload.length / 16
    req << blocks.chr
    req << @flags.chr
    req << @key
    req << @iv
    req << payload
    @udp.connect(@host, 1331)
    start_time = Time.now
    @udp.send(req, 0)
    resp = @udp.recvfrom(req.length).first
    end_time = Time.now
    reserved = resp.unpack('L>').first
    [ resp[4..-1], end_time - start_time ]
  end

  # Request an abritrary amount of data to be en/decrypted.  Returns the same
  # 2-tuple as request()
  def process(payload)
    resp = ''
    time = 0.0
    backup_iv = @iv
    until payload.empty? do
      chunk = payload[0, 1280]
      payload = payload[1280..-1].to_s
      r, t = request(chunk)
      time += t
      resp += r

      # When we're en/decrypting we use the last cipherblock as the IV for the
      # next chunk.  This is either the source or the result for decryption /
      # encryption, respectively.
      if (@flags & 1) > 0
        @iv = chunk[-16, 16]
      else
        @iv = r[-16, 16]
      end
    end
    @iv = backup_iv
    resp[0 - @trim..-1] = '' if @trim > 0
    [ resp, time ]
  end

end

if $0 == __FILE__
  payload = nil
  cstyle = false
  octets = false
  ucrypt = UCrypt.new

  # Gather our command line options
  opts = ARGV.dup
  opts = [ '-?' ] if opts.empty?
  arg = nil
  until opts.empty? do
    arg = opts.shift
    if arg == '-k'
      ucrypt.key = ([opts.shift.to_s].pack('H*') + "\0" * 32)[0, 32]
    elsif arg == '-x'
      ucrypt.extra = opts.shift.to_i
    elsif arg == '-d'
      ucrypt.flags |= 1
    elsif arg == '-h'
      ucrypt.flags |= 2
    elsif arg == '-p'
      payload = opts.shift.to_s.dup
    elsif arg == '-i'
      ucrypt.iv = ([opts.shift.to_s].pack('H*') + ucrypt.iv)[0, 16]
    elsif arg == '-c'
      cstyle = true
    elsif arg == '-o'
      octets = true
    elsif arg == '-t'
      ucrypt.trim = opts.shift.to_i
    elsif arg == '-?'
      $stderr.puts "Usage: #{$0} [options...] <host>"
      $stderr.puts "options: [-k key] [-i iv] [-x extra] [-p payload] [-t bytes]"
      $stderr.puts "         [-d] [-h] [-c] [-o] <host>"
      $stderr.puts "  -k: 256 bit AES key (in hex)"
      $stderr.puts "  -i: 16 byte initialization vector (in hex)"
      $stderr.puts "  -x: extra en/decryption rounds for perf tests"
      $stderr.puts "  -p: specify a payload on the command line rather than stdin"
      $stderr.puts "  -t: trim the given number of bytes off the end of the output"
      $stderr.puts "  -d: decrypt instead of encrypt"
      $stderr.puts "  -h: use hardware instead of software"
      $stderr.puts "  -c: output result in C-style hex"
      $stderr.puts "  -o: output raw octets instead of hex"
      exit(0)
    elsif opts.empty?
      ucrypt.host = arg
    else
      $stderr.puts "Unknown option: #{arg}"
      exit(1)
    end
  end

  # Read payload from stdin if none was given
  begin
    Timeout.timeout(1) { payload ||= $stdin.read }
  rescue
    $stderr.puts "Timed out reading payload from stdin"
    exit(1)
  end
  payload.force_encoding('BINARY')

  # Describe the operation we're about to perform
  op = (ucrypt.flags[0] == 0 ? 'Encrypt' : 'Decrypt')
  $stderr.puts "#{op}ing #{(payload.length + 15) / 16 * 16} bytes on #{ucrypt.host}"
  $stderr.puts "Extra: #{ucrypt.extra}"
  $stderr.puts "Flags: #{'%b' % ucrypt.flags}"
  $stderr.print "Key:   "
  ucrypt.key.each_byte { |b| $stderr.print('%02x' % b) }
  $stderr.print "\nIV:    "
  ucrypt.iv.each_byte { |b| $stderr.print('%02x' % b) }
  $stderr.puts "\n========================"

  # Request that our operation be performed
  resp, local = ucrypt.process(payload)

  # Now output the result in the requested format
  if octets
    print resp
    $stderr.puts
  else
    i = 0
    resp.each_byte do |b|
      if cstyle
        print("\\x%02x" % b)
      else
        print("%02x " % b)
        i += 1
        (puts ; i = 0) if (i >= 24)
      end
    end
    puts
  end

  # Finally, provide timing information
  $stderr.puts "========================"
  $stderr.puts "Local time:  #{'%8d' % (local * 1000000).to_i} microseconds"
  trim = resp.length - payload.length
  $stderr.puts "Trim #{trim} bytes" if trim > 0
end
