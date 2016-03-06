class BtcRpcClientAddons
# bitcoin-cli getrawtransaction 8fa2c12da6271d2403b0fb4774d506cdab86ee0319f211e18d862ab581ff9dfd 1

  def self.get_input_address(txid)
    input_addresses = []
    ans = BtcRpcClient.call('getrawtransaction', '8fa2c12da6271d2403b0fb4774d506cdab86ee0319f211e18d862ab581ff9dfd', 1)

    ans["vin"].each do |vin|
      pub_key = vin["scriptSig"]["asm"].split[1]

      pub_key_bytes = [pub_key].pack('H*')
      hash_temp   = Digest::SHA256.digest(pub_key_bytes)
      hash160     = Digest::RMD160.digest(hash_temp)

      # Add version byte in front of RIPEMD-160 hash 
      hash160_with_version = [("00" + hash160.unpack('H*').first)].pack("H*")

      # Perform SHA-256 hash on the extended RIPEMD-160 result 
      checksum_hash_temp = Digest::SHA256.digest(hash160_with_version)
      checksum_hash      = Digest::SHA256.digest(checksum_hash_temp)
      checksum           = checksum_hash[0, 4]

      # Add the 4 checksum bytes from point 7 at the end of extended RIPEMD-160 hash from point 4. This is the 25-byte binary Bitcoin Address. 
      binary_address = hash160_with_version + checksum
      binary_address_hex_string = binary_address.unpack("H*").first

      address = encode_base58(binary_address_hex_string)
      input_addresses << address
    end
    input_addresses
  end


  private

  def self.encode_base58(hex)
    leading_zero_bytes  = (hex.match(/^([0]+)/) ? $1 : '').size / 2
    ("1"*leading_zero_bytes) + int_to_base58( hex.to_i(16) )
  end

  def self.int_to_base58(int_val, leading_zero_bytes=0)
    alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    base58_val, base = '', alpha.size
    while int_val > 0
      int_val, remainder = int_val.divmod(base)
      base58_val = alpha[remainder] + base58_val
    end
    base58_val
  end


end