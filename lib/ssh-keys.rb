require 'tempfile'

module Aussiegeek
  class SshKey
    class InvalidKey < StandardError; end
    attr_reader :key_type, :key_length, :fingerprint, :comment

    def initialize(ssh_key)
      tmpfile = Tempfile.new('ruby_ssh-key' + Time.now.to_i.to_s)
      tmpfile << ssh_key
      tmpfile.close
      output = `ssh-keygen -l -f #{tmpfile.path}`
      status = $?.to_i
      if status > 0
        raise InvalidKey
      end
      @key_length, @fingerprint, @path, @key_type = output.split(' ')
      @key_length = @key_length.to_i
      @key_type = @key_type.match(/[a-zA-Z0-9]+/)[0].downcase
      tmpfile.unlink
    end
  end
end
