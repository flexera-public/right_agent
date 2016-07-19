require 'digest/sha2'

#
# Copyright (c) 2009-2011 RightScale Inc
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

module RightScale

  # List of authorized users for Managed Login feature
  class LoginPolicy
    PUBLIC_KEY_REGEXP      = /(.*)?(ssh-[a-z]{1,3})\s+(\S+)\s*(.*)?$/

    include Serializable

    attr_accessor :audit_id, :created_at, :exclusive, :users

    # Initialize fields from given arguments
    def initialize(*args)
      @audit_id       = args[0]
      @created_at     = Time.at( (args[1]||Time.now).to_i )
      @exclusive      = args[2] || false
      @users          = args[3] || []
    end

    # Array of serialized fields given to constructor
    def serialized_members
      [ @audit_id, @created_at.to_i, @exclusive, @users ]
    end

    # Compute a cryptographic hash of the information in this policy; helps
    # callers compare two policies to see if they are equivalent.
    # @see https://github.com/rightscale/cmaro/domain/login_policy.go
    def fingerprint
      h = Digest::SHA2.new
      h << (self.exclusive ? 'true' : 'false')

      users = self.users.sort { |a, b| a.uuid <=> b.uuid }
      users.each do |u|
        h << format(",(%d,%s,%s,%d,%s",
                    u.uuid, u.common_name,
                    (u.superuser ? 'true' : 'false'),
                    (u.expires_at ? u.expires_at.to_i : 0),
                    u.username)

        u.public_key_fingerprints.each do |fp|
          h << "," << fp
        end
        h << ')'
      end

      h.hexdigest
    end

    # Utility method to parse an SSH2-format public key and return a 4-tuple consisting
    # of its constituent parts:
    #  * leading comment (optional)
    #  * algorithm (ssh-rsa or ssh-dsa)
    #  * public key material, as a base64 string
    #  * trailing comment or email (optional)
    #
    # === Parameters
    # str(String):: the unparsed public key
    #
    # === Return
    # components (Array|nil):: a 4-tuple of key components, or nil if the key was not a valid public key
    #
    def self.parse_public_key(str)
      match = PUBLIC_KEY_REGEXP.match(str)

      if match
        #Return a nice array of strings with no leading/trailing whitespace, and empty
        #strings transformed into nil
        return match[1..4].map { |x| x.strip! ; x.empty? ? nil : x }
      else
        return nil
      end
    end
  end
end
