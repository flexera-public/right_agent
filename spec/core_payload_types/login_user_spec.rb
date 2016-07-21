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

require File.expand_path(File.join(File.dirname(__FILE__), '..', 'spec_helper'))
require File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'lib', 'right_agent', 'core_payload_types'))

# Copy of the old model for RightScale::LoginUser before the public_keys member was added
module LoginUserSpec
  class LoginUserBeforePublicKeys
    include RightScale::Serializable

    attr_accessor :uuid, :username, :public_key, :common_name, :superuser, :expires_at

    def initialize(*args)
      @uuid        = args[0]
      @username    = args[1]
      @public_key  = args[2]
      @common_name = args[3] || ''
      @superuser   = args[4] || false
      @expires_at  = Time.at(args[5]) if args[5] && (args[5] != 0)
    end

    def serialized_members
      [ @uuid, @username, @public_key, @common_name, @superuser, @expires_at.to_i ]
    end
  end
end

describe RightScale::LoginUser do
  context '.fingerprint' do
    # Shared with CMARO specs. See https://github.com/rightscale/cmaro/domain/login_policy_test.go
    let(:keys) {
      [
        'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDW5pCQxyHOX/GoBtCypA312KPW4xGG9KgYueU11AH+s3NnhNWRxV0NFxyBpS9ti5trgRQtz96nslbhv3xwOMhxi6phHr3RM1gFsP2KCzmWrVtwnivL/EEP4exT8ksnS6tM0o4YcK35R+pqCcef6zvu0+36PeUCMxPMXui37Q2DH8VW2oAtv4yXgaZKIPf+6T86Nl1lfXYwSa49RVWIugcCZ1hlOWxTA7Qp1zmP1VQsl10o7NlK5ftOhgZkvu8KBPmL8qqD9YzoQgHpAx77cquV1if3ZcZIDCCbzo5mD60uEiBzNssE38aMilc9XtRR4b0Wb+/ousfzbOe8lB0hGRfZ alice@initech.com',
        'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDMJRT7/ESoJwmMY5pD5cXcHU24pXnBYv9hSaYcowshuSTRtCYr+7RRcxtGy7vSI6IFiA1+8fp0RXMN0XwGC1wx2ndOWFW4pHNy7wNr8CDJDnl4wyL90XK6MJQBqpmHL+NMA9YyVixzPYrW/foaRUyP/uTr5fVnTySvfQHSmqwDD5NcwJqt4Gz4w47hNKwlCwXq1DG5+KyR5n2SdpcdIkZLB9H8luvTLucv4ozoibi7JNYkJ+mR1oumcXrvUDDO24cvIBYyoVLGIFXcP5jvshijcEzmRz8/lzeJ0fzJXIN+rs7fuunJkuC/85fHwroeae5RB82HLOHWapGX6taevrBp bob@initech.com'
      ]
    }
    let(:fingerprints) do
      [
        'abd8e6410457ad1681123bc5997de6efc8dd3c2f',
        '21fdda62b604e30ef36f8af3b42eb74832492808'
      ]
    end

    it 'interoperates with golang' do
      described_class.fingerprint(keys[0]).should == fingerprints[0]
      described_class.fingerprint(keys[1]).should == fingerprints[1]
    end
  end

  # ensures that the serialization downgrade case works.
  def test_serialization_downgrade(user, public_key)
    json = user.to_json
    old_json = json.gsub("RightScale::LoginUser", "LoginUserSpec::LoginUserBeforePublicKeys")
    old_user = JSON.parse(old_json)
    old_user.class.should == LoginUserSpec::LoginUserBeforePublicKeys
    old_user.public_key.should == public_key
  end

  it 'should serialize old version without public_keys member' do
    num = rand(2**32).to_s(32)
    pub = rand(2**32).to_s(32)
    public_key = "ssh-rsa #{pub} #{num}@rightscale.com"
    user = LoginUserSpec::LoginUserBeforePublicKeys.new("v0-#{num}", "rs-#{num}", public_key, "#{num}@rightscale.old", true, nil)
    json = user.to_json
    json = json.gsub("LoginUserSpec::LoginUserBeforePublicKeys", "RightScale::LoginUser")
    user = JSON.parse(json)
    user.public_key.should == public_key
    user.public_keys.should == [public_key]
    test_serialization_downgrade(user, public_key)
  end

  it 'should serialize current version with single public_key' do
    num = rand(2**32).to_s(32)
    pub = rand(2**32).to_s(32)
    public_key = "ssh-rsa #{pub} #{num}@rightscale.com"
    user = RightScale::LoginUser.new("v0-#{num}", "rs-#{num}", public_key, "#{num}@rightscale.old", true, nil, nil)
    json = user.to_json
    user = JSON.parse(json)
    user.class.should == RightScale::LoginUser
    user.public_key.should == public_key
    user.public_keys.should == [public_key]
    test_serialization_downgrade(user, public_key)
  end

  it 'should serialize current version with multiple public_keys and fingerprints' do
    num = rand(2**32).to_s(32)
    public_keys = []
    fingerprints = []
    3.times do |i|
      pub = rand(2**32).to_s(32)
      public_keys << "ssh-rsa #{pub} #{num}@rightscale.com"
      fingerprints << "sha#{i}"
    end
    new_user = RightScale::LoginUser.new("v0-#{num}", "rs-#{num}", nil, "#{num}@rightscale.old", true, nil, public_keys,
                                         nil, fingerprints)
    new_user.public_key.should == public_keys.first
    new_user.public_keys.should == public_keys
    new_user.public_key_fingerprints.should == fingerprints
    test_serialization_downgrade(new_user, public_keys.first)
  end

end
