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

describe RightScale::LoginPolicy do
  describe '#fingerprint' do
    let(:finger0) { 'abd8e6410457ad1681123bc5997de6efc8dd3c2f' }

    let(:finger1) { '21fdda62b604e30ef36f8af3b42eb74832492808' }

    let(:golang) { '0f4bba48af7f56e72cb00bfe5551f3f8a796f946fb10ad925459b7d4e6ff45f8' }

    let(:u0) do
      RightScale::LoginUser.new(1, 'alice', 'ssh-rsa aaa', 'alice@initech.com', false, nil, nil, nil, [finger0])
    end

    let(:u1) do
      ea = Time.at(2147483647)
      RightScale::LoginUser.new(2, 'bob', 'ssh-rsa bbb', 'bob@initech.com', false, ea, nil, nil, [finger1])
    end

    let(:policy) do
      RightScale::LoginPolicy.new(0, nil, false, [u0, u1])
    end

    it 'should interoperate with golang' do
      policy.fingerprint.should == golang
    end
  end
end
