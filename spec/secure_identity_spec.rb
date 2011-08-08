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

require File.expand_path(File.join(File.dirname(__FILE__), 'spec_helper'))

describe RightScale::SecureIdentity do

  it 'should obscure the secret token when generating the agent identity' do
    id = 12345
    secret = "mum's the word"
    identity = RightScale::SecureIdentity.derive(id, secret)
    identity.should_not =~ /#{secret}/
  end

  it 'should detect tampering with verifiers' do
    id = 12345
    secret = "mum's the word"
    ts = Time.now

    identity = RightScale::SecureIdentity.derive(id, secret)
    verifier = RightScale::SecureIdentity.create_verifier(id, secret, ts)
    bad1     = RightScale::SecureIdentity.create_verifier(id+1, secret, ts)
    bad2     = RightScale::SecureIdentity.create_verifier(id, secret, ts-1)
    bad3     = RightScale::SecureIdentity.create_verifier(id, secret + "foom", ts)

    verifier.should_not == bad1
    verifier.should_not == bad2
    verifier.should_not == bad3
  end

end
