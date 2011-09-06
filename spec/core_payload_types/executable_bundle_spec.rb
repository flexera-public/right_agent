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

require File.expand_path(File.join(File.dirname(__FILE__), '..', 'spec_helper'))
require File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'lib', 'right_agent', 'core_payload_types'))

module RightScale
  describe ExecutableBundle do
    context 'serialized_members' do
      it 'contains 7 elements' do
        ExecutableBundle.new.serialized_members.count.should == 7
      end
    end
    context 'debug_cookbooks' do
      context 'when set' do
        let(:expected_debug_cookbooks) { [{ :foo=>'bar' }] }
        let(:bundle) { ExecutableBundle.new(nil, nil, nil, nil, nil, nil, expected_debug_cookbooks.clone) }

        it 'should serialize in as the seventh parameter' do
          bundle.debug_cookbooks.should == expected_debug_cookbooks
        end

        it 'should serialize out as the seventh parameter' do
          bundle.serialized_members[6].should == expected_debug_cookbooks
        end
      end
      context 'when not set' do
        let(:bundle) { ExecutableBundle.new }
        it 'should be nil' do
          bundle.debug_cookbooks.should be_nil
        end

        it "should serialize to nil" do
          bundle.serialized_members[6].should be_nil
        end
      end
    end
  end
end
