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

describe RightScale::Platform do
  subject { RightScale::Platform }

  context :shell do
    context :uptime do
      it 'should be positive' do
        subject.shell.uptime.should > 0
      end

      it 'should be strictly increasing' do
        u0 = subject.shell.uptime
        sleep(1)
        u1 = subject.shell.uptime

        (u1 - u0).should >= 0
      end
    end

    context :booted_at do
      it 'should be some time in the past' do
        Time.at(subject.shell.booted_at).to_i.should < Time.now.to_i
      end

      it 'should be constant' do
        b0 = subject.shell.booted_at
        sleep(1)
        b1 = subject.shell.booted_at

        b0.should == b1
      end
    end
  end

  context 'cloud-family queries' do
    # PLEASE NOTE: we are unable to use the magic RSpec "subject" because
    # we are dispatching calls to a Singleton and we must partially mock its
    # calls, and both __send__ and flexmock partial-mocking gets confused by
    # the fact that #subject returns a Proc, not the actual subject. Do not
    # attempt to use the pretty RSpec feature within this context. You have
    # been warned!
    before(:each) do
      @subject = subject.instance
      @subject.instance_variable_set(:@ec2, nil)
      @subject.instance_variable_set(:@rackspace, nil)
      @subject.instance_variable_set(:@eucalyptus, nil)
    end

    ['ec2', 'rackspace', 'eucalyptus'].each do |cloud|
      it "should detect #{cloud}" do
        query = "#{cloud}?".to_sym
        flexmock(@subject).should_receive(:read_cloud_file).once.and_return(cloud)
        @subject.__send__(query).should be_true
      end
    end
  end
end
