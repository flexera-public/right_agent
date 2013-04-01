#--  -*- mode: ruby; encoding: utf-8 -*-
# Copyright: Copyright (c) 2009-2013 RightScale, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# 'Software'), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#++

require File.expand_path(File.join(File.dirname(__FILE__), '..', 'spec_helper'))
require File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'lib', 'right_agent', 'core_payload_types'))

module RightScale
  describe RightScriptInstantiation do
    let(:nickname)        { 'foo' }
    let(:source)          { "echo 'hello world'" }
    let(:parameters)      { { 'ADMIN_PASSWORD' => 'clandestine' } }
    let(:attachments)     { [] }
    let(:packages)        { '' }
    let(:id)              { 123 }
    let(:ready)           { true }
    let(:external_inputs) { {} }
    let(:input_flags)     { {} }
    let(:display_version) { 'HEAD' }

    context 'given all fields' do
      subject do
        described_class.new(
          nickname, source, parameters, attachments, packages, id, ready,
          external_inputs, input_flags, display_version)
      end

      its(:title) { should == "'#{nickname}' #{display_version}" }
      its(:nickname) { should == nickname }
      its(:source) { should == source }
      its(:parameters) { should == parameters }
      its(:attachments) { should == attachments }
      its(:packages) { should == packages }
      its(:id) { should == id }
      its(:ready) { should == ready }
      its(:external_inputs) { should == external_inputs }
      its(:input_flags) { should == input_flags }
      its(:display_version) { should == display_version }
    end

    context 'given minimal fields' do
      subject do
        described_class.new(
          nickname, source, parameters, attachments, packages, id, ready)
      end

      its(:title) { should == nickname }
      its(:nickname) { should == nickname }
      its(:source) { should == source }
      its(:parameters) { should == parameters }
      its(:attachments) { should == attachments }
      its(:packages) { should == packages }
      its(:id) { should == id }
      its(:ready) { should == ready }
      its(:external_inputs) { should be_nil }
      its(:input_flags) { should be_nil }
      its(:display_version) { should be_nil }
    end
  end
end
