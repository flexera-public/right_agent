# Copyright (c) 2009-2011 RightScale, Inc, All Rights Reserved Worldwide.
#
# THIS PROGRAM IS CONFIDENTIAL AND PROPRIETARY TO RIGHTSCALE
# AND CONSTITUTES A VALUABLE TRADE SECRET.  Any unauthorized use,
# reproduction, modification, or disclosure of this program is
# strictly prohibited.  Any use of this program by an authorized
# licensee is strictly subject to the terms and conditions,
# including confidentiality obligations, set forth in the applicable
# License Agreement between RightScale.com, Inc. and
# the licensee.

require File.join(File.dirname(__FILE__), 'spec_helper')

module ActiveRecord
  class ActiveRecordError < Exception; end
  class StatementInvalid < ActiveRecordError; end
  class RecordNotFound < Exception; end
end

class MysqlError < Exception; end

describe RightScale::ModelsHelper do

  include RightScale::ModelsHelper

  before(:each) do
    flexmock(RightScale::Log).should_receive(:info).never.by_default
    flexmock(RightScale::Log).should_receive(:warning).never.by_default
    flexmock(RightScale::Log).should_receive(:error).never.by_default
    @audit_formatter = flexmock(RightScale::AuditFormatter)
    @audit_formatter.should_receive(:error).never.by_default
    @audit = flexmock("audit")
    @audit.should_receive(:append).never.by_default
    @last_error = nil
  end

  context :retrieve do

    it 'should yield and return result from block' do
      called = 0
      result = retrieve("something") { called += 1 }
      called.should == 1
      result.should == 1
      @last_error.should be_nil
    end

    it 'should detect not found but not log warning nor audit by default' do
      called = 0
      result = retrieve("something") { called += 1; nil }
      called.should == 1
      result.should == nil
      @last_error.should == "Could not find something"
    end

    it 'should detect not found and log warning if log enabled' do
      flexmock(RightScale::Log).should_receive(:warning).with(/Could not find something/).once
      called = 0
      result = retrieve("something", audit = nil, log = true) { called += 1; nil }
      called.should == 1
      result.should == nil
      @last_error.should == "Could not find something"
    end

    it 'should detect not found and audit if audit enabled' do
      @audit_formatter.should_receive(:error).with("Could not find something").once
      @audit.should_receive(:append).once
      called = 0
      result = retrieve("something", @audit) { called += 1; nil }
      called.should == 1
      result.should == nil
      @last_error.should == "Could not find something"
    end

    it 'should catch and log exception and return nil by default' do
      flexmock(RightScale::Log).should_receive(:error).with("Failed to retrieve something", NoMethodError, :trace).once
      called = 0
      result = retrieve("something") do
        called += 1
        nil + "string"
      end
      called.should == 1
      result.should == nil
      error = /Failed to retrieve something \(NoMethodError.*undefined method.*models_helper_spec.*\)$/
      (@last_error.should =~ error).should be_true
    end

    it 'should audit exception if audit enabled' do
      error = /Failed to retrieve something \(NoMethodError.*undefined method.*models_helper_spec.*\)$/
      @audit_formatter.should_receive(:error).with(error).once
      @audit.should_receive(:append).once
      flexmock(RightScale::Log).should_receive(:error).once
      called = 0
      result = retrieve("something", @audit) do
        called += 1
        nil + "string"
      end
      called.should == 1
      result.should == nil
      (@last_error.should =~ error).should be_true
    end

    it 'should not log or audit an error from a previous retrieval' do
      called = 0
      result = retrieve("something") { called += 1; nil }
      called.should == 1
      result.should == nil
      @last_error.should == "Could not find something"
      result = retrieve("something", audit = true, log = true) { called += 1 }
      called.should == 2
      @last_error.should == "Could not find something"
    end

  end

  context :create do

    it 'should yield and return result from block' do
      called = 0
      result = create("something") { called += 1 }
      called.should == 1
      result.should == 1
    end

    it 'should catch and log exception and return nil by default' do
      flexmock(RightScale::Log).should_receive(:error).with("Failed to create something", NoMethodError, :trace).once
      called = 0
      result = create("something") do
        called += 1
        nil + "string"
      end
      called.should == 1
      result.should == nil
      error = /Failed to create something \(NoMethodError.*undefined method.*models_helper_spec.*\)$/
      (@last_error.should =~ error).should be_true
    end

    it 'should audit exception if audit enabled' do
      error = /Failed to create something \(NoMethodError.*undefined method.*models_helper_spec.*\)$/
      @audit_formatter.should_receive(:error).with(error).once
      @audit.should_receive(:append).once
      flexmock(RightScale::Log).should_receive(:error).once
      called = 0
      result = create("something", @audit) do
        called += 1
        nil + "string"
      end
      called.should == 1
      result.should == nil
      (@last_error.should =~ error).should be_true
    end

  end

  context :query do

    it 'should run query, yielding to block and returning result from query block' do
      called = 0
      result = query("query database") { called += 1 }
      called.should == 1
      result.should == 1
    end

    it 'should catch and log exception and return nil by default' do
      flexmock(RightScale::Log).should_receive(:error).with("Failed to query database", NoMethodError, :trace).once
      called = 0
      result = query("query database") do
        called += 1
        nil + "string"
      end
      called.should == 1
      result.should == nil
      error = /Failed to query database \(NoMethodError.*undefined method.*models_helper_spec.*\)$/
      (@last_error.should =~ error).should be_true
    end

    it 'should audit exception if audit enabled' do
      error = /Failed to query database \(NoMethodError.*undefined method.*models_helper_spec.*\)$/
      @audit_formatter.should_receive(:error).with(error).once
      @audit.should_receive(:append).once
      flexmock(RightScale::Log).should_receive(:error).once
      called = 0
      result = query("query database", @audit) do
        called += 1
        nil + "string"
      end
      called.should == 1
      result.should == nil
      (@last_error.should =~ error).should be_true
    end

    it 'should return nil if catch RecordNotFound exception and not log error' do
      called = 0
      result = query("query database") do
        called += 1
        raise ActiveRecord::RecordNotFound.new("Missing")
      end
      called.should == 1
      result.should == nil
      @last_error.should be_nil
    end

    it 'should retry query up to 3 times if is a MySQL or ActiveRecord error' do
      flexmock(RightScale::Log).should_receive(:info).with("Retrying query...").times(3)
      flexmock(RightScale::Log).should_receive(:warning).with("Aborting query after 3 failed retries").once
      flexmock(RightScale::Log).should_receive(:error).with("Failed running MySQL query",
                                                            ActiveRecord::StatementInvalid, :trace).times(3)
      flexmock(RightScale::Log).should_receive(:error).with("Failed to query database",
                                                            ActiveRecord::StatementInvalid, :trace).once
      called = 0
      result = query("query database") do
        called += 1
        raise ActiveRecord::StatementInvalid.new("Invalid query")
      end
      called.should == 4
      result.should == nil
      error = /Failed to query database \(ActiveRecord::StatementInvalid.*Invalid query in .*models_helper_spec.*\)$/
      (@last_error.should =~ error).should be_true
    end

  end

end
