# encoding: utf-8

#--
# Copyright (c) 2013 RightScale Inc
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
#++

require File.expand_path(File.join(File.dirname(__FILE__), 'spec_helper'))
require File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'lib', 'right_agent', 'clients', 'api_client'))

describe RightScale::ApiClient do

  include FlexMock::ArgumentTypes

  before(:each) do
    @log = flexmock(RightScale::Log)
    @log.should_receive(:error).by_default.and_return { |m| raise RightScale::Log.format(*m) }
    @log.should_receive(:warning).by_default.and_return { |m| raise RightScale::Log.format(*m) }
    @timer = flexmock("timer", :cancel => true, :interval= => 0).by_default
    flexmock(EM::PeriodicTimer).should_receive(:new).and_return(@timer).and_yield.by_default
    @account_id = 123
    @agent_id = "rs-instance-1-1"
    @instance_href = "/api/clouds/1/instances/11"
    @links = {"links" => [{"rel" => "self", "href" => @instance_href}]}
    @http_client = flexmock("http client")
    @http_client.should_receive(:get).and_return(@links).by_default
    flexmock(RightScale::BalancedHttpClient).should_receive(:new).and_return(@http_client).by_default
    @url = "http://test.com"
    @auth_header = {"Authorization" => "Bearer <session>"}
    @auth_client = AuthClientMock.new(@url, @auth_header, :authorized, @account_id, @agent_id)
    @options = {}
    @client = RightScale::ApiClient.new(@auth_client, @options)
    @version = RightScale::AgentConfig.protocol_version
    @payload = {:agent_identity => @agent_id}
    @target = nil
    @token = "random token"
  end

  context :initialize do
    it "initializes options" do
      @options = {
        :open_timeout => 1,
        :request_timeout => 2,
        :listen_timeout => 3,
        :retry_timeout => 4,
        :retry_intervals => [1, 2, 3],
        :reconnect_interval => 5 }
      @client = RightScale::ApiClient.new(@auth_client, @options)
      options = @client.instance_variable_get(:@options)
      options[:server_name] = "RightApi"
      options[:api_version] = "1.5"
      options[:open_timeout] = 1
      options[:request_timeout] = 2
      options[:retry_timeout] = 3
      options[:retry_intervals] = [1, 2, 3]
      options[:reconnect_interval] = 4
      options[:health_check_path] = "/api/right_net/health-check"
    end
  end

  context :push do
    it "makes mapped request" do
      flexmock(@client).should_receive(:make_request).with(:post, "/api/audit_entries/111/append", {:detail => "details"},
          "update_entry", @token, Hash).and_return(nil).once
      @client.push("/auditor/update_entry", @payload.merge(:audit_id => 111, :detail => "details"), @target, @token).should be_nil
    end

    it "does not require token" do
      flexmock(@client).should_receive(:make_request).with(:post, "/api/audit_entries/111/append", {:detail => "details"},
          "update_entry", nil, Hash).and_return(nil).once
      @client.push("/auditor/update_entry", @payload.merge(:audit_id => 111, :detail => "details"), @target).should be_nil
    end
  end

  context :request do
    it "makes mapped request" do
      flexmock(@client).should_receive(:make_request).with(:post, "/api/right_net/booter/declare", {:agent_id => @agent_id,
          :account_id => @account_id, :r_s_version => @version}, "declare", @token, Hash).and_return(nil).once
      @client.push("/booter/declare", @payload.merge(:r_s_version => @version), @target, @token).should be_nil
    end

    it "does not require token" do
      flexmock(@client).should_receive(:make_request).with(:post, "/api/right_net/booter/declare", {:agent_id => @agent_id,
          :account_id => @account_id, :r_s_version => @version}, "declare", nil, Hash).and_return(nil).once
      @client.push("/booter/declare", @payload.merge(:r_s_version => @version), @target).should be_nil
    end
  end

  context :support? do
    it "returns true if request type is supported" do
      @client.support?("/booter/declare").should be_true
    end

    it "returns false if request type is not supported" do
      @client.support?("/instance_scheduler/execute").should be_false
    end
  end

  context :map_request do
    it "raises if request type not supported" do
      lambda { @client.send(:map_request, "/instance_scheduler/execute", @payload, @token) }.should \
          raise_error(ArgumentError, "Unsupported request type: /instance_scheduler/execute")
    end

    it "makes request" do
      flexmock(@client).should_receive(:make_request).with(:post, "/api/right_net/booter/declare", {:agent_id => @agent_id,
          :account_id => @account_id, :r_s_version => @version}, "declare", @token, Hash).and_return(nil).once
      @client.send(:map_request, "/booter/declare", @payload.merge(:r_s_version => @version), @token).should be_nil
    end

    it "converts audit entry href in result to an audit ID" do
      flexmock(@client).should_receive(:make_request).with(:post, "/api/audit_entries",
          {:audit_entry => {:auditee_href => @instance_href, :summary => "summary"}}, "create_entry", @token, Hash).
          and_return("/api/audit_entries/111").once
      @client.send(:map_request, "/auditor/create_entry", @payload.merge(:summary => "summary"), @token).should == "111"
    end
  end

  context :parameterize do

    context "for audits" do
      before(:each) do
        @path, @params, @options = @client.send(:parameterize, "auditor", "update_entry", @payload.merge(:audit_id => 111,
                                                :detail => "details"), "/api/audit_entries/:id/append")
      end

      it "converts audit parameters" do
        @params.should == {:detail => "details"}
      end

      it "substitutes audit ID into path" do
        @path.should == "/api/audit_entries/111/append"
      end

      it "adds parameter filter to options" do
        @options.should == {:filter_params => ["detail", "text"]}
      end
    end

    context "for tags" do
      before(:each) do
        @path, @params, @options = @client.send(:parameterize, "router", "add_tags", @payload.merge(:tags => ["a:b=c", nil, [nil, "x:y=z"]]),
                                                "/api/tags/multi_add")
      end

      it "adds resource hrefs to parameters" do
        @params[:resource_hrefs].should == [@instance_href]
      end

      it "ensures that tags parameter is properly formed" do
        @params[:tags].should == ["a:b=c", "x:y=z"]
      end

      it "does not add tags if not present" do
        _, @params, _ = @client.send(:parameterize, "router", "query_tags", @payload, "/api/tags/multi_add")
        @params.should_not have_key(:tags)
      end
    end

    context "otherwise" do
      before(:each) do
        @path, @params, @options = @client.send(:parameterize, "booter", "declare", @payload.merge(:r_s_version => @version),
                                                "/api/right_net/booter/declare")
      end

      it "adds account ID to parameters" do
        @params[:account_id].should == @account_id
      end

      it "converts all payload parameters" do
        @params[:agent_id].should == @agent_id
        @params[:r_s_version].should == @version
      end

      it "maps payload parameter names as needed" do
        @params[:agent_id].should == @agent_id
        @params[:agent_identity].should be_nil
      end
    end
  end

  context :parameterize_audit do

    context "create_entry" do
      it "stores instance href" do
        @client.send(:parameterize_audit, "create_entry", @payload)[:audit_entry][:auditee_href].should == @instance_href
      end

      context "summary" do
        it "stores summary if non-blank" do
          @client.send(:parameterize_audit, "create_entry", :summary => "hello")[:audit_entry][:summary].should == "hello"
          @client.send(:parameterize_audit, "create_entry", :summary => "")[:audit_entry].should_not have_key(:summary)
          @client.send(:parameterize_audit, "create_entry", {})[:audit_entry].should_not have_key(:summary)
        end

        it "truncates summary if too long" do
          @client.send(:parameterize_audit, "create_entry", :summary => "hello " * 50)[:audit_entry][:summary].size.should == 255
        end
      end

      it "stores detail if non-blank" do
        @client.send(:parameterize_audit, "create_entry", :detail => "details")[:audit_entry][:detail].should == "details"
        @client.send(:parameterize_audit, "create_entry", :detail => "")[:audit_entry].should_not have_key(:detail)
        @client.send(:parameterize_audit, "create_entry", {})[:audit_entry].should_not have_key(:detail)
      end

      it "stores user email if non-blank" do
        @client.send(:parameterize_audit, "create_entry", :user_email => "email")[:user_email].should == "email"
        @client.send(:parameterize_audit, "create_entry", :user_email => "").should_not have_key(:user_email)
        @client.send(:parameterize_audit, "create_entry", {}).should_not have_key(:user_email)
      end

      it "stores notify category if present" do
        @client.send(:parameterize_audit, "create_entry", :category => "Notification")[:notify].should == "Notification"
        @client.send(:parameterize_audit, "create_entry", {}).should_not have_key(:notify)
      end
    end

    context "update_entry" do
      it "stores offset if present" do
        @client.send(:parameterize_audit, "update_entry", :offset => 100)[:offset].should == 100
        @client.send(:parameterize_audit, "update_entry", {}).should_not have_key(:offset)
      end

      context "summary" do
        it "stores summary if non-blank" do
          @client.send(:parameterize_audit, "update_entry", :summary => "hello")[:summary].should == "hello"
          @client.send(:parameterize_audit, "update_entry", :summary => "").should_not have_key(:summary)
          @client.send(:parameterize_audit, "update_entry", {}).should_not have_key(:summary)
        end

        it "truncates summary if too long" do
          @client.send(:parameterize_audit, "update_entry", :summary => "hello " * 50)[:summary].size.should == 255
        end

        it "stores notify category if present and summary is non-blank" do
          @client.send(:parameterize_audit, "update_entry", :summary => "hello", :category => "Notification")[:notify].should == "Notification"
          @client.send(:parameterize_audit, "update_entry", :category => "Notification").should_not have_key(:notify)
        end
      end

      it "stores detail if non-blank" do
        @client.send(:parameterize_audit, "update_entry", :detail => "details")[:detail].should == "details"
        @client.send(:parameterize_audit, "update_entry", :detail => "").should_not have_key(:detail)
        @client.send(:parameterize_audit, "update_entry", {}).should_not have_key(:detail)
      end
    end

    context "otherwise" do
      it "raises unknown audit" do
        lambda { @client.send(:parameterize_audit, "bogus", {}) }.should raise_error(ArgumentError)
      end
    end
  end

  context :truncate do
    it "returns non-string as is" do
      @client.send(:truncate, nil, 5).should == nil
    end

    it "returns strings shorter than limit as is" do
      @client.send(:truncate, "hello", 5).should == "hello"
    end

    it "requires max length to be greater than 3" do
      @client.send(:truncate, "hello", 4).should == "h..."
      lambda { @client.send(:truncate, "hello", 3) }.should raise_error(ArgumentError)
    end

    it "truncates strings that are too long" do
      @client.send(:truncate, "how you doing", 10).bytesize.should == 10
    end

    it "ends truncated string with an ellipsis" do
      @client.send(:truncate, "how you doing", 10).should == "how you..."
    end

    it "accounts for multi-byte characters" do
      @client.send(:truncate, "Schös Tägli wünschi", 20).should == "Schös Tägli wü..."
      @client.send(:truncate, "Schös Tägli wünschi", 19).should == "Schös Tägli w..."
      @client.send(:truncate, "Schös Tägli wünschi", 18).should == "Schös Tägli w..."
      @client.send(:truncate, "Schös Tägli wünschi", 17).should == "Schös Tägli ..."
    end
  end

  context :non_blank do
    it "returns nil if value nil" do
      @client.send(:non_blank, nil).should be_nil
    end

    it "returns nil if value is empty" do
      @client.send(:non_blank, "").should be_nil
    end

    it "returns nil if value nil" do
      @client.send(:non_blank, "hello").should == "hello"
    end
  end

  context :enable_use do
    it "makes API request to get links for setting instance href" do
      flexmock(@client).should_receive(:make_request).with(:get, "/api/sessions/instance", {},
          {:api_version => "1.5", :auth_header => @auth_header}).and_return(@links).once
      @client.instance_variable_get(:@instance_href).should == @instance_href
      @client.send(:enable_use).should be_true
    end
  end
end
