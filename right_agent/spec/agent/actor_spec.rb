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

describe RightScale::Actor do
  class ::WebDocumentImporter
    include RightScale::Actor
    expose :import, :cancel

    def import
      1
    end
    def cancel
      0
    end
    def continue
      1
    end
  end

  module ::Actors
    class ComedyActor
      include RightScale::Actor
      expose :fun_tricks
      def fun_tricks
        :rabbit_in_the_hat
      end
    end
  end

  class ::Actors::InvalidActor
    include RightScale::Actor
    expose :non_existing
  end
  
  describe ".expose" do
    before :each do
      @exposed = WebDocumentImporter.instance_variable_get(:@exposed).dup
    end
    
    after :each do
      WebDocumentImporter.instance_variable_set(:@exposed, @exposed)
    end
    
    
    it "should single expose method only once" do
      3.times { WebDocumentImporter.expose(:continue) }
      WebDocumentImporter.provides_for("webfiles").should == ["/webfiles/import", "/webfiles/cancel", "/webfiles/continue"]
    end
  end
  
  describe ".default_prefix" do
    it "is calculated as default prefix as const path of class name" do
      Actors::ComedyActor.default_prefix.should == "actors/comedy_actor"
      WebDocumentImporter.default_prefix.should == "web_document_importer"
    end
  end

  describe ".provides_for(prefix)" do
    before :each do
      @provides = Actors::ComedyActor.provides_for("money")
    end
    
    it "returns an array" do
      @provides.should be_kind_of(Array)
    end

    it "maps exposed service methods to prefix" do
      @provides.should == ["/money/fun_tricks"]
      wdi_provides = WebDocumentImporter.provides_for("webfiles")
      wdi_provides.should include("/webfiles/import")
      wdi_provides.should include("/webfiles/cancel")
    end
    
    it "should not include methods not existing in the actor class" do
      Actors::InvalidActor.provides_for("money").should_not include("/money/non_existing")
    end
  end
end
