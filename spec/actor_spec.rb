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

describe RightScale::Actor do
  class ::WebDocumentImporter
    include RightScale::Actor
    expose_non_idempotent :import, :cancel
    expose_idempotent :special

    def import; 1 end
    def cancel; 0 end
    def continue; 1 end
    def special; 2 end
    def more_special; 3 end
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

  before :each do
    @log = flexmock(RightScale::Log)
    @log.should_receive(:warning).by_default.and_return { |m| raise RightScale::Log.format(*m) }
    @log.should_receive(:error).by_default.and_return { |m| raise RightScale::Log.format(*m) }
  end

  describe "expose" do

    before :each do
      @exposed = WebDocumentImporter.instance_variable_get(:@exposed).dup
    end

    after :each do
      WebDocumentImporter.instance_variable_set(:@exposed, @exposed)
    end

    context "idempotent" do

      it "exposes as idempotent" do
        WebDocumentImporter.expose_idempotent(:more_special)
        WebDocumentImporter.provides_for("webfiles").sort.should == [
          "/webfiles/cancel", "/webfiles/import", "/webfiles/more_special", "/webfiles/special"]
        WebDocumentImporter.idempotent?(:special).should be_true
        WebDocumentImporter.idempotent?(:more_special).should be_true
      end

      it "treats already exposed non-idempotent method as non-idempotent" do
        @log.should_receive(:warning).with(/Method cancel declared both idempotent and non-idempotent/).once
        WebDocumentImporter.expose_idempotent(:cancel)
        WebDocumentImporter.provides_for("webfiles").sort.should == [
          "/webfiles/cancel", "/webfiles/import", "/webfiles/special"]
        WebDocumentImporter.idempotent?(:cancel).should be_false
      end

    end

    context "non_idempotent" do

      it "exposes as non-idempotent" do
        WebDocumentImporter.expose_non_idempotent(:continue)
        WebDocumentImporter.provides_for("webfiles").sort.should == [
          "/webfiles/cancel", "/webfiles/continue", "/webfiles/import", "/webfiles/special"]
        WebDocumentImporter.idempotent?(:import).should be_false
        WebDocumentImporter.idempotent?(:cancel).should be_false
        WebDocumentImporter.idempotent?(:continue).should be_false
      end

      it "treats already exposed idempotent method as non-idempotent" do
        @log.should_receive(:warning).with(/Method special declared both idempotent and non-idempotent/).once
        WebDocumentImporter.expose_non_idempotent(:special)
        WebDocumentImporter.provides_for("webfiles").sort.should == [
          "/webfiles/cancel", "/webfiles/import", "/webfiles/special"]
        WebDocumentImporter.idempotent?(:special).should be_false
      end

      it "defaults expose method to declare non_idempotent" do
        WebDocumentImporter.expose(:continue)
        WebDocumentImporter.provides_for("webfiles").sort.should == [
          "/webfiles/cancel", "/webfiles/continue", "/webfiles/import", "/webfiles/special"]
        WebDocumentImporter.idempotent?(:continue).should be_false
      end

    end

  end

  describe "default_prefix" do

    it "is calculated as default prefix as const path of class name" do
      Actors::ComedyActor.default_prefix.should == "actors/comedy_actor"
      WebDocumentImporter.default_prefix.should == "web_document_importer"
    end

  end

  describe "provides_for" do

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
      wdi_provides.should include("/webfiles/special")
    end

    it "excludes methods not existing in the actor class" do
      @log.should_receive(:warning).with("Exposing non-existing method non_existing in actor money").once
      Actors::InvalidActor.provides_for("money").should_not include("/money/non_existing")
    end

  end

  describe "idempotent?" do

    it "returns whether idempotent" do
      WebDocumentImporter.idempotent?(:import).should be_false
      WebDocumentImporter.idempotent?(:special).should be_true
    end

  end

end
