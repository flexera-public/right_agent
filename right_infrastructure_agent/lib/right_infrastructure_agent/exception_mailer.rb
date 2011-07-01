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

require 'action_mailer'

module RightScale

  class ExceptionMailer < ActionMailer::Base

    cattr_accessor :notification_recipients
    cattr_accessor :notification_sender

    def self.configure_exception_callback(options)
      # Add an exception callback to options so we can send out notification emails
      ActionMailer::Base.delivery_method = :sendmail

      self.notification_recipients = options[:notify] || nil

      name = "#{options[:agent_name]}_agent"
      name = "#{ENV['RAILS_ENV']}_#{name}" if ENV['RAILS_ENV']
      meth = "#{options[:agent_type]}_receive_loop".to_sym
      self.notification_sender = "#{name}@#{`hostname --fqdn 2> /dev/null || hostname 2> /dev/null`}"
      options[:exception_callback] = Proc.new do |e, msg, _|
        self.deliver_notification(meth, msg, e)
      end
    end

    def notification(meth, msg, e)
      recipients  notification_recipients
      from        notification_sender
      subject     "@@ RightNet #{notification_sender} #{meth||'misc'} (#{e.class.name}) #{e.message}"

      contents = "A #{e.class.name} occurred during RightNet #{notification_sender} message handling:"
      contents += "\n  #{e.message}" if e.message
      contents += "\n\nException backtrace:"
      contents += "\n\n" + e.backtrace.join("\n")

      if msg
        contents += "\n\nMessage being processed:\n\n"
        contents += msg.inspect
      end

      body        contents
    end

  end # ExceptionMailer

end # RightScale
