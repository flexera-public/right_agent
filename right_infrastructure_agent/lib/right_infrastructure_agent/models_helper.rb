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

module RightScale

  # Helper methods for accessing ActiveRecord models
  # They are only usable when executing in a Rails environment
  module ModelsHelper

    include OperationResultHelper

    protected

    # Retrieve database object
    # Audit and/or log error if given block returns nil or raises, return block result otherwise
    # Store any error message in @last_error
    #
    # === Parameters
    # description(String):: Description of object that is used in error messages
    # audit(AuditEntry):: Audit entry used to append error message if any, default to nil
    # log(Boolean):: Whether to log message when object does not exist, default to false
    #
    # === Block
    # Performs query to retrieve object, required
    #
    # === Return
    # item(Object):: Value returned by block, or nil if not found or failed
    def retrieve(description, audit = nil, log = false)
      begin
        unless item = yield
          @last_error = "Could not find #{description}"
          Log.warning(@last_error) if log
        end
      rescue Exception => e
        description = "Failed to retrieve #{description}"
        Log.error(description, e, :trace)
        @last_error = Log.format(description, e)
        item = nil
      end
      audit.append(AuditFormatter.error(@last_error)) if audit && item.nil? && @last_error
      item
    end

    # Create database object
    # Audit and/or log error if given block returns nil or raises, return block result otherwise
    # Store any error message in @last_error
    #
    # === Parameters
    # description(String):: Description of object that is used in error messages
    # audit(AuditEntry):: Audit entry used to append error message if any, default to nil
    #
    # === Block
    # Creates object and returns it, required
    #
    # === Return
    # (Object):: Value returned by block, or nil if failed
    def create(description, audit = nil)
      begin
        yield
      rescue Exception => e
        description = "Failed to create #{description}"
        Log.error(description, e, :trace)
        @last_error = Log.format(description, e)
        audit.append(AuditFormatter.error(@last_error)) if audit
        nil
      end
    end

    # Query database using retry on failure and reconnect handling
    # Store any error message in @last_error
    #
    # === Parameters
    # description(String):: Description of query action that is used in error messages
    # audit(AuditEntry):: Audit entry used to append error message if any, default to nil
    # options(Hash):: Hash of additional options, default to empty.  Supported options are:
    #   :include_backtrace_in_last_error - passes the :trace option to Log.format if there is an exception
    #   :email_errors
    #
    # === Block
    # Accesses MySQL and returns result, required
    #
    # === Return
    # (Object|nil):: Value returned by block, or nil if failed
    def query(description, audit = nil, options = {}, &blk)
      begin
        ModelsImporter.instance.run_query(&blk)
      rescue Exception => e
        description = "Failed to #{description}"
        Log.error(description, e, :trace)
        if options[:include_backtrace_in_last_error]
          @last_error = Log.format(description, e, :trace)
        else
          @last_error = Log.format(description, e)
        end
        audit.append(AuditFormatter.error(@last_error)) if audit

        if(options[:email_errors])
          ExceptionMailer.deliver_notification(description, e.message, e)
        end

        nil
      end
    end

    # Retrieve existing audit or create new one
    #
    # === Parameters
    # options(Hash):: Hash which should include :audit_id if audit is to be retrieved
    #   and :agent_identity if audit is to be created
    # new_audit_args(Array):: Pass-through arguments to audit creation method
    #
    # === Return
    # (AuditEntry):: Audit entry model
    def retrieve_or_create_audit(options, new_audit_args)
      if options[:audit_id] && options[:audit_id] != -1
        audit_id = options[:audit_id]
        retrieve("audit with id #{audit_id}") { @auditor.audit_with_id(audit_id) }
      else
        create("audit for instance agent #{options[:agent_identity]}") { @auditor.new_audit(*new_audit_args) }
      end
    end

    # Retrieve existing user or get default user stub
    #
    # === Parameters
    # options[:user_id](Integer):: user id or zero or nil
    # instance(Instance):: instance for account
    #
    # === Return
    # result(OperationResult):: success result with user as content or error result
    def retrieve_or_default_user(options, instance)
      user_id = (options[:user_id] || 0).to_i  # ensure user id is non-nil integer
      if user_id == 0
        current_user = User.new(:email => 'alerter@rightscale.com')
        current_user.id = 0
      else
        account = instance.account
        current_user = retrieve("User with id #{user_id}", audit = nil, log = true) do
          query("retrieve users in account #{account}") { account.users.detect { |u| u.id == user_id } }
        end
        return error_result(@last_error) unless current_user
      end
      return success_result(current_user)
    end

    # Retrieve InstanceApiToken model with given id
    #
    # === Parameters
    # id(Integer):: id of InstanceApiToken to be retrieved
    #
    # === Return
    # token(InstanceApiToken):: Corresponding API token
    # nil:: If no token with such id exist
    def instance_token(id)
      token = run_query { InstanceApiToken.find(id) }
    end

    # Retrieve Instance model with given API token id
    #
    # === Parameters
    # id(Integer):: id of InstanceApiToken of instance to be retrieved
    #
    # === Return
    # instance(Ec2Instance|Instance):: Corresponding instance
    # nil:: If no token with such id exist
    def instance(id)
      token = instance_token(id)
      token && token.instance
    end

    # Get instance from api token id
    #
    # === Parameters
    # token_id(Integer):: API token id
    #
    # === Return
    # instance(Instance):: Corresponding instance
    def instance_from_token_id(token_id)
      @cache ||= InstanceTokensCache.new
      instance = @cache[token_id]
    end

    # Get instance model corresponding to instance agent with given identity
    #
    # === Parameters
    # identity(String):: Serialized instance agent identity
    #
    # === Return
    # instance(Instance):: Corresponding instance
    #
    # === Raise
    # RightScale::Exceptions::Argument:: Invalid agent identity
    def instance_from_agent_id(identity)
      raise RightScale::Exceptions::Argument, "Invalid identity token" unless AgentIdentity.valid?(identity)
      instance = instance_from_token_id(AgentIdentity.parse(identity).base_id)
    end

    # Retrieve account with given id
    #
    # === Parameters
    # id(Integer):: id of account to be retrieved
    #
    # === Return
    # account(Account):: Corresponding account
    # nil:: If no account with such id exist
    def account(id)
      account = run_query { Account.find(id) }
    end

    # Retrieve RightScript with given id
    #
    # === Parameters
    # id(Integer):: id of RightScript to be retrieved
    #
    # === Return
    # script(RightScript):: Corresponding RightScript
    # nil:: If no RightScript with such id exist
    def right_script(id)
      script = run_query { RightScript.find(id) }
    end

    # Retrieve Chef recipe with given id
    #
    # === Parameters
    # id(Integer):: id of ServerTemplateChefRecipe to be retrieved
    #
    # === Return
    # recipe(ServerTemplateChefRecipe):: Corresponding recipe
    # nil:: If no recipe with such id exist
    def recipe(id)
      recipe = run_query { ServerTemplateChefRecipe.find(id) }
    end

    # Retrieve Permission with given ID
    #
    # === Parameters
    # id(Integer):: id of Permission to be retrieved
    #
    # === Return
    # permission(Permission):: Corresponding permission
    # nil:: If no permission with such id exists
    def permission(id)
      permission = run_query { Permission.find(id) }
    end

    # Retrieve UserCredential with given ID
    #
    # === Parameters
    # id(Integer):: id of UserCredential to be retrieved
    #
    # === Return
    # user_credential(UserCredential):: Corresponding permission
    # nil:: If no credential with such id exists
    def user_credential(id)
      user_credential = run_query { UserCredential.find(id) }
    end

    # Retrieve Setting with given ID
    #
    # === Parameters
    # id(Integer):: id of Setting to be retrieved
    #
    # === Return
    # setting(Setting):: Corresponding permission
    # nil:: If no setting with such id exists
    def setting(id)
      setting = run_query { Setting.find(id) }
    end

    # Retrieve RightScript with given name on given instance
    #
    # === Parameters
    # name(String):: Name of RightScript that should be retrieved
    # instance(Instance):: Instance on which RightScript is defined
    #
    # === Return
    # script(RightScript):: Corresponding RightScript
    def right_script_from_name(name, instance)
      script = nil
      template = run_query { instance.server_template }
      if template
        script = run_query { template.right_scripts.find_by_name(name) }
      end
      script
    end

    # Retrieve recipe with given name on given instance
    #
    # === Parameters
    # name(String):: Name of recipe that should be retrieved
    # instance(Instance):: Instance on which recipe is defined
    #
    # === Return
    # recipe(ServerTemplateChefRecipe):: Corresponding recipe
    def recipe_from_name(name, instance)
      recipe = nil
      template = run_query { instance.server_template }
      if template
        recipe = run_query { template.server_template_chef_recipes.find_by_recipe(name) }
      end
      recipe
    end

    # Retrieve all software repositories
    #
    # === Return
    # repos(Array):: Array of Repository
    def repositories
      repos = run_query { ::Repository.find(:all) }
    end

    # Run database query block
    # When catch a MySQL disconnect error, reconnect and rerun block, retry indefinitely
    # When catch other MySQL and ActiveRecord errors, rerun block, retry up to 3 times
    #
    # === Block
    # Accesses MySQL and returns result, required
    #
    # === Return
    # res(Object|nil):: Value returned by given block, or nil if desired data was not found
    #
    # === Raise
    # RuntimeError:: Block is missing
    # Also re-raises any query block exceptions
    def run_query
      raise 'Missing block' unless block_given?
      res = nil
      disconnected = true
      while disconnected do
        retries = 0
        begin
          res = yield
          disconnected = false
        rescue ActiveRecord::RecordNotFound
          res = nil
          disconnected = false
        rescue Exception => e
          if disconnected = is_disconnect_error?(e)
            Log.error("Failed running MySQL query", e, :trace)
            ActiveRecordInitializer.reconnect if defined?(ActiveRecordInitializer)
          elsif is_retryable_error?(e)
            if retries >= 3
              Log.warning("Aborting query after 3 failed retries")
              raise # re-raise the exception
            else
              retries += 1
              Log.error("Failed running MySQL query", e, :trace)
              Log.info("Retrying query...")
              retry
            end
          else
            raise # re-raise the exception
          end
        end
      end
      res
    end

    # Is given exception a MySQL connection exception?
    #
    # === Parameter
    # e(Exception):: Exception to be tested
    #
    # === Return
    # (Boolean):: true if exception is a MySQL disconnect exception, otherwise false or nil
    def is_disconnect_error?(e)
      if e.is_a?(MysqlError) || e.is_a?(ActiveRecord::StatementInvalid)
        db_connection_errors = ActiveRecord::ConnectionAdapters::MysqlAdapter::LOST_CONNECTION_ERROR_MESSAGES
        db_connection_errors << "Can't connect to"
        db_connection_errors.find {|err| e.message.include?(err)}
      end
    end

    # Is given exception a MySQL exception worth retrying, e.g., a deadlock or timeout?
    #
    # === Parameter
    # e(Exception):: Exception to be tested
    #
    # === Return
    # (Boolean):: true if worth retrying, otherwise false or nil
    def is_retryable_error?(e)
      if e.is_a?(MysqlError) || e.is_a?(ActiveRecord::ActiveRecordError)
#        retryable_errors = ["Deadlock found", "Lock wait timeout"]
#        retryable_errors.find { |err| e.message.include?(err) }
        true
      end
    end

    # Add a one-shot timer to the EM event loop and rescue any exception
    #
    # === Parameters
    # delay(Integer):: Seconds to delay before executing block
    #
    # === Block
    # Code to be executed after the delay; must be provided
    #
    # === Return
    # true:: Always return true
    def add_timer(delay)
      EM.add_timer(delay) do
        begin
          yield
        rescue Exception => e
          Log.error("Failed time-delayed task", e, :trace)
        end
      end
      true
    end

  end # ModelHelpers

end # RightScale
