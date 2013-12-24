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

module RightScale

  # HTTP interface to RightApi for use when mapping actor-based requests to API requests
  class ApiClient < BaseClient

    # RightApi API version for use in X-API-Version header
    API_VERSION = "1.5"

    # Path for RightApi health check
    HEALTH_CHECK_PATH = "/api/right_net/health-check"

    # Maximum length of an audit summary as enforced by RightApi
    MAX_AUDIT_SUMMARY_LENGTH = 255

    # Default time to wait for HTTP connection to open
    DEFAULT_OPEN_TIMEOUT = 2

    # Default time to wait for response from request, which is chosen to be 5 seconds greater
    # than the response timeout inside the RightNet router
    DEFAULT_REQUEST_TIMEOUT = 35

    # Map from actor-based request paths to RightApi HTTP verb and path; only requests whose type
    # matches an entry in this hash will be routed to the RightApi; all others will be routed to RightNet
    API_MAP = {
      "/auditor/create_entry"              => [:post, "/api/audit_entries"],
      "/auditor/update_entry"              => [:post, "/api/audit_entries/:id/append"],
      "/booter/declare"                    => [:post, "/api/right_net/booter/declare"],
      "/booter/set_r_s_version"            => [:put,  "/api/right_net/booter/set_r_s_version"],
      "/booter/get_repositories"           => [:get,  "/api/right_net/booter/get_repositories"],
      "/booter/get_boot_bundle"            => [:get,  "/api/right_net/booter/get_boot_bundle"],
      "/booter/get_decommission_bundle"    => [:get,  "/api/right_net/booter/get_decommission_bundle"],
      "/booter/get_missing_attributes"     => [:get,  "/api/right_net/booter/get_missing_attributes"],
      "/booter/get_login_policy"           => [:get,  "/api/right_net/booter/get_login_policy"],
      "/forwarder/schedule_right_script"   => [:post, "/api/right_net/scheduler/schedule_right_script"],
      "/forwarder/schedule_recipe"         => [:post, "/api/right_net/scheduler/schedule_recipe"],
      "/forwarder/shutdown"                => [:post, "/api/right_net/scheduler/shutdown"],
      "/key_server/retrieve_public_keys"   => [:get,  "/api/right_net/key_server/retrieve_public_keys"],
      "/mapper/ping"                       => [:post, HEALTH_CHECK_PATH],
      "/mapper/query_tags"                 => [:post, "/api/tags/by_resource"],
      "/mapper/add_tags"                   => [:post, "/api/tags/multi_add"],
      "/mapper/delete_tags"                => [:post, "/api/tags/multi_delete"],
      "/state_recorder/record"             => [:put,  "/api/right_net/state_recorder/record"],
      "/storage_valet/get_planned_volumes" => [:get,  "/api/right_net/storage_valet/get_planned_volumes"],
      "/storage_valet/attach_volume"       => [:post, "/api/right_net/storage_valet/attach_volume"],
      "/storage_valet/detach_volume"       => [:post, "/api/right_net/storage_valet/detach_volume"],
      "/updater/update_inputs"             => [:post, "/api/right_net/scheduler/update_inputs"],
      "/vault/read_documents"              => [:get,  "/api/right_net/vault/read_documents"] }

    # Request parameter name map
    PARAM_NAME_MAP = {
      :agent_identity => :agent_id,
      :klass          => :class_name }

    # Symbols for audit request parameters whose values are to be hidden when logging
    AUDIT_FILTER_PARAMS = [ "detail", "text"]

    # Create RightApi client of specified type
    #
    # @param [AuthClient] auth_client providing authorization session for HTTP requests
    #
    # @option options [Numeric] :open_timeout maximum wait for connection; defaults to DEFAULT_OPEN_TIMEOUT
    # @option options [Numeric] :request_timeout maximum wait for response; defaults to DEFAULT_REQUEST_TIMEOUT
    # @option options [Numeric] :retry_timeout maximum before stop retrying; defaults to DEFAULT_RETRY_TIMEOUT
    # @option options [Array] :retry_intervals between successive retries; defaults to DEFAULT_RETRY_INTERVALS
    # @option options [Boolean] :retry_enabled for requests that fail to connect or that return a retry result
    # @option options [Proc] :exception_callback for unexpected exceptions
    #
    # @raise [ArgumentError] auth client does not support this client type
    def initialize(auth_client, options)
      init(:api, auth_client, options.merge(:api_version => API_VERSION, :health_check_path => HEALTH_CHECK_PATH))
    end

    # Determine whether request supported by this client
    #
    # @param [String] type of request as path specifying actor and action
    #
    # @return [Array] HTTP verb and path
    def support?(type)
      API_MAP.has_key?(type)
    end

    # Make request via HTTP after mapping it to RightApi format
    # Concatenate audit ID and request token for identifying request in HTTP header
    # Rely on underlying HTTP client to log request and response
    # Retry request if response indicates to or if there are "not responding" failures
    #
    # @param [Symbol] kind of request: :send_push or :send_request
    # @param [String] type of request as path specifying actor and action
    # @param [Hash, NilClass] payload for request
    # @param [String, Hash, NilClass] target for request
    # @param [String, NilClass] request_token uniquely identifying this request;
    #   defaults to randomly generated ID
    #
    # @return [Object, NilClass] result of request with nil meaning no result
    #
    # @raise [ArgumentError] request type does not map to supported request
    # @raise [RightScale::Exceptions::Unauthorized] authorization failed
    # @raise [RightScale::Exceptions::ConnectivityFailure] could not make connection to send request
    # @raise [RightScale::Exceptions::StructuredError] mismatch in state from which transitioning
    # @raise [RightScale::Exceptions::Application] request could not be processed by target
    # @raise [RightScale::Exceptions::Terminating] closing client and terminating service
    def make_request(kind, type, payload, target, request_token)
      raise RightScale::Exceptions::Terminating if state == :closing
      raise RightScale::Exceptions::ConnectivityFailure unless state == :connected
      verb, path = API_MAP[type]
      raise ArgumentError.new("Unsupported request type: #{type}") if path.nil?
      actor, action = type.split("/")[1..-1]
      request_token = [payload.is_a?(Hash) && payload[:audit_id],
                       request_token || RightSupport::Data::UUID.generate].compact.join(":")
      original_request_token = request_token
      started_at = @stats["requests sent"].update(action, request_token)
      attempts = 0

      begin
        attempts += 1
        params = {:request_token => request_token}
        options = {
          :open_timeout => @options[:open_timeout],
          :request_timeout => @options[:request_timeout],
          :request_uuid => request_token,
          :auth_header => @auth_client.auth_header }
        if actor == "auditor"
          result = make_audit_request(verb, path, action, payload, options)
        elsif actor == "mapper" && action =~ /tags/
          result = make_tags_request(verb, path, payload, options)
        else
          params[:account_id] = @auth_client.account_id
          payload.each { |k, v| params[PARAM_NAME_MAP[k.to_sym] || k.to_sym] = v } if payload.is_a?(Hash)
          result = @http_client.send(verb, path, params, options)
        end
      rescue StandardError => e
        request_token = handle_exception(e, action, type, original_request_token, started_at, attempts)
        retry
      end

      @stats["requests sent"].finish(started_at, original_request_token)
      result
    end

    protected

    # Perform any other steps needed to make this client fully usable
    # once HTTP client has been created and service known to be accessible
    #
    # @return [TrueClass] always true
    def init_client_usage
      options = {
        :api_version => @options[:api_version],
        :auth_header => @auth_client.auth_header }
      response = @http_client.get("/api/sessions/instance", nil, options)
      @instance_href = response["links"].select { |link| link["rel"] == "self" }.first["href"]
      true
    end

    # Translate tags request to RightApi request
    #
    # @param [Symbol] verb for HTTP REST request
    # @param [String] path in URI for desired resource
    # @param [Hash] payload from submitted request
    # @param [Hash] options for HTTP request
    #
    # @return [Object] result of final request to RightApi
    def make_tags_request(verb, path, payload, options)
      params = {:resource_hrefs => [@instance_href]}
      params[:tags] = Array(payload[:tags]).flatten.compact if payload[:tags]
      @http_client.send(verb, path, params, options)
    end

    # Translate audit request to RightApi request
    # Truncate audit summary to MAX_AUDIT_SUMMARY_LENGTH, the limit imposed by RightApi
    #
    # @param [Symbol] verb for HTTP REST request
    # @param [String] path in URI for desired resource
    # @param [String] action requested: create_entry or update_entry
    # @param [Hash] payload from submitted request
    # @param [Hash] options for HTTP request
    #
    # @return [Object] result of request to RightApi
    #
    # @raise [ArgumentError] unknown request action
    def make_audit_request(verb, path, action, payload, options)
      params = {}
      path = path.sub(/:id/, payload[:audit_id].to_s || "")
      filter_params = {:filter_params => AUDIT_FILTER_PARAMS}
      case action
      when "create_entry"
        params[:audit_entry] = {
          :auditee_href => @instance_href,
          :summary      => truncate(payload[:summary], MAX_AUDIT_SUMMARY_LENGTH) }
        params[:audit_entry][:detail] = payload[:detail] if payload[:detail]
        params[:user_email] = payload[:user_email] if payload[:user_email]
        params[:notify] = payload[:category] if payload[:category]
        result = @http_client.send(verb, path, params, options.merge(filter_params))
        # Convert returned audit entry href to audit ID
        result.sub!(/^.*\/api\/audit_entries\//, "")
      when "update_entry"
        params[:offset] = payload[:offset] if payload[:offset]
        if (summary = payload[:summary]) && !summary.empty?
          params[:summary] = truncate(summary, MAX_AUDIT_SUMMARY_LENGTH)
          params[:notify] = payload[:category] if payload[:category]
        end
        if (detail = payload[:detail]) && !detail.empty?
          params[:detail] = detail
        end
        result = @http_client.send(verb, path, params, options.merge(filter_params))
      else
        raise ArgumentError.new("Unknown audit request action: #{action}")
      end
      result
    end

    # Truncate string if it exceeds maximum length
    # Do length check with bytesize rather than size since this code
    # is running with ruby 1.9.2 while the API uses 1.8.7, otherwise
    # multi-byte characters could cause this code to be too lenient
    #
    # @param [String, NilClass] value to be truncated
    # @param [Integer] max_length allowed; must be greater than 3
    #
    # @return [String, NilClass] truncated string or original value if it is not a string
    #
    # @raise [ArgumentError] max_length too small
    def truncate(value, max_length)
      raise ArgumentError.new("max_length must be greater than 3") if max_length <= 3
      if value.is_a?(String) && value.bytesize > max_length
        max_truncated = max_length - 3
        truncated = value[0, max_truncated]
        while truncated.bytesize > max_truncated do
          truncated.chop!
        end
        truncated + "..."
      else
        value
      end
    end

  end # ApiClient

end # RightScale
