# Copyright (c) 2011 RightScale, Inc, All Rights Reserved Worldwide.
#
# THIS PROGRAM IS CONFIDENTIAL AND PROPRIETARY TO RIGHTSCALE
# AND CONSTITUTES A VALUABLE TRADE SECRET.  Any unauthorized use,
# reproduction, modification, or disclosure of this program is
# strictly prohibited.  Any use of this program by an authorized
# licensee is strictly subject to the terms and conditions,
# including confidentiality obligations, set forth in the applicable
# License Agreement between RightScale.com, Inc. and the licensee.

# Wasabi replicator actor in charge of updating the core db for changes
# which occur to global objects in the wasabi db.
class WasabiReplicatorSink

  include RightScale::Actor
  include RightScale::ModelsHelper

  on_exception { |meth, deliverable, e| RightScale::ExceptionMailer.deliver_notification(meth, deliverable, e) }

  # Set agent identity for routing
  #
  # === Parameters
  # identity(String):: Agent identity
  def initialize(identity)
    @identity = identity
  end

  # Asks the specified right_site core object (klass, id) to update its attributes
  # when it is modified in the library.
  #
  # === Parameters
  # options[:klass]:: the model (class) of the object being updated (String representation)
  # options[:id]:: the unique identifier of the object being updated
  # options[:schema_version]:: the schema version of the model (class)
  # options[:global_object_version]:: the global object version of the model (class)
  # options[:attrs]:: all attributes defined for the object represented by klass and id in yaml
  #
  # === Return
  # res(RightScale::OperationResult):: success or error with message
  def handle_global_object_change(options)
    options = RightScale::SerializationHelper.symbolize_keys(options)
    attrs   = options[:attrs]
    klass   = options[:klass].constantize

    RightScale::Log.info("GlobalObjectReplica: Processing global object change for #{klass.name}/#{options[:id]}")

    action  = "wasabi_replicator_sink/handle_global_object_change for #{klass.name}/#{options[:id]} " +
              "(schema verison #{options[:schema_version]}, global object version #{options[:global_object_version]})"
    success = query(action, nil, :include_backtrace_in_last_error => true) do
      klass.handle_global_object_change(options[:id], options[:schema_version], options[:global_object_version], attrs)
      true
    end
    success ? success_result : error_result(@last_error)
  end

  # Compares checksum parameter of a replicated table and, if they do not match, begins the synchronization
  # process by sending library_replicator/verify_replica_range request.
  #
  # === Parameters
  # options[:class_name]:: Name of a class that acts_as_global_object_replica
  # options[:global_object_version_sum]:: The sum of global_object_versions for the table in the library
  #
  # === Return
  # res(RightScale::OperationResult):: success or error
  def verify_replicas(options)
    options = RightScale::SerializationHelper.symbolize_keys(options)

    replica_class = options[:class_name].constantize
    checksum_type = options[:checksum_type]
    checksum_value = options[:checksum_value]

    success = query("wasabi_replicator_sink/verify_replicas for  #{replica_class.name}", nil, :email_errors => true) do
      if(replica_class.calculate_global_object_checksum(checksum_type) == checksum_value)
        RightScale::Log.info("GlobalObjectReplica: Verified #{replica_class.name} global_object_version_sum.")
        set_global_object_replication_status(replica_class.name, checksum_type, :completed => true)
      else
        RightScale::Log.info("GlobalObjectReplica: Verification of #{replica_class.name} global_object_version_sum failed.  Beginning synchronization.")
        set_global_object_replication_status(replica_class.name, checksum_type, :start => true)

        max_id = replica_class.max_id
        verify_next_replica_range(replica_class, checksum_type, max_id, 0, max_id)
      end
      true
    end

    set_global_object_replication_status(replica_class.name, checksum_type, :failed => true) unless success

    success ? success_result : error_result(@last_error)
  end

  # Updates rows using any recieved synchronization data and sends a library_replicator/verify_replica_range request for
  # the next range to process.
  #
  # === Parameters
  # options[:class_name]:: Name of a class that acts_as_global_object_replica
  # options[:has_more]:: Indicates at least one more range should be verified
  # options[:last_end_id]:: The greatest row id verified by the library so far.
  # options[:records_for_synchronization]:: A blank array (if the last verification check was positive) or an array
  #   of hashes to be used to update the replicated table.
  #   Each hash should contain the keys used in handle_global_object_change: :id, :schema_version, :global_object_version, :attrs
  # === Return
  # res(RightScale::OperationResult):: success or error
  def synchronize_replica_range(options)
    options = RightScale::SerializationHelper.symbolize_keys(options)

    replica_class = options[:class_name].constantize
    checksum_type = options[:checksum_type]
    max_id_at_start = options[:max_id_at_start]
    begin_id = options[:begin_id]
    end_id = options[:end_id]
    checksum_matched = options[:checksum_matched]
    records = options[:records_to_synchronize]
    has_more = options[:has_more]


    success = query("wasabi_replicator_sink/synchronize_replica_range for #{replica_class.name}", nil, :email_errors => true) do
      RightScale::Log.info("GlobalObjectReplica: Synchronizing #{replica_class.name} range #{begin_id}-#{end_id} (#{checksum_type} " +
                           "#{checksum_matched ? 'match' : 'mismatch'}) #{records.size} rows received.")
      records.each do |h|
        h = RightScale::SerializationHelper.symbolize_keys(h)
        replica_class.handle_global_object_change(h[:id], h[:schema_version], h[:global_object_version], h[:attrs])
      end

      in_sync = checksum_matched || !records.blank?

      if(has_more || !in_sync)
        set_global_object_replication_status(replica_class.name, checksum_type, :percent_complete => end_id / [max_id_at_start, 1].max) if in_sync

        next_begin_id, next_end_id = calculate_next_range_for_binary_sync(max_id_at_start, replica_class.will_replicate_initialization_chunk_size, begin_id, end_id, in_sync)
        verify_next_replica_range(replica_class, checksum_type, max_id_at_start, next_begin_id, next_end_id)
      else
        RightScale::Log.info("GlobalObjectReplica: Synchronization of #{replica_class.name} complete at row #{end_id}")
        set_global_object_replication_status(replica_class.name, checksum_type, :completed => true)
      end
      true
    end

    set_global_object_replication_status(replica_class.name, checksum_type, :failed => true) unless success

    success ? success_result : error_result(@last_error)
  end

  expose :handle_global_object_change, :verify_replicas, :synchronize_replica_range

  # Calculates the checksum for the next synchronization range to the library in a library_replicator/verify_replica_range request.
  # === Parameters
  # replica_class:: A class that acts_as_global_object_replica
  # checksum_type:: The type of checksum to perform, currently can be: 'global_object_version_sum'
  # max_id_at_start:: The max_id of the replica_class when we first started synchronization process
  # begin_id:: The first id in the checksum range (or nil for all rows)
  # end_id:: The last id in the checksum range (or nil for all rows)
  def verify_next_replica_range(replica_class, checksum_type, max_id_at_start, begin_id, end_id)
    send_push("/wasabi_replicator_source/verify_replica_range", {:class_name => replica_class.name,
      :schema_version => replica_class.will_replicate_current_schema_version,
      :checksum_type => checksum_type,
      :max_id_at_start => max_id_at_start,
      :begin_id => begin_id,
      :end_id => end_id,
      :send_records_on_checksum_mismatch => calc_size(begin_id, end_id) <= replica_class.will_replicate_initialization_chunk_size,
      :checksum_value => replica_class.calculate_global_object_checksum(checksum_type, begin_id, end_id),
      :from => @identity})
  end

  # Calculates the begin_id and end_id for the next range to compare given the current range & status.  Basically successive
  # calls to this method will result in a binary depth-first search finding out of sync ranges by using the following rules:
  #  1. If the current range is not in_sync, return the left half as the next range.
  #  2. If the current range is a left half (of some greater range) and it is in_sync, return the corresponding right half as the next range.
  #  3. If the current range is a right half and it is in_sync, move up until we are part of a left half, then return the corresponding right half as the next range.
  #
  # === Parameters
  # max_id:: The max when the search started.  This is needed so we can calculate the left/right halves consistently during the whole search.
  # min_size:: The minimum chunk size that is used to retrieve records.
  # last_begin_id:: The first id in the current checksum range
  # last_end_id:: The last id in the current checksum range
  # in_sync:: True if the current checksum range is synchronized, i.e. if we do not need to go deeper here.
  #
  # === Returns
  # The next range to search in the form [next_begin_id, next_end_id]
  def calculate_next_range_for_binary_sync(max_id, min_size, last_begin_id, last_end_id, in_sync)
    last_size, last_center = calc_size_and_center(last_begin_id, last_end_id)

    next_begin_id = nil
    next_end_id = nil

    if !in_sync
      if last_size <= min_size
        raise StandardError.new("Unexpected state: Not in sync, but last_size #{last_size} is less " +
          "then min_size #{min_size}.  This shouldn't happen because we should have recieved sync records " +
          "from the library an applied them.")
      else
        # Check the left half next (i.e. depth-first search)
        next_begin_id = last_begin_id
        next_end_id = last_center
      end
    else
      if last_end_id >= max_id
        # we're past the end, just do the next initialization chunk size
        next_begin_id = last_end_id + 1
        next_end_id = last_end_id + min_size
      else
        # We are in sync in the last range.  Figure out where we are in our depth first search and
        # check the next right branch
        cur_begin_id = 0
        cur_end_id = max_id
        cur_size, cur_center = calc_size_and_center(cur_begin_id, cur_end_id)

        while cur_size > last_size
          if last_center < cur_center
            # We are going to move down a left branch.  Save the corresponding right branch, if we
            # don't go down anymore lefts, this is the branch to sync next.
            next_begin_id = cur_center + 1
            next_end_id = cur_end_id

            cur_end_id = cur_center
          else
            cur_begin_id = cur_center + 1
          end

          cur_size, cur_center = calc_size_and_center(cur_begin_id, cur_end_id)
        end
      end
    end

    if next_begin_id.nil?  || next_end_id.nil?
      raise StandardError.new("Unexpected state: Nil result when caclulating next range for binary sync: max_id=#{max_id}, " +
        "min_size=#{min_size}, last_begin=#{last_begin_id}, last_end=#{last_end_id}, in_sync=#{in_sync}")
    end

    return next_begin_id, next_end_id
  end

  def calc_size(begin_id, end_id)
    end_id - begin_id + 1
  end

  def calc_size_and_center(begin_id, end_id)
    return calc_size(begin_id, end_id), ((begin_id + end_id) / 2)
  end

  def set_global_object_replication_status(class_name, checksum_type, options = {})
    begin
      status = GlobalObjectReplicationStatus.find_or_initialize_by_name(class_name)
      status.last_sync_at = Time.now
      status.last_sync_status = if options[:failed]
        status.last_sync_status = "failed" + status.last_sync_status.sub("in progress", "")
      elsif options[:completed]
        'completed'
      elsif options[:start]
        "in progress 0%"
      elsif options[:percent_complete] && options[:percent_complete] > 100
        "in progress unknown %"
      else
        "in progress #{options[:percent_complete]}%"
      end
      status.last_sync_checksum_type = checksum_type
      status.last_sync_start_at = Time.now if options[:start]
      status.save!
    rescue Exception => e
      RightScale::Log.error("Failed to update global object replication status", e, :trace)
    end
  end
end
