require 'puppet'
require 'yaml'

begin
  require 'dogapi'
rescue LoadError => e
  Puppet.info "You need the `dogapi` gem to use the Datadog report (run puppet with puppet_run_reports on your master)"
end

Puppet::Reports.register_report(:datadog_reports) do

  configfile = "/etc/datadog-agent/datadog-reports.yaml"
  raise(Puppet::ParseError, "Datadog report config file #{configfile} not readable") unless File.readable?(configfile)
  config = YAML.load_file(configfile)
  API_KEY = config[:datadog_api_key]
  API_URL = config[:api_url]

  # if need be initialize the regex
  if !config[:hostname_extraction_regex].nil?
    begin
      HOSTNAME_EXTRACTION_REGEX = Regexp.new config[:hostname_extraction_regex]
    rescue
      raise(Puppet::ParseError, "Invalid hostname_extraction_regex #{HOSTNAME_REGEX}")
    end
  else
    HOSTNAME_EXTRACTION_REGEX = nil
  end

  desc <<-DESC
  Send notification of metrics to Datadog
  DESC

  def pluralize(number, noun)
    begin
      if number == 0 then
        "no #{noun}"
      elsif number < 1 then
        "less than 1 #{noun}"
      elsif number == 1 then
        "1 #{noun}"
      else
        "#{number.round} #{noun}s"
      end
    rescue
      "#{number} #{noun}(s)"
    end
  end


  def process
    @summary = self.summary
    @msg_host = self.host
    unless HOSTNAME_EXTRACTION_REGEX.nil?
      m = @msg_host.match(HOSTNAME_EXTRACTION_REGEX)
      if !m.nil? && !m[:hostname].nil?
        @msg_host = m[:hostname]
      end
    end
    @msg_environment = self.environment
    @noop = self.noop

    event_title = ''
    alert_type = ''
    event_priority = 'low'
    event_data = ''

    if defined?(self.status)
      # for puppet log format 2 and above
      @status = self.status
      if @status == 'failed'
        event_title = "Puppet failed on #{@msg_host}"
        alert_type = "error"
        event_priority = "normal"
        check_status = 2
      elsif @status == 'changed'
        event_title = "Puppet changed resources on #{@msg_host}"
        alert_type = "success"
        event_priority = "normal"
        check_status = 0
      elsif @status == "unchanged"
        event_title = "Puppet ran on, and left #{@msg_host} unchanged"
        alert_type = "success"
        check_status = 0
      else
        event_title = "Puppet ran on #{@msg_host}"
        alert_type = "success"
        check_status = 0
      end

    else
      # for puppet log format 1
      event_title = "Puppet ran on #{@msg_host}"
    end

    # Extract statuses
    total_resource_count = self.resource_statuses.length
    changed_resources    = self.resource_statuses.values.find_all {|s| s.changed }
    failed_resources     = self.resource_statuses.values.find_all {|s| s.failed }

    # Little insert if we know the config
    config_version_blurb = if defined?(self.configuration_version) then "applied version #{self.configuration_version} and" else "" end

    event_data << "Puppet #{config_version_blurb} changed #{pluralize(changed_resources.length, 'resource')} out of #{total_resource_count}."

    # List changed resources
    if changed_resources.length > 0
      event_data << "\nThe resources that changed are:\n@@@\n"
      changed_resources.each {|s| event_data << "#{s.title} in #{s.file}:#{s.line}\n" }
      event_data << "\n@@@\n"
    end

    # List failed resources
    if failed_resources.length > 0
      event_data << "\nThe resources that failed are:\n@@@\n"
      failed_resources.each {|s| event_data << "#{s.title} in #{s.file}:#{s.line}\n" }
      event_data << "\n@@@\n"
      check_status = 2
    else
      check_status = 0
    end

    # Check for a running environment other than production when not running in noop mode
    if @msg_environment != 'production' && @noop == false
      environment_check_status = 2
      environment_check_message = "#{@msg_host} is configured to use environment #{@msg_environment} rather than production"
    else
      environment_check_status = 0
      environment_check_message = "#{@msg_host} is configured to use environment production"
    end

    Puppet.debug "Sending metrics for #{@msg_host} to Datadog"
    @dog = Dogapi::Client.new(API_KEY, nil, nil, nil, nil, nil, API_URL)
    @dog.batch_metrics do
      self.metrics.each { |metric,data|
        data.values.each { |val|
          name = "puppet.#{val[1].gsub(/ /, '_')}.#{metric}".downcase
          value = val[2]
          @dog.emit_point("#{name}", value, :host => "#{@msg_host}")
        }
      }
    end

    Puppet.debug "Sending events for #{@msg_host} to Datadog"
    @dog.emit_event(Dogapi::Event.new(event_data,
                                      :msg_title => event_title,
                                      :event_type => 'config_management.run',
                                      :event_object => @msg_host,
                                      :alert_type => alert_type,
                                      :priority => event_priority,
                                      :source_type_name => 'puppet'
                                      ), :host => @msg_host)

    Puppet.debug "Sending puppet.status service check for #{@msg_host} to Datadog"
    @dog.service_check('puppet.status', @msg_host, check_status, message: event_data)

    Puppet.debug "Sending puppet.environment service check for #{@msg_host} to Datadog"
    @dog.service_check('puppet.environment', @msg_host, environment_check_status, message: environment_check_message)
  end
end
