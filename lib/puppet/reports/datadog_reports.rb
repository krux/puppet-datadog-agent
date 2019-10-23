require 'puppet'
require 'yaml'
require 'json'
require 'open3'

begin
  require 'dogapi'
rescue LoadError => e
  Puppet.info "You need the `dogapi` gem to use the Datadog report (run puppet with puppet_run_reports on your master)"
end

def get_secret(secret_name, secret_backend_command)
  # Need to load the agent config to get the secret backend executable
  if ! secret_backend_command.nil?
    secret_payload = {
      "version": "1.0",
      "secrets": [secret_name]
    }.to_json
  else
    raise(Puppet::ParseError, "Datadog report API key is configured to use a secret but secret_backend_command not set in datadog.yaml")
  end

  stdout, stderr, status = Open3.capture3(secret_backend_command, stdin_data: secret_payload)
  secret_json = JSON.parse(stdout)

  # Return the returned secret
  secret_json[secret_name]['value']
end

Puppet::Reports.register_report(:datadog_reports) do

  configfile = "/etc/datadog-agent/datadog-reports.yaml"
  raise(Puppet::ParseError, "Datadog report config file #{configfile} not readable") unless File.readable?(configfile)
  config = YAML.load_file(configfile)

  # Add support for secrets management: https://docs.datadoghq.com/agent/guide/secrets-management/?tab=linux
  if config[:datadog_api_key] =~ /^ENC\[/
    # Secret management is enabled. Parse the secret name so we can look it up the way datadog agent does
    unless config[:secret_backend_command]
      raise(Puppet::ParseError, "Datadog report API key is configured to use a secret but secret_backend_command not set in datadog-reports.yaml")
    end

    secret_name = config[:datadog_api_key].gsub(/(^ENC\[|\]$)/, '')
    API_KEY = get_secret(secret_name, config[:secret_backend_command])
  else
    API_KEY = config[:datadog_api_key]
  end

  API_URL = config[:api_url]

  unless config[:check_environments].nil?
    if config[:check_environments].is_a? Array
      CHECK_ENVIRONMENTS = config[:check_environments]
    else
      raise(Puppet::ParseError, "Invalid parameter check_environments. Must be an Array. Got #{config[:check_environments].class} instead")
    end
  end

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
    end

    # Check for a running environment other than what is defined for check_environments in parameters
    if CHECK_ENVIRONMENTS
      if CHECK_ENVIRONMENTS.include?(@msg_environment) && @noop == false
        environment_check_status = 0
        environment_check_message = "#{@msg_host} is configured to use environment #{@msg_environment}"
      else
        environment_check_status = 2
        environment_check_message = "#{@msg_host} is using environment #{@msg_environment} rather than one of:\n#{CHECK_ENVIRONMENTS.join(', ')}"
      end
    else
      # Set to unknown status because we don't know if the environment is a valid one or not
      environment_check_status = 3
      environment_check_message = "Environment check not configured for #{@msg_host}. To enable, configure check_environments parameter"
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

    environment_tag = "puppet.environment:#{@msg_environment}"
    Puppet.debug "Tagging #{@msg_host} with '#{@environment_tag}'"
    @dog.add_tags(@msg_host, [environment_tag])

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
