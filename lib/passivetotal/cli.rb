require 'getoptlong'
require 'passivetotal/api'

module PassiveTotal # :nodoc:
  # Handles all the command-line parsing and dispatching queries to the PassiveTotal::API instance
  # CLInterface is aliased by CLI
	class CLInterface
    # parses the command line and yields an options hash
    # === Default Options
    # options = {
    #   :method => :usage,
    #   :query => nil,
    #   :set => nil,
    #   :debug => false,
    #   :apikey => ENV['PASSIVETOTAL_APIKEY']
    # }
    def self.parse_command_line(args)
      origARGV = ARGV.dup
      ARGV.replace(args)
      opts = GetoptLong.new(
      	[ '--help', '-h', GetoptLong::NO_ARGUMENT ],
      	[ '--debug', '-v', GetoptLong::NO_ARGUMENT ],
        [ '--username', '-u', GetoptLong::REQUIRED_ARGUMENT ],
        [ '--apikey', '-k', GetoptLong::REQUIRED_ARGUMENT ],
      	[ '--metadata', '-m', GetoptLong::REQUIRED_ARGUMENT ],
      	[ '--passive', '-p', GetoptLong::REQUIRED_ARGUMENT ],
      	[ '--subdomains', '-s', GetoptLong::REQUIRED_ARGUMENT ],
      	[ '--classification', '-c', GetoptLong::REQUIRED_ARGUMENT ],
      	[ '--tags', '-t', GetoptLong::REQUIRED_ARGUMENT ],
      	[ '--sinkhole', '-x', GetoptLong::REQUIRED_ARGUMENT ],
      	[ '--evercompromised', '-e', GetoptLong::REQUIRED_ARGUMENT ],
      	[ '--dynamic', '-d', GetoptLong::REQUIRED_ARGUMENT ],
      	[ '--watching', '-w', GetoptLong::REQUIRED_ARGUMENT ],
      	[ '--sslcertificate', '-l', GetoptLong::REQUIRED_ARGUMENT ],
        [ '--ssl_history', '-H', GetoptLong::REQUIRED_ARGUMENT ],
        [ '--trackers', '-T', GetoptLong::REQUIRED_ARGUMENT ],
        [ '--osint', '-o', GetoptLong::REQUIRED_ARGUMENT ],
        [ '--malware', '-M', GetoptLong::REQUIRED_ARGUMENT ],
        [ '--set', '-i', GetoptLong::REQUIRED_ARGUMENT ]
      )
      
      options = {
        :method => :usage,
        :query => nil,
        :set => nil,
        :debug => false,
        :apikey => ENV['PASSIVETOTAL_APIKEY'],
        :username => ENV['PASSIVETOTAL_USERNAME']
      }

      opts.each do |opt, arg|
        case opt
        when '--help'
          options[:method] = :usage
        when '--debug'
          options[:debug] = true
        when '--username'
          options[:username] = arg
        when '--apikey'
          options[:apikey] = arg
        when '--metadata'
          options[:method] = :metadata
          options[:query] = arg
        when '--passive'
          options[:method] = :passive
          options[:query] = arg
        when '--subdomains'
          options[:method] = :subdomains
          options[:query] = arg
        when '--classification'
          options[:method] = :classification
          options[:query] = arg
        when '--tags'
          options[:method] = :tags
          options[:query] = arg
        when '--sinkhole'
          options[:method] = :sinkhole
          options[:query] = arg
        when '--evercompromised'
          options[:method] = :ever_compromised
          options[:query] = arg
        when '--dynamic'
          options[:method] = :dynamic
          options[:query] = arg
        when '--watching'
          options[:method] = :watching
          options[:query] = arg
        when '--sslcertificate'
          options[:method] = :ssl_certificate
          options[:query] = arg
        when '--ssl_history'
          options[:method] = :ssl_certificate_history
          options[:query] = arg
        when '--trackers'
          options[:method] = :trackers
          options[:query] = arg
        when '--osint'
          options[:method] = :osint
          options[:query] = arg
        when '--malware'
          options[:method] = :malware
          options[:query] = arg
        when '--set'
          options[:set] = arg.dup
        else
          options[:method] = :usage
        end
      end
      
      if options[:method] == :tags and options[:set]
        if options[:set] =~ /^\-/
          options[:set].gsub!(/^\-/,'')
          options[:method] = :remove_tag
        else
          options[:method] = :add_tag
        end
      end
      args = ARGV.dup
      ARGV.replace(origARGV)

      if options[:debug]
        $stderr.puts "PassiveTotal CLI Options"
        $stderr.puts "  username: #{options[:username]}"
        $stderr.puts "    apikey: #{options[:apikey]}"
        $stderr.puts "     debug: #{options[:debug]}"
        $stderr.puts "    method: #{options[:method]}"
        $stderr.puts "     query: #{options[:query]}"
        $stderr.puts "       set: #{options[:set]}"
      end
      
      return options
    end
    
    # returns a string containing the usage information
    def self.usage
      help_text = "Usage: #{$0} [-v] [-u <username>] [-k <apikey>] <action flag> <query> [-i <value>]\n"
      help_text << "-h                Help\n"
      help_text << "-v                Verbose output\n"
      help_text << "-u <username>     Sets the Username, defaults to the environment variable PASSIVETOTAL_USERNAME\n"
      help_text << "-k <apikey>       Sets the APIKEY, defaults to the environment variable PASSIVETOTAL_APIKEY\n"
      help_text << "ACTIONS (You have to select one, last one wins)"
      help_text << "  -m <ip or dom>  Queries metadata for given IP or domain\n"
      help_text << "  -p <ip or dom>  Queries passive DNS data for given IP or domain\n"
      help_text << "  -c <ip or dom>  Queries (or sets) the classification for a given IP or domain\n"
      help_text << "  -t <ip or dom>  Queries (adds or removes) the tags associated with a given IP or domain\n"
      help_text << "                  * To remove a tag, prepend a dash, '-' to the tag name when using the -i option\n"
      help_text << "  -e <ip or dom>  Queries (or sets) the ever compromised flag on a given IP or domain\n"
      help_text << "  -w <ip or dom>  Queries (or sets) the watched flag on a given IP or domain\n"
      help_text << "  -s <dom>        Queries the subdomains for a given domain\n"
      help_text << "  -d <dom>        Queries (or sets) if a domain is a dynamic DNS domain\n"
      help_text << "  -x <ip>         Queries (or sets) if a given IP is a sinkhole\n"
      help_text << "  -l <hash> Queries for SSL certificates/IP addresses associated with a given SHA-1 hash\n"
      help_text << "  -H <ip or hash> Queries for SSL certificate history associated with a given IP or SHA-1 hash\n"
      help_text << "  -T <ip or dom>  Queries for Tracker information associated with a given IP or domain\n"
      help_text << "  -o <ip or dom>  Queries for OSINT on a given IP or domain\n"
      help_text << "  -M <ip or dom>  Queries for Malware sample records for a given IP or domain\n"
      help_text << "SETTING VALUES"
      help_text << "  -i <value>      Sets the value, used in conjuntion with -c, -t, -e, -w, -d, or -x\n"
      help_text << "                  Valid values for -i depend on what it's used with:\n"
      help_text << "                  -c : malicious, non-malicious, suspicious, unknown\n"
      help_text << "                  -t : <a tag name consisting of characters: [a-zA-Z_]>\n"
      help_text << "                  -e, -w, -d, -x: true, false\n"
      help_text
    end
    
    # main method, takes command-line arguments and performs the desired queries and outputs
    def self.run(args)
      options = parse_command_line(args)
      return usage() if options[:method] == :usage
      pt = PassiveTotal::API.new(options[:username], options[:apikey])
      if pt.respond_to?(options[:method])
        if options[:set]
          data = pt.send(options[:method], options[:query], options[:set])
        else
          data = pt.send(options[:method], options[:query])
        end
        data.response.results['response_time'] = data.response_time
        return JSON.pretty_generate(data.response.results)
      end
      return ''
    end
  end
  # Alias for the CLInterface class
  CLI = PassiveTotal::CLInterface
end
