# PassiveTotal

The PassiveTotal gem is (currently) a thin wrapper around PassiveTotal.org's Web-based API.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'passivetotal'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install passivetotal

## Command Line Tool

Included in the gem is a command-line tool, passivetotal, with the following usage:

	Usage: passivetotal [-h] [-v] [-k <apikey>] [[-m|-p|-c|-t|-e|-w] <ip or dom>] [[-s|-d] <dom>] [-x <ip>] [-l <ip or hash>] [-i <value>]
	-h                Help
	-v                Verbose output
	-k <apikey>       Sets the APIKEY, defaults to the environment variable PASSIVETOTAL_APIKEY
	ACTIONS (You have to select one, last one wins)  -m <ip or dom>  Queries metadata for given IP or domain
	  -p <ip or dom>  Queries passive DNS data for given IP or domain
	  -c <ip or dom>  Queries (or sets) the classification for a given IP or domain
	  -t <ip or dom>  Queries (adds or removes) the tags associated with a given IP or domain
	                  * To remove a tag, prepend a dash, '-' to the tag name when using the -i option
	  -e <ip or dom>  Queries (or sets) the ever compromised flag on a given IP or domain
	  -w <ip or dom>  Queries (or sets) the watched flag on a given IP or domain
	  -s <dom>        Queries the subdomains for a given domain
	  -d <dom>        Queries (or sets) if a domain is a dynamic DNS domain
	  -x <ip>         Queries (or sets) if a given IP is a sinkhole
	  -l <ip or hash> Queries for SSL Certificates/IP addresses associated with a given IP or SHA-1 hash
	SETTING VALUES  -i <value>      Sets the value, used in conjuntion with -c, -t, -e, -w, -d, or -x
	                  Valid values for -i depend on what it's used with:
	                  -c : targeted, crime, multiple, benign
	                  -t : <a tag name consisting of characters: [a-zA-Z_]>
	                  -e, -w, -d, -x: true, false

## Usage

    # Initialize the API wrapper with an apikey (using the default endpoint URL of https://api.passivetotal.org/v2/)
    pt = PassiveTotal::API.new(user, apikey)
    # Create an array to shove results into
    res = Array.new
    # query enrichment for the domain, www.passivetotal.org
    res << @pt.enrichment('www.passivetotal.org')
    # query enrichment for the ipv4 address, 107.170.89.121
    res << @pt.enrichment('107.170.89.121')
    # query passive DNS results for the domain, www.passivetotal.org
    res << @pt.passive('www.passivetotal.org')
    # query passive DNS results for the ipv4 address, 107.170.89.121
    res << @pt.passive('107.170.89.121')
    # query for subdomains of passivetotal.org
    #res << @pt.subdomains('passivetotal.org')
    # query for unique IPv4 resolutions of passivetotal.org
    res << @pt.unique('passivetotal.org')
    # query for the classification of www.passivetotal.org
    res << @pt.classification('www.passivetotal.org')
    # set the classification of www.passivetotal.org as benign
    res << @pt.classification('www.passivetotal.org', 'non-malicious')
    # query for the tags associated with www.chrisleephd.us
    res << @pt.tags('www.chrisleephd.us')
    # add the "cool" tag to www.chrisleephd.us
    res << @pt.add_tag('www.chrisleephd.us', 'cool')
    # remove the "cool" tag from www.chrisleephd.us (aww, I was cool for a few milliseconds :( )
    res << @pt.remove_tag('www.chrisleephd.us', 'cool')
    # query if 107.170.89.121 is a sinkhole
    res << @pt.sinkhole('107.170.89.121')
    # set 107.170.89.121 as not a sinkhole
    res << @pt.sinkhole('107.170.89.121', false)
    # query if www.passivetotal.org has ever been listed as compromised
    res << @pt.ever_compromised('www.passivetotal.org')
    # set the ever_compromised flag for www.passivetotal.org to false to indicate that it was never compromised or that it is in sole control of a malicious actor.
    res << @pt.ever_compromised('www.passivetotal.org', false)
    # check if www.passivetotal.org is a dynamic dns domain/host
    res << @pt.dynamic('www.passivetotal.org')
    # flag www.passivetotal.org as not a dynamic dns domain/host
    res << @pt.dynamic('www.passivetotal.org', false)
    # check if www.passivetotal.org is being watched
    res << @pt.monitor('www.passivetotal.org')
    # unwatch www.passivetotal.org
    res << @pt.monitor('www.passivetotal.org', false)
    # list sites associated with SSL certificates with SHA-1 hash of e9a6647d6aba52dc47b3838c920c9ee59bad7034
    res << @pt.ssl_certificate('e9a6647d6aba52dc47b3838c920c9ee59bad7034')
    # list sites associated with SSL certificates with SHA-1 hash of e9a6647d6aba52dc47b3838c920c9ee59bad7034
    res << @pt.ssl_certificate('2317683628587350290823564500811277499', 'serialNumber')
    # retrieve certificate history based on SHA-1 hash of e9a6647d6aba52dc47b3838c920c9ee59bad7034
    res << @pt.ssl_certificate_history('e9a6647d6aba52dc47b3838c920c9ee59bad7034')
    # retrieve certificate history from IPv4 address of 52.8.228.23
    res << @pt.ssl_certificate_history('52.8.228.23')
    # dump all this glorious information to feast your eyes upon
    pp res

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake test` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/chrislee35/passivetotal.


## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).

