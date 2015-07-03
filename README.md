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

## Usage

    # Initialize the API wrapper with an apikey (using the default endpoint URL of https://www.passivetotal.org/api/v1/)
    pt = PassiveTotal::API.new(apikey)
    # Create an array to shove results into
    res = []
    # query metadata for the domain, www.passivetotal.org
    res << @pt.metadata('www.passivetotal.org')
    # query metadata for the ipv4 address, 107.170.89.121
    res << @pt.metadata('107.170.89.121')
    # query passive DNS results for the domain, www.passivetotal.org
    res << @pt.passive('www.passivetotal.org')
    # query passive DNS results for the ipv4 address, 107.170.89.121
    res << @pt.passive('107.170.89.121')
    # query for subdomains of passivetotal.org
    res << @pt.subdomains('passivetotal.org')
    # query for unique IPv4 resolutions of passivetotal.org
    res << @pt.unique('passivetotal.org')
    # query for the classification of www.passivetotal.org
    res << @pt.classification('www.passivetotal.org')
    # set the classification of www.passivetotal.org as benign
    res << @pt.classification('www.passivetotal.org', 'benign')
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
    res << @pt.watching('www.passivetotal.org')
    # unwatch www.passivetotal.org
    res << @pt.watching('www.passivetotal.org', false)
    # list SSL certificates associated with IPV4 address 104.131.121.205
    res << @pt.ssl_certificate('104.131.121.205')
    # list sites associated with SSL certificates with SHA-1 hash of e9a6647d6aba52dc47b3838c920c9ee59bad7034
    res << @pt.ssl_certificate('e9a6647d6aba52dc47b3838c920c9ee59bad7034')
    # dump all this glorious information to feast your eyes upon
    pp res

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake test` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/chrislee35/passivetotal.


## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).

