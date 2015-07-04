require 'test_helper'
require 'pp'

class PassivetotalTest < Minitest::Test
  def setup
    if ENV['PASSIVETOTAL_APIKEY']
      apikey = ENV['PASSIVETOTAL_APIKEY']
    else
      print "Enter PassiveTotal APIKEY: "
      $stdout.flush
      apikey = $stdin.gets.chomp
    end
    @pt = PassiveTotal::API.new(apikey)
  end
  
  def test_that_it_has_a_version_number
    refute_nil ::PassiveTotal::VERSION
  end
  
  def test_errors
    assert_raises(ArgumentError) do
      res = @pt.metadata(nil)
    end
    assert_raises(ArgumentError) do
      res = @pt.metadata("test")
    end
    assert_raises(ArgumentError) do
      res = @pt.metadata("1.2.3.4.5")
    end
    assert_raises(ArgumentError) do
      res = @pt.add_tag("www.chrisleephd.us", "_test")
    end
    assert_raises(ArgumentError) do
      res = @pt.metadata("e9a6647d6aba52dc47b3838c920c9ee59bad7034")
    end
    assert_raises(ArgumentError) do
      res = @pt.ssl_certificate("x9a6647d6aba52dc47b3838c920c9ee59bad7034")
    end
    assert_raises(ArgumentError) do
      res = @pt.ssl_certificate("0e9a6647d6aba52dc47b3838c920c9ee59bad7034")
    end
    assert_raises(ArgumentError) do
      pt = PassiveTotal::API.new("apikey")
    end
    pt = PassiveTotal::API.new("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
    data = pt.metadata('www.passivetotal.org')
    assert_equal(false, data.response.success)
    assert_equal("API key is invalid", data.response.error)
  end

  def test_metadata
    res = @pt.metadata('www.passivetotal.org')
    assert_equal(true, res.response.success)
  end
  
  def test_passive
    res = @pt.passive('www.passivetotal.org')
    assert_equal(true, res.response.success)
    res = @pt.passive('107.170.89.121')
    assert_equal(true, res.response.success)
  end
  
  def test_subdomains
    res = @pt.subdomains('passivetotal.org')
    assert_equal(true, res.response.success)
  end
  
  def test_unique
    res = @pt.unique('passivetotal.org')
    assert_equal(true, res.response.success)
  end
  
  def test_classification
    res = @pt.classification('www.passivetotal.org')
    assert_equal(true, res.response.success)
    res = @pt.classification('www.passivetotal.org', 'benign')
    assert_equal(true, res.response.success)    
  end
  
  def test_tags
    res = @pt.tags('www.chrisleephd.us')
    assert_equal(true, res.response.success)
    assert_equal([], res.response.results['tags'])
    res = @pt.add_tag('www.chrisleephd.us', 'cool')
    assert_equal(true, res.response.success)
    res = @pt.tags('www.chrisleephd.us')
    assert_equal(['cool'], res.response.results['tags'])
    res = @pt.remove_tag('www.chrisleephd.us', 'cool')
    assert_equal(true, res.response.success)
    res = @pt.tags('www.chrisleephd.us')
    assert_equal(true, res.response.success)    
    assert_equal([], res.response.results['tags'])    
  end
  
  def test_sinkhole
    res = @pt.sinkhole('107.170.89.121')
    assert_equal(true, res.response.success)
    assert_equal(false, res.response.results['sinkhole'])
    res = @pt.sinkhole('107.170.89.121', false)
    assert_equal(true, res.response.success)
    res = @pt.sinkhole('107.170.89.121')
    assert_equal(true, res.response.success)
    assert_equal(false, res.response.results['sinkhole'])
  end
  
  def test_ever_compromised
    res = @pt.ever_compromised('www.passivetotal.org')
    assert_equal(true, res.response.success)
    assert_equal(false, res.response.results['ever_compromised'])
    res = @pt.ever_compromised('www.passivetotal.org', false)
    assert_equal(true, res.response.success)
    res = @pt.ever_compromised('www.passivetotal.org')
    assert_equal(true, res.response.success)
    assert_equal(false, res.response.results['ever_compromised'])
  end
  
  def test_dynamic
    res = @pt.dynamic('www.passivetotal.org')
    assert_equal(true, res.response.success)
    assert_equal(false, res.response.results['dynamic'])
    res = @pt.dynamic('www.passivetotal.org', false)
    assert_equal(true, res.response.success)
    res = @pt.dynamic('www.passivetotal.org')
    assert_equal(true, res.response.success)
    assert_equal(false, res.response.results['dynamic'])
  end
  
  def test_watching
    res = @pt.watching('www.passivetotal.org')
    assert_equal(true, res.response.success)
    assert_equal(false, res.response.results['watching'])
    res = @pt.watching('www.passivetotal.org', false)
    assert_equal(true, res.response.success)
    res = @pt.watching('www.passivetotal.org')
    assert_equal(true, res.response.success)
    assert_equal(false, res.response.results['watching'])
  end
  
  def test_ssl
    res = @pt.ssl_certificate('104.131.121.205')
    assert_equal(true, res.response.success)
    res = @pt.ssl_certificate('e9a6647d6aba52dc47b3838c920c9ee59bad7034')
    assert_equal(true, res.response.success)
  end
  
  def test_example
    return
    apikey = ENV['PASSIVETOTAL_APIKEY']
    # EXAMPLE STARTS HERE
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
    # EXAMPLE ENDS HERE
  end
  
end
