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
    if ENV['PASSIVETOTAL_USERNAME']
      username = ENV['PASSIVETOTAL_USERNAME']
    else
      print "Enter PassiveTotal Username: "
      $stdout.flush
      username = $stdin.gets.chomp
    end
    @pt = PassiveTotal::API.new(username, apikey)
  end
  
  def test_that_it_has_a_version_number
    refute_nil ::PassiveTotal::VERSION
  end
  
  def test_invalid_apikey
    assert_raises(ArgumentError) do
      res = PassiveTotal::API.new("bad_apikey", "jhgoioiug")
    end
    pt = PassiveTotal::API.new("bad_username", "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2")
    tran = pt.account
    assert_equal({"message"=>"invalid credentials"}, tran.response.results)
    refute(tran.response.success)
  end    
  
  def field_tester(res, fields)
    fields.each do |field|
      assert(res.has_key?(field), "data structure lacks field, #{field} : #{Kernel.caller[2]}")
    end
  end
  
  def test_account
    tran = @pt.account
    res = tran.response.results
    field_tester(res, ['username', 'firstName', 'lastName', 'lastActive', 'firstActive', 'organization'])
  end
  
  def test_account_history
    tran = @pt.account_history
    res = tran.response.results
    field_tester(res, ['history'])
    res['history'].each do |rec|
      rec['additional'] ||= {} # to fix entries before 2015-06-21
      field_tester(rec, ['username','additional','focus','source','context','dt','type'])
    end
  end
  
  def test_account_organization
    assert_raises(PassiveTotal::APIUsageError) do
      tran = @pt.account_organization
      res = tran.response.results
      unless res == {}
        field_tester(res, ['activeMembers', 'status', 'name', 'lastActive', 'acceptableDomains', 'searchQuota', 'registered','watchQuota'])
        raise PassiveTotal::APIUsageError('this is working, I just need to throw an exception to make the test pass')
      end
    end
  end
  
  def test_account_organization_teamstream
    tran = @pt.account_organization_teamstream
    res = tran.response.results
    answer = {"message"=>
  "no organization found associated with this account. You have requested this URI [/v2/account/organization/teamstream] but did you mean /v2/account/organization/teamstream or /v2/account/organization ?"}
    assert_equal(answer, res)
  end
  
  def test_account_sources  
    tran = @pt.account_sources('riskiq')
    res = tran.response.results
    field_tester(res, ['sources'])
    res['sources'].each do |rec|
      field_tester(rec, ['active', 'source', 'configuration'])
    end
  end
  
  def test_passive
    tran = @pt.passive('www.passivetotal.org')
    res = tran.response.results
    field_tester(res, ['totalRecords', 'queryValue', 'lastSeen', 'pager', 'results'])
    res['results'].each do |rec|
      field_tester(rec, ['recordHash','resolve','value','source','lastSeen','collected','firstSeen'])
    end
    tran = @pt.passive('107.170.89.121')
    res = tran.response.results
    field_tester(res, ['totalRecords', 'queryValue', 'lastSeen', 'pager', 'results'])
    res['results'].each do |rec|
      field_tester(rec, ['recordHash','resolve','value','source','lastSeen','collected','firstSeen'])
    end
  end
  
  def test_unique
    tran = @pt.unique('passivetotal.org')
    res = tran.response.results
    pp res
    field_tester(res, ['queryType', 'queryValue', 'total', 'pager', 'results', 'frequency'])
    res['results'].each do |ip|
      assert_match(/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/, ip, "failed IPv4 regular expression")
    end
    res['frequency'].each do |ip, count|
      assert_match(/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/, ip, "failed IPv4 regular expression")
      assert_instance_of(Integer, count)
    end
  end
  
  def test_enrichment
    tran = @pt.enrichment('www.passivetotal.org')
    res = tran.response.results
    field_tester(res, ['primaryDomain', 'tags', 'dynamicDns', 'queryValue', 'subdomains', 'tld', 'everCompromised','queryType'])
    tran = @pt.enrichment('52.8.228.23')
    res = tran.response.results
    field_tester(res, ['network', 'autonomousSystemName', 'tags', 'country', 'sinkhole', 'latitude', 'longitude', 'everCompromised', 'queryType', 'autonomousSystemNumber'])
    assert_raises(ArgumentError) do
     res = @pt.enrichment(nil, nil)
    end
    assert_raises(ArgumentError) do
     res = @pt.enrichment("test")
    end
    assert_raises(ArgumentError) do
     res = @pt.enrichment("1.2.3.4.5")
    end
    assert_raises(ArgumentError) do
     res = @pt.enrichment("e9a6647d6aba52dc47b3838c920c9ee59bad7034")
    end
  end
  
  def test_bulk_enrichment
    tran = @pt.bulk_enrichment(['www.passivetotal.org','52.8.228.23'])
    res = tran.response.results
    field_tester(res, ['results'])
    field_tester(res['results'], ['www.passivetotal.org','52.8.228.23'])
    field_tester(res['results']['www.passivetotal.org'], ['primaryDomain', 'tags', 'dynamicDns', 'queryValue', 'subdomains', 'tld', 'everCompromised','queryType'])
    field_tester(res['results']['52.8.228.23'], ['network', 'autonomousSystemName', 'tags', 'country', 'sinkhole', 'latitude', 'longitude', 'everCompromised', 'queryType', 'autonomousSystemNumber'])
  end
  
  def test_osint
    res = @pt.osint("xxxmobiletubez.com").response.results
    field_tester(res, ['results'])
    res['results'].each do |rec|
      field_tester(rec, ['source', 'sourceUrl', 'inReport', 'tags'])
    end
  end
  
  def test_bulk_osint
    res = @pt.bulk_osint(["passivetotal.org", "xxxmobiletubez.com"]).response.results
    field_tester(res, ['results'])
    field_tester(res['results'], ["passivetotal.org", "xxxmobiletubez.com"])
    assert_equal(res['results']['passivetotal.org']['results'], [])
    res['results']['xxxmobiletubez.com']['results'].each do |rec|
      field_tester(rec, ['source', 'source_url', 'tags'])
    end
  end
  
  def test_whois
    res = @pt.whois("passivetotal.org").response.results
    field_tester(res, ['contactEmail','domain','billing','zone','nameServers','registered',
      'lastLoadedAt','whoisServer','registryUpdatedAt','expiresAt','registrar','admin','tech','registrant'])
    field_tester(res['admin'], ['city','name','country','telephone','state','street','postalCode','organization','email'])
    field_tester(res['tech'], ['city','name','country','telephone','state','street','postalCode','organization','email'])
    field_tester(res['registrant'], ['city','name','country','telephone','state','street','postalCode','organization','email'])
    #field_tester(res['billing'], ['city','name','country','telephone','state','street','postalCode','organization','email'])
    res = @pt.whois("proxy4655031@1and1-private-registration.com", "email").response.results
    field_tester(res, ['results'])
    res['results'].each do |rec|
      field_tester(rec, ['contactEmail','domain','billing','zone','nameServers','registered',
        'lastLoadedAt','whoisServer','registryUpdatedAt','expiresAt','registrar','admin','tech','registrant'])
      field_tester(rec['admin'], ['city','name','country','telephone','state','street','postalCode','organization','email'])
      field_tester(rec['tech'], ['city','name','country','telephone','state','street','postalCode','organization','email'])
      field_tester(rec['registrant'], ['city','name','country','telephone','state','street','postalCode','organization','email'])
      #field_tester(res['billing'], ['city','name','country','telephone','state','street','postalCode','organization','email'])
    end
  end
  
  def test_subdomains
    res = @pt.subdomains("*.passivetotal.org").response.results
    field_tester(res, ['queryValue', 'subdomains'])
  end
  
  def test_malware
    res = @pt.malware("noorno.com").response.results
    field_tester(res, ['results'])
    res['results'].each do |rec|
      field_tester(rec, ['source', 'sourceUrl', 'sample', 'collectionDate'])
    end
    res = @pt.malware("98.124.243.47").response.results
    field_tester(res, ['results'])
    res['results'].each do |rec|
      field_tester(rec, ['source', 'sourceUrl', 'sample', 'collectionDate'])
    end
  end
  
  def test_bulk_malware
    res = @pt.bulk_malware(["passivetotal.org", "xxxvideotube.org"]).response.results
    field_tester(res, ['results'])
    field_tester(res['results'], ["passivetotal.org", "xxxvideotube.org"])
    field_tester(res['results']['passivetotal.org'], ['results'])
    assert_equal(res['results']['passivetotal.org']['results'], [])
    field_tester(res['results']['xxxvideotube.org'], ['results'])
    res['results']['xxxvideotube.org']['results'].each do |rec|
      field_tester(rec, ['source', 'sourceUrl', 'sample', 'collectionDate'])
    end
  end
  
  def test_classification
    tran = @pt.classification('www.passivetotal.org')
    res = tran.response.results
    field_tester(res, ['classification'])
    tran = @pt.classification('www.passivetotal.org', 'non-malicious')
    res = tran.response.results
    assert_equal({"classification"=>"non_malicious"}, res)
  end
  
  def test_bulk_classification
    tran = @pt.bulk_classification(["passivetotal.org", "www.passivetotal.org"])
    res = tran.response.results
    field_tester(res, ['results'])
    field_tester(res['results'], ["passivetotal.org", "www.passivetotal.org"])
    field_tester(res['results']["passivetotal.org"], ['classification'])
    field_tester(res['results']["www.passivetotal.org"], ['classification'])
    assert_equal('non_malicious', res['results']["passivetotal.org"]['classification'])
  end  
    
  def test_tags
    #flunk("the API is returning a scalar instead of a list of tags...")
    res = @pt.remove_tag('www.chrisleephd.us', 'cool').response.results
    res = @pt.tags('www.chrisleephd.us').response.results
    field_tester(res, ['tags'])
    assert_equal(["registered"], res['tags'])
    @pt.add_tag('www.chrisleephd.us', 'cool')
    res = @pt.tags('www.chrisleephd.us').response.results
    field_tester(res, ['tags'])
    assert_equal(['cool', "registered"], res['tags'])
    res = @pt.remove_tag('www.chrisleephd.us', 'cool').response.results
    res = @pt.tags('www.chrisleephd.us').response.results
    field_tester(res, ['tags'])
    assert_equal(["registered"], res['tags'])
    assert_raises(ArgumentError) do
      res = @pt.add_tag("www.chrisleephd.us", "_test")
    end
  end
  
  def test_sinkhole
    res = @pt.sinkhole('107.170.89.121').response.results
    field_tester(res, ['sinkhole'])
    assert_equal(false, res['sinkhole'])
    res = @pt.sinkhole('107.170.89.121', true).response.results
    field_tester(res, ['sinkhole'])
    assert_equal(true, res['sinkhole'])
    res = @pt.sinkhole('107.170.89.121').response.results
    field_tester(res, ['sinkhole'])
    assert_equal(true, res['sinkhole'])
    res = @pt.sinkhole('107.170.89.121', false).response.results
    field_tester(res, ['sinkhole'])
    assert_equal(false, res['sinkhole'])
    res = @pt.sinkhole('107.170.89.121').response.results
    field_tester(res, ['sinkhole'])
    assert_equal(false, res['sinkhole'])
  end
  
  def test_ever_compromised
    #flunk("the API won't let me set the ever-compromised flag")
    res = @pt.ever_compromised('107.170.89.121').response.results
    field_tester(res, ['everCompromised'])
    assert_equal(false, res['everCompromised'])
    res = @pt.ever_compromised('107.170.89.121', true).response.results
    field_tester(res, ['everCompromised'])
    assert_equal(true, res['everCompromised'])
    res = @pt.ever_compromised('107.170.89.121').response.results
    field_tester(res, ['everCompromised'])
    assert_equal(true, res['everCompromised'])
    res = @pt.ever_compromised('107.170.89.121', false).response.results
    field_tester(res, ['everCompromised'])
    assert_equal(false, res['everCompromised'])
    res = @pt.ever_compromised('107.170.89.121').response.results
    field_tester(res, ['everCompromised'])
    assert_equal(false, res['everCompromised'])
  end
  
  def test_dynamic
    res = @pt.dynamic('www.passivetotal.org').response.results
    field_tester(res, ['dynamicDns'])
    assert_equal(false, res['dynamicDns'])
    res = @pt.dynamic('www.passivetotal.org', true).response.results
    field_tester(res, ['dynamicDns'])
    assert_equal(true, res['dynamicDns'])
    res = @pt.dynamic('www.passivetotal.org').response.results
    field_tester(res, ['dynamicDns'])
    assert_equal(true, res['dynamicDns'])
    res = @pt.dynamic('www.passivetotal.org', false).response.results
    field_tester(res, ['dynamicDns'])
    assert_equal(false, res['dynamicDns'])
    res = @pt.dynamic('www.passivetotal.org').response.results
    field_tester(res, ['dynamicDns'])
    assert_equal(false, res['dynamicDns'])
  end
  
  def test_monitoring
    res = @pt.monitor('www.passivetotal.org').response.results
    field_tester(res, ['monitor'])
    assert_equal(false, res['monitor'])
  end
  
  def test_boolean_error
    res = @pt.ever_compromised('107.170.89.121').response.results
    refute(res['everCompromised'])
    res = @pt.ever_compromised('107.170.89.121', true).response.results
    assert(res['everCompromised'])
    res = @pt.ever_compromised('107.170.89.121').response.results
    assert(res['everCompromised'])
    res = @pt.ever_compromised('107.170.89.121', "true").response.results
    assert_nil(res['everCompromised'])
    res = @pt.ever_compromised('107.170.89.121').response.results
    assert(res['everCompromised'])
    res = @pt.ever_compromised('107.170.89.121', false).response.results
    refute(res['everCompromised'])
    res = @pt.ever_compromised('107.170.89.121').response.results
    refute(res['everCompromised'])
    res = @pt.ever_compromised('107.170.89.121', "false").response.results
    assert_nil(res['everCompromised'])
    res = @pt.ever_compromised('107.170.89.121').response.results
    refute(res['everCompromised'])
  end
  
  def test_ssl_by_serial
    api_example = {"serialNumber"=>"2317683628587350290823564500811277499",
     "issuerStreetAddress"=>nil,
     "subjectOrganizationUnitName"=>nil,
     "subjectOrganizationName"=>nil,
     "subjectSerialNumber"=>nil,
     "subjectEmailAddress"=>nil,
     "expirationDate"=>"Apr 27 23:59:59 2017 GMT",
     "fingerprint"=>"e9:a6:64:7d:6a:ba:52:dc:47:b3:83:8c:92:0c:9e:e5:9b:ad:70:34",
     "issuerSerialNumber"=>nil,
     "issuerLocalityName"=>nil,
     "issuerGivenName"=>nil,
     "issuerOrganizationName"=>"thawte, inc.",
     "issuerCountry"=>"us",
     "subjectCommonName"=>"www.passivetotal.org",
     "sha1"=>"e9a6647d6aba52dc47b3838c920c9ee59bad7034",
     "sslVersion"=>"2",
     "subjectSurname"=>nil,
     "subjectStateOrProvinceName"=>nil,
     "subjectCountry"=>nil,
     "issuerSurname"=>nil,
     "subjectGivenName"=>nil,
     "issuerProvince"=>nil,
     "issuerOrganizationUnitName"=>"domain validated ssl",
     "subjectProvince"=>nil,
     "subjectLocalityName"=>nil,
     "subjectStreetAddress"=>nil,
     "issuerStateOrProvinceName"=>nil,
     "issuerCommonName"=>"thawte dv ssl ca - g2",
     "issueDate"=>"Apr 28 00:00:00 2015 GMT",
     "issuerEmailAddress"=>nil}
    fields = api_example.keys
    tran = @pt.ssl_certificate('2317683628587350290823564500811277499', 'serialNumber')
    res = tran.response.results

    field_tester(res, ['results'])
    res['results'].each do |rec|
      field_tester(rec, fields)
    end
  end
  
  def test_ssl_by_hash
    api_example = {"serialNumber"=>"2317683628587350290823564500811277499",
     "issuerStreetAddress"=>nil,
     "subjectOrganizationUnitName"=>nil,
     "subjectOrganizationName"=>nil,
     "subjectSerialNumber"=>nil,
     "subjectEmailAddress"=>nil,
     "expirationDate"=>"Apr 27 23:59:59 2017 GMT",
     "fingerprint"=>"e9:a6:64:7d:6a:ba:52:dc:47:b3:83:8c:92:0c:9e:e5:9b:ad:70:34",
     "issuerSerialNumber"=>nil,
     "issuerLocalityName"=>nil,
     "issuerGivenName"=>nil,
     "issuerOrganizationName"=>"thawte, inc.",
     "issuerCountry"=>"us",
     "subjectCommonName"=>"www.passivetotal.org",
     "sha1"=>"e9a6647d6aba52dc47b3838c920c9ee59bad7034",
     "sslVersion"=>"2",
     "subjectSurname"=>nil,
     "subjectStateOrProvinceName"=>nil,
     "subjectCountry"=>nil,
     "issuerSurname"=>nil,
     "subjectGivenName"=>nil,
     "issuerProvince"=>nil,
     "issuerOrganizationUnitName"=>"domain validated ssl",
     "subjectProvince"=>nil,
     "subjectLocalityName"=>nil,
     "subjectStreetAddress"=>nil,
     "issuerStateOrProvinceName"=>nil,
     "issuerCommonName"=>"thawte dv ssl ca - g2",
     "issueDate"=>"Apr 28 00:00:00 2015 GMT",
     "issuerEmailAddress"=>nil}
    fields = api_example.keys

    res = @pt.ssl_certificate('e9a6647d6aba52dc47b3838c920c9ee59bad7034').response.results
    res['results'].each do |r|
      field_tester(r, fields)
    end
    assert_raises(ArgumentError) do
      res = @pt.ssl_certificate("x9a6647d6aba52dc47b3838c920c9ee59bad7034")
    end
    assert_raises(ArgumentError) do
      res = @pt.ssl_certificate("0e9a6647d6aba52dc47b3838c920c9ee59bad7034")
    end
  end
  
  def test_ssl_history
    res = @pt.ssl_certificate_history('e9a6647d6aba52dc47b3838c920c9ee59bad7034').response.results
    field_tester(res, ['results'])
    res['results'].each do |rec|
      field_tester(rec, ['sha1', 'firstSeen', 'lastSeen'])
    end
    res = @pt.ssl_certificate_history('52.8.228.23').response.results
    field_tester(res, ['results'])
    res['results'].each do |rec|
      field_tester(rec, ['sha1', 'firstSeen', 'lastSeen'])
    end
  end
  
  def test_components
    res = @pt.components('passivetotal.org').response.results
    field_tester(res, ['results'])
    res['results'].each do |rec|
      field_tester(rec, ['category', 'hostname', 'lastSeen', 'firstSeen', 'label'])
    end
  end
  
  def test_trackers
    res = @pt.trackers('passivetotal.org').response.results
    field_tester(res, ['results'])
    res['results'].each do |rec|
      field_tester(rec, ['lastSeen', 'hostname', 'attributeType', 'firstSeen', 'attributeValue'])
    end
    
    res = @pt.trackers('UA-49901229', 'GoogleAnalyticsAccountNumber').response.results
    field_tester(res, ['results'])
    res['results'].each do |rec|
      field_tester(rec, ['everBlacklisted', 'alexaRank', 'hostname'])
    end
  end
  
  def test_example
    return
    user = ENV['PASSIVETOTAL_USERNAME']
    apikey = ENV['PASSIVETOTAL_APIKEY']
    # EXAMPLE STARTS HERE
    # Initialize the API wrapper with an apikey (using the default endpoint URL of https://api.passivetotal.org/v2/)
    pt = PassiveTotal::API.new(user, apikey)
    # Create an array to shove results into
    res = Array.new
    # ACCOUNT API
    # Get account details your account.
    res << pt.account
    # Get history associated with your account.
    res << pt.history
    # Get details about the organization your account is associated with.
    #res << pt.organization
    # Get the teamstream for the organization your account is associated with.
    res << pt.teamstream
    # Get source details for a specific source.
    res << pt.sources('riskiq')
    
    # DNS API
    # query passive DNS results for the domain, www.passivetotal.org
    res << pt.passive('www.passivetotal.org')
    # query passive DNS results for the ipv4 address, 107.170.89.121
    res << pt.passive('107.170.89.121')
    # query for unique IPv4 resolutions of passivetotal.org
    res << pt.unique('passivetotal.org')
    
    # ENRICHMENT API
    # query enrichment for the domain, www.passivetotal.org
    res << pt.enrichment('www.passivetotal.org')
    # query enrichment for the ipv4 address, 107.170.89.121
    res << pt.enrichment('107.170.89.121')
    # Get malware data
    res << pt.malware('noorno.com')
    # query for malware sample records by the ip addres 98.124.243.47
    res << pt.malware("98.124.243.47")
    # Get opensource intelligence data
    res << pt.osint("xxxmobiletubez.com")
    # query for subdomains of passivetotal.org
    res << pt.subdomains('*.passivetotal.org')
    
    # WHOIS API
    # Get WHOIS data for a domain or IP address
    res << pt.whois("passivetotal.org")
    # Get WHOIS records based on field matching queries.
    res << pt.whois("proxy4655031@1and1-private-registration.com", "email")
    
    # ACTIONS API
    # query for the tags associated with www.chrisleephd.us
    res << pt.tags('www.chrisleephd.us')
    # add the "cool" tag to www.chrisleephd.us
    res << pt.add_tag('www.chrisleephd.us', 'cool')
    # remove the "cool" tag from www.chrisleephd.us (aww, I was cool for a few milliseconds :( )
    res << pt.remove_tag('www.chrisleephd.us', 'cool')    
    # query for the classification of www.passivetotal.org
    res << pt.classification('www.passivetotal.org')
    # set the classification of www.passivetotal.org as benign
    res << pt.classification('www.passivetotal.org', 'non-malicious')
    # query if www.passivetotal.org has ever been listed as compromised
    res << pt.ever_compromised('www.passivetotal.org')
    # set the ever_compromised flag for www.passivetotal.org to false to indicate that it was never compromised or that it is in sole control of a malicious actor.
    res << pt.ever_compromised('www.passivetotal.org', false)
    # check if www.passivetotal.org is a dynamic dns domain/host
    res << pt.dynamic('www.passivetotal.org')
    # flag www.passivetotal.org as not a dynamic dns domain/host
    res << pt.dynamic('www.passivetotal.org', false)
    # check if www.passivetotal.org is being watched
    res << pt.monitor('www.passivetotal.org')
    # unwatch www.passivetotal.org
    res << pt.monitor('www.passivetotal.org', false)
    # query if 107.170.89.121 is a sinkhole
    res << pt.sinkhole('107.170.89.121')
    # set 107.170.89.121 as not a sinkhole
    res << pt.sinkhole('107.170.89.121', false)
    
    # HOST API
    # Get detailed information about a host
    res << pt.components('passivetotal.org')
    # Get all tracking codes for a domain or IP address.
    res << pt.trackers('passivetotal.org')
    # Get hosts matching a specific tracker ID
    res << pt.trackers('UA-49901229', 'GoogleAnalyticsAccountNumber')
    
    # SSL API
    # list sites associated with SSL certificates with SHA-1 hash of e9a6647d6aba52dc47b3838c920c9ee59bad7034
    res << pt.ssl_certificate('e9a6647d6aba52dc47b3838c920c9ee59bad7034')
    # list sites associated with SSL certificates with SHA-1 hash of e9a6647d6aba52dc47b3838c920c9ee59bad7034
    res << pt.ssl_certificate('2317683628587350290823564500811277499', 'serialNumber')
    # retrieve certificate history based on SHA-1 hash of e9a6647d6aba52dc47b3838c920c9ee59bad7034
    res << pt.ssl_certificate_history('e9a6647d6aba52dc47b3838c920c9ee59bad7034')
    # retrieve certificate history from IPv4 address of 52.8.228.23
    res << pt.ssl_certificate_history('52.8.228.23')

    # dump all this glorious information to feast your eyes upon
    pp res
    # EXAMPLE ENDS HERE
  end
  
end
